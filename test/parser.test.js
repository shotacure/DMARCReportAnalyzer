// ar_parser.js の純粋ロジックに対するユニットテスト (DOM 不要)
// node --test で実行。
"use strict";
const test = require("node:test");
const assert = require("node:assert/strict");
const ArParser = require("../parser/ar_parser.js");

// --- テスト用のレコード/レポート生成ヘルパー ---
const rec = (o) => ({
  sourceIp: o.ip,
  count: o.count,
  headerFrom: o.hf || "example.com",
  envelopeFrom: o.ef || "",
  envelopeTo: "",
  disposition: o.disp || "none",
  dkimPolicyResult: o.dkim || "fail",
  spfPolicyResult: o.spf || "fail",
  reasons: o.reasons || [],
  dkimResults: o.dkimResults || [],
  spfResults: o.spfResults || []
});

const makeReport = (org, domain, records, opts = {}) => ({
  reportKey: `${org}!${domain}!${opts.id || "r"}`,
  reportId: opts.id || "r",
  reporter: { orgName: org, email: "a@b.c", extraContactInfo: "" },
  dateRange: { begin: opts.begin || 1700000000, end: opts.end || 1700086400 },
  metadataErrors: [],
  policy: { domain, adkim: "r", aspf: "r", p: "none", sp: "none", pct: 100, fo: "0", np: "" },
  records,
  summary: ArParser.computeSummary(records, domain),
  warnings: []
});

test("computeSummary: DMARC pass は DKIM か SPF の OR、配送成否を正しく分離", () => {
  const records = [
    rec({ ip: "1.1.1.1", count: 10, dkim: "pass", spf: "pass", disp: "none" }), // full pass, delivered
    rec({ ip: "2.2.2.2", count: 5, dkim: "fail", spf: "pass", disp: "none" }),  // spf only, delivered
    rec({ ip: "3.3.3.3", count: 3, dkim: "fail", spf: "fail", disp: "none" }),  // delivered fail
    rec({ ip: "4.4.4.4", count: 2, dkim: "fail", spf: "fail", disp: "reject" }) // blocked
  ];
  const s = ArParser.computeSummary(records, "example.com");
  assert.equal(s.totalCount, 20);
  assert.equal(s.passCount, 10);            // DKIM+SPF 両方
  assert.equal(s.dkimPassCount, 10);
  assert.equal(s.spfPassCount, 15);
  assert.equal(s.deliveredPassCount, 15);   // 配送 & DMARC pass
  assert.equal(s.deliveredFailCount, 3);    // 配送 & DMARC fail
  assert.equal(s.rejectCount, 2);
  assert.equal(s.quarantineCount, 0);
  assert.equal(s.noneCount, 18);
  assert.equal(s.uniqueSourceIps, 4);
});

test("aggregateSummaries: 生レコードから再集計し、上位N件の二重トランケーションで欠落しない", () => {
  // 40 個の異なる /16 送信元 (各 count=1)。
  // 1 レポートあたり topSourceIps は 20 件、topIpRanges は 30 件に切り詰められるが、
  // 集約の uniqueSourceIps / uniqueIpRanges は完全な 40 でなければならない。
  const records = [];
  for (let i = 0; i < 40; i++) {
    records.push(rec({ ip: `10.${i}.0.1`, count: 1, dkim: "pass", spf: "pass", disp: "none" }));
  }
  const report = makeReport("Org", "example.com", records);

  // 前提: per-report の表示用リストは切り詰められている
  assert.equal(report.summary.topSourceIps.length, 20);
  assert.ok(report.summary.topIpRanges.length <= 30);

  const agg = ArParser.aggregateSummaries([report]);
  assert.equal(agg.totalCount, 40);
  assert.equal(agg.uniqueSourceIps, 40, "全送信元 IP が正確に数えられる");
  assert.equal(agg.uniqueIpRanges, 40, "全 IP 範囲が正確に数えられる");
});

test("aggregateSummaries: 複数レポートにまたがる低ボリューム送信元を取りこぼさない", () => {
  // 各レポートで高ボリュームのフィラーに埋もれる稀少 IP "9.9.9.9" を 2 レポートに 1 件ずつ配置。
  const build = (id, fillerBase) => {
    const records = [rec({ ip: "9.9.9.9", count: 1, dkim: "fail", spf: "fail", disp: "none" })];
    for (let i = 0; i < 35; i++) records.push(rec({ ip: `${fillerBase}.${i}.0.5`, count: 50, dkim: "pass", spf: "pass", disp: "none" }));
    return makeReport("Org", "example.com", records, { id });
  };
  const agg = ArParser.aggregateSummaries([build("a", "11"), build("b", "12")]);
  // 稀少 IP も含め全ユニーク送信元が数えられる (9.9.9.9 + 70 フィラー = 71)
  assert.equal(agg.uniqueSourceIps, 71);
});

test("sanitizeXml: BOM 除去・diskim 修正・裸の & エスケープ・制御文字除去", () => {
  const dirty = "﻿<feedback><x>a & b</x><diskim>d</diskim>\x07</feedback>";
  const clean = ArParser.sanitizeXml(dirty);
  assert.ok(!clean.startsWith("﻿"), "BOM が除去される");
  assert.ok(clean.includes("a &amp; b"), "裸の & が &amp; になる");
  assert.ok(clean.includes("<dkim>d</dkim>"), "diskim タグが dkim に修正される");
  assert.ok(!clean.includes("\x07"), "制御文字が除去される");
  // 既存の正しいエンティティは二重エスケープしない
  assert.equal(ArParser.sanitizeXml("<x>a &amp; b &#10; &#x41;</x>"), "<x>a &amp; b &#10; &#x41;</x>");
});
