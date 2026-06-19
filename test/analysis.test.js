// analysis.js の純粋ロジックに対するユニットテスト (DOM 不要)
// node --test で実行。
"use strict";
const test = require("node:test");
const assert = require("node:assert/strict");
const Analysis = require("../parser/analysis.js");

// IP 範囲分類のヘルパー: 必要フィールドのみ与える
const ent = (o) => ({
  count: o.count || 0,
  dmarcPass: o.dmarcPass || 0,
  deliveredPass: o.deliveredPass || 0,
  deliveredFail: o.deliveredFail || 0,
  reject: o.reject || 0,
  quarantine: o.quarantine || 0
});

test("classifyIpRangeTag: 全認証成功・全配送 → legitimate", () => {
  assert.equal(Analysis.classifyIpRangeTag(ent({ count: 10, dmarcPass: 10, deliveredPass: 10 })), "legitimate");
});

test("classifyIpRangeTag: 認証成功実績ありだが未認証配送も混在 → misconfigured", () => {
  // 過去に pass しつつ、未認証のまま配送されたメールがある
  assert.equal(Analysis.classifyIpRangeTag(ent({ count: 10, dmarcPass: 6, deliveredPass: 6, deliveredFail: 4 })), "misconfigured");
});

test("classifyIpRangeTag: 認証成功実績ゼロで未認証配送 → threat", () => {
  assert.equal(Analysis.classifyIpRangeTag(ent({ count: 5, dmarcPass: 0, deliveredFail: 5 })), "threat");
});

test("classifyIpRangeTag: 認証成功実績ゼロで全ブロック → blocked", () => {
  assert.equal(Analysis.classifyIpRangeTag(ent({ count: 5, dmarcPass: 0, reject: 5 })), "blocked");
  assert.equal(Analysis.classifyIpRangeTag(ent({ count: 5, dmarcPass: 0, quarantine: 5 })), "blocked");
});

test("classifyIpRangeTag: 件数ゼロ → unknown", () => {
  assert.equal(Analysis.classifyIpRangeTag(ent({ count: 0 })), "unknown");
});

test("classifyIpRangeTag: 認証成功 + 残りはブロック (未認証配送なし) → legitimate", () => {
  assert.equal(Analysis.classifyIpRangeTag(ent({ count: 10, dmarcPass: 6, deliveredPass: 6, reject: 4 })), "legitimate");
});

// --- ポリシー助言 ---
const keysOf = (advices) => advices.map(a => a.key);
const find = (advices, key) => advices.find(a => a.key === key);

test("computePolicyAdvice: p=none は danger の advicePNone を含む", () => {
  const a = Analysis.computePolicyAdvice({}, { p: "none", sp: "none", adkim: "s", aspf: "s", pct: 100, fo: "1", np: "reject" });
  const adv = find(a, "advicePNone");
  assert.ok(adv && adv.level === "danger");
});

test("computePolicyAdvice: sp が p より弱いと adviceSpWeak (sp=none は danger)", () => {
  const a = Analysis.computePolicyAdvice({ deliveredFailCount: 0, rejectCount: 0 },
    { p: "reject", sp: "none", adkim: "s", aspf: "s", pct: 100, fo: "1", np: "reject" });
  const adv = find(a, "adviceSpWeak");
  assert.ok(adv, "adviceSpWeak が含まれる");
  assert.equal(adv.level, "danger");
  assert.deepEqual(adv.args, ["none", "reject"]);
});

test("computePolicyAdvice: sp が p と同等なら adviceSpWeak は出ない", () => {
  const a = Analysis.computePolicyAdvice({ deliveredFailCount: 0, rejectCount: 0 },
    { p: "reject", sp: "reject", adkim: "s", aspf: "s", pct: 100, fo: "1", np: "reject" });
  assert.equal(find(a, "adviceSpWeak"), undefined);
});

test("computePolicyAdvice: adkim=r と aspf=r の両方を助言", () => {
  const a = Analysis.computePolicyAdvice({ deliveredFailCount: 0, rejectCount: 0 },
    { p: "reject", sp: "reject", adkim: "r", aspf: "r", pct: 100, fo: "1", np: "reject" });
  assert.ok(keysOf(a).includes("adviceAdkimRelaxed"));
  assert.ok(keysOf(a).includes("adviceAspfRelaxed"));
});

test("computePolicyAdvice: p=reject かつ np 未設定で adviceNpMissing", () => {
  const a = Analysis.computePolicyAdvice({ deliveredFailCount: 0, rejectCount: 0 },
    { p: "reject", sp: "reject", adkim: "s", aspf: "s", pct: 100, fo: "1", np: "" });
  assert.ok(keysOf(a).includes("adviceNpMissing"));
});

test("computePolicyAdvice: pct<100 は args に pct を持つ", () => {
  const a = Analysis.computePolicyAdvice({ deliveredFailCount: 0, rejectCount: 0 },
    { p: "reject", sp: "reject", adkim: "s", aspf: "s", pct: 50, fo: "1", np: "reject" });
  const adv = find(a, "advicePctPartial");
  assert.ok(adv);
  assert.deepEqual(adv.args, [50]);
});

test("computePolicyAdvice: 強制運用中の fo=0 で adviceFo", () => {
  const a = Analysis.computePolicyAdvice({ deliveredFailCount: 0, rejectCount: 0 },
    { p: "reject", sp: "reject", adkim: "s", aspf: "s", pct: 100, fo: "0", np: "reject" });
  assert.ok(keysOf(a).includes("adviceFo"));
});

test("computePolicyAdvice: 完全クリーンな p=reject は advicePRejectClean (alignParts 付き)", () => {
  const a = Analysis.computePolicyAdvice(
    { deliveredFailCount: 0, rejectCount: 0, dkimPassCount: 100, spfPassCount: 80, passCount: 80 },
    { p: "reject", sp: "reject", adkim: "s", aspf: "s", pct: 100, fo: "1", np: "reject" });
  const adv = find(a, "advicePRejectClean");
  assert.ok(adv && adv.level === "ok");
  // dkimPass(100) > full(80) → SPF 非整合が 20 件 → alignParts に "SPF"
  assert.deepEqual(adv.alignParts, ["SPF"]);
});
