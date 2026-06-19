// DMARCReportAnalyzer - parser/ar_parser.js
// 集約レポート (Aggregate Report) XML パーサー
// RFC 7489 に準拠した DMARC 集約レポート XML を正規化データに変換する。
// DOMParser を使用し、外部ライブラリに依存しない。
// 全要素を網羅的に取得し、情報欠落を warnings として報告する。

const ArParser = (() => {
  "use strict";

  // =========================================================
  // ヘルパー: XML 要素から安全にテキストを取得
  // =========================================================
  const getText = (parent, tagName) => {
    if (!parent) return "";
    const el = parent.querySelector(tagName);
    return el?.textContent?.trim() || "";
  };

  const getInt = (parent, tagName) => {
    const val = parseInt(getText(parent, tagName), 10);
    return isNaN(val) ? 0 : val;
  };

  // =========================================================
  // IP アドレスを Class C 範囲に変換
  // IPv4: "192.168.1.42" → "192.168.1.xxx"
  // IPv6: 先頭48ビット (/48) → "2001:db8:85a3:xxxx:..."
  // =========================================================
  const toIpRange = (ip) => {
    if (!ip) return "unknown";
    if (ip.includes(".") && !ip.includes(":")) {
      const parts = ip.split(".");
      if (parts.length === 4) return `${parts[0]}.${parts[1]}.${parts[2]}.xxx`;
      return ip;
    }
    try {
      let expanded = ip;
      if (expanded.includes("::")) {
        const halves = expanded.split("::");
        const left = halves[0] ? halves[0].split(":") : [];
        const right = halves[1] ? halves[1].split(":") : [];
        const missing = 8 - left.length - right.length;
        const middle = Array(missing).fill("0");
        expanded = [...left, ...middle, ...right].join(":");
      }
      const groups = expanded.split(":");
      if (groups.length >= 3) {
        const prefix = groups.slice(0, 3).map(g => g.replace(/^0+/, "") || "0").join(":");
        return `${prefix}:xxxx:...`;
      }
    } catch (e) { /* パース失敗時はそのまま返す */ }
    return ip;
  };

  // =========================================================
  // 詳細統計ヘルパー: レコード群をキー別にグループ化し統計を返す
  // =========================================================
  const computeDetailedStats = (entries) => {
    const map = new Map();
    for (const e of entries) {
      const existing = map.get(e.key);
      if (existing) {
        existing.count += e.count;
        existing.dkimPass += e.dkimPass;
        existing.spfPass += e.spfPass;
        existing.fullPass += e.fullPass;
        existing.dmarcPass += (e.dmarcPass || 0);
        existing.deliveredPass += e.deliveredPass;
        existing.deliveredFail += e.deliveredFail;
        existing.quarantine += e.quarantine;
        existing.reject += e.reject;
      } else {
        map.set(e.key, { ...e, dmarcPass: e.dmarcPass || 0 });
      }
    }

    return [...map.values()]
      .sort((a, b) => b.count - a.count)
      .slice(0, 30)
      .map(s => ({
        key: s.key,
        count: s.count,
        fullPass: s.fullPass,
        dmarcPass: s.dmarcPass,
        dkimPass: s.dkimPass,
        spfPass: s.spfPass,
        deliveredPass: s.deliveredPass,
        deliveredFail: s.deliveredFail,
        quarantine: s.quarantine,
        reject: s.reject
      }));
  };

  // =========================================================
  // IP 範囲の適応的集約: 同じ /16 (IPv4) または /32 (IPv6) に
  // 属するエントリが2つ以上ある場合、より広い範囲にマージする
  // 例: 106.117.1.xxx + 106.117.5.xxx → 106.117.xxx.xxx
  // =========================================================
  const mergeIpRanges = (entries) => {
    // 各エントリの親範囲 (/16 or /32) を判定
    const getParentKey = (key) => {
      // IPv4: "192.168.1.xxx" → 親 "192.168", マージ後 "192.168.xxx.xxx"
      if (key.includes(".") && !key.includes(":")) {
        const parts = key.split(".");
        if (parts.length >= 2) {
          return { parent: `${parts[0]}.${parts[1]}`, merged: `${parts[0]}.${parts[1]}.xxx.xxx` };
        }
      }
      // IPv6: "2001:db8:85a3:xxxx:..." → 親 "2001:db8", マージ後 "2001:db8:xxxx:..."
      if (key.includes(":")) {
        const parts = key.split(":");
        if (parts.length >= 2) {
          return { parent: `${parts[0]}:${parts[1]}`, merged: `${parts[0]}:${parts[1]}:xxxx:...` };
        }
      }
      return null;
    };

    // 親範囲ごとにグループ化
    const parentGroups = new Map();
    const noParent = [];
    for (const e of entries) {
      const pr = getParentKey(e.key);
      if (!pr) { noParent.push(e); continue; }
      if (!parentGroups.has(pr.parent)) {
        parentGroups.set(pr.parent, { mergedKey: pr.merged, items: [] });
      }
      parentGroups.get(pr.parent).items.push(e);
    }

    // 同じ親に2つ以上のエントリがあればマージ、1つならそのまま
    const result = [...noParent];
    for (const [, group] of parentGroups) {
      if (group.items.length >= 2) {
        // 統計値を合算してマージ
        const merged = {
          key: group.mergedKey, count: 0, fullPass: 0, dmarcPass: 0, dkimPass: 0, spfPass: 0,
          deliveredPass: 0, deliveredFail: 0, quarantine: 0, reject: 0
        };
        for (const item of group.items) {
          merged.count += item.count;
          merged.fullPass += item.fullPass;
          merged.dmarcPass += (item.dmarcPass || 0);
          merged.dkimPass += item.dkimPass;
          merged.spfPass += item.spfPass;
          merged.deliveredPass += item.deliveredPass;
          merged.deliveredFail += item.deliveredFail;
          merged.quarantine += item.quarantine;
          merged.reject += item.reject;
        }
        result.push(merged);
      } else {
        result.push(...group.items);
      }
    }

    return result.sort((a, b) => b.count - a.count);
  };

  // =========================================================
  // ポリシーオーバーライド詳細の集約:
  // 理由(type) + IP範囲(ipRange) をキーにしてグループ化
  // =========================================================
  const aggregateOverrideDetails = (entries) => {
    const map = new Map();
    for (const e of entries) {
      const key = `${e.type}|${e.ipRange}`;
      const existing = map.get(key);
      if (existing) {
        existing.count += e.count;
      } else {
        map.set(key, { type: e.type, comment: e.comment, ipRange: e.ipRange, count: e.count });
      }
    }
    return [...map.values()].sort((a, b) => b.count - a.count);
  };

  // =========================================================
  // XML サニタイズ: ISP 固有の XML 不整合を DOMParser に渡す前に修正
  // 現場の集約レポートは ISP ごとに細かな破損があるため、
  // DOMParser が parsererror を返す前に既知のパターンを正規化する。
  // =========================================================
  const sanitizeXml = (xmlText) => {
    let sanitized = String(xmlText);
    // UTF-8 BOM を除去 (先頭に残ると DOMParser が稀に失敗する)
    if (sanitized.charCodeAt(0) === 0xFEFF) sanitized = sanitized.slice(1);
    // 宣言前の先頭空白・制御文字を除去 (<?xml または < より前のゴミ)
    sanitized = sanitized.replace(/^[\s﻿\x00-\x1F]+(?=<)/, "");
    // XML 1.0 で不正な制御文字を除去 (TAB/LF/CR を除く C0 制御文字)
    sanitized = sanitized.replace(/[\x00-\x08\x0B\x0C\x0E-\x1F]/g, "");
    // Microsoft の既知の typo: <diskim> → <dkim> (開きタグ・閉じタグ両方)
    sanitized = sanitized.replace(/<(\/?)diskim>/g, "<$1dkim>");
    // エンティティ化されていない裸の & を &amp; に修正
    // (有効な &name; / &#10; / &#x1F; のみ温存)
    sanitized = sanitized.replace(/&(?!(?:[a-zA-Z][a-zA-Z0-9]*|#\d+|#x[0-9a-fA-F]+);)/g, "&amp;");
    return sanitized;
  };

  // =========================================================
  // 情報欠落チェック: レポート全体の完全性を検証
  // =========================================================
  const validateReport = (report) => {
    const warnings = [];
    if (!report.reporter.orgName) warnings.push({ field: "org_name", message: "Reporter organization name is missing" });
    if (!report.reportId) warnings.push({ field: "report_id", message: "Report ID is missing" });
    if (!report.reporter.email) warnings.push({ field: "email", message: "Reporter contact email is missing" });
    if (report.dateRange.begin === 0) warnings.push({ field: "date_range.begin", message: "Report date range begin is missing or zero" });
    if (report.dateRange.end === 0) warnings.push({ field: "date_range.end", message: "Report date range end is missing or zero" });
    if (!report.policy.domain) warnings.push({ field: "policy.domain", message: "Published policy domain is missing" });
    if (!report.policy.p) warnings.push({ field: "policy.p", message: "Published policy disposition (p=) is missing" });
    if (report.records.length === 0) warnings.push({ field: "records", message: "Report contains no record entries" });

    for (let i = 0; i < report.records.length; i++) {
      const rec = report.records[i];
      const prefix = `record[${i}]`;
      if (!rec.sourceIp) warnings.push({ field: `${prefix}.source_ip`, message: `Record #${i + 1}: source IP is missing` });
      if (rec.count === 0) warnings.push({ field: `${prefix}.count`, message: `Record #${i + 1}: message count is zero` });
      if (!rec.dkimPolicyResult) warnings.push({ field: `${prefix}.policy_evaluated.dkim`, message: `Record #${i + 1}: DKIM policy evaluation result is missing` });
      if (!rec.spfPolicyResult) warnings.push({ field: `${prefix}.policy_evaluated.spf`, message: `Record #${i + 1}: SPF policy evaluation result is missing` });
      if (!rec.disposition) warnings.push({ field: `${prefix}.disposition`, message: `Record #${i + 1}: disposition is missing` });
      if (rec.dkimResults.length === 0 && rec.spfResults.length === 0) warnings.push({ field: `${prefix}.auth_results`, message: `Record #${i + 1}: no DKIM or SPF auth_results present` });
      if (!rec.headerFrom) warnings.push({ field: `${prefix}.header_from`, message: `Record #${i + 1}: header_from identifier is missing` });
    }
    return warnings;
  };

  // =========================================================
  // メイン: XML テキスト → 正規化済みレポートオブジェクト
  // =========================================================
  const parse = (xmlText) => {
    const sanitizedXml = sanitizeXml(xmlText);
    const parser = new DOMParser();
    const doc = parser.parseFromString(sanitizedXml, "text/xml");

    const parseError = doc.querySelector("parsererror");
    if (parseError) throw new Error(`XML parse error: ${parseError.textContent}`);

    const feedback = doc.querySelector("feedback");
    if (!feedback) throw new Error("Invalid DMARC report: <feedback> element not found.");

    const metadata = feedback.querySelector("report_metadata");
    const orgName = getText(metadata, "org_name");
    const email = getText(metadata, "email");
    const extraContactInfo = getText(metadata, "extra_contact_info");
    const reportId = getText(metadata, "report_id");
    const dateRange = metadata?.querySelector("date_range");
    const dateBegin = getInt(dateRange, "begin");
    const dateEnd = getInt(dateRange, "end");

    const metadataErrors = [];
    const errorElements = metadata?.querySelectorAll("error") || [];
    for (const errEl of errorElements) {
      const errText = errEl.textContent?.trim();
      if (errText) metadataErrors.push(errText);
    }

    const policy = feedback.querySelector("policy_published");
    const domain = getText(policy, "domain");
    const policyAdkim = getText(policy, "adkim") || "r";
    const policyAspf = getText(policy, "aspf") || "r";
    const policyP = getText(policy, "p");
    const policySp = getText(policy, "sp") || policyP;
    const policyPct = getInt(policy, "pct") || 100;
    const policyFo = getText(policy, "fo") || "0";
    const policyNp = getText(policy, "np");

    const recordElements = feedback.querySelectorAll("record");
    const records = [];

    for (const rec of recordElements) {
      const row = rec.querySelector("row");
      const sourceIp = getText(row, "source_ip");
      const count = getInt(row, "count");
      const headerFrom = getText(rec, "identifiers > header_from");
      const envelopeFrom = getText(rec, "identifiers > envelope_from");
      const envelopeTo = getText(rec, "identifiers > envelope_to");

      const pe = row?.querySelector("policy_evaluated");
      const disposition = getText(pe, "disposition");
      const dkimPolicyResult = getText(pe, "dkim");
      const spfPolicyResult = getText(pe, "spf");

      const reasons = [];
      const reasonElements = pe?.querySelectorAll("reason") || [];
      for (const r of reasonElements) {
        reasons.push({ type: getText(r, "type"), comment: getText(r, "comment") });
      }

      const authResults = rec.querySelector("auth_results");
      const dkimResults = [];
      const dkimElements = authResults?.querySelectorAll("dkim") || [];
      for (const d of dkimElements) {
        dkimResults.push({
          domain: getText(d, "domain"), selector: getText(d, "selector"),
          result: getText(d, "result") || getText(d, "r"),
          humanResult: getText(d, "human_result")
        });
      }

      const spfResults = [];
      const spfElements = authResults?.querySelectorAll("spf") || [];
      for (const s of spfElements) {
        spfResults.push({
          domain: getText(s, "domain"), scope: getText(s, "scope"),
          result: getText(s, "result") || getText(s, "r")
        });
      }

      records.push({
        sourceIp, count, headerFrom, envelopeFrom, envelopeTo,
        disposition, dkimPolicyResult, spfPolicyResult,
        reasons, dkimResults, spfResults
      });
    }

    const reportKey = `${orgName}!${domain}!${dateBegin}!${dateEnd}!${reportId}`;
    const report = {
      reportKey, reportId,
      reporter: { orgName, email, extraContactInfo },
      dateRange: { begin: dateBegin, end: dateEnd },
      metadataErrors,
      policy: { domain, adkim: policyAdkim, aspf: policyAspf, p: policyP, sp: policySp, pct: policyPct, fo: policyFo, np: policyNp },
      records,
      summary: computeSummary(records, domain),
      warnings: []
    };
    report.warnings = validateReport(report);
    return report;
  };

  // =========================================================
  // サマリー計算: レコード群から統計値を算出
  // policyDomain: Header From との一致判定に使用
  // =========================================================
  const computeSummary = (records, policyDomain) => {
    let totalCount = 0;
    let passCount = 0;
    let dkimPassCount = 0;
    let spfPassCount = 0;
    let rejectCount = 0;
    let quarantineCount = 0;
    let noneCount = 0;
    let deliveredPassCount = 0;
    let deliveredFailCount = 0;
    const sourceIps = new Map();
    const ipRanges = new Map();
    const overrideReasons = new Map();
    const ipRangeEntries = [];

    // DKIM 署名ドメイン+セレクタの集計 (署名ドメインとセレクタで一意化)
    const dkimSigMap = new Map();
    // SPF 認証ドメインの集計
    const spfDomainMap = new Map();
    // Header From vs Envelope From の不一致検出
    const envelopeMap = new Map();
    // サブドメイン別の集計 (header_from がポリシードメインのサブドメインの場合)
    const subdomainMap = new Map();
    // ポリシーオーバーライド理由と IP 範囲の紐づけ
    const overrideDetailEntries = [];

    const lowerPolicyDomain = (policyDomain || "").toLowerCase();

    for (const rec of records) {
      totalCount += rec.count;

      const isDkimPass = rec.dkimPolicyResult === "pass";
      const isSpfPass = rec.spfPolicyResult === "pass";
      const isFullPass = isDkimPass && isSpfPass;
      // DMARC は DKIM か SPF のどちらか一方が pass すれば合格 (RFC 7489)
      const isDmarcPass = isDkimPass || isSpfPass;
      const isDelivered = rec.disposition !== "quarantine" && rec.disposition !== "reject";

      if (isDkimPass) dkimPassCount += rec.count;
      if (isSpfPass) spfPassCount += rec.count;
      if (isFullPass) passCount += rec.count;

      // 配送済の認証成功/失敗は DMARC 判定 (OR) で分離
      if (isDelivered && isDmarcPass) deliveredPassCount += rec.count;
      if (isDelivered && !isDmarcPass) deliveredFailCount += rec.count;

      switch (rec.disposition) {
        case "reject":     rejectCount += rec.count;     break;
        case "quarantine": quarantineCount += rec.count;  break;
        default:           noneCount += rec.count;        break;
      }

      const ipTotal = sourceIps.get(rec.sourceIp) || 0;
      sourceIps.set(rec.sourceIp, ipTotal + rec.count);

      const range = toIpRange(rec.sourceIp);
      const rangeTotal = ipRanges.get(range) || 0;
      ipRanges.set(range, rangeTotal + rec.count);

      ipRangeEntries.push({
        key: range, count: rec.count,
        dkimPass: isDkimPass ? rec.count : 0,
        spfPass: isSpfPass ? rec.count : 0,
        fullPass: isFullPass ? rec.count : 0,
        dmarcPass: isDmarcPass ? rec.count : 0,
        deliveredPass: (isDelivered && isDmarcPass) ? rec.count : 0,
        deliveredFail: (isDelivered && !isDmarcPass) ? rec.count : 0,
        quarantine: rec.disposition === "quarantine" ? rec.count : 0,
        reject: rec.disposition === "reject" ? rec.count : 0
      });

      for (const reason of rec.reasons) {
        if (reason.type) {
          const existing = overrideReasons.get(reason.type) || 0;
          overrideReasons.set(reason.type, existing + rec.count);
          // オーバーライド理由と IP 範囲を紐づけて追跡
          overrideDetailEntries.push({
            type: reason.type,
            comment: reason.comment || "",
            ipRange: toIpRange(rec.sourceIp),
            count: rec.count
          });
        }
      }

      // DKIM 署名の集計: domain + selector をキーにしてグループ化
      for (const dk of rec.dkimResults) {
        if (!dk.domain) continue;
        const sigKey = `${dk.domain.toLowerCase()}/${dk.selector || "(none)"}`;
        const existing = dkimSigMap.get(sigKey);
        const isPass = dk.result === "pass";
        // 署名ドメインが Header From ドメインと一致するか (第三者署名の判定)
        const isThirdParty = dk.domain.toLowerCase() !== lowerPolicyDomain;
        if (existing) {
          existing.count += rec.count;
          existing.pass += isPass ? rec.count : 0;
          existing.fail += isPass ? 0 : rec.count;
        } else {
          dkimSigMap.set(sigKey, {
            domain: dk.domain.toLowerCase(),
            selector: dk.selector || "(none)",
            count: rec.count,
            pass: isPass ? rec.count : 0,
            fail: isPass ? 0 : rec.count,
            isThirdParty
          });
        }
      }

      // SPF ドメインの集計: domain をキーにしてグループ化、scope を追跡
      for (const sp of rec.spfResults) {
        if (!sp.domain) continue;
        const spKey = sp.domain.toLowerCase();
        const isPass = sp.result === "pass";
        const scope = sp.scope || "mfrom";
        const existing = spfDomainMap.get(spKey);
        if (existing) {
          existing.count += rec.count;
          existing.pass += isPass ? rec.count : 0;
          existing.fail += isPass ? 0 : rec.count;
          if (!existing.scopes.has(scope)) existing.scopes.add(scope);
        } else {
          spfDomainMap.set(spKey, {
            domain: sp.domain.toLowerCase(),
            count: rec.count,
            pass: isPass ? rec.count : 0,
            fail: isPass ? 0 : rec.count,
            scopes: new Set([scope])
          });
        }
      }

      // Envelope From と Header From の不一致検出
      const hf = (rec.headerFrom || "").toLowerCase();
      const ef = (rec.envelopeFrom || "").toLowerCase();
      if (hf && ef && hf !== ef) {
        const mismatchKey = `${hf}|${ef}`;
        const existing = envelopeMap.get(mismatchKey);
        if (existing) {
          existing.count += rec.count;
          existing.pass += isDmarcPass ? rec.count : 0;
          existing.fail += isDmarcPass ? 0 : rec.count;
        } else {
          envelopeMap.set(mismatchKey, {
            headerFrom: hf, envelopeFrom: ef,
            count: rec.count,
            pass: isDmarcPass ? rec.count : 0,
            fail: isDmarcPass ? 0 : rec.count
          });
        }
      }

      // サブドメイン検出: headerFrom がポリシードメインのサブドメインかチェック
      if (hf && lowerPolicyDomain && hf !== lowerPolicyDomain && hf.endsWith("." + lowerPolicyDomain)) {
        const existing = subdomainMap.get(hf);
        if (existing) {
          existing.count += rec.count;
          existing.pass += isDmarcPass ? rec.count : 0;
          existing.fail += isDmarcPass ? 0 : rec.count;
          existing.reject += rec.disposition === "reject" ? rec.count : 0;
        } else {
          subdomainMap.set(hf, {
            subdomain: hf,
            count: rec.count,
            pass: isDmarcPass ? rec.count : 0,
            fail: isDmarcPass ? 0 : rec.count,
            reject: rec.disposition === "reject" ? rec.count : 0
          });
        }
      }
    }

    return {
      totalCount, passCount, dkimPassCount, spfPassCount,
      rejectCount, quarantineCount, noneCount,
      deliveredPassCount, deliveredFailCount,
      dkimPassRate: totalCount > 0 ? (dkimPassCount / totalCount * 100) : 0,
      spfPassRate: totalCount > 0 ? (spfPassCount / totalCount * 100) : 0,
      fullPassRate: totalCount > 0 ? (passCount / totalCount * 100) : 0,
      uniqueSourceIps: sourceIps.size,
      uniqueIpRanges: ipRanges.size,
      topSourceIps: [...sourceIps.entries()]
        .sort((a, b) => b[1] - a[1]).slice(0, 20)
        .map(([ip, count]) => ({ ip, count })),
      topIpRanges: mergeIpRanges(computeDetailedStats(ipRangeEntries)),
      overrideReasons: [...overrideReasons.entries()]
        .sort((a, b) => b[1] - a[1])
        .map(([type, count]) => ({ type, count })),
      // DKIM 署名ドメイン+セレクタの一覧 (件数順)
      dkimSignatures: [...dkimSigMap.values()]
        .sort((a, b) => b.count - a.count),
      // SPF 認証ドメインの一覧 (件数順、scopes を配列に変換)
      spfDomains: [...spfDomainMap.values()]
        .sort((a, b) => b.count - a.count)
        .map(s => ({ ...s, scopes: [...s.scopes] })),
      // Header From / Envelope From の不一致ペア (件数順)
      envelopeMismatches: [...envelopeMap.values()]
        .sort((a, b) => b.count - a.count),
      // サブドメイン別の集計 (検出されたもののみ)
      subdomains: [...subdomainMap.values()]
        .sort((a, b) => b.count - a.count),
      // ポリシーオーバーライドの詳細 (理由 + IP 範囲)
      overrideDetails: aggregateOverrideDetails(overrideDetailEntries)
    };
  };

  // =========================================================
  // 複数レポートの統合サマリー
  // =========================================================
  const aggregateSummaries = (reports) => {
    let totalCount = 0, passCount = 0, dkimPassCount = 0, spfPassCount = 0;
    let rejectCount = 0, quarantineCount = 0, noneCount = 0;
    let deliveredPassCount = 0, deliveredFailCount = 0;
    const sourceIps = new Map();
    const reporters = new Map();
    const domains = new Map();
    const overrideReasons = new Map();
    const ipRangeEntries = [];
    const reporterEntries = [];
    let dateRangeMin = Infinity, dateRangeMax = 0;
    let totalWarnings = 0, reportsWithWarnings = 0, reportsWithMetadataErrors = 0;
    const warningFieldCounts = new Map();

    // 集約用: DKIM 署名 / SPF ドメイン / Envelope 不一致 / サブドメイン / オーバーライド詳細
    const dkimSigMap = new Map();
    const spfDomainMap = new Map();
    const envelopeMap = new Map();
    const subdomainMap = new Map();
    const overrideDetailEntries = [];

    for (const report of reports) {
      const s = report.summary;
      totalCount += s.totalCount;
      passCount += s.passCount;
      dkimPassCount += s.dkimPassCount;
      spfPassCount += s.spfPassCount;
      rejectCount += s.rejectCount;
      quarantineCount += s.quarantineCount;
      noneCount += s.noneCount;
      deliveredPassCount += s.deliveredPassCount;
      deliveredFailCount += s.deliveredFailCount;

      if (report.dateRange.begin > 0 && report.dateRange.begin < dateRangeMin) dateRangeMin = report.dateRange.begin;
      if (report.dateRange.end > 0 && report.dateRange.end > dateRangeMax) dateRangeMax = report.dateRange.end;

      const rCount = reporters.get(report.reporter.orgName) || 0;
      reporters.set(report.reporter.orgName, rCount + 1);

      const dCount = domains.get(report.policy.domain) || 0;
      domains.set(report.policy.domain, dCount + s.totalCount);

      // 送信元 IP / IP 範囲 / レポーター別の統計は、各レポートで上位 N 件に
      // 切り詰められた summary ではなく生レコードから再集計する。
      // summary 経由だと「単一レポートでは少量だが多数のレポートに分散する
      // 送信元」が二重トランケーション (per-report top-N → aggregate top-N) で
      // 欠落し、分散スプーフィングを取りこぼすため。
      for (const rec of report.records) {
        const isDkimPass = rec.dkimPolicyResult === "pass";
        const isSpfPass = rec.spfPolicyResult === "pass";
        const isFullPass = isDkimPass && isSpfPass;
        const isDmarcPass = isDkimPass || isSpfPass;
        const isDelivered = rec.disposition !== "quarantine" && rec.disposition !== "reject";

        const stat = {
          count: rec.count,
          dkimPass: isDkimPass ? rec.count : 0,
          spfPass: isSpfPass ? rec.count : 0,
          fullPass: isFullPass ? rec.count : 0,
          dmarcPass: isDmarcPass ? rec.count : 0,
          deliveredPass: (isDelivered && isDmarcPass) ? rec.count : 0,
          deliveredFail: (isDelivered && !isDmarcPass) ? rec.count : 0,
          quarantine: rec.disposition === "quarantine" ? rec.count : 0,
          reject: rec.disposition === "reject" ? rec.count : 0
        };

        // 送信元 IP は完全な解像度で集計 (uniqueSourceIps を正確にするため)
        sourceIps.set(rec.sourceIp, (sourceIps.get(rec.sourceIp) || 0) + rec.count);
        // IP 範囲 (Class C / IPv6 /48) — 後段で mergeIpRanges に渡す
        ipRangeEntries.push({ key: toIpRange(rec.sourceIp), ...stat });
        // レポーター別
        reporterEntries.push({ key: report.reporter.orgName, ...stat });
      }

      for (const reason of s.overrideReasons) {
        const existing = overrideReasons.get(reason.type) || 0;
        overrideReasons.set(reason.type, existing + reason.count);
      }

      // DKIM 署名の集約: 各レポートの dkimSignatures をマージ
      for (const sig of (s.dkimSignatures || [])) {
        const sigKey = `${sig.domain}/${sig.selector}`;
        const existing = dkimSigMap.get(sigKey);
        if (existing) {
          existing.count += sig.count;
          existing.pass += sig.pass;
          existing.fail += sig.fail;
        } else {
          dkimSigMap.set(sigKey, { ...sig });
        }
      }

      // SPF ドメインの集約
      for (const sp of (s.spfDomains || [])) {
        const existing = spfDomainMap.get(sp.domain);
        if (existing) {
          existing.count += sp.count;
          existing.pass += sp.pass;
          existing.fail += sp.fail;
          for (const sc of sp.scopes) { if (!existing.scopes.includes(sc)) existing.scopes.push(sc); }
        } else {
          spfDomainMap.set(sp.domain, { ...sp, scopes: [...sp.scopes] });
        }
      }

      // Envelope 不一致の集約
      for (const em of (s.envelopeMismatches || [])) {
        const emKey = `${em.headerFrom}|${em.envelopeFrom}`;
        const existing = envelopeMap.get(emKey);
        if (existing) {
          existing.count += em.count;
          existing.pass += em.pass;
          existing.fail += em.fail;
        } else {
          envelopeMap.set(emKey, { ...em });
        }
      }

      // サブドメインの集約
      for (const sd of (s.subdomains || [])) {
        const existing = subdomainMap.get(sd.subdomain);
        if (existing) {
          existing.count += sd.count;
          existing.pass += sd.pass;
          existing.fail += sd.fail;
          existing.reject += sd.reject;
        } else {
          subdomainMap.set(sd.subdomain, { ...sd });
        }
      }

      // ポリシーオーバーライド詳細の集約
      for (const od of (s.overrideDetails || [])) {
        overrideDetailEntries.push(od);
      }

      if (report.warnings && report.warnings.length > 0) {
        reportsWithWarnings++;
        totalWarnings += report.warnings.length;
        const seenFields = new Set();
        for (const w of report.warnings) {
          const category = w.field.replace(/\[\d+\]/, "[*]");
          if (!seenFields.has(category)) {
            seenFields.add(category);
            warningFieldCounts.set(category, (warningFieldCounts.get(category) || 0) + 1);
          }
        }
      }
      if (report.metadataErrors && report.metadataErrors.length > 0) reportsWithMetadataErrors++;
    }

    return {
      totalCount, passCount, dkimPassCount, spfPassCount,
      rejectCount, quarantineCount, noneCount,
      deliveredPassCount, deliveredFailCount,
      dkimPassRate: totalCount > 0 ? (dkimPassCount / totalCount * 100) : 0,
      spfPassRate: totalCount > 0 ? (spfPassCount / totalCount * 100) : 0,
      fullPassRate: totalCount > 0 ? (passCount / totalCount * 100) : 0,
      reportCount: reports.length,
      uniqueSourceIps: sourceIps.size,
      uniqueIpRanges: new Set(ipRangeEntries.map(e => e.key)).size,
      dateRangeMin: dateRangeMin === Infinity ? 0 : dateRangeMin,
      dateRangeMax,
      topSourceIps: [...sourceIps.entries()]
        .sort((a, b) => b[1] - a[1]).slice(0, 20)
        .map(([ip, count]) => ({ ip, count })),
      topIpRanges: mergeIpRanges(computeDetailedStats(ipRangeEntries)),
      topReporters: computeDetailedStats(reporterEntries),
      reporters: [...reporters.entries()]
        .sort((a, b) => b[1] - a[1])
        .map(([name, count]) => ({ name, count })),
      domains: [...domains.entries()]
        .sort((a, b) => b[1] - a[1])
        .map(([domain, count]) => ({ domain, count })),
      overrideReasons: [...overrideReasons.entries()]
        .sort((a, b) => b[1] - a[1])
        .map(([type, count]) => ({ type, count })),
      // DKIM 署名の集約結果
      dkimSignatures: [...dkimSigMap.values()].sort((a, b) => b.count - a.count),
      // SPF ドメインの集約結果
      spfDomains: [...spfDomainMap.values()].sort((a, b) => b.count - a.count),
      // Envelope 不一致の集約結果
      envelopeMismatches: [...envelopeMap.values()].sort((a, b) => b.count - a.count),
      // サブドメイン別の集約結果
      subdomains: [...subdomainMap.values()].sort((a, b) => b.count - a.count),
      // ポリシーオーバーライド詳細の集約結果
      overrideDetails: aggregateOverrideDetails(overrideDetailEntries),
      warningsSummary: {
        totalWarnings, reportsWithWarnings, reportsWithMetadataErrors,
        byField: [...warningFieldCounts.entries()]
          .sort((a, b) => b[1] - a[1])
          .map(([field, count]) => ({ field, count }))
      }
    };
  };

  return { parse, computeSummary, aggregateSummaries, toIpRange, sanitizeXml };
})();

// Node (テスト) 用エクスポート。ブラウザでは module が未定義のため無視される。
if (typeof module !== "undefined" && module.exports) module.exports = ArParser;
