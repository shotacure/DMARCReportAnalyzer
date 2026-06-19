// DMARCReportAnalyzer - parser/analysis.js
// 純粋な分析ロジック (送信元分類・ポリシー助言)。
// 表示やローカライズには依存せず、tag 文字列やメッセージキーのみを返す。
// ブラウザ (dashboard) と Node (テスト) の両方から読み込める。

const Analysis = (() => {
  "use strict";

  // =========================================================
  // IP 範囲の自動分類タグを算出 (ローカライズ前の tag 文字列を返す)
  //   legitimate    … DMARC 認証成功実績あり、未認証配送なし
  //   misconfigured … 認証成功実績はあるが未認証配送も混在 (設定不備)
  //   blocked       … 認証成功実績ゼロ、すべて reject/quarantine
  //   threat        … 認証成功実績ゼロなのに一部が配送された (最も危険)
  //   unknown       … 判定不能 (件数ゼロ)
  // =========================================================
  const classifyIpRangeTag = (e) => {
    const dp = e.dmarcPass || 0;          // DMARC pass (DKIM か SPF) の実績
    const count = e.count || 0;
    const deliveredFail = e.deliveredFail || 0;

    // 認証に一度も成功していない送信元
    if (dp === 0) {
      if (count === 0) return "unknown";
      if (deliveredFail > 0) return "threat";  // 未認証なのに素通り
      return "blocked";                        // すべてブロック済み
    }

    // dp > 0: 過去に DMARC 認証成功の実績がある (DKIM 秘密鍵がなければ pass 不可)
    if (dp === count && deliveredFail === 0) return "legitimate"; // 全て正常配送
    // 認証成功実績がありながら未認証のまま配送されたメールも存在する
    // → 正規鍵を持つ送信元の設定不備、または過去の設定ミスの履歴
    if (deliveredFail > 0) return "misconfigured";
    // 認証成功 + 残りはブロック済み (未認証配送なし) → 正規送信元
    return "legitimate";
  };

  // =========================================================
  // 公開ポリシーの強度ランク (none < quarantine < reject)
  // =========================================================
  const policyRank = (d) => d === "reject" ? 3 : d === "quarantine" ? 2 : 1;

  // =========================================================
  // ポリシー推奨アドバイスを算出
  // 返り値: [{ level, key, args?, alignParts? }]
  //   level     … "danger" | "warn" | "ok" (表示色)
  //   key       … i18n メッセージキー
  //   args      … "#1","#2"… を順に置換する値の配列 (任意)
  //   alignParts… advicePRejectClean に付与するアライメント注記 (任意)
  // =========================================================
  const computePolicyAdvice = (agg, policy) => {
    const advices = [];
    const p = policy.p || "none";
    const deliveredFail = Number(agg.deliveredFailCount) || 0;
    const rejectCount = Number(agg.rejectCount) || 0;

    // --- 主ポリシー p= ---
    if (p === "none") {
      advices.push({ level: "danger", key: "advicePNone" });
    } else if (p === "quarantine") {
      advices.push({ level: "warn", key: deliveredFail === 0 ? "advicePQuarantine" : "advicePQuarantineWithFail" });
    } else if (p === "reject" && deliveredFail === 0 && rejectCount === 0) {
      const dkimOnly = (Number(agg.dkimPassCount) || 0) - (Number(agg.passCount) || 0);
      const spfOnly = (Number(agg.spfPassCount) || 0) - (Number(agg.passCount) || 0);
      const alignParts = [];
      if (dkimOnly > 0) alignParts.push("SPF");
      if (spfOnly > 0) alignParts.push("DKIM");
      advices.push({ level: "ok", key: "advicePRejectClean", alignParts });
    }

    // --- サブドメインポリシー sp=: 主ポリシーより弱いとサブドメインが手薄 ---
    const sp = policy.sp || p;
    if (p !== "none" && policyRank(sp) < policyRank(p)) {
      advices.push({ level: sp === "none" ? "danger" : "warn", key: "adviceSpWeak", args: [sp, p] });
    }

    // --- アライメント adkim / aspf=relaxed ---
    if (policy.adkim === "r") advices.push({ level: "warn", key: "adviceAdkimRelaxed" });
    if (policy.aspf === "r") advices.push({ level: "warn", key: "adviceAspfRelaxed" });

    // --- 存在しないサブドメインのポリシー np= (RFC 9091) ---
    // p=reject なのに np 未指定だと、実在しないサブドメインを騙る攻撃に弱い
    if (p === "reject" && !policy.np) {
      advices.push({ level: "warn", key: "adviceNpMissing" });
    }

    // --- pct < 100: 一部にしか適用されていない ---
    if (Number(policy.pct) < 100) advices.push({ level: "warn", key: "advicePctPartial", args: [policy.pct] });

    // --- 失敗レポート fo=: 強制運用中に fo=0 だと片側失敗を取りこぼす ---
    if (p !== "none" && (policy.fo || "0") === "0") {
      advices.push({ level: "warn", key: "adviceFo" });
    }

    return advices;
  };

  return { classifyIpRangeTag, computePolicyAdvice, policyRank };
})();

// Node (テスト) 用エクスポート。ブラウザでは module が未定義のため無視される。
if (typeof module !== "undefined" && module.exports) module.exports = Analysis;
