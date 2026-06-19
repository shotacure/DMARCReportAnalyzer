// DMARCReportAnalyzer - background.js
// バックグラウンドスクリプト: フォルダ内メッセージのスキャン、添付ファイル抽出、
// レポート解析パイプラインの管理を担当する。
// 外部通信は一切行わない。すべての処理はローカルで完結する。

// =========================================================
// 定数
// =========================================================
const STORAGE_KEY_SETTINGS = "dmarcraSettings";
const DASHBOARD_PATH = "dashboard/dashboard.html";
const DEFAULT_SETTINGS = {
  arFolderId: null,
  frFolderId: null,
  lastScanTime: 0
};

// =========================================================
// スキャン結果のメモリキャッシュ
// Thunderbird の background script は拡張が無効化されるまで永続する。
// =========================================================
let cachedResults = null;

// =========================================================
// ツールバーボタンのクリックでダッシュボードをタブで開く
// 既に開いているタブがあればそちらにフォーカスする
// =========================================================
browser.browserAction.onClicked.addListener(async () => {
  const dashboardUrl = browser.runtime.getURL(DASHBOARD_PATH);
  const tabs = await browser.tabs.query({});
  const existingTab = tabs.find(t => t.url === dashboardUrl);
  if (existingTab) {
    await browser.tabs.update(existingTab.id, { active: true });
    await browser.windows.update(existingTab.windowId, { focused: true });
  } else {
    await browser.tabs.create({ url: dashboardUrl });
  }
});

// =========================================================
// 設定の読み書き
// =========================================================
const getSettings = async () => {
  const data = await browser.storage.local.get(STORAGE_KEY_SETTINGS);
  return { ...DEFAULT_SETTINGS, ...(data[STORAGE_KEY_SETTINGS] || {}) };
};

const saveSettings = async (settings) => {
  await browser.storage.local.set({ [STORAGE_KEY_SETTINGS]: settings });
};

// =========================================================
// フォルダ一覧の取得: パスに "dmarc" を含むフォルダのみ返す
// =========================================================
const getAllFolders = async () => {
  const accounts = await browser.accounts.list();
  const folders = [];
  const walk = (folderList, accountName) => {
    for (const folder of folderList) {
      if (folder.path.toLowerCase().includes("dmarc")) {
        folders.push({
          accountId: folder.accountId, path: folder.path,
          name: folder.name, accountName,
          label: `${accountName} - ${folder.path}`
        });
      }
      if (folder.subFolders?.length) walk(folder.subFolders, accountName);
    }
  };
  for (const account of accounts) walk(account.folders, account.name);
  return folders;
};

// =========================================================
// フォルダ自動検出
// =========================================================
const autoDetectFolders = async () => {
  const accounts = await browser.accounts.list();
  let detectedAr = null, detectedFr = null;
  const walk = (folderList, accountName, parentIsDmarc) => {
    for (const folder of folderList) {
      const lowerName = folder.name.toLowerCase();
      const isDmarcFolder = folder.path.toLowerCase().includes("dmarc");
      if (parentIsDmarc) {
        if (!detectedAr && (lowerName.includes("aggregate") || lowerName.includes("ar")))
          detectedAr = { accountId: folder.accountId, path: folder.path };
        if (!detectedFr && (lowerName.includes("forensic") || lowerName.includes("fr")))
          detectedFr = { accountId: folder.accountId, path: folder.path };
      }
      if (folder.subFolders?.length) walk(folder.subFolders, accountName, isDmarcFolder);
    }
  };
  for (const account of accounts) {
    walk(account.folders, account.name, false);
    if (detectedAr && detectedFr) break;
  }
  return { arFolderId: detectedAr, frFolderId: detectedFr };
};

// =========================================================
// フォルダ解決: 保存済み設定を検証し、なければ自動検出にフォールバック
// =========================================================
const resolveFolders = async (settings) => {
  let needsSave = false;
  const allFolders = await getAllFolders();
  const folderExists = (folderId) => {
    if (!folderId) return false;
    return allFolders.some(f => f.accountId === folderId.accountId && f.path === folderId.path);
  };
  const arValid = folderExists(settings.arFolderId);
  const frValid = folderExists(settings.frFolderId);
  if (!arValid || !frValid) {
    const detected = await autoDetectFolders();
    if (!arValid && detected.arFolderId) { settings.arFolderId = detected.arFolderId; needsSave = true; }
    if (!frValid && detected.frFolderId) { settings.frFolderId = detected.frFolderId; needsSave = true; }
    if (needsSave) await saveSettings(settings);
  }
  return settings;
};

// =========================================================
// メッセージスキャン: 指定フォルダ内のメッセージを取得
// sinceMs を渡すと、対応バージョン (TB121+) ではサーバ/DB 側で日付を
// 絞り込み、フォルダ全件の列挙を避けて高速化する。
// 古いバージョン (folder.id を持たない) や query 非対応時は全件取得に
// フォールバックする (date は呼び出し側で再フィルタされるため安全)。
// =========================================================
const listMessagesInFolder = async (accountId, path, sinceMs = 0) => {
  const accounts = await browser.accounts.list();
  const account = accounts.find(a => a.id === accountId);
  if (!account) return [];
  const findFolder = (folders, targetPath) => {
    for (const f of folders) {
      if (f.path === targetPath) return f;
      if (f.subFolders?.length) { const found = findFolder(f.subFolders, targetPath); if (found) return found; }
    }
    return null;
  };
  const folder = findFolder(account.folders, path);
  if (!folder) return [];

  let page = null;
  // folder.id は TB121+ で付与され、同バージョンで query({folderId,...}) が使える。
  // id が無いバージョンに folderId を渡すと全フォルダ検索になり得るため必ず存在チェック。
  if (sinceMs > 0 && folder.id && browser.messages.query) {
    try {
      page = await browser.messages.query({ folderId: folder.id, fromDate: new Date(sinceMs) });
    } catch (e) { page = null; }
  }
  if (!page) page = await browser.messages.list(folder);

  const messages = [];
  messages.push(...page.messages);
  while (page.id) { page = await browser.messages.continueList(page.id); messages.push(...page.messages); }
  return messages;
};

// =========================================================
// スキャン進捗を dashboard へ通知 (受信側がいなくてもエラーにしない)
// =========================================================
const notifyProgress = (phase, done, total) => {
  browser.runtime.sendMessage({ type: "scanProgress", phase, done, total }).catch(() => {});
};

// =========================================================
// 添付ファイル抽出
// =========================================================
const ATTACHMENT_MIME_TYPES = [
  "application/zip", "application/x-zip-compressed",
  "application/gzip", "application/x-gzip",
  "application/xml", "text/xml"
];

const extractReportAttachments = async (messageId) => {
  const attachments = await browser.messages.listAttachments(messageId);
  const reportFiles = [];
  for (const att of attachments) {
    const isReportType = ATTACHMENT_MIME_TYPES.includes(att.contentType?.toLowerCase());
    const name = (att.name || "").toLowerCase();
    const isReportExt = name.endsWith(".zip") || name.endsWith(".gz") || name.endsWith(".xml") || name.endsWith(".gzip");
    if (isReportType || isReportExt) {
      const file = await browser.messages.getAttachmentFile(messageId, att.partName);
      reportFiles.push({ name: att.name, contentType: att.contentType, data: await file.arrayBuffer() });
    }
  }
  return reportFiles;
};

// =========================================================
// 解凍パイプライン (gzip を zip より先に判定)
// =========================================================
const decompressAttachment = async (attachment) => {
  const { name, data } = attachment;
  const lowerName = (name || "").toLowerCase();
  const contentType = (attachment.contentType || "").toLowerCase();
  const xmlTexts = [];

  if (lowerName.endsWith(".gz") || lowerName.endsWith(".gzip") || contentType.includes("gzip")) {
    const xml = decompressGzip(data);
    if (xml) xmlTexts.push(xml);
  } else if (lowerName.endsWith(".zip") || contentType === "application/zip" || contentType === "application/x-zip-compressed") {
    if (typeof JSZip === "undefined") return xmlTexts;
    const zip = await JSZip.loadAsync(data);
    for (const [filename, zipEntry] of Object.entries(zip.files)) {
      if (zipEntry.dir) continue;
      const entryName = filename.toLowerCase();
      if (entryName.endsWith(".xml")) xmlTexts.push(await zipEntry.async("string"));
      else if (entryName.endsWith(".gz") || entryName.endsWith(".gzip")) {
        const xml = decompressGzip(await zipEntry.async("arraybuffer"));
        if (xml) xmlTexts.push(xml);
      }
    }
  } else if (lowerName.endsWith(".xml") || contentType.includes("xml")) {
    xmlTexts.push(new TextDecoder("utf-8").decode(data));
  }
  return xmlTexts;
};

const decompressGzip = (arrayBuffer) => {
  if (typeof pako === "undefined") return null;
  try { return new TextDecoder("utf-8").decode(pako.inflate(new Uint8Array(arrayBuffer))); }
  catch (e) { console.error("DMARCReportAnalyzer: gzip decompression failed:", e); return null; }
};

// =========================================================
// メッセージハンドラ
// =========================================================
browser.runtime.onMessage.addListener((request, sender, sendResponse) => {
  const handle = async () => {
    switch (request.command) {
      case "getSettings": return await getSettings();
      case "saveSettings": await saveSettings(request.settings); return { success: true };
      case "getFolders": return await getAllFolders();
      case "autoDetectFolders": return await autoDetectFolders();
      case "resolveSettings": {
        let settings = await getSettings();
        return await resolveFolders(settings);
      }
      case "getLastResults": return cachedResults;

      case "scanReports": {
        let settings = await getSettings();
        settings = await resolveFolders(settings);
        const sinceMs = request.since || 0;
        const sinceDays = request.sinceDay || 0;
        // 前期比較用: 今期と同じ幅の前期も一緒にスキャン
        // 例: 1か月選択 → 2か月前までスキャンして今期/前期に分離
        const periodMs = sinceDays > 0 ? sinceDays * 24 * 60 * 60 * 1000 : 0;
        const previousSinceMs = (sinceMs > 0 && periodMs > 0) ? sinceMs - periodMs : 0;
        const scanSinceMs = previousSinceMs > 0 ? previousSinceMs : sinceMs;

        const results = { ar: [], fr: [], errors: [] };
        const arPrevious = []; // 前期の集約レポート
        const seenKeys = new Set();
        results.scanPeriodDays = sinceDays;
        results.issues = { noAttachment: [], decompressFailed: [], parseFailed: [], incompleteReport: [], unknownFormat: [] };

        // 集約レポートフォルダのスキャン
        if (settings.arFolderId) {
          try {
            const { accountId, path } = settings.arFolderId;
            const messages = await listMessagesInFolder(accountId, path, scanSinceMs);
            const arTotal = messages.length;
            let arProcessed = 0;
            for (const msg of messages) {
              arProcessed++;
              if (arProcessed % 25 === 0 || arProcessed === arTotal) notifyProgress("aggregate", arProcessed, arTotal);
              if (scanSinceMs > 0 && msg.date && msg.date.getTime() < scanSinceMs) continue;
              try {
                const attachments = await extractReportAttachments(msg.id);
                if (attachments.length === 0) {
                  results.issues.noAttachment.push({ messageId: msg.id, date: msg.date?.toISOString(), subject: msg.subject, folder: "aggregate" });
                  continue;
                }
                for (const att of attachments) {
                  let xmlTexts;
                  try { xmlTexts = await decompressAttachment(att); }
                  catch (decompErr) { results.issues.decompressFailed.push({ messageId: msg.id, date: msg.date?.toISOString(), subject: msg.subject, attachment: att.name, error: decompErr.message || decompErr.toString() }); continue; }
                  if (xmlTexts.length === 0) { results.issues.unknownFormat.push({ messageId: msg.id, date: msg.date?.toISOString(), subject: msg.subject, attachment: att.name, contentType: att.contentType }); continue; }
                  for (const xml of xmlTexts) {
                    try {
                      const report = ArParser.parse(xml);
                      if (!seenKeys.has(report.reportKey)) {
                        seenKeys.add(report.reportKey);
                        // メッセージ日時で今期/前期に分類
                        const msgTime = msg.date ? msg.date.getTime() : 0;
                        const isCurrent = sinceMs === 0 || msgTime >= sinceMs;
                        if (isCurrent) {
                          results.ar.push(report);
                        } else {
                          arPrevious.push(report);
                        }
                        if (report.warnings.length > 0) results.issues.incompleteReport.push({ messageId: msg.id, date: msg.date?.toISOString(), subject: msg.subject, reportKey: report.reportKey, reporter: report.reporter.orgName, domain: report.policy.domain, warningCount: report.warnings.length, warnings: report.warnings });
                      }
                    } catch (parseErr) { results.issues.parseFailed.push({ messageId: msg.id, date: msg.date?.toISOString(), subject: msg.subject, attachment: att.name, error: parseErr.message }); }
                  }
                }
              } catch (e) { results.errors.push({ messageId: msg.id, subject: msg.subject, error: e.toString() }); }
            }
          } catch (e) { results.errors.push({ folder: "aggregate", error: e.toString() }); }
        }

        // フォレンジックレポートフォルダのスキャン (今期のみ)
        if (settings.frFolderId) {
          try {
            const { accountId, path } = settings.frFolderId;
            const messages = await listMessagesInFolder(accountId, path, sinceMs);
            const frTotal = messages.length;
            let frProcessed = 0;
            for (const msg of messages) {
              frProcessed++;
              if (frProcessed % 25 === 0 || frProcessed === frTotal) notifyProgress("forensic", frProcessed, frTotal);
              if (sinceMs > 0 && msg.date && msg.date.getTime() < sinceMs) continue;
              try {
                const full = await browser.messages.getFull(msg.id);
                const report = FrParser.parse(msg.id, msg.date?.toISOString(), msg.subject, full.headers || {});
                if (!seenKeys.has(report.reportKey)) {
                  seenKeys.add(report.reportKey);
                  results.fr.push(report);
                  if (report.warnings.length > 0) results.issues.incompleteReport.push({ messageId: msg.id, date: msg.date?.toISOString(), subject: msg.subject, reportKey: report.reportKey, reporter: "(forensic)", domain: report.reportedDomain, warningCount: report.warnings.length, warnings: report.warnings });
                }
              } catch (e) { results.errors.push({ messageId: msg.id, subject: msg.subject, error: e.toString() }); }
            }
          } catch (e) { results.errors.push({ folder: "forensic", error: e.toString() }); }
        }

        results.issuesSummary = {
          noAttachment: results.issues.noAttachment.length, decompressFailed: results.issues.decompressFailed.length,
          parseFailed: results.issues.parseFailed.length, incompleteReport: results.issues.incompleteReport.length,
          unknownFormat: results.issues.unknownFormat.length,
          totalIssues: results.issues.noAttachment.length + results.issues.decompressFailed.length + results.issues.parseFailed.length + results.issues.incompleteReport.length + results.issues.unknownFormat.length,
          fatalErrors: results.errors.length
        };

        if (results.ar.length > 0) {
          results.aggregate = ArParser.aggregateSummaries(results.ar);

          // 前期の集約サマリー (比較用)
          if (arPrevious.length > 0) {
            results.previousAggregate = ArParser.aggregateSummaries(arPrevious);
          }

          // フォレンジックレポートをドメイン別にグループ化
          const frByDomain = new Map();
          for (const fr of results.fr) {
            const d = (fr.reportedDomain || "").toLowerCase();
            if (!frByDomain.has(d)) frByDomain.set(d, []);
            frByDomain.get(d).push(fr);
          }

          const byDomain = new Map();
          for (const r of results.ar) { const d = r.policy.domain; if (!byDomain.has(d)) byDomain.set(d, []); byDomain.get(d).push(r); }

          // 前期レポートもドメイン別にグループ化
          const prevByDomain = new Map();
          for (const r of arPrevious) { const d = r.policy.domain; if (!prevByDomain.has(d)) prevByDomain.set(d, []); prevByDomain.get(d).push(r); }

          results.domainDetails = [];
          for (const [domain, domainReports] of byDomain) {
            const latestReport = domainReports.reduce((a, b) => a.dateRange.end > b.dateRange.end ? a : b);
            const dd = {
              domain, reportCount: domainReports.length, policy: latestReport.policy,
              aggregate: ArParser.aggregateSummaries(domainReports),
              timeSeries: domainReports.map(r => ({ begin: r.dateRange.begin, delivered: r.summary.noneCount, deliveredFail: r.summary.deliveredFailCount, quarantine: r.summary.quarantineCount, reject: r.summary.rejectCount })),
              // ドメインに紐づくフォレンジックレポート
              forensicReports: frByDomain.get(domain.toLowerCase()) || []
            };
            // ドメイン別の前期サマリー
            const prevReports = prevByDomain.get(domain);
            if (prevReports && prevReports.length > 0) {
              dd.previousAggregate = ArParser.aggregateSummaries(prevReports);
            }
            results.domainDetails.push(dd);
          }
          results.domainDetails.sort((a, b) => b.aggregate.totalCount - a.aggregate.totalCount);
        }

        settings.lastScanTime = Date.now();
        await saveSettings(settings);
        cachedResults = results;
        return results;
      }

      default: return { error: `Unknown command: ${request.command}` };
    }
  };
  handle().then(sendResponse).catch(e => sendResponse({ error: e.toString() }));
  return true;
});
