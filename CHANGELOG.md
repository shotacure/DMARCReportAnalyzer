# Changelog

All notable changes to **DMARC Report Analyzer** are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [1.1.1] - 2026-08-13

### Removed
- **`fo=0` policy advice** — the suggestion to switch to `fo=1` has been dropped.
  The value came from the aggregate report's `<policy_published>`, where many
  reporters omit `<fo>` entirely; an omitted element was indistinguishable from
  an explicit `fo=0`, so the warning fired on domains that do publish `fo=1`.
  Failure (`ruf`) reports are also rarely sent in practice, making the advice
  low-value even when correct.

## [1.1.0] - 2026-06-20

### Added
- **"Misconfigured" source classification** — IP ranges that have valid signing
  keys (some messages authenticate) yet also deliver unauthenticated mail are now
  flagged ⚠️ *Misconfigured* instead of being hidden under ✅ *Legitimate*. This
  surfaces real configuration gaps in otherwise-trusted senders.
- **Expanded policy advice** — per-domain recommendations now also cover:
  - `aspf=r` (relaxed SPF alignment) — suggests `aspf=s`.
  - `sp=` weaker than `p=` — warns that subdomains are less protected.
  - missing `np=` under `p=reject` — suggests `np=reject` to block non-existent
    subdomain spoofing.
  - `fo=0` while enforcing — suggests `fo=1` for fuller failure reporting.
- **JSON export** — structured export alongside CSV for SIEM / scripting use.
- **Scan progress** — the status bar now shows live `processed / total` counts
  during long scans.
- **Sortable tables** — click any column header in the IP / reporter tables to
  sort; **click-to-copy** on IP-range cells for faster incident reporting.
- **Domain quick-filter** — filter visible domain sections by name when many
  domains are present.
- **Accessibility** — health badges expose `aria-label`; table headers use
  `scope="col"`.

### Changed
- **More accurate aggregation** — domain/global summaries are now recomputed from
  raw records instead of each report's pre-truncated top-N lists. This eliminates
  a double-truncation that could drop low-volume sources spread across many
  reports (relevant to distributed-spoofing detection), and makes
  `uniqueSourceIps` / `uniqueIpRanges` exact.
- **Hardened XML sanitizer** — now strips UTF-8 BOM, removes invalid XML control
  characters, escapes bare `&`, and normalizes the Microsoft `<diskim>` typo
  (open and close tags), reducing parse failures from quirky ISP reports.
- Pure analysis logic (classification + policy advice) extracted to
  `parser/analysis.js`, shared by the dashboard and covered by unit tests.
- Faster scans on Thunderbird 121+ via server-side date filtering
  (`messages.query`), with a safe fallback on older versions.
- Internal: statistic cards unified into a single shared builder; version is now
  sourced solely from `manifest.json`.

### Fixed
- `tagMisconfigured` localization (present in all 12 languages) was never shown;
  it is now wired to the new classification.

### Notes
- Added unit tests (`npm test`, Node's built-in test runner) covering the
  aggregation accuracy fix, source classification, and policy advice.
