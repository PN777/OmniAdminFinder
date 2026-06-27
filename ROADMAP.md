# Roadmap

This document outlines the planned milestones and long-term direction for OmniAdminFinder.

> Items are subject to change based on community feedback and contributor availability.

---

## v1.0 — Initial Release ✅

- [x] Asynchronous scanning engine (`aiohttp` + `asyncio`)
- [x] Built-in default and extended path wordlists
- [x] Domain/path-aware wordlist mutations
- [x] Semaphore-bound concurrency control
- [x] Configurable timeout, retries, rate-limiting
- [x] Response fingerprinting (status, title, forms, body)
- [x] Technology detection (CMS/framework signatures)
- [x] Confidence scoring and ranked output
- [x] Multi-format reporting (TXT, JSON, CSV)
- [x] Proxy support
- [x] SSL toggle
- [x] Custom User-Agent
- [x] Redirect follow/disable policy
- [x] Full CLI with argparse

---

## v1.1 — Robustness & DX

- [ ] `robots.txt` and `sitemap.xml` path extraction
- [ ] Retry-with-backoff strategy for transient failures
- [ ] `--resume` flag to continue interrupted scans
- [ ] Progress bar (via `rich` or `tqdm`)
- [ ] Configurable minimum confidence threshold via CLI
- [ ] Colorized console output
- [ ] Structured logging with log-level flags

---

## v1.2 — Expanded Detection

- [ ] Expanded technology signature library (50+ signatures)
- [ ] Header-based fingerprinting (X-Powered-By, Server, cookies)
- [ ] CMS-specific path bundles (WordPress, Joomla, Drupal, Magento presets)
- [ ] Custom signature YAML/JSON extension files
- [ ] Form field detection heuristics (login, search, CSRF tokens)

---

## v1.3 — Output & Integrations

- [ ] HTML report generation
- [ ] Markdown report generation
- [ ] Burp Suite-compatible target output
- [ ] Nuclei template export
- [ ] Webhook notification support (Slack, Discord)
- [ ] Output deduplication and diff mode

---

## v2.0 — Advanced Engine

- [ ] Authenticated session scanning (cookie/header injection)
- [ ] WAF/IDS evasion controls (header rotation, random delays, decoy paths)
- [ ] Distributed scan coordination (multi-host targets)
- [ ] Plugin system for custom classifiers and reporters
- [ ] REST API mode for integration with pipelines
- [ ] Docker image with pre-built wordlists

---

## Long-Term / Wishlist

- [ ] Machine-learning-assisted confidence scoring
- [ ] Passive discovery from JS/HTML link extraction
- [ ] Browser automation fallback (Playwright/Selenium) for JS-heavy pages
- [ ] Web UI dashboard for scan management

---

## Completed Milestones

See [CHANGELOG.md](./CHANGELOG.md) for a full record of completed work.

---

*Have a feature idea? Open a [Feature Request](https://github.com/PN777/OmniAdminFinder/issues/new?template=feature_request.yml).*
