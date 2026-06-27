# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [1.0.0] — 2026-06-27

### Added
- Asynchronous scanning engine built on `aiohttp` + `asyncio` with semaphore-bound concurrency.
- Built-in default and extended path wordlists (300+ candidates).
- Domain-aware hostname mutation generator.
- Extension expansion for bare paths (`.php`, `.asp`, `.aspx`, `.html`, `.htm`, `.jsp`).
- Heuristic confidence scoring (status codes, title/body keywords, form detection, redirects).
- Technology fingerprinting library with 30+ signatures (WordPress, Joomla, Drupal, Django, Laravel, Rails, Flask, phpMyAdmin, Jenkins, Grafana, and more).
- Multi-format report output: `.txt` (human-readable), `.json` (structured), `.csv` (tabular).
- Full CLI via `argparse` with flags for concurrency, timeout, rate-limiting, proxy, SSL, UA, extensions, and redirect policy.
- `omnifinder/` Python package with separated modules: `cli`, `scanner`, `analyzer`, `fingerprint`, `reporter`, `utils`.
- Standalone `admin_finder.py` single-file entry point for direct use without installation.
- Community health files: `CONTRIBUTING.md`, `SECURITY.md`, `CODE_OF_CONDUCT.md`.
- `ROADMAP.md` with planned milestones through v2.0.
- GitHub issue templates (bug report, feature request, config).
- GitHub pull request template.
- GitHub Actions CI workflow (lint with `ruff`, test with `pytest` on Python 3.10–3.12).
- Comprehensive test suite (`tests/test_scanner.py`) covering classifier, wordlist generator, utils, and data models.
- `pyproject.toml` with full package metadata and console script entry points.
- MIT License.
