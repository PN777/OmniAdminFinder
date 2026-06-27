# Contributing to OmniAdminFinder

Thank you for considering a contribution to OmniAdminFinder!  
Please read this guide before opening issues or pull requests.

---

## Table of Contents

- [Code of Conduct](#code-of-conduct)
- [How Can I Contribute?](#how-can-i-contribute)
- [Development Setup](#development-setup)
- [Branching & Commits](#branching--commits)
- [Pull Request Process](#pull-request-process)
- [Style Guide](#style-guide)
- [Testing](#testing)
- [Reporting Bugs](#reporting-bugs)
- [Requesting Features](#requesting-features)
- [Security Issues](#security-issues)

---

## Code of Conduct

This project follows the [Contributor Covenant Code of Conduct](./CODE_OF_CONDUCT.md).  
All contributors are expected to uphold it.

---

## How Can I Contribute?

- **Bug reports** — open a GitHub Issue using the bug report template
- **Feature requests** — open a GitHub Issue using the feature request template
- **Documentation improvements** — PRs welcome for typos, clarity, or gaps
- **Code contributions** — new features, bug fixes, performance improvements

> [!IMPORTANT]
> Open an issue **before** starting significant new feature work.  
> This prevents duplicate effort and aligns the contribution with project direction.

---

## Development Setup

```bash
git clone https://github.com/PN777/OmniAdminFinder.git
cd OmniAdminFinder

python -m venv .venv
source .venv/bin/activate        # Windows: .venv\Scripts\Activate.ps1

pip install -r requirements.txt
pip install pytest ruff pytest-asyncio

# Verify linting
ruff check .

# Run tests
pytest -q
```

---

## Branching & Commits

| Branch | Purpose |
|---|---|
| `main` | Stable, release-ready code |
| `develop` | Integration branch for in-progress work |
| `feature/<name>` | Individual feature branches |
| `fix/<name>` | Bug-fix branches |

**Commit message format:**

```
<type>: <short summary>

[optional body]
[optional footer]
```

Types: `feat`, `fix`, `docs`, `test`, `refactor`, `chore`, `perf`, `ci`

Examples:
```
feat: add robots.txt path extraction
fix: handle redirect loop during SSL bypass
docs: update CLI reference table
```

---

## Pull Request Process

1. Fork the repository and create your branch from `main` or `develop`.
2. Write or update tests for any code changes.
3. Run `ruff check .` and `pytest -q` — both must pass cleanly.
4. Update `CHANGELOG.md` under `[Unreleased]` with a brief summary.
5. Open a PR against `main` (or `develop` for large work).
6. Fill out the pull request template completely.
7. Address reviewer comments promptly.

PRs that do not pass CI, are missing tests for new logic, or skip the PR template will be placed on hold until resolved.

---

## Style Guide

- Target **Python 3.10+** syntax.
- Line length: **100 characters** (configured in `pyproject.toml`).
- Use `ruff` for linting and formatting checks.
- Type annotations are expected for all public functions and class methods.
- Docstrings for all public classes and methods (Google-style preferred).
- Avoid external dependencies beyond what is already in `requirements.txt` unless clearly justified.

---

## Testing

Tests live in `tests/`. Use `pytest`:

```bash
pytest -q              # quick run
pytest -v              # verbose
pytest --tb=short      # short tracebacks
```

Coverage expectations:
- New features must include at least one test.
- Bug fixes must include a regression test.

---

## Reporting Bugs

Use the [Bug Report](.github/ISSUE_TEMPLATE/bug_report.yml) issue template.

Include:
- OS and Python version
- Exact command used
- Full error output / traceback
- Expected vs. actual behavior

---

## Requesting Features

Use the [Feature Request](.github/ISSUE_TEMPLATE/feature_request.yml) issue template.

Describe:
- The problem your feature solves
- Your proposed solution
- Alternatives considered

---

## Security Issues

**Do not open public GitHub issues for security vulnerabilities.**  
See [SECURITY.md](./SECURITY.md) for the responsible disclosure process.
