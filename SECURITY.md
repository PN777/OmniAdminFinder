# Security Policy

## Supported Versions

| Version | Supported |
|---|---|
| Latest (`main`) | ✅ |
| Older releases | ❌ (upgrade recommended) |

---

## Responsible Disclosure

OmniAdminFinder takes security seriously.

If you discover a vulnerability in this project's **code, dependencies, or documentation**, please report it privately so it can be addressed before public disclosure.

**Please do NOT open a public GitHub Issue for security vulnerabilities.**

---

## Reporting a Vulnerability

1. **Email** the maintainer directly via the contact on [GitHub profile](https://github.com/PN777).
2. Include in your report:
   - A clear description of the vulnerability.
   - Steps to reproduce or a proof-of-concept.
   - The potential impact.
   - Any suggested mitigations (optional but appreciated).
3. You will receive an acknowledgement within **72 hours**.
4. We target a fix and coordinated disclosure within **14 days** of confirmed receipt for critical issues.

---

## Scope

| In scope | Out of scope |
|---|---|
| Bugs in `admin_finder.py` that cause unintended behavior | Issues with third-party targets scanned using this tool |
| Dependency vulnerabilities in `requirements.txt` | Social engineering |
| Documentation that could cause harm if followed | Issues with user's own environment/OS |

---

## Ethical Use

This tool is intended exclusively for **authorized** security assessments and defensive research.  
Misuse of this tool to scan targets without explicit permission is out of scope for any security report and may violate applicable law.

---

## Credits

Responsibly disclosed vulnerabilities will be credited in `CHANGELOG.md` upon release (unless anonymity is requested).
