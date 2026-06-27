"""
Technology fingerprinting and response classification for OmniAdminFinder.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field

# ---------------------------------------------------------------------------
# Technology signature library
# ---------------------------------------------------------------------------

TECH_SIGNATURES: dict[str, list[str]] = {
    "WordPress": ["wp-login", "wp-admin", "wordpress", "wp-content", "wp-json"],
    "Joomla": ["joomla", "com_users", "com_admin", "administrator/index.php"],
    "Drupal": ["drupal", "sites/default", "node/add", "admin/config"],
    "Magento": ["magento", "mage", "adminhtml", "skin/adminhtml"],
    "PrestaShop": ["prestashop", "ps_", "backoffice"],
    "OpenCart": ["opencart", "route=common/dashboard"],
    "TYPO3": ["typo3", "typo3conf"],
    "Django": ["django", "csrfmiddlewaretoken", "django-admin"],
    "Laravel": ["laravel", "_token", "laravel_session"],
    "Rails": ["ruby on rails", "rails", "authenticity_token"],
    "Flask": ["flask", "werkzeug"],
    "Symfony": ["symfony", "sf_redirect", "_sf2_"],
    "CodeIgniter": ["codeigniter", "ci_session"],
    "CakePHP": ["cakephp", "cake_"],
    "ASP.NET": ["asp.net", "__viewstate", "__eventvalidation", "aspnetcore"],
    "PHP": [".php", "x-powered-by: php"],
    "Apache": ["server: apache", "apache"],
    "Nginx": ["server: nginx", "nginx"],
    "IIS": ["server: microsoft-iis", "x-aspnet-version"],
    "Tomcat": ["apache tomcat", "tomcat", "jsessionid"],
    "phpMyAdmin": ["phpmyadmin", "pma_"],
    "Adminer": ["adminer"],
    "cPanel": ["cpanel", "whm", "x-cpanel-version"],
    "Plesk": ["plesk", "sw_auth_key"],
    "Webmin": ["webmin", "miniserv"],
    "Jenkins": ["jenkins", "x-jenkins", "hudson"],
    "GitLab": ["gitlab", "gl-"],
    "Grafana": ["grafana", "x-grafana"],
    "Kibana": ["kibana", "kbn-"],
    "Elasticsearch": ["elasticsearch", "x-elastic"],
    "Prometheus": ["prometheus", "alertmanager"],
}

# ---------------------------------------------------------------------------
# Admin keyword sets
# ---------------------------------------------------------------------------

ADMIN_TITLE_KEYWORDS: frozenset[str] = frozenset([
    "admin", "administrator", "dashboard", "control panel", "management",
    "login", "sign in", "signin", "backend", "backoffice", "cpanel",
    "portal", "console", "secure", "staff", "manage", "panel",
    "configuration", "settings", "cms", "system",
])

ADMIN_BODY_KEYWORDS: list[str] = [
    "admin panel", "administration", "dashboard", "control panel",
    "manage users", "user management", "system settings", "site settings",
    "logout", "log out", "sign out", "welcome admin", "admin area",
    "administrator login", "secure area",
]

LOGIN_INPUT_KEYWORDS: frozenset[str] = frozenset([
    "password", "passwd", "pwd", "pass", "username", "user",
    "email", "login", "credential",
])


# ---------------------------------------------------------------------------
# Data model
# ---------------------------------------------------------------------------

@dataclass
class Fingerprint:
    """Structured fingerprint extracted from an HTTP response."""
    title: str = ""
    forms_count: int = 0
    has_login_inputs: bool = False
    technologies: list[str] = field(default_factory=list)
    body_preview: str = ""


# ---------------------------------------------------------------------------
# Classifier
# ---------------------------------------------------------------------------

class ResponseClassifier:
    """
    Extracts fingerprints from HTTP responses and computes a confidence score.

    Confidence is a heuristic integer in [0, 100] indicating how likely
    the probed URL is an administrative interface.
    """

    # ------------------------------------------------------------------
    # Extraction helpers
    # ------------------------------------------------------------------

    @staticmethod
    def extract_title(body: str) -> str:
        """Return the text content of the first <title> element, stripped."""
        match = re.search(r"<title[^>]*>(.*?)</title>", body, re.IGNORECASE | re.DOTALL)
        if match:
            return re.sub(r"\s+", " ", match.group(1)).strip()[:200]
        return ""

    @staticmethod
    def count_forms(body: str) -> int:
        """Return the number of <form> elements in the response body."""
        return len(re.findall(r"<form[\s>]", body, re.IGNORECASE))

    @staticmethod
    def has_login_inputs(body: str) -> bool:
        """Return True if the body contains common authentication input names."""
        body_lower = body.lower()
        return any(kw in body_lower for kw in LOGIN_INPUT_KEYWORDS)

    @staticmethod
    def detect_technologies(body: str, headers: dict[str, str]) -> list[str]:
        """
        Match known technology signatures against the response body and headers.

        Returns a deduplicated list of matched technology names.
        """
        combined = body.lower() + " " + " ".join(
            f"{k}: {v}" for k, v in headers.items()
        ).lower()
        found: list[str] = []
        for tech, signatures in TECH_SIGNATURES.items():
            for sig in signatures:
                if sig.lower() in combined:
                    found.append(tech)
                    break
        return found

    # ------------------------------------------------------------------
    # Fingerprint builder
    # ------------------------------------------------------------------

    def fingerprint(self, body: str, headers: dict[str, str]) -> Fingerprint:
        """Build a :class:`Fingerprint` from raw response data."""
        return Fingerprint(
            title=self.extract_title(body),
            forms_count=self.count_forms(body),
            has_login_inputs=self.has_login_inputs(body),
            technologies=self.detect_technologies(body, headers),
            body_preview=body[:500],
        )

    # ------------------------------------------------------------------
    # Confidence scorer
    # ------------------------------------------------------------------

    def score(
        self,
        status: int,
        title: str,
        body: str,
        redirect_url: str,
        forms_count: int,
        technologies: list[str],
        has_login_inputs: bool,
    ) -> int:
        """
        Compute a heuristic confidence score in [0, 100].

        Returns 0 for responses that are clearly not admin pages (404, 5xx).
        """
        score = 0

        # --- Status code ---
        if status == 200:
            score += 20
        elif status in (301, 302, 303, 307, 308):
            score += 10
            if redirect_url:
                rd = redirect_url.lower()
                if any(kw in rd for kw in ["login", "admin", "signin", "auth", "panel"]):
                    score += 15
        elif status == 401:
            score += 30  # Auth-required is a strong positive signal
        elif status == 403:
            score += 12
        else:
            return 0  # 404 / 5xx → not interesting

        # --- Title keywords ---
        if title:
            title_lower = title.lower()
            if any(kw in title_lower for kw in ADMIN_TITLE_KEYWORDS):
                score += 20

        # --- Body keywords ---
        if body:
            body_lower = body.lower()
            for kw in ADMIN_BODY_KEYWORDS:
                if kw in body_lower:
                    score += 5
                    break

        # --- Login form signals ---
        if has_login_inputs:
            score += 10
        if forms_count >= 1:
            score += 5
        if forms_count >= 2:
            score += 5

        # --- Technology fingerprints ---
        if technologies:
            score += min(len(technologies) * 4, 15)

        return min(score, 100)
