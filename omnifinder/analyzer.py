"""
Wordlist generation and path analysis for OmniAdminFinder.
"""

from __future__ import annotations

import logging

from omnifinder.utils import domain_mutations

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Built-in path dictionaries
# ---------------------------------------------------------------------------

DEFAULT_PATHS: list[str] = [
    "admin", "admin/", "administrator", "administrator/", "admin.php",
    "admin.html", "admin.asp", "admin.aspx", "admin/login", "admin/login.php",
    "admin/index.php", "admin/index.html", "admin/dashboard", "adminpanel",
    "wp-admin", "wp-admin/", "wp-login.php", "wp-admin/index.php",
    "login", "login.php", "login.html", "login.asp", "login.aspx",
    "signin", "signin.php", "sign-in", "sign-in.php",
    "dashboard", "dashboard/", "dashboard.php",
    "panel", "panel/", "cpanel", "cpanel/", "control", "controlpanel",
    "manage", "manage/", "manager", "management", "management/",
    "backend", "backend/", "backoffice", "back-office",
    "siteadmin", "site-admin", "adminsite", "admin-site",
    "moderator", "moderator/", "mod/", "staff", "staff/",
    "user/admin", "users/admin", "account/admin",
    "secure", "secure/", "security", "auth", "auth/",
    "cms", "cms/", "cms/admin", "cms/login",
    "joomla/administrator", "administrator/index.php",
    "drupal/admin", "drupal/user/login",
    "phpmyadmin", "phpmyadmin/", "pma/", "sqlmanager",
    "webadmin", "webadmin/", "web-admin", "web-admin/",
    "portal", "portal/", "portal/login", "portal/admin",
    "system/admin", "system/login", "system/dashboard",
    "config", "configuration", "setup", "install",
    "api/admin", "api/v1/admin", "api/auth",
    "django-admin", "django-admin/",
    "_admin", "_administrator", "_login",
    "old-admin", "oldadmin", "admin-old",
    "test/admin", "dev/admin", "staging/admin",
    "console", "console/", "webconsole", "adminconsole",
    "secret", "private", "restricted",
    "filemanager", "file-manager", "fileman",
    "maintenance", "maint",
    "shell", "cmd", "exec",
    "typo3", "typo3/", "typo3/admin",
    "magento/admin", "index.php/admin",
    "prestashop/admin", "opencart/admin",
    "laravel/admin", "laravel-admin",
    "rails/admin", "rails-admin", "active_admin",
    "flask/admin", "flask-admin",
]

EXTENDED_PATHS: list[str] = [
    "admin1", "admin2", "admin123", "adm", "adm/",
    "superadmin", "super-admin", "superuser",
    "root", "root/", "sysadmin",
    "master", "master/",
    "ops", "operations", "devops",
    "tools", "tools/admin",
    "utility", "utilities",
    "user-management", "usermanagement",
    "account", "accounts", "account-manager",
    "member", "members", "membership",
    "subscriber", "subscribers",
    "editor", "editors", "author", "authors",
    "finance/admin", "billing/admin", "support/admin",
    "helpdesk", "help-desk", "support", "ticket",
    "crm", "crm/admin", "crm/login",
    "erp", "erp/admin",
    "analytics", "analytics/admin", "stats", "statistics",
    "reports", "reporting",
    "logs", "log", "audit",
    "inventory", "warehouse",
    "shop/admin", "store/admin", "ecommerce/admin",
    "payment", "payments", "checkout/admin",
    "order", "orders", "order-management",
    "product", "products", "catalog/admin",
    "category", "categories",
    "media", "media/admin", "uploads", "files",
    "gallery", "gallery/admin",
    "mail", "mailer", "email/admin", "newsletter",
    "cron", "scheduler", "tasks",
    "backup", "backups", "restore",
    "cache", "cache/admin",
    "search/admin", "index/admin",
    "health", "status", "ping", "monitor", "monitoring",
    "metrics", "prometheus", "grafana",
    "kibana", "elasticsearch/admin",
    "jenkins", "ci", "build",
    "git", "gitlab", "bitbucket",
    "adminer", "adminer.php", "database",
    "redis", "memcache", "queue",
    "swagger", "swagger-ui", "api-docs", "openapi",
    "graphql", "graphiql",
]

DEFAULT_EXTENSIONS: list[str] = ["", ".php", ".asp", ".aspx", ".html", ".htm", ".jsp"]


# ---------------------------------------------------------------------------
# Wordlist generator
# ---------------------------------------------------------------------------

class WordlistGenerator:
    """
    Generates a deduplicated, extension-expanded list of admin path candidates.

    Sources (in priority order):
    1. Custom wordlist file (if supplied via ``-w``).
    2. Built-in ``DEFAULT_PATHS`` + ``EXTENDED_PATHS``.
    3. Domain-derived mutations from the target hostname.
    """

    def __init__(
        self,
        target_url: str,
        custom_wordlist: str | None = None,
        extensions: list[str] | None = None,
    ) -> None:
        self.target_url = target_url
        self.custom_wordlist = custom_wordlist
        self.extensions = extensions or DEFAULT_EXTENSIONS

    def _load_custom(self) -> list[str]:
        if not self.custom_wordlist:
            return []
        try:
            with open(self.custom_wordlist, encoding="utf-8", errors="ignore") as fh:
                return [ln.strip().lstrip("/") for ln in fh if ln.strip()]
        except OSError as exc:
            logger.warning("Cannot read wordlist %s: %s", self.custom_wordlist, exc)
            return []

    def _base_paths(self) -> list[str]:
        if self.custom_wordlist:
            return self._load_custom()
        return DEFAULT_PATHS + EXTENDED_PATHS + domain_mutations(self.target_url)

    def _deduplicate(self, paths: list[str]) -> list[str]:
        seen: set[str] = set()
        unique: list[str] = []
        for p in paths:
            key = p.lower().rstrip("/")
            if key not in seen:
                seen.add(key)
                unique.append(p)
        return unique

    def _expand_extensions(self, paths: list[str]) -> list[str]:
        expanded: list[str] = []
        seen: set[str] = set()
        for path in paths:
            # Only expand bare paths (last segment has no dot)
            last_segment = path.split("/")[-1]
            has_ext = "." in last_segment
            if has_ext:
                if path not in seen:
                    expanded.append(path)
                    seen.add(path)
            else:
                for ext in self.extensions:
                    candidate = path.rstrip("/") + ext
                    if candidate not in seen:
                        expanded.append(candidate)
                        seen.add(candidate)
        return expanded

    def generate(self) -> list[str]:
        """Return the full, deduplicated, extension-expanded path list."""
        base = self._deduplicate(self._base_paths())
        return self._expand_extensions(base)
