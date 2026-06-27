"""
Utility helpers for OmniAdminFinder.
"""

from __future__ import annotations

import hashlib
import logging
from urllib.parse import urlparse

logger = logging.getLogger(__name__)


def validate_url(raw: str) -> str:
    """
    Normalise and validate a target URL.

    Prepends ``https://`` if no scheme is present.
    Raises :class:`SystemExit` if the host cannot be parsed.
    """
    if not raw.startswith(("http://", "https://")):
        raw = "https://" + raw
    parsed = urlparse(raw)
    if not parsed.hostname:
        raise SystemExit(f"[ERROR] Invalid URL: {raw!r}")
    return raw.rstrip("/")


def md5_preview(data: bytes, preview_bytes: int = 4096) -> str:
    """Return a hex MD5 digest of the first *preview_bytes* of *data*."""
    return hashlib.md5(data[:preview_bytes]).hexdigest()


def configure_logging(verbose: bool = False) -> None:
    """Configure root logger format and level."""
    level = logging.DEBUG if verbose else logging.INFO
    logging.basicConfig(
        level=level,
        format="%(asctime)s  %(levelname)-8s  %(message)s",
        datefmt="%H:%M:%S",
    )


def domain_mutations(target_url: str) -> list[str]:
    """
    Generate target-derived path mutations from the hostname.

    For example, ``https://acme.example.com`` → ``["acme-admin", "admin-acme", "acmeadmin"]``.
    """
    parsed = urlparse(target_url)
    hostname = parsed.hostname or ""
    parts = hostname.split(".")
    if not parts or not parts[0]:
        return []
    name = parts[0]
    return [f"{name}-admin", f"admin-{name}", f"{name}admin"]
