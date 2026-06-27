"""
Async HTTP scanning engine for OmniAdminFinder.
"""

from __future__ import annotations

import asyncio
import logging
import time
from dataclasses import asdict, dataclass, field

import aiohttp
from aiohttp import ClientTimeout, TCPConnector

from omnifinder.fingerprint import ResponseClassifier
from omnifinder.utils import md5_preview

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Result model
# ---------------------------------------------------------------------------

@dataclass
class ProbeResult:
    """Stores every field captured from a single HTTP probe."""
    url: str
    status: int
    title: str = ""
    forms_count: int = 0
    has_login_inputs: bool = False
    redirect_url: str = ""
    response_time_ms: float = 0.0
    content_length: int = 0
    body_preview: str = ""
    body_hash: str = ""
    technologies: list[str] = field(default_factory=list)
    confidence: int = 0
    server_header: str = ""
    content_type: str = ""

    def to_dict(self) -> dict:
        """Serialise to a plain dict (suitable for JSON/CSV export)."""
        return asdict(self)


# ---------------------------------------------------------------------------
# Scanner
# ---------------------------------------------------------------------------

class AsyncAdminProber:
    """
    Concurrent async HTTP probe engine.

    Dispatches all candidate paths through an :class:`asyncio.Semaphore`-bounded
    pool of aiohttp requests, parses each response, scores it, and returns a
    list of :class:`ProbeResult` objects sorted by descending confidence.
    """

    DEFAULT_UA = (
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
        "AppleWebKit/537.36 (KHTML, like Gecko) "
        "Chrome/124.0.0.0 Safari/537.36"
    )

    def __init__(
        self,
        target_url: str,
        concurrency: int = 50,
        timeout: float = 5.0,
        rate_limit: float = 0.0,
        retries: int = 1,
        verify_ssl: bool = True,
        user_agent: str | None = None,
        proxy: str | None = None,
        max_redirects: int = 5,
        follow_redirects: bool = True,
        verbose: bool = False,
        min_confidence: int = 1,
    ) -> None:
        self.target_url = target_url.rstrip("/")
        self.concurrency = concurrency
        self.timeout = timeout
        self.rate_limit = rate_limit
        self.retries = max(retries, 0)
        self.verify_ssl = verify_ssl
        self.user_agent = user_agent or self.DEFAULT_UA
        self.proxy = proxy
        self.max_redirects = max_redirects
        self.follow_redirects = follow_redirects
        self.verbose = verbose
        self.min_confidence = min_confidence
        self._classifier = ResponseClassifier()

    # ------------------------------------------------------------------
    # Internal: probe a single path
    # ------------------------------------------------------------------

    async def _probe_one(
        self,
        session: aiohttp.ClientSession,
        semaphore: asyncio.Semaphore,
        path: str,
    ) -> ProbeResult | None:
        url = f"{self.target_url}/{path.lstrip('/')}"
        async with semaphore:
            if self.rate_limit > 0:
                await asyncio.sleep(self.rate_limit)

            last_exc: Exception | None = None
            for attempt in range(self.retries + 1):
                if attempt > 0:
                    # Exponential backoff: 0.5s, 1s, 2s …
                    await asyncio.sleep(0.5 * (2 ** (attempt - 1)))

                t0 = time.monotonic()
                try:
                    async with session.get(
                        url,
                        proxy=self.proxy,
                        allow_redirects=self.follow_redirects,
                        max_redirects=self.max_redirects,
                        ssl=self.verify_ssl,
                    ) as resp:
                        elapsed_ms = (time.monotonic() - t0) * 1000
                        body_bytes = await resp.read()
                        try:
                            body = body_bytes.decode("utf-8", errors="replace")
                        except Exception:
                            body = ""

                        headers = dict(resp.headers)
                        fp = self._classifier.fingerprint(body, headers)

                        redirect_url = str(resp.url) if resp.history else ""

                        confidence = self._classifier.score(
                            status=resp.status,
                            title=fp.title,
                            body=body,
                            redirect_url=redirect_url,
                            forms_count=fp.forms_count,
                            technologies=fp.technologies,
                            has_login_inputs=fp.has_login_inputs,
                        )

                        if self.verbose:
                            logger.debug(
                                "[%d] %s  score=%d%%  %.0fms",
                                resp.status, url, confidence, elapsed_ms,
                            )

                        return ProbeResult(
                            url=url,
                            status=resp.status,
                            title=fp.title,
                            forms_count=fp.forms_count,
                            has_login_inputs=fp.has_login_inputs,
                            redirect_url=redirect_url,
                            response_time_ms=round(elapsed_ms, 1),
                            content_length=len(body_bytes),
                            body_preview=fp.body_preview,
                            body_hash=md5_preview(body_bytes),
                            technologies=fp.technologies,
                            confidence=confidence,
                            server_header=headers.get("Server", ""),
                            content_type=headers.get("Content-Type", ""),
                        )

                except asyncio.TimeoutError as exc:
                    last_exc = exc
                    if self.verbose:
                        logger.debug("TIMEOUT attempt %d/%d %s", attempt + 1, self.retries + 1, url)
                except aiohttp.ClientError as exc:
                    last_exc = exc
                    if self.verbose:
                        logger.debug(
                            "CLIENT_ERROR attempt %d/%d %s — %s",
                            attempt + 1, self.retries + 1, url, exc,
                        )
                    break  # Non-transient client errors are not retried
                except Exception as exc:
                    logger.warning("Unexpected error probing %s: %s", url, exc)
                    break

            if last_exc and self.verbose:
                logger.debug("FAILED after %d attempt(s): %s", self.retries + 1, url)
        return None

    # ------------------------------------------------------------------
    # Public: run all paths
    # ------------------------------------------------------------------

    async def run(self, paths: list[str]) -> list[ProbeResult]:
        """
        Probe all *paths* concurrently and return findings sorted by
        descending confidence.
        """
        semaphore = asyncio.Semaphore(self.concurrency)
        connector = TCPConnector(ssl=self.verify_ssl, limit=self.concurrency)
        timeout_obj = ClientTimeout(total=self.timeout)
        headers = {"User-Agent": self.user_agent}

        async with aiohttp.ClientSession(
            timeout=timeout_obj,
            connector=connector,
            headers=headers,
        ) as session:
            tasks = [self._probe_one(session, semaphore, path) for path in paths]
            raw = await asyncio.gather(*tasks, return_exceptions=False)

        results: list[ProbeResult] = [
            r for r in raw
            if r is not None and r.confidence >= self.min_confidence
        ]
        results.sort(key=lambda r: r.confidence, reverse=True)
        return results
