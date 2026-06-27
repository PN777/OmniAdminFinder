"""
Command-line interface entry point for OmniAdminFinder.
"""

from __future__ import annotations

import argparse
import asyncio
import sys
import time
from datetime import datetime, timezone

from omnifinder import __version__
from omnifinder.analyzer import WordlistGenerator
from omnifinder.reporter import ReportGenerator, ScanStats
from omnifinder.scanner import AsyncAdminProber
from omnifinder.utils import configure_logging, validate_url

# ---------------------------------------------------------------------------
# Banner
# ---------------------------------------------------------------------------

BANNER = rf"""
  ___                 _    _       _       _____ _           _
 / _ \  _ __ ___  _ _ \  / /_  _ | |_  _ |  ___(_)_ __  __| | ___ _ __
| | | || '_ ` _ \| '_ \| / _ \| || __|(_)| |_  | | '_ \/ _` |/ _ \ '__|
| |_| || | | | | | | | | | (_) | || |_  _ |  _| | | | | | (_| |  __/ |
 \___/ |_| |_| |_|_| |_|_|\___/|_| \__|(_)|_|   |_|_| |_|\__,_|\___|_|

  v{__version__}  |  Asynchronous admin interface discovery engine
  For authorized security research only.
"""


# ---------------------------------------------------------------------------
# Console summary printer
# ---------------------------------------------------------------------------

def print_summary(results, stats: ScanStats) -> None:
    sep = "=" * 80
    print(f"\n{sep}")
    print("OMNIADMINFINDER \u2013 DISCOVERY REPORT")
    print(f"Target:           {stats.target}")
    print(f"Timestamp:        {stats.timestamp}")
    print(f"Paths probed:     {stats.total_probed}")
    print(f"Likely admin:     {stats.total_found}")
    print(f"Scan duration:    {stats.duration_seconds:.1f}s")
    print(sep)

    if results:
        for i, r in enumerate(results, 1):
            tech = f"  Tech: {', '.join(r.technologies)}" if r.technologies else ""
            forms = f"  Forms: {r.forms_count}" if r.forms_count else ""
            redir = f"  \u2192 {r.redirect_url}" if r.redirect_url else ""
            title = f'  "{r.title}"' if r.title else ""
            print(
                f"\n  {i}. {r.url}\n"
                f"     [{r.status}] Score: {r.confidence}%{title}"
                f"{tech}{forms}{redir}\n"
                f"     {r.response_time_ms}ms  {r.content_length} bytes"
            )
    else:
        print("\n  No likely admin interfaces found.\n")

    print(sep)


# ---------------------------------------------------------------------------
# Argument parser
# ---------------------------------------------------------------------------

def _positive_int(value: str) -> int:
    """argparse type: integer that must be >= 1."""
    try:
        ivalue = int(value)
    except ValueError:
        raise argparse.ArgumentTypeError(f"{value!r} is not a valid integer") from None
    if ivalue < 1:
        raise argparse.ArgumentTypeError(f"must be >= 1 (got {ivalue})")
    return ivalue


def _positive_float(value: str) -> float:
    """argparse type: float that must be > 0."""
    try:
        fvalue = float(value)
    except ValueError:
        raise argparse.ArgumentTypeError(f"{value!r} is not a valid number") from None
    if fvalue <= 0:
        raise argparse.ArgumentTypeError(f"must be > 0 (got {fvalue})")
    return fvalue


def _non_negative_float(value: str) -> float:
    """argparse type: float that must be >= 0."""
    try:
        fvalue = float(value)
    except ValueError:
        raise argparse.ArgumentTypeError(f"{value!r} is not a valid number") from None
    if fvalue < 0:
        raise argparse.ArgumentTypeError(f"must be >= 0 (got {fvalue})")
    return fvalue


def _non_negative_int(value: str) -> int:
    """argparse type: integer that must be >= 0."""
    try:
        ivalue = int(value)
    except ValueError:
        raise argparse.ArgumentTypeError(f"{value!r} is not a valid integer") from None
    if ivalue < 0:
        raise argparse.ArgumentTypeError(f"must be >= 0 (got {ivalue})")
    return ivalue


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="omniadminfinder",
        description=(
            "OmniAdminFinder — Asynchronous admin interface discovery engine.\n"
            "For authorized security research ONLY."
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    p.add_argument("url", help="Target base URL (e.g. https://example.com)")
    p.add_argument("-w", "--wordlist", metavar="FILE",
                   help="Custom path wordlist (one path per line)")
    p.add_argument("-t", "--threads", type=_positive_int, default=50, metavar="N",
                   help="Max concurrent requests, >= 1 (default: 50)")
    p.add_argument("-T", "--timeout", type=_positive_float, default=5.0, metavar="SEC",
                   help="Request timeout in seconds, > 0 (default: 5.0)")
    p.add_argument("-r", "--rate-limit", type=_non_negative_float, default=0.0, metavar="SEC",
                   help="Delay between requests in seconds, >= 0 (default: 0.0)")
    p.add_argument("-R", "--retries", type=_non_negative_int, default=1, metavar="N",
                   help="Retry attempts per path on transient error (default: 1)")
    p.add_argument("-o", "--output", default="admin_scan", metavar="PREFIX",
                   help="Output filename prefix (default: admin_scan)")
    p.add_argument("-v", "--verbose", action="store_true",
                   help="Enable verbose/debug logging")
    p.add_argument("--no-ssl-verify", action="store_true",
                   help="Disable SSL certificate verification")
    p.add_argument("--extensions", metavar="CSV",
                   help='Comma-separated extension list (e.g. ".php,.asp,.html")')
    p.add_argument("--user-agent", metavar="UA",
                   help="Override User-Agent header")
    p.add_argument("--proxy", metavar="URL",
                   help="Proxy URL (e.g. http://127.0.0.1:8080)")
    p.add_argument("--max-redirects", type=_non_negative_int, default=5, metavar="N",
                   help="Max redirects to follow, >= 0 (default: 5)")
    p.add_argument("--no-follow-redirects", action="store_true",
                   help="Disable redirect following")
    p.add_argument("--no-banner", action="store_true",
                   help="Suppress startup banner")
    p.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    return p


# ---------------------------------------------------------------------------
# Async core
# ---------------------------------------------------------------------------

async def _async_main(args: argparse.Namespace) -> None:
    import logging
    configure_logging(args.verbose)
    logger = logging.getLogger(__name__)

    target = validate_url(args.url)

    if not args.no_banner:
        print(BANNER)

    extensions: list[str] | None = None
    if args.extensions:
        extensions = [
            e.strip() if e.strip().startswith(".") else f".{e.strip()}"
            for e in args.extensions.split(",")
        ]

    logger.info("Target      : %s", target)
    logger.info("Concurrency : %d", args.threads)
    logger.info("Timeout     : %.1fs", args.timeout)
    logger.info("SSL verify  : %s", not args.no_ssl_verify)
    if args.proxy:
        logger.info("Proxy       : %s", args.proxy)

    # Generate wordlist
    generator = WordlistGenerator(
        target_url=target,
        custom_wordlist=args.wordlist,
        extensions=extensions,
    )
    paths = generator.generate()
    logger.info("Paths queued: %d", len(paths))

    # Run scanner
    prober = AsyncAdminProber(
        target_url=target,
        concurrency=args.threads,
        timeout=args.timeout,
        rate_limit=args.rate_limit,
        retries=args.retries,
        verify_ssl=not args.no_ssl_verify,
        user_agent=args.user_agent,
        proxy=args.proxy,
        max_redirects=args.max_redirects,
        follow_redirects=not args.no_follow_redirects,
        verbose=args.verbose,
    )

    logger.info("Scan started …")
    t0 = time.monotonic()
    results = await prober.run(paths)
    duration = time.monotonic() - t0

    timestamp = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
    stats = ScanStats(
        target=target,
        timestamp=timestamp,
        total_probed=len(paths),
        total_found=len(results),
        duration_seconds=round(duration, 2),
        concurrency=args.threads,
        timeout=args.timeout,
    )

    print_summary(results, stats)

    reporter = ReportGenerator(output_prefix=args.output, stats=stats)
    reporter.write_all(results)


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

def main() -> None:
    parser = build_parser()
    args = parser.parse_args()
    try:
        asyncio.run(_async_main(args))
    except KeyboardInterrupt:
        print("\n[!] Interrupted by user.")
        sys.exit(0)


if __name__ == "__main__":
    main()
