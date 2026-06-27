"""
Report generation for OmniAdminFinder (TXT, JSON, CSV).
"""

from __future__ import annotations

import csv
import json
import logging
from dataclasses import asdict, dataclass

from omnifinder.scanner import ProbeResult

logger = logging.getLogger(__name__)


@dataclass
class ScanStats:
    """High-level statistics for a completed scan."""
    target: str
    timestamp: str
    total_probed: int = 0
    total_found: int = 0
    duration_seconds: float = 0.0
    concurrency: int = 50
    timeout: float = 5.0


class ReportGenerator:
    """
    Writes scan findings to three output formats:

    * ``<prefix>.txt``  — human-readable ranked summary
    * ``<prefix>.json`` — structured findings + stats for automation
    * ``<prefix>.csv``  — flat tabular export for spreadsheet analysis
    """

    _CSV_FIELDS = [
        "url", "status", "confidence", "title", "technologies",
        "forms_count", "has_login_inputs", "redirect_url",
        "response_time_ms", "content_length", "server_header",
        "content_type", "body_hash",
    ]

    def __init__(self, output_prefix: str, stats: ScanStats) -> None:
        self.prefix = output_prefix
        self.stats = stats

    # ------------------------------------------------------------------
    # Public entry point
    # ------------------------------------------------------------------

    def write_all(self, results: list[ProbeResult]) -> None:
        """Write TXT, JSON, and CSV reports for *results*."""
        self._write_txt(results)
        self._write_json(results)
        self._write_csv(results)
        logger.info("Reports written → %s.{txt,json,csv}", self.prefix)

    # ------------------------------------------------------------------
    # Format writers
    # ------------------------------------------------------------------

    def _write_txt(self, results: list[ProbeResult]) -> None:
        sep = "=" * 80
        lines: list[str] = [
            sep,
            "OMNIADMINFINDER \u2013 DISCOVERY REPORT",
            f"Target: {self.stats.target}",
            f"Timestamp: {self.stats.timestamp}",
            f"Total paths probed: {self.stats.total_probed}",
            f"Likely admin pages: {self.stats.total_found}",
            f"Scan duration: {self.stats.duration_seconds:.1f}s",
            sep,
            "",
        ]
        if results:
            for i, r in enumerate(results, 1):
                lines.append(f"{i}. {r.url}")
                lines.append(f"   Status: {r.status}  |  Score: {r.confidence}%")
                if r.title:
                    lines.append(f"   Title: {r.title}")
                if r.technologies:
                    lines.append(f"   Tech: {', '.join(r.technologies)}")
                if r.forms_count:
                    lines.append(f"   Forms: {r.forms_count} detected")
                if r.redirect_url:
                    lines.append(f"   Redirects to: {r.redirect_url}")
                lines.append(
                    f"   Response time: {r.response_time_ms}ms,"
                    f" Length: {r.content_length} bytes"
                )
                lines.append("")
        else:
            lines.append("No likely admin interfaces found.")

        with open(f"{self.prefix}.txt", "w", encoding="utf-8") as fh:
            fh.write("\n".join(lines))

    def _write_json(self, results: list[ProbeResult]) -> None:
        payload = {
            "stats": asdict(self.stats),
            "findings": [r.to_dict() for r in results],
        }
        with open(f"{self.prefix}.json", "w", encoding="utf-8") as fh:
            json.dump(payload, fh, indent=2, ensure_ascii=False)

    def _write_csv(self, results: list[ProbeResult]) -> None:
        with open(f"{self.prefix}.csv", "w", newline="", encoding="utf-8") as fh:
            writer = csv.DictWriter(fh, fieldnames=self._CSV_FIELDS, extrasaction="ignore")
            writer.writeheader()
            for r in results:
                row = r.to_dict()
                row["technologies"] = "|".join(row.get("technologies", []))
                writer.writerow(row)
