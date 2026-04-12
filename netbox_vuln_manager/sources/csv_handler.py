"""
Generic CSV vulnerability source — designed for Nexpose exports but usable
with any CSV-formatted vulnerability report.

Config keys:
  file_path   (required for file-based)  Absolute path to the CSV file
  column_map  (optional)  Dict mapping our field names to CSV column headers.
                          See NEXPOSE_COLUMN_MAP for the default Nexpose layout.
  delimiter   (optional)  CSV delimiter, default ","
  encoding    (optional)  File encoding, default "utf-8"
  skip_rows   (optional)  Number of header rows to skip before the column row, default 0
  date_format (optional)  strptime format for date columns, default auto-detect

Nexpose default export columns (simplified asset-vulnerability report):
  Asset IP Address, Asset Names, Vulnerability ID, Vulnerability Title,
  CVE IDs, CVSS Score, CVSS v3 Score, Risk Score, Severity, Proof,
  Vulnerability Since, Last Tested, Solution

Column map format:
  {
    "asset_ip":        "Asset IP Address",
    "asset_hostname":  "Asset Names",
    "external_id":     "Vulnerability ID",
    "vuln_title":      "Vulnerability Title",
    "cve_id":          "CVE IDs",
    "cvss_v2_score":   "CVSS Score",
    "cvss_v3_score":   "CVSS v3 Score",
    "severity":        "Severity",
    "description":     "Proof",
    "first_seen":      "Vulnerability Since",
    "last_seen":       "Last Tested",
    "remediation":     "Solution",
  }
"""

from __future__ import annotations

import csv
import io
import logging
from datetime import datetime, timezone
from pathlib import Path
from typing import Iterator

from .base import BaseVulnerabilitySource, NormalisedFinding
from ..choices import SeverityChoices

logger = logging.getLogger(__name__)

# Default column mapping for a Nexpose simplified asset-vulnerability export.
NEXPOSE_COLUMN_MAP: dict[str, str] = {
    "asset_ip": "Asset IP Address",
    "asset_hostname": "Asset Names",
    "external_id": "Vulnerability ID",
    "vuln_title": "Vulnerability Title",
    "cve_id": "CVE IDs",
    "cvss_v2_score": "CVSS Score",
    "cvss_v3_score": "CVSS v3 Score",
    "severity": "Severity",
    "description": "Proof",
    "first_seen": "Vulnerability Since",
    "last_seen": "Last Tested",
    "remediation": "Solution",
    "risk_score": "Risk Score",
}

# Nexpose severity strings → our internal severity
_NEXPOSE_SEVERITY_MAP = {
    "critical": SeverityChoices.CRITICAL,
    "severe": SeverityChoices.HIGH,
    "high": SeverityChoices.HIGH,
    "moderate": SeverityChoices.MEDIUM,
    "medium": SeverityChoices.MEDIUM,
    "low": SeverityChoices.LOW,
    "info": SeverityChoices.INFO,
    "informational": SeverityChoices.INFO,
}

_DATE_FORMATS = [
    "%Y-%m-%dT%H:%M:%S",
    "%Y-%m-%d %H:%M:%S",
    "%Y-%m-%d",
    "%m/%d/%Y",
    "%d/%m/%Y",
    "%d-%b-%Y",
]


def _parse_date(value: str, fmt: str | None = None) -> datetime | None:
    if not value or value.strip() in ("", "N/A", "None", "-"):
        return None
    value = value.strip()
    formats = [fmt] if fmt else _DATE_FORMATS
    for f in formats:
        try:
            return datetime.strptime(value, f).replace(tzinfo=timezone.utc)
        except ValueError:
            continue
    return None


def _parse_float(value: str) -> float | None:
    try:
        return float(value.strip()) if value and value.strip() else None
    except (ValueError, AttributeError):
        return None


class CSVSource(BaseVulnerabilitySource):
    """
    Generic CSV vulnerability source.

    Accepts a file path (for Nexpose and similar offline exports) or raw CSV
    content passed in via ``config["csv_content"]`` (for testing or upload
    scenarios).
    """

    source_type = "csv"

    def validate_config(self) -> list[str]:
        errors = []
        has_file = bool(self.config.get("file_path"))
        has_content = bool(self.config.get("csv_content"))
        if not has_file and not has_content:
            errors.append("Either file_path or csv_content is required")
        if has_file and not Path(self.config["file_path"]).exists():
            errors.append(f"file_path does not exist: {self.config['file_path']}")
        return errors

    def fetch(self) -> Iterator[NormalisedFinding]:
        column_map = self.config.get("column_map") or NEXPOSE_COLUMN_MAP
        delimiter = self.config.get("delimiter", ",")
        encoding = self.config.get("encoding", "utf-8")
        skip_rows = int(self.config.get("skip_rows", 0))
        date_format = self.config.get("date_format")

        content = self._get_content(encoding)
        reader = csv.DictReader(
            io.StringIO(content),
            delimiter=delimiter,
        )

        for _ in range(skip_rows):
            next(reader, None)

        for row_num, row in enumerate(reader, start=1 + skip_rows):
            try:
                finding = self._normalise(row, column_map, date_format)
                if not finding.vuln_title and not finding.cve_id:
                    logger.debug("Row %d: no title or CVE ID, skipping", row_num)
                    continue
                yield finding
            except Exception as exc:
                logger.warning("Row %d: failed to parse — %s", row_num, exc)

    def _get_content(self, encoding: str) -> str:
        if self.config.get("csv_content"):
            return self.config["csv_content"]
        path = Path(self.config["file_path"])
        return path.read_text(encoding=encoding, errors="replace")

    def _normalise(
        self,
        row: dict,
        column_map: dict[str, str],
        date_format: str | None,
    ) -> NormalisedFinding:
        def col(field_name: str) -> str:
            header = column_map.get(field_name, "")
            return (row.get(header) or "").strip()

        severity_raw = col("severity").lower()
        severity = _NEXPOSE_SEVERITY_MAP.get(severity_raw)
        if severity is None:
            # Fall back to CVSS-based severity
            score = _parse_float(col("cvss_v3_score")) or _parse_float(col("cvss_v2_score"))
            severity = SeverityChoices.from_cvss(score)

        # CVE IDs column may contain multiple comma-separated values; use first.
        raw_cve = col("cve_id")
        cve_id = None
        if raw_cve:
            candidates = [c.strip().upper() for c in raw_cve.split(",") if c.strip()]
            for candidate in candidates:
                if candidate.startswith("CVE-"):
                    cve_id = candidate
                    break

        first_seen = _parse_date(col("first_seen"), date_format)
        last_seen = _parse_date(col("last_seen"), date_format) or datetime.now(tz=timezone.utc)

        return NormalisedFinding(
            cve_id=cve_id,
            vuln_title=col("vuln_title") or cve_id or col("external_id"),
            description=col("description"),
            severity=severity,
            cvss_v2_score=_parse_float(col("cvss_v2_score")),
            cvss_v3_score=_parse_float(col("cvss_v3_score")),
            asset_ip=col("asset_ip") or None,
            asset_hostname=col("asset_hostname"),
            external_id=col("external_id"),
            first_seen=first_seen,
            last_seen=last_seen,
            remediation=col("remediation"),
            raw=dict(row),
        )
