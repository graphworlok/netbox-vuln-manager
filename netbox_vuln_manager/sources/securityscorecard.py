"""
SecurityScorecard vulnerability source.

Config keys:
  api_key   (required) SSC API token
  domain    (required) Target portfolio domain(s), comma-separated or list
  base_url  (optional) API base URL, defaults to https://api.securityscorecard.io
  factors   (optional) list of factor slugs to include; empty = all

The SSC API surfaces findings as "issues" grouped by factor (network_security,
dns_health, patching_cadence, etc.).  This handler maps each issue to a
NormalisedFinding.  CVE IDs are extracted from issue metadata where present.
"""

from __future__ import annotations

import logging
from datetime import datetime, timezone
from typing import Iterator

from .base import BaseVulnerabilitySource, NormalisedFinding
from ..choices import SeverityChoices

logger = logging.getLogger(__name__)

_SSC_BASE = "https://api.securityscorecard.io"

# SSC issue severity → internal severity
_SEVERITY_MAP = {
    "positive": SeverityChoices.NONE,
    "info": SeverityChoices.INFO,
    "low": SeverityChoices.LOW,
    "medium": SeverityChoices.MEDIUM,
    "high": SeverityChoices.HIGH,
}

# SSC factor slugs that are vulnerability-relevant (not just hygiene scores)
_VULN_FACTORS = {
    "network_security",
    "patching_cadence",
    "endpoint_security",
    "application_security",
    "cubit_score",
}


class SecurityScorecardSource(BaseVulnerabilitySource):
    """Fetch issues from SecurityScorecard portfolio API."""

    source_type = "securityscorecard"

    def validate_config(self) -> list[str]:
        errors = []
        if not self.config.get("api_key"):
            errors.append("api_key is required")
        if not self.config.get("domain"):
            errors.append("domain is required (comma-separated list of target domains)")
        return errors

    def fetch(self) -> Iterator[NormalisedFinding]:
        domains = self.config["domain"]
        if isinstance(domains, str):
            domains = [d.strip() for d in domains.split(",") if d.strip()]

        for domain in domains:
            yield from self._fetch_domain(domain)

    def _fetch_domain(self, domain: str) -> Iterator[NormalisedFinding]:
        session = self._requests_session()
        base = self.config.get("base_url", _SSC_BASE).rstrip("/")
        headers = {
            "Authorization": f"Token {self.config['api_key']}",
            "Accept": "application/json",
        }
        factors_filter = self.config.get("factors") or list(_VULN_FACTORS)
        if isinstance(factors_filter, str):
            factors_filter = [f.strip() for f in factors_filter.split(",")]

        for factor in factors_filter:
            page = 1
            while True:
                url = f"{base}/companies/{domain}/issues/{factor}"
                resp = session.get(
                    url,
                    headers=headers,
                    params={"page": page, "per_page": 100},
                )

                if resp.status_code == 404:
                    logger.debug("Factor %s not found for domain %s", factor, domain)
                    break

                resp.raise_for_status()
                data = resp.json()
                entries = data.get("entries") or []

                for entry in entries:
                    yield self._normalise(entry, domain=domain, factor=factor)

                # SSC uses total + count for pagination
                if data.get("total", 0) <= page * 100:
                    break
                page += 1

    def _normalise(self, item: dict, domain: str, factor: str) -> NormalisedFinding:
        severity_raw = item.get("severity", "medium").lower()
        severity = _SEVERITY_MAP.get(severity_raw, SeverityChoices.MEDIUM)

        # CVE IDs sometimes appear in the issue type or detail field
        cve_id = None
        detail = item.get("detail") or {}
        if isinstance(detail, dict):
            cve_id = detail.get("cve") or detail.get("cve_id") or None
        if not cve_id:
            issue_type = item.get("type", "")
            if issue_type.upper().startswith("CVE-"):
                cve_id = issue_type.upper()

        # Asset hostname / IP come from the issue record
        asset_ip = (
            item.get("ip_address")
            or item.get("ip")
            or (detail.get("ip_address") if isinstance(detail, dict) else None)
            or None
        )
        asset_hostname = (
            item.get("hostname")
            or item.get("domain", domain)
        )

        title = item.get("type", factor).replace("_", " ").title()
        if cve_id:
            title = cve_id

        first_seen = _parse_ssc_ts(item.get("first_seen_time") or item.get("created_at"))
        last_seen = _parse_ssc_ts(item.get("last_seen_time") or item.get("updated_at"))

        return NormalisedFinding(
            cve_id=cve_id,
            vuln_title=title,
            description=item.get("description") or str(detail),
            severity=severity,
            references=item.get("references") or [],
            asset_hostname=asset_hostname,
            asset_ip=asset_ip,
            external_id=item.get("id") or item.get("issue_id") or "",
            first_seen=first_seen,
            last_seen=last_seen or datetime.now(tz=timezone.utc),
            raw={"domain": domain, "factor": factor, **item},
        )


def _parse_ssc_ts(ts: str | None) -> datetime | None:
    if not ts:
        return None
    for fmt in ("%Y-%m-%dT%H:%M:%SZ", "%Y-%m-%dT%H:%M:%S.%fZ", "%Y-%m-%d"):
        try:
            return datetime.strptime(ts, fmt).replace(tzinfo=timezone.utc)
        except ValueError:
            continue
    return None
