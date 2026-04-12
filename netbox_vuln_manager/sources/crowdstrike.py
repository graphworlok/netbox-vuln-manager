"""
CrowdStrike Falcon Spotlight vulnerability source.

Config keys:
  client_id     (required) OAuth2 client ID
  client_secret (required) OAuth2 client secret
  base_url      (optional) CrowdStrike base URL, defaults to US-1 cloud
  filter        (optional) FQL filter string, e.g. "status:'open'"
  page_size     (optional) results per page (default 400, max 400)

This handler supports two modes:
  1. falconpy  — uses the crowdstrike-falconpy SDK if installed (preferred)
  2. direct    — plain requests OAuth2 flow (fallback, no extra dependency)
"""

from __future__ import annotations

import logging
from datetime import datetime, timezone
from typing import Iterator

from .base import BaseVulnerabilitySource, NormalisedFinding
from ..choices import SeverityChoices

logger = logging.getLogger(__name__)

_FALCON_BASE = "https://api.crowdstrike.com"

# CrowdStrike severity strings → our internal severity
_SEVERITY_MAP = {
    "CRITICAL": SeverityChoices.CRITICAL,
    "HIGH": SeverityChoices.HIGH,
    "MEDIUM": SeverityChoices.MEDIUM,
    "LOW": SeverityChoices.LOW,
    "INFORMATIONAL": SeverityChoices.INFO,
    "UNKNOWN": SeverityChoices.NONE,
}


def _parse_cs_ts(ts: str | None) -> datetime | None:
    """Parse CrowdStrike ISO-8601 timestamp to aware datetime."""
    if not ts:
        return None
    try:
        # CrowdStrike uses RFC 3339 with 'Z' suffix
        ts = ts.replace("Z", "+00:00")
        return datetime.fromisoformat(ts)
    except (ValueError, AttributeError):
        return None


class CrowdStrikeSource(BaseVulnerabilitySource):
    """Fetch vulnerability findings from CrowdStrike Falcon Spotlight."""

    source_type = "crowdstrike"

    def validate_config(self) -> list[str]:
        errors = []
        if not self.config.get("client_id"):
            errors.append("client_id is required")
        if not self.config.get("client_secret"):
            errors.append("client_secret is required")
        return errors

    def fetch(self) -> Iterator[NormalisedFinding]:
        try:
            import falconpy  # noqa: F401
            yield from self._fetch_via_falconpy()
        except ImportError:
            logger.debug("falconpy not installed, falling back to direct API calls")
            yield from self._fetch_direct()

    # ------------------------------------------------------------------
    # falconpy path
    # ------------------------------------------------------------------

    def _fetch_via_falconpy(self) -> Iterator[NormalisedFinding]:
        from falconpy import SpotlightVulnerabilities

        sdk = SpotlightVulnerabilities(
            client_id=self.config["client_id"],
            client_secret=self.config["client_secret"],
            base_url=self.config.get("base_url", _FALCON_BASE),
        )

        fql_filter = self.config.get("filter", "status:'open'")
        after = None

        while True:
            params = {
                "filter": fql_filter,
                "limit": self.config.get("page_size", 400),
                "facet": ["cve", "host_info", "remediation"],
            }
            if after:
                params["after"] = after

            response = sdk.query_vulnerabilities_combined(**params)

            if response["status_code"] != 200:
                logger.error(
                    "CrowdStrike API error %s: %s",
                    response["status_code"],
                    response.get("body", {}).get("errors"),
                )
                break

            body = response["body"]
            resources = body.get("resources") or []
            for item in resources:
                yield self._normalise(item)

            pagination = body.get("meta", {}).get("pagination", {})
            after = pagination.get("after")
            if not after or not resources:
                break

    # ------------------------------------------------------------------
    # Direct REST path (no falconpy dependency)
    # ------------------------------------------------------------------

    def _get_token(self) -> str:
        session = self._requests_session()
        base = self.config.get("base_url", _FALCON_BASE).rstrip("/")
        resp = session.post(
            f"{base}/oauth2/token",
            data={
                "client_id": self.config["client_id"],
                "client_secret": self.config["client_secret"],
            },
        )
        resp.raise_for_status()
        return resp.json()["access_token"]

    def _fetch_direct(self) -> Iterator[NormalisedFinding]:
        token = self._get_token()
        session = self._requests_session()
        base = self.config.get("base_url", _FALCON_BASE).rstrip("/")
        headers = {"Authorization": f"Bearer {token}"}
        fql_filter = self.config.get("filter", "status:'open'")
        page_size = self.config.get("page_size", 400)
        after = None

        while True:
            params = {
                "filter": fql_filter,
                "limit": page_size,
                "facet": "cve,host_info,remediation",
            }
            if after:
                params["after"] = after

            resp = session.get(
                f"{base}/spotlight/combined/vulnerabilities/v1",
                headers=headers,
                params=params,
            )

            if resp.status_code == 401:
                # Token may have expired mid-sync on large environments
                token = self._get_token()
                headers["Authorization"] = f"Bearer {token}"
                continue

            resp.raise_for_status()
            body = resp.json()
            resources = body.get("resources") or []
            for item in resources:
                yield self._normalise(item)

            pagination = body.get("meta", {}).get("pagination", {})
            after = pagination.get("after")
            if not after or not resources:
                break

    # ------------------------------------------------------------------
    # Normalisation
    # ------------------------------------------------------------------

    def _normalise(self, item: dict) -> NormalisedFinding:
        cve = item.get("cve") or {}
        host = item.get("host_info") or {}
        remediation_list = item.get("remediation", {}).get("entities") or []
        remediation_text = "; ".join(
            r.get("action", "") for r in remediation_list if r.get("action")
        )

        cvss_v2 = None
        cvss_v3 = None
        try:
            cvss_v2 = float(cve.get("base_score", 0)) or None
        except (TypeError, ValueError):
            pass
        try:
            cvss_v3 = float(cve.get("cvss3_score", 0)) or None
        except (TypeError, ValueError):
            pass

        # CrowdStrike calls severity "CRITICAL", "HIGH", etc.
        severity_raw = (
            item.get("severity", "")
            or cve.get("severity", "")
        ).upper()
        severity = _SEVERITY_MAP.get(severity_raw, SeverityChoices.NONE)

        return NormalisedFinding(
            cve_id=cve.get("id") or None,
            vuln_title=cve.get("id") or item.get("id", ""),
            description=cve.get("description", ""),
            severity=severity,
            cvss_v2_score=cvss_v2,
            cvss_v3_score=cvss_v3,
            cvss_v3_vector=cve.get("vector", ""),
            references=[
                url
                for ref in (cve.get("references") or [])
                for url in ([ref] if isinstance(ref, str) else [])
            ],
            published_date=_parse_cs_ts(cve.get("published_date")),
            asset_hostname=host.get("hostname", ""),
            asset_ip=host.get("local_ip") or host.get("external_ip") or None,
            external_id=item.get("id", ""),
            first_seen=_parse_cs_ts(item.get("created_timestamp")),
            last_seen=_parse_cs_ts(item.get("updated_timestamp"))
                      or datetime.now(tz=timezone.utc),
            exploitability=str(item.get("exprt_rating", "")),
            remediation=remediation_text,
            raw=item,
        )
