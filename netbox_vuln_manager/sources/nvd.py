"""
NVD API v2 enricher.

Fetches CVE detail from the NIST National Vulnerability Database and updates
existing Vulnerability records in NetBox.  Does NOT create new Vulnerability
objects — that is the job of the source handlers (CrowdStrike, SSC, CSV).

Config (from plugin default_settings or passed directly):
  nvd_api_key   (optional) API key; without it rate limit is 5 req/30 s
  nvd_base_url  (optional) override API base URL

Rate limiting
-------------
NIST enforces:
  - Without key: 5 requests per 30-second rolling window
  - With key:   50 requests per 30-second rolling window

This module sleeps automatically between requests.  The recommended NVD
approach is to request 2000 results per page and use lastModStartDate /
lastModEndDate when fetching incremental updates.

Reference: https://nvd.nist.gov/developers/vulnerabilities
"""

from __future__ import annotations

import logging
import time
from datetime import date, datetime, timezone
from typing import Iterator

import requests

logger = logging.getLogger(__name__)

_NVD_BASE = "https://services.nvd.nist.gov/rest/json/cves/2.0"
_PAGE_SIZE = 2000

# Seconds to sleep between requests (conservative — stays well inside limits)
_SLEEP_NO_KEY = 6.5   # ~4.6 req/30 s (under the 5/30 s limit)
_SLEEP_WITH_KEY = 0.7  # ~43 req/30 s (under the 50/30 s limit)


def _parse_nvd_date(s: str | None) -> datetime | None:
    if not s:
        return None
    for fmt in ("%Y-%m-%dT%H:%M:%S.%f", "%Y-%m-%dT%H:%M:%S"):
        try:
            return datetime.strptime(s[:26], fmt).replace(tzinfo=timezone.utc)
        except ValueError:
            continue
    return None


def _extract_cvss(cve_item: dict) -> dict:
    """Return the best available CVSS scores and vector from a CVE item."""
    metrics = cve_item.get("metrics", {})
    result = {
        "cvss_v3_score": None,
        "cvss_v3_vector": "",
        "cvss_v2_score": None,
    }

    # Prefer v3.1, then v3.0, then v2.0
    for key in ("cvssMetricV31", "cvssMetricV30"):
        entries = metrics.get(key, [])
        if entries:
            data = entries[0].get("cvssData", {})
            result["cvss_v3_score"] = data.get("baseScore")
            result["cvss_v3_vector"] = data.get("vectorString", "")
            break

    entries_v2 = metrics.get("cvssMetricV2", [])
    if entries_v2:
        data = entries_v2[0].get("cvssData", {})
        result["cvss_v2_score"] = data.get("baseScore")

    return result


def _extract_cwe(cve_item: dict) -> str:
    weaknesses = cve_item.get("weaknesses", [])
    for w in weaknesses:
        for desc in w.get("description", []):
            val = desc.get("value", "")
            if val.startswith("CWE-"):
                return val
    return ""


def _extract_description(cve_item: dict) -> str:
    for desc in cve_item.get("descriptions", []):
        if desc.get("lang") == "en":
            return desc.get("value", "")
    return ""


def _extract_references(cve_item: dict) -> list[str]:
    return [r["url"] for r in cve_item.get("references", []) if r.get("url")]


def _extract_cpe_vendor_product(cve_item: dict) -> tuple[str, str]:
    """Best-effort extraction of primary vendor and product from CPE data."""
    configs = cve_item.get("configurations", [])
    for cfg in configs:
        for node in cfg.get("nodes", []):
            for match in node.get("cpeMatch", []):
                uri = match.get("criteria", "")
                parts = uri.split(":")
                # cpe:2.3:a:vendor:product:...
                if len(parts) >= 5:
                    vendor = parts[3].replace("_", " ").title()
                    product = parts[4].replace("_", " ").title()
                    return vendor, product
    return "", ""


class NVDEnricher:
    """
    Fetch CVE detail from NVD and yield update dicts keyed by CVE ID.

    Usage::

        enricher = NVDEnricher(api_key="...", proxy="http://proxy:3128")
        for cve_id, updates in enricher.fetch_updates(cve_ids=["CVE-2021-44228"]):
            Vulnerability.objects.filter(cve_id=cve_id).update(**updates)
    """

    def __init__(self, api_key: str = "", proxy: str = "", base_url: str = ""):
        self.api_key = api_key
        self.base_url = base_url or _NVD_BASE
        self.sleep_secs = _SLEEP_NO_KEY if not api_key else _SLEEP_WITH_KEY
        self._session = requests.Session()
        if proxy:
            self._session.proxies.update({"http": proxy, "https": proxy})
        if api_key:
            self._session.headers["apiKey"] = api_key

    # ------------------------------------------------------------------
    # Public interfaces
    # ------------------------------------------------------------------

    def fetch_by_ids(self, cve_ids: list[str]) -> Iterator[tuple[str, dict]]:
        """
        Yield (cve_id, update_dict) for each CVE ID in *cve_ids*.

        Fetches one at a time; use for targeted refreshes of small sets.
        """
        for cve_id in cve_ids:
            item = self._fetch_one(cve_id)
            if item:
                yield cve_id, self._to_update_dict(item)
            time.sleep(self.sleep_secs)

    def fetch_modified_since(
        self, since: datetime
    ) -> Iterator[tuple[str, dict]]:
        """
        Yield (cve_id, update_dict) for all CVEs modified after *since*.

        Uses NVD's lastModStartDate parameter and pages through results.
        Suitable for incremental daily/weekly runs.
        """
        start_str = since.strftime("%Y-%m-%dT%H:%M:%S.000")
        yield from self._fetch_page_iter(
            params={"lastModStartDate": start_str},
        )

    def fetch_all(self) -> Iterator[tuple[str, dict]]:
        """
        Yield (cve_id, update_dict) for every CVE in NVD.

        Full download — use only for the initial population run.
        """
        yield from self._fetch_page_iter(params={})

    # ------------------------------------------------------------------
    # Internal
    # ------------------------------------------------------------------

    def _fetch_page_iter(
        self, params: dict
    ) -> Iterator[tuple[str, dict]]:
        start_index = 0
        while True:
            page_params = {
                **params,
                "resultsPerPage": _PAGE_SIZE,
                "startIndex": start_index,
            }
            try:
                resp = self._session.get(self.base_url, params=page_params, timeout=60)
                resp.raise_for_status()
            except requests.RequestException as exc:
                logger.error("NVD API request failed: %s", exc)
                return

            body = resp.json()
            vulns = body.get("vulnerabilities", [])
            for entry in vulns:
                item = entry.get("cve", {})
                cve_id = item.get("id")
                if cve_id:
                    yield cve_id, self._to_update_dict(item)

            total = body.get("totalResults", 0)
            start_index += len(vulns)
            if start_index >= total or not vulns:
                break

            time.sleep(self.sleep_secs)

    def _fetch_one(self, cve_id: str) -> dict | None:
        try:
            resp = self._session.get(
                self.base_url,
                params={"cveId": cve_id},
                timeout=30,
            )
            resp.raise_for_status()
            vulns = resp.json().get("vulnerabilities", [])
            if vulns:
                return vulns[0].get("cve", {})
        except requests.RequestException as exc:
            logger.warning("NVD fetch failed for %s: %s", cve_id, exc)
        return None

    def _to_update_dict(self, item: dict) -> dict:
        cvss = _extract_cvss(item)
        vendor, product = _extract_cpe_vendor_product(item)
        pub_raw = item.get("published")
        mod_raw = item.get("lastModified")

        pub_date = None
        if pub_raw:
            dt = _parse_nvd_date(pub_raw)
            pub_date = dt.date() if dt else None

        mod_dt = _parse_nvd_date(mod_raw)
        mod_date = mod_dt.date() if mod_dt else None

        return {
            "description":      _extract_description(item) or None,
            "cvss_v3_score":    cvss["cvss_v3_score"],
            "cvss_v3_vector":   cvss["cvss_v3_vector"],
            "cvss_v2_score":    cvss["cvss_v2_score"],
            "cwe_id":           _extract_cwe(item),
            "affected_vendor":  vendor,
            "affected_product": product,
            "references":       _extract_references(item),
            "published_date":   pub_date,
            "modified_date":    mod_date,
            "nvd_last_modified": mod_dt,
        }
