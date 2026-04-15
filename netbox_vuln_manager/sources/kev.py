"""
CISA Known Exploited Vulnerabilities (KEV) enricher.

Downloads the full KEV catalogue from CISA and updates kev_* fields on
existing Vulnerability records.

Feed URL: https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json

The catalogue is a single JSON file (~300 KB as of 2025) listing every CVE
that CISA has confirmed is actively exploited in the wild.  It is updated
on an ad-hoc basis, typically several times per week.

Fields populated:
  kev_listed          True for every CVE in the catalogue
  kev_added_date      Date CISA added the entry
  kev_due_date        Required remediation deadline (federal agencies)
  kev_ransomware_use  True when CISA notes ransomware use

CVEs that are NOT in the new download but were previously listed are NOT
automatically delisted — the command that calls this enricher is responsible
for that (it receives the full set and can compare).
"""

from __future__ import annotations

import logging
from datetime import date
from typing import Iterator

import requests

logger = logging.getLogger(__name__)

_KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"


def _parse_date(s: str | None) -> date | None:
    if not s:
        return None
    try:
        return date.fromisoformat(s[:10])
    except ValueError:
        return None


class KEVEnricher:
    """
    Download the CISA KEV catalogue and yield update dicts keyed by CVE ID.

    Usage::

        enricher = KEVEnricher(proxy="http://proxy:3128")
        listed_ids, updates = enricher.fetch()
        # listed_ids — set of all CVE IDs currently in KEV
        # updates    — dict[cve_id, field_update_dict]
    """

    def __init__(self, proxy: str = "", url: str = ""):
        self.url = url or _KEV_URL
        self._session = requests.Session()
        if proxy:
            self._session.proxies.update({"http": proxy, "https": proxy})

    def fetch(self) -> tuple[set[str], dict[str, dict]]:
        """
        Return (listed_cve_ids, updates_by_cve_id).

        listed_cve_ids  — complete set of CVE IDs present in this download
        updates_by_cve_id — maps each CVE ID to a dict of field values
        """
        try:
            resp = self._session.get(self.url, timeout=60)
            resp.raise_for_status()
        except requests.RequestException as exc:
            logger.error("Failed to download CISA KEV: %s", exc)
            return set(), {}

        data = resp.json()
        entries = data.get("vulnerabilities", [])
        logger.info("CISA KEV: %d entries downloaded", len(entries))

        listed: set[str] = set()
        updates: dict[str, dict] = {}

        for entry in entries:
            cve_id = entry.get("cveID", "").strip().upper()
            if not cve_id:
                continue
            listed.add(cve_id)
            updates[cve_id] = {
                "kev_listed":        True,
                "kev_added_date":    _parse_date(entry.get("dateAdded")),
                "kev_due_date":      _parse_date(entry.get("dueDate")),
                "kev_ransomware_use": (
                    str(entry.get("knownRansomwareCampaignUse", "")).strip().lower()
                    == "known"
                ),
            }

        return listed, updates
