"""
EPSS (Exploit Prediction Scoring System) enricher — FIRST.org.

Fetches the daily EPSS probability score and percentile rank for CVEs and
updates the epss_* fields on existing Vulnerability records.

API: https://api.first.org/data/v1/epss
  - Free, no authentication required
  - Returns the current day's score by default
  - Accepts up to ~1,000 CVE IDs per request as comma-separated query param
  - Full daily dump also available as a gzipped CSV (~10 MB):
    https://epss.cyentia.com/epss_scores-YYYY-MM-DD.csv.gz

Fields populated:
  epss_score       Probability (0–1) of exploitation within 30 days
  epss_percentile  Fraction of CVEs with a lower score (0–1)
  epss_date        Date of this score

Reference: https://www.first.org/epss/api
"""

from __future__ import annotations

import logging
import time
from datetime import date
from typing import Iterator

import requests

logger = logging.getLogger(__name__)

_EPSS_API = "https://api.first.org/data/v1/epss"
_BATCH_SIZE = 100    # API accepts ~1 000; conservative batch keeps URLs short
_SLEEP_SECS = 1.0


class EPSSEnricher:
    """
    Fetch EPSS scores for a list of CVE IDs and yield update dicts.

    Usage::

        enricher = EPSSEnricher(proxy="http://proxy:3128")
        for cve_id, updates in enricher.fetch(cve_ids):
            Vulnerability.objects.filter(cve_id=cve_id).update(**updates)
    """

    def __init__(self, proxy: str = "", api_url: str = ""):
        self.api_url = api_url or _EPSS_API
        self._session = requests.Session()
        if proxy:
            self._session.proxies.update({"http": proxy, "https": proxy})

    def fetch(self, cve_ids: list[str]) -> Iterator[tuple[str, dict]]:
        """
        Yield (cve_id, update_dict) for every CVE ID that has an EPSS score.
        CVEs with no score entry are silently skipped.
        """
        for i in range(0, len(cve_ids), _BATCH_SIZE):
            batch = cve_ids[i: i + _BATCH_SIZE]
            yield from self._fetch_batch(batch)
            if i + _BATCH_SIZE < len(cve_ids):
                time.sleep(_SLEEP_SECS)

    def _fetch_batch(self, cve_ids: list[str]) -> Iterator[tuple[str, dict]]:
        params = {"cve": ",".join(cve_ids), "pretty": "false"}
        try:
            resp = self._session.get(self.api_url, params=params, timeout=30)
            resp.raise_for_status()
        except requests.RequestException as exc:
            logger.warning("EPSS API request failed for batch: %s", exc)
            return

        data = resp.json().get("data", [])
        for entry in data:
            cve_id = entry.get("cve", "").strip().upper()
            if not cve_id:
                continue
            try:
                score = float(entry["epss"])
                pct   = float(entry["percentile"])
            except (KeyError, TypeError, ValueError):
                continue

            score_date = None
            raw_date = entry.get("date")
            if raw_date:
                try:
                    score_date = date.fromisoformat(raw_date[:10])
                except ValueError:
                    pass

            yield cve_id, {
                "epss_score":       round(score, 6),
                "epss_percentile":  round(pct, 6),
                "epss_date":        score_date,
            }
