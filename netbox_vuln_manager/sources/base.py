"""
Base class for all vulnerability source handlers.

Each handler is responsible for:
  1. Fetching raw data from its source (API, file, etc.)
  2. Normalising records into the common NormalisedFinding dict
  3. Returning those dicts to the sync engine (management command / celery task)

The sync engine handles asset matching, NetBox object creation/update, and
SyncLog recording.  Handlers must NOT write to the database directly.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from datetime import datetime
from typing import Iterator, Optional

logger = logging.getLogger(__name__)


@dataclass
class NormalisedFinding:
    """
    Source-agnostic representation of a single vulnerability finding.

    All fields are optional except ``vuln_title`` and ``source_type``.  The
    sync engine will skip records where neither a CVE ID nor a title is
    present.
    """

    # --- Vulnerability identity ---
    cve_id: Optional[str] = None          # "CVE-2021-44228"
    vuln_title: str = ""                   # human-readable name
    description: str = ""
    severity: str = "medium"              # maps to SeverityChoices
    cvss_v2_score: Optional[float] = None
    cvss_v3_score: Optional[float] = None
    cvss_v3_vector: str = ""
    cwe_id: str = ""
    references: list[str] = field(default_factory=list)
    published_date: Optional[datetime] = None
    remediation: str = ""

    # --- Asset identity ---
    asset_hostname: str = ""
    asset_ip: Optional[str] = None        # dotted-decimal IPv4 or IPv6

    # --- Finding metadata ---
    external_id: str = ""                 # ID in the source system
    first_seen: Optional[datetime] = None
    last_seen: Optional[datetime] = None
    exploitability: str = ""

    # --- Source-specific extras (pass-through) ---
    raw: dict = field(default_factory=dict)


class BaseVulnerabilitySource:
    """
    Abstract base class for vulnerability source handlers.

    Subclasses must implement:
      - fetch()  →  Iterator[NormalisedFinding]
    """

    source_type: str = ""  # Must match SourceTypeChoices value

    def __init__(self, config: dict):
        self.config = config
        self._session = None  # Requests session, initialised lazily by subclasses

    # ------------------------------------------------------------------
    # Public interface
    # ------------------------------------------------------------------

    def fetch(self) -> Iterator[NormalisedFinding]:
        """
        Yield NormalisedFinding instances for every finding available from
        this source.  May yield lazily / page-by-page.
        """
        raise NotImplementedError

    def validate_config(self) -> list[str]:
        """
        Return a list of validation error strings.  Empty list = valid.
        Called before a sync is started so the user gets early feedback.
        """
        return []

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    def _get_proxy(self) -> dict | None:
        proxy = self.config.get("proxy") or self.config.get("http_proxy")
        if proxy:
            return {"http": proxy, "https": proxy}
        return None

    def _requests_session(self):
        """Return a lazily-initialised requests.Session with proxy support."""
        if self._session is None:
            import requests
            self._session = requests.Session()
            proxies = self._get_proxy()
            if proxies:
                self._session.proxies.update(proxies)
        return self._session
