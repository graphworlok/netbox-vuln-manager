"""
Management command: enrich_cves

Enriches existing Vulnerability records in NetBox with data from three
authoritative external feeds:

  nvd   — NIST NVD API v2 (CVSS scores, vectors, CWE, CPE vendor/product,
           descriptions, references, published/modified dates)
  kev   — CISA Known Exploited Vulnerabilities catalogue (kev_listed,
           kev_due_date, kev_ransomware_use)
  epss  — FIRST.org EPSS scores (exploit probability, percentile)

Usage
-----
  # Run all three feeds against all CVEs in the database
  python manage.py enrich_cves

  # Only specific feeds
  python manage.py enrich_cves --feed nvd
  python manage.py enrich_cves --feed kev --feed epss

  # NVD incremental: only CVEs modified in the last N days (default 7)
  python manage.py enrich_cves --feed nvd --days-back 1

  # NVD full refresh (ignores nvd_last_modified, re-fetches everything)
  python manage.py enrich_cves --feed nvd --full

  # Dry run: show what would change without writing to the database
  python manage.py enrich_cves --dry-run

Scheduling
----------
Add a cron entry or systemd timer to run this daily, e.g.:

  # /etc/cron.d/netbox-enrich-cves
  0 3 * * * netbox  /opt/netbox/venv/bin/python /opt/netbox/netbox/manage.py \\
      enrich_cves --days-back 1 >> /var/log/netbox/enrich_cves.log 2>&1

  # Weekly full NVD refresh (covers gaps from API outages)
  0 4 * * 0 netbox  /opt/netbox/venv/bin/python /opt/netbox/netbox/manage.py \\
      enrich_cves --feed nvd --full >> /var/log/netbox/enrich_cves.log 2>&1

API keys / proxy
----------------
Configure in NetBox's PLUGINS_CONFIG:

  PLUGINS_CONFIG = {
      "netbox_vuln_manager": {
          "nvd_api_key":  "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx",
          "http_proxy":   "http://proxy.example.com:3128",
      }
  }
"""

from __future__ import annotations

import logging
from datetime import datetime, timedelta, timezone

from django.core.management.base import BaseCommand
from django.db import transaction

logger = logging.getLogger(__name__)


def _plugin_setting(key: str, default=None):
    """Read a value from the plugin's runtime configuration."""
    try:
        from netbox.plugins import get_plugin_config
        return get_plugin_config("netbox_vuln_manager", key) or default
    except Exception:
        return default


def _get_proxy() -> str:
    return _plugin_setting("http_proxy", "") or ""


# ---------------------------------------------------------------------------
# NVD enrichment
# ---------------------------------------------------------------------------

def run_nvd(
    cve_ids: list[str],
    *,
    days_back: int,
    full: bool,
    dry_run: bool,
) -> dict[str, int]:
    from ...models import Vulnerability
    from ...sources.nvd import NVDEnricher

    api_key = _plugin_setting("nvd_api_key", "")
    enricher = NVDEnricher(api_key=api_key, proxy=_get_proxy())

    counts = {"updated": 0, "skipped": 0, "errors": 0}

    if full:
        logger.info("NVD: full refresh of all CVEs (%d in DB)", len(cve_ids))
        source = enricher.fetch_all()
    else:
        since = datetime.now(tz=timezone.utc) - timedelta(days=days_back)
        logger.info(
            "NVD: incremental fetch — CVEs modified since %s",
            since.strftime("%Y-%m-%d"),
        )
        source = enricher.fetch_modified_since(since)

    # Only update CVEs we actually have in the database
    cve_id_set = set(cve_ids)

    for cve_id, updates in source:
        if full and cve_id not in cve_id_set:
            continue  # NVD has it but we don't — not our job to create it
        try:
            # Strip None values so we don't overwrite populated fields
            clean = {k: v for k, v in updates.items() if v is not None}
            if not clean:
                counts["skipped"] += 1
                continue
            if not dry_run:
                with transaction.atomic():
                    Vulnerability.objects.filter(cve_id=cve_id).update(**clean)
            counts["updated"] += 1
        except Exception as exc:
            logger.warning("NVD update failed for %s: %s", cve_id, exc)
            counts["errors"] += 1

    return counts


# ---------------------------------------------------------------------------
# KEV enrichment
# ---------------------------------------------------------------------------

def run_kev(cve_ids: list[str], *, dry_run: bool) -> dict[str, int]:
    from ...models import Vulnerability
    from ...sources.kev import KEVEnricher

    enricher = KEVEnricher(proxy=_get_proxy())
    listed_ids, updates = enricher.fetch()

    if not updates:
        return {"updated": 0, "delisted": 0, "errors": 0}

    cve_id_set = set(cve_ids)
    counts = {"updated": 0, "delisted": 0, "errors": 0}

    # --- Apply new / updated KEV entries ---
    for cve_id, fields in updates.items():
        if cve_id not in cve_id_set:
            continue
        try:
            if not dry_run:
                with transaction.atomic():
                    Vulnerability.objects.filter(cve_id=cve_id).update(**fields)
            counts["updated"] += 1
        except Exception as exc:
            logger.warning("KEV update failed for %s: %s", cve_id, exc)
            counts["errors"] += 1

    # --- Delist CVEs that were previously marked but are no longer in KEV ---
    # (CISA occasionally removes entries after corrections)
    if not dry_run:
        try:
            removed = (
                Vulnerability.objects
                .filter(cve_id__in=cve_id_set, kev_listed=True)
                .exclude(cve_id__in=listed_ids)
                .update(
                    kev_listed=False,
                    kev_added_date=None,
                    kev_due_date=None,
                    kev_ransomware_use=False,
                )
            )
            counts["delisted"] = removed
        except Exception as exc:
            logger.warning("KEV delist step failed: %s", exc)

    return counts


# ---------------------------------------------------------------------------
# EPSS enrichment
# ---------------------------------------------------------------------------

def run_epss(cve_ids: list[str], *, dry_run: bool) -> dict[str, int]:
    from ...models import Vulnerability
    from ...sources.epss import EPSSEnricher

    enricher = EPSSEnricher(proxy=_get_proxy())
    counts = {"updated": 0, "errors": 0}

    for cve_id, fields in enricher.fetch(cve_ids):
        try:
            if not dry_run:
                with transaction.atomic():
                    Vulnerability.objects.filter(cve_id=cve_id).update(**fields)
            counts["updated"] += 1
        except Exception as exc:
            logger.warning("EPSS update failed for %s: %s", cve_id, exc)
            counts["errors"] += 1

    return counts


# ---------------------------------------------------------------------------
# Management command
# ---------------------------------------------------------------------------

class Command(BaseCommand):
    help = "Enrich CVE records with data from NVD, CISA KEV, and EPSS."

    def add_arguments(self, parser):
        parser.add_argument(
            "--feed",
            action="append",
            choices=["nvd", "kev", "epss"],
            dest="feeds",
            metavar="FEED",
            help=(
                "Feed(s) to run: nvd, kev, epss. "
                "Repeat to select multiple. Default: all three."
            ),
        )
        parser.add_argument(
            "--days-back",
            type=int,
            default=7,
            metavar="N",
            help=(
                "For NVD incremental mode: fetch CVEs modified in the last N days. "
                "Default: 7."
            ),
        )
        parser.add_argument(
            "--full",
            action="store_true",
            help="NVD full refresh: re-fetch all CVEs regardless of last-modified date.",
        )
        parser.add_argument(
            "--dry-run",
            action="store_true",
            help="Fetch data but do not write anything to the database.",
        )

    def handle(self, *args, **options):
        from ...models import Vulnerability

        feeds = options["feeds"] or ["nvd", "kev", "epss"]
        dry_run = options["dry_run"]
        days_back = options["days_back"]
        full = options["full"]

        if dry_run:
            self.stdout.write(self.style.WARNING("DRY RUN — no database writes"))

        # Collect all CVE IDs we know about (non-null cve_id only)
        cve_ids = list(
            Vulnerability.objects
            .filter(cve_id__isnull=False)
            .values_list("cve_id", flat=True)
        )

        if not cve_ids:
            self.stdout.write("No CVE records in database — nothing to enrich.")
            return

        self.stdout.write(f"Enriching {len(cve_ids)} CVE records…")

        if "nvd" in feeds:
            self.stdout.write("\n[NVD] Fetching from NIST NVD API v2…")
            counts = run_nvd(cve_ids, days_back=days_back, full=full, dry_run=dry_run)
            self.stdout.write(
                self.style.SUCCESS(
                    f"  NVD: {counts['updated']} updated, "
                    f"{counts.get('skipped', 0)} skipped, "
                    f"{counts['errors']} errors"
                )
            )

        if "kev" in feeds:
            self.stdout.write("\n[KEV] Fetching CISA Known Exploited Vulnerabilities…")
            counts = run_kev(cve_ids, dry_run=dry_run)
            self.stdout.write(
                self.style.SUCCESS(
                    f"  KEV: {counts['updated']} listed, "
                    f"{counts['delisted']} delisted, "
                    f"{counts['errors']} errors"
                )
            )

        if "epss" in feeds:
            self.stdout.write("\n[EPSS] Fetching FIRST.org EPSS scores…")
            counts = run_epss(cve_ids, dry_run=dry_run)
            self.stdout.write(
                self.style.SUCCESS(
                    f"  EPSS: {counts['updated']} updated, "
                    f"{counts['errors']} errors"
                )
            )

        self.stdout.write(self.style.SUCCESS("\nEnrichment complete."))
