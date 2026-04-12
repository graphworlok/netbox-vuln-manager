"""
Management command: sync_vulnerabilities

Syncs vulnerability findings from one or all configured VulnerabilitySource
objects into NetBox.

Usage:
  python manage.py sync_vulnerabilities               # all enabled sources
  python manage.py sync_vulnerabilities --source 1    # specific source by PK
  python manage.py sync_vulnerabilities --source mycs # specific source by name
  python manage.py sync_vulnerabilities --dry-run     # fetch but do not write

The ``run_sync(source)`` function is also importable for use from views/tasks.
"""

from __future__ import annotations

import logging
from datetime import datetime, timezone
from typing import TYPE_CHECKING

from django.core.management.base import BaseCommand, CommandError
from django.db import transaction
from django.utils import timezone as django_tz

if TYPE_CHECKING:
    from ...models import VulnerabilitySource as _VS

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Public interface — callable from views / celery tasks
# ---------------------------------------------------------------------------

def run_sync(source: "_VS", dry_run: bool = False) -> "SyncLog":
    """
    Run a full sync for ``source`` and return the completed SyncLog.
    Raises on fatal errors.
    """
    from ...models import SyncLog, VulnerabilitySource
    from ...sources import get_source_handler

    log = SyncLog.objects.create(source=source)

    try:
        handler_cls = get_source_handler(source.source_type)
        handler = handler_cls(source.config)

        errors = handler.validate_config()
        if errors:
            raise ValueError("Config validation failed: " + "; ".join(errors))

        for finding_data in handler.fetch():
            try:
                _process_finding(source, finding_data, log, dry_run=dry_run)
            except Exception as exc:
                logger.warning("Failed to process finding %s: %s", finding_data.external_id, exc)
                log.records_failed += 1

        log.status = "success" if log.records_failed == 0 else "partial"
        log.message = (
            f"Processed {log.records_processed} records: "
            f"{log.records_created} created, {log.records_updated} updated, "
            f"{log.records_failed} failed, {log.assets_created} assets created."
        )

    except Exception as exc:
        log.status = "failed"
        log.message = str(exc)
        logger.exception("Sync of %s failed", source)
        raise
    finally:
        log.completed_at = django_tz.now()
        if not dry_run:
            log.save()
            # Update the source's last-sync fields
            VulnerabilitySource.objects.filter(pk=source.pk).update(
                last_sync_at=log.completed_at,
                last_sync_status=log.status,
                last_sync_message=log.message,
            )

    return log


# ---------------------------------------------------------------------------
# Internal processing
# ---------------------------------------------------------------------------

def _process_finding(source, finding_data, log, *, dry_run: bool):
    from ...models import Vulnerability, VulnerabilityFinding
    from ...choices import SeverityChoices

    log.records_processed += 1

    # 1. Resolve or create the Vulnerability record
    vuln = _get_or_create_vulnerability(finding_data, source)

    # 2. Resolve asset
    asset_obj, asset_ct = _match_asset(
        source=source,
        hostname=finding_data.asset_hostname,
        ip=finding_data.asset_ip,
        log=log,
        dry_run=dry_run,
    )

    if dry_run:
        log.records_updated += 1
        return

    # 3. Upsert the Finding
    first_seen = finding_data.first_seen or django_tz.now()
    last_seen = finding_data.last_seen or django_tz.now()

    lookup = {}
    if finding_data.external_id:
        lookup = {"source": source, "external_id": finding_data.external_id}
    else:
        lookup = {
            "source": source,
            "vulnerability": vuln,
            "asset_hostname": finding_data.asset_hostname,
            "asset_ip": finding_data.asset_ip,
        }

    with transaction.atomic():
        finding, created = VulnerabilityFinding.objects.get_or_create(
            **lookup,
            defaults={
                "vulnerability": vuln,
                "severity": finding_data.severity,
                "asset_hostname": finding_data.asset_hostname,
                "asset_ip": finding_data.asset_ip,
                "first_seen": first_seen,
                "last_seen": last_seen,
                "exploitability": finding_data.exploitability,
                "remediation": finding_data.remediation,
                "raw_data": finding_data.raw,
                "asset_type": asset_ct,
                "asset_id": asset_obj.pk if asset_obj else None,
            },
        )

        if not created:
            # Update mutable fields but preserve analyst notes
            finding.severity = finding_data.severity
            finding.last_seen = last_seen
            finding.exploitability = finding_data.exploitability
            finding.remediation = finding_data.remediation
            finding.raw_data = finding_data.raw
            if asset_obj and not finding.asset_id:
                from django.contrib.contenttypes.models import ContentType
                finding.asset_type = asset_ct
                finding.asset_id = asset_obj.pk
            finding.save()
            log.records_updated += 1
        else:
            log.records_created += 1

        # 4. Compute risk score
        _compute_risk_score(finding, vuln)


def _get_or_create_vulnerability(finding_data, source):
    from ...models import Vulnerability
    from ...choices import SeverityChoices

    if finding_data.cve_id:
        vuln, created = Vulnerability.objects.get_or_create(
            cve_id=finding_data.cve_id,
            defaults={
                "title": finding_data.vuln_title or finding_data.cve_id,
                "description": finding_data.description,
                "severity": finding_data.severity,
                "cvss_v2_score": finding_data.cvss_v2_score,
                "cvss_v3_score": finding_data.cvss_v3_score,
                "cvss_v3_vector": finding_data.cvss_v3_vector,
                "cwe_id": finding_data.cwe_id,
                "references": finding_data.references,
                "published_date": finding_data.published_date.date()
                    if finding_data.published_date else None,
                "origin_source": source,
            },
        )
        if not created:
            # Refresh CVSS scores if we have better data
            updated = False
            if finding_data.cvss_v3_score and not vuln.cvss_v3_score:
                vuln.cvss_v3_score = finding_data.cvss_v3_score
                updated = True
            if finding_data.cvss_v2_score and not vuln.cvss_v2_score:
                vuln.cvss_v2_score = finding_data.cvss_v2_score
                updated = True
            if updated:
                vuln.save()
        return vuln

    # Non-CVE: match by title
    vuln, _ = Vulnerability.objects.get_or_create(
        cve_id=None,
        title=finding_data.vuln_title,
        defaults={
            "description": finding_data.description,
            "severity": finding_data.severity,
            "cvss_v2_score": finding_data.cvss_v2_score,
            "cvss_v3_score": finding_data.cvss_v3_score,
            "origin_source": source,
        },
    )
    return vuln


def _match_asset(source, hostname, ip, log, *, dry_run):
    """
    Try to find an existing NetBox Device, VirtualMachine, or IPAddress that
    matches the given hostname/IP.  If ``auto_create_assets`` is enabled on
    the source and no match is found, create a placeholder IPAddress.

    Returns (object_or_None, ContentType_or_None).
    """
    from django.contrib.contenttypes.models import ContentType

    strategy = source.asset_match_strategy

    # Try Device first
    if strategy in ("hostname", "both") and hostname:
        obj = _find_device_by_hostname(hostname)
        if obj:
            return obj, ContentType.objects.get_for_model(obj)

    if strategy in ("ip", "both") and ip:
        obj = _find_asset_by_ip(ip)
        if obj:
            return obj, ContentType.objects.get_for_model(obj)

    if strategy == "hostname" and hostname and not ip:
        pass  # already tried above

    # No match — optionally auto-create
    if source.auto_create_assets and not dry_run:
        obj = _create_ip_placeholder(ip, hostname)
        if obj:
            log.assets_created += 1
            return obj, ContentType.objects.get_for_model(obj)

    return None, None


def _find_device_by_hostname(hostname: str):
    try:
        from dcim.models import Device
        return Device.objects.get(name__iexact=hostname)
    except Exception:
        pass
    try:
        from virtualization.models import VirtualMachine
        return VirtualMachine.objects.get(name__iexact=hostname)
    except Exception:
        pass
    return None


def _find_asset_by_ip(ip: str):
    try:
        from ipam.models import IPAddress
        from netaddr import IPAddress as NetAddr
        addr = NetAddr(ip)
        # Match with or without prefix length
        matches = IPAddress.objects.filter(address__net_host=str(addr))
        if matches.exists():
            return matches.first()
    except Exception:
        pass
    # Also try Device primary IPs
    try:
        from dcim.models import Device
        from ipam.models import IPAddress
        ip_obj = IPAddress.objects.filter(address__startswith=ip).first()
        if ip_obj:
            device = Device.objects.filter(primary_ip4=ip_obj).first() \
                     or Device.objects.filter(primary_ip6=ip_obj).first()
            if device:
                return device
            return ip_obj
    except Exception:
        pass
    return None


def _create_ip_placeholder(ip: str | None, hostname: str):
    """Create a minimal NetBox IPAddress for an unknown asset."""
    if not ip:
        return None
    try:
        from ipam.models import IPAddress
        obj, created = IPAddress.objects.get_or_create(
            address=f"{ip}/32",
            defaults={"description": f"Auto-created by vuln-manager (hostname: {hostname})"},
        )
        if created:
            logger.info("Auto-created IPAddress %s for asset %s / %s", obj, hostname, ip)
        return obj
    except Exception as exc:
        logger.warning("Failed to auto-create IPAddress for %s: %s", ip, exc)
        return None


def _compute_risk_score(finding, vuln):
    """Compute and store a RiskScore for the finding."""
    from ...models import RiskScore

    base = float(vuln.cvss_v3_score or vuln.cvss_v2_score or 0)
    # Simple temporal adjustment: exploitable vulns get a small boost
    temporal = base
    if finding.exploitability and finding.exploitability.lower() in ("high", "functional"):
        temporal = min(10.0, base * 1.1)

    RiskScore.objects.create(
        finding=finding,
        base_score=base or None,
        temporal_score=temporal or None,
        calculated_score=round(temporal, 1),
        factors={
            "exploitability": finding.exploitability,
            "severity": finding.severity,
        },
    )


# ---------------------------------------------------------------------------
# Management command
# ---------------------------------------------------------------------------

class Command(BaseCommand):
    help = "Sync vulnerability findings from configured sources into NetBox."

    def add_arguments(self, parser):
        parser.add_argument(
            "--source",
            metavar="PK_OR_NAME",
            help="Sync only this source (PK or name). Omit to sync all enabled sources.",
        )
        parser.add_argument(
            "--dry-run",
            action="store_true",
            help="Fetch and parse but do not write to the database.",
        )

    def handle(self, *args, **options):
        from ...models import VulnerabilitySource

        dry_run = options["dry_run"]
        source_arg = options.get("source")

        if source_arg:
            try:
                pk = int(source_arg)
                sources = VulnerabilitySource.objects.filter(pk=pk)
            except ValueError:
                sources = VulnerabilitySource.objects.filter(name=source_arg)
            if not sources.exists():
                raise CommandError(f"No source found matching '{source_arg}'")
        else:
            sources = VulnerabilitySource.objects.filter(enabled=True)

        if not sources.exists():
            self.stdout.write("No enabled sources found.")
            return

        for source in sources:
            self.stdout.write(f"Syncing '{source.name}' ({source.source_type})…")
            try:
                log = run_sync(source, dry_run=dry_run)
                self.stdout.write(
                    self.style.SUCCESS(
                        f"  ✓ {log.status}: {log.records_created} created, "
                        f"{log.records_updated} updated, "
                        f"{log.records_failed} failed"
                        + (f", {log.assets_created} assets created" if log.assets_created else "")
                    )
                )
            except Exception as exc:
                self.stdout.write(self.style.ERROR(f"  ✗ Failed: {exc}"))
