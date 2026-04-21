from django.contrib.contenttypes.fields import GenericForeignKey
from django.contrib.contenttypes.models import ContentType
from django.db import models
from django.urls import reverse
from netbox.models import NetBoxModel

from ..choices import FindingStatusChoices, SeverityChoices


class VulnerabilityFinding(NetBoxModel):
    """
    A specific occurrence of a Vulnerability on an asset.

    Assets are referenced via a generic FK so we can point at Device,
    VirtualMachine, IPAddress, or any future NetBox object without schema
    changes.
    """

    vulnerability = models.ForeignKey(
        "Vulnerability",
        on_delete=models.CASCADE,
        related_name="findings",
    )
    source = models.ForeignKey(
        "VulnerabilitySource",
        on_delete=models.PROTECT,
        related_name="findings",
    )

    # --- Asset reference (generic) ---
    asset_type = models.ForeignKey(
        ContentType,
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        limit_choices_to={
            "app_label__in": ["dcim", "virtualization", "ipam"],
        },
        related_name="+",
    )
    asset_id = models.PositiveBigIntegerField(null=True, blank=True)
    asset = GenericForeignKey("asset_type", "asset_id")

    # Denormalised asset identifiers for quick display / filtering without
    # joining to the referenced table.
    asset_hostname = models.CharField(max_length=256, blank=True)
    asset_ip = models.GenericIPAddressField(null=True, blank=True, verbose_name="Asset IP")

    # --- Finding metadata ---
    # ID of this finding in the originating source system.
    external_id = models.CharField(max_length=256, blank=True, db_index=True)

    status = models.CharField(
        max_length=32,
        choices=FindingStatusChoices,
        default=FindingStatusChoices.OPEN,
    )
    severity = models.CharField(
        max_length=16,
        choices=SeverityChoices,
        default=SeverityChoices.MEDIUM,
        help_text="Severity as reported by the source, may differ from the vulnerability definition.",
    )

    first_seen = models.DateTimeField()
    last_seen = models.DateTimeField()

    # Exploitability as reported by the source (e.g. CrowdStrike Spotlight
    # exprt_rating, or Nexpose exploitability score).
    exploitability = models.CharField(max_length=64, blank=True)

    # Remediation recommendation from source.
    remediation = models.TextField(blank=True)

    notes = models.TextField(
        blank=True,
        help_text="Analyst notes. Not overwritten on re-sync.",
    )

    # Raw JSON from the source system for traceability.
    raw_data = models.JSONField(default=dict, blank=True)

    class Meta:
        ordering = ["-last_seen", "status"]
        verbose_name = "Vulnerability Finding"
        verbose_name_plural = "Vulnerability Findings"
        indexes = [
            models.Index(fields=["asset_type", "asset_id"], name="nvmgr_finding_asset_idx"),
            models.Index(fields=["status", "severity"], name="nvmgr_finding_status_sev_idx"),
            models.Index(fields=["last_seen"], name="nvmgr_finding_last_seen_idx"),
        ]

    def __str__(self):
        asset_label = self.asset_hostname or str(self.asset_ip) or "unknown asset"
        return f"{self.vulnerability} on {asset_label}"

    def get_absolute_url(self):
        return reverse("plugins:netbox_vuln_manager:vulnerabilityfinding", args=[self.pk])

    @property
    def is_open(self):
        return self.status == FindingStatusChoices.OPEN

    @property
    def risk_score(self):
        """Return the latest calculated risk score, if one exists."""
        return self.risk_scores.order_by("-assessed_at").first()
