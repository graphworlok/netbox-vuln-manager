from django.db import models
from django.urls import reverse
from netbox.models import NetBoxModel

from ..choices import SourceTypeChoices, AssetMatchStrategyChoices, SyncStatusChoices


class VulnerabilitySource(NetBoxModel):
    """
    A configured vulnerability data source (CrowdStrike, SecurityScorecard,
    CSV/Nexpose, …).

    Credentials and connection parameters are stored in the ``config``
    JSONField.  Never expose this field directly in templates or API responses
    — use the sanitised ``safe_config`` property instead.
    """

    name = models.CharField(max_length=128, unique=True)
    source_type = models.CharField(
        max_length=32,
        choices=SourceTypeChoices,
    )
    enabled = models.BooleanField(default=True)
    description = models.CharField(max_length=512, blank=True)

    # --- Sync behaviour ---
    auto_create_assets = models.BooleanField(
        default=False,
        help_text=(
            "When enabled, assets found in vulnerability data that do not exist "
            "in NetBox will be created automatically. Use with caution."
        ),
    )
    asset_match_strategy = models.CharField(
        max_length=16,
        choices=AssetMatchStrategyChoices,
        default=AssetMatchStrategyChoices.IP,
        help_text="How to match vulnerability report assets to NetBox objects.",
    )
    # If set, only import findings for these severities and above.
    min_severity = models.CharField(
        max_length=16,
        blank=True,
        help_text="Minimum severity to import. Leave blank to import all.",
    )

    # --- Connection config (credentials etc.) ---
    # Stored as JSON so each source type can define its own schema.
    # CrowdStrike:  {"client_id": "...", "client_secret": "...", "base_url": "..."}
    # SSC:          {"api_key": "...", "domain": "...", "base_url": "..."}
    # CSV:          {"column_map": {...}, "delimiter": ",", "encoding": "utf-8"}
    config = models.JSONField(
        default=dict,
        blank=True,
        help_text="Source-specific configuration (credentials, column maps, …).",
    )

    # --- Sync state ---
    last_sync_at = models.DateTimeField(null=True, blank=True)
    last_sync_status = models.CharField(
        max_length=16,
        choices=SyncStatusChoices,
        blank=True,
    )
    last_sync_message = models.TextField(blank=True)

    class Meta:
        ordering = ["name"]
        verbose_name = "Vulnerability Source"
        verbose_name_plural = "Vulnerability Sources"

    def __str__(self):
        return self.name

    def get_absolute_url(self):
        return reverse("plugins:netbox_vuln_manager:vulnerabilitysource", args=[self.pk])

    @property
    def safe_config(self):
        """Return config with secrets redacted."""
        secret_keys = {"client_secret", "api_key", "password", "token", "secret"}
        return {
            k: "***" if k in secret_keys else v
            for k, v in self.config.items()
        }
