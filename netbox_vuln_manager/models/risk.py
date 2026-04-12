from django.db import models


class RiskScore(models.Model):
    """
    A point-in-time risk score for a VulnerabilityFinding.

    Scores are additive/historical: each sync may append a new record so
    trends can be charted.  The current score is always the most recent.
    """

    finding = models.ForeignKey(
        "VulnerabilityFinding",
        on_delete=models.CASCADE,
        related_name="risk_scores",
    )
    assessed_at = models.DateTimeField(auto_now_add=True)

    # Base score = CVSS score from the vulnerability definition.
    base_score = models.DecimalField(max_digits=4, decimal_places=1, null=True, blank=True)

    # Temporal score = base adjusted for exploit availability, patch level, etc.
    temporal_score = models.DecimalField(max_digits=4, decimal_places=1, null=True, blank=True)

    # Environmental score = temporal adjusted for asset criticality / exposure.
    environmental_score = models.DecimalField(max_digits=4, decimal_places=1, null=True, blank=True)

    # Final calculated score (0–10).
    calculated_score = models.DecimalField(max_digits=4, decimal_places=1)

    # Factors used to derive the score (for audit/display).
    factors = models.JSONField(default=dict, blank=True)

    class Meta:
        ordering = ["-assessed_at"]
        verbose_name = "Risk Score"
        verbose_name_plural = "Risk Scores"

    def __str__(self):
        return f"Risk {self.calculated_score} for finding #{self.finding_id} @ {self.assessed_at:%Y-%m-%d}"


class SyncLog(models.Model):
    """Audit log of each sync run for a VulnerabilitySource."""

    source = models.ForeignKey(
        "VulnerabilitySource",
        on_delete=models.CASCADE,
        related_name="sync_logs",
    )
    started_at = models.DateTimeField(auto_now_add=True)
    completed_at = models.DateTimeField(null=True, blank=True)

    status = models.CharField(
        max_length=16,
        choices=[
            ("running", "Running"),
            ("success", "Success"),
            ("partial", "Partial"),
            ("failed", "Failed"),
        ],
        default="running",
    )
    message = models.TextField(blank=True)

    records_processed = models.PositiveIntegerField(default=0)
    records_created = models.PositiveIntegerField(default=0)
    records_updated = models.PositiveIntegerField(default=0)
    records_failed = models.PositiveIntegerField(default=0)
    assets_created = models.PositiveIntegerField(
        default=0,
        help_text="Number of NetBox assets auto-created during this sync.",
    )

    class Meta:
        ordering = ["-started_at"]
        verbose_name = "Sync Log"
        verbose_name_plural = "Sync Logs"

    def __str__(self):
        return f"Sync of {self.source} @ {self.started_at:%Y-%m-%d %H:%M}"

    def duration(self):
        if self.completed_at and self.started_at:
            return self.completed_at - self.started_at
        return None
