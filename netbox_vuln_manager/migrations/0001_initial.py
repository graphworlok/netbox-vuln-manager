import django.db.models.deletion
import django.contrib.contenttypes.fields
from django.db import migrations, models
import taggit.managers
import utilities.json


class Migration(migrations.Migration):

    initial = True

    dependencies = [
        ("contenttypes", "0002_remove_content_type_name"),
        ("extras", "0001_initial"),  # NetBox extras (tags, custom fields)
    ]

    operations = [
        # ----------------------------------------------------------------
        # VulnerabilitySource  (must come before Vulnerability and Finding)
        # ----------------------------------------------------------------
        migrations.CreateModel(
            name="VulnerabilitySource",
            fields=[
                ("id", models.BigAutoField(auto_created=True, primary_key=True, serialize=False)),
                ("created", models.DateTimeField(auto_now_add=True, null=True)),
                ("last_updated", models.DateTimeField(auto_now=True, null=True)),
                ("custom_field_data", models.JSONField(blank=True, default=dict, encoder=utilities.json.CustomFieldJSONEncoder)),
                ("name", models.CharField(max_length=128, unique=True)),
                ("source_type", models.CharField(max_length=32)),
                ("enabled", models.BooleanField(default=True)),
                ("description", models.CharField(blank=True, max_length=512)),
                ("auto_create_assets", models.BooleanField(default=False)),
                ("asset_match_strategy", models.CharField(default="ip", max_length=16)),
                ("min_severity", models.CharField(blank=True, max_length=16)),
                ("config", models.JSONField(blank=True, default=dict)),
                ("last_sync_at", models.DateTimeField(blank=True, null=True)),
                ("last_sync_status", models.CharField(blank=True, max_length=16)),
                ("last_sync_message", models.TextField(blank=True)),
                ("tags", taggit.managers.TaggableManager(
                    help_text="A comma-separated list of tags.",
                    through="extras.TaggedItem",
                    to="extras.Tag",
                    verbose_name="Tags",
                )),
            ],
            options={"ordering": ["name"], "verbose_name": "Vulnerability Source", "verbose_name_plural": "Vulnerability Sources"},
        ),
        # ----------------------------------------------------------------
        # Vulnerability
        # ----------------------------------------------------------------
        migrations.CreateModel(
            name="Vulnerability",
            fields=[
                ("id", models.BigAutoField(auto_created=True, primary_key=True, serialize=False)),
                ("created", models.DateTimeField(auto_now_add=True, null=True)),
                ("last_updated", models.DateTimeField(auto_now=True, null=True)),
                ("custom_field_data", models.JSONField(blank=True, default=dict, encoder=utilities.json.CustomFieldJSONEncoder)),
                ("cve_id", models.CharField(blank=True, max_length=32, null=True, unique=True, verbose_name="CVE ID")),
                ("title", models.CharField(max_length=512)),
                ("description", models.TextField(blank=True)),
                ("severity", models.CharField(default="medium", max_length=16)),
                ("cvss_v2_score", models.DecimalField(blank=True, decimal_places=1, max_digits=4, null=True, verbose_name="CVSS v2 Score")),
                ("cvss_v3_score", models.DecimalField(blank=True, decimal_places=1, max_digits=4, null=True, verbose_name="CVSS v3 Score")),
                ("cvss_v3_vector", models.CharField(blank=True, max_length=128, verbose_name="CVSS v3 Vector")),
                ("cwe_id", models.CharField(blank=True, max_length=32, verbose_name="CWE ID")),
                ("affected_vendor", models.CharField(blank=True, max_length=256)),
                ("affected_product", models.CharField(blank=True, max_length=256)),
                ("affected_versions", models.TextField(blank=True)),
                ("published_date", models.DateField(blank=True, null=True)),
                ("modified_date", models.DateField(blank=True, null=True)),
                ("references", models.JSONField(blank=True, default=list)),
                ("origin_source", models.ForeignKey(
                    blank=True,
                    null=True,
                    on_delete=django.db.models.deletion.SET_NULL,
                    related_name="originated_vulnerabilities",
                    to="netbox_vuln_manager.vulnerabilitysource",
                )),
                ("tags", taggit.managers.TaggableManager(
                    help_text="A comma-separated list of tags.",
                    through="extras.TaggedItem",
                    to="extras.Tag",
                    verbose_name="Tags",
                )),
            ],
            options={"ordering": ["-cvss_v3_score", "-cvss_v2_score", "cve_id", "title"], "verbose_name": "Vulnerability", "verbose_name_plural": "Vulnerabilities"},
        ),
        # ----------------------------------------------------------------
        # VulnerabilityFinding
        # ----------------------------------------------------------------
        migrations.CreateModel(
            name="VulnerabilityFinding",
            fields=[
                ("id", models.BigAutoField(auto_created=True, primary_key=True, serialize=False)),
                ("created", models.DateTimeField(auto_now_add=True, null=True)),
                ("last_updated", models.DateTimeField(auto_now=True, null=True)),
                ("custom_field_data", models.JSONField(blank=True, default=dict, encoder=utilities.json.CustomFieldJSONEncoder)),
                ("asset_id", models.PositiveBigIntegerField(blank=True, null=True)),
                ("asset_hostname", models.CharField(blank=True, max_length=256)),
                ("asset_ip", models.GenericIPAddressField(blank=True, null=True, verbose_name="Asset IP")),
                ("external_id", models.CharField(blank=True, db_index=True, max_length=256)),
                ("status", models.CharField(default="open", max_length=32)),
                ("severity", models.CharField(default="medium", max_length=16)),
                ("first_seen", models.DateTimeField()),
                ("last_seen", models.DateTimeField()),
                ("exploitability", models.CharField(blank=True, max_length=64)),
                ("remediation", models.TextField(blank=True)),
                ("notes", models.TextField(blank=True)),
                ("raw_data", models.JSONField(blank=True, default=dict)),
                ("vulnerability", models.ForeignKey(
                    on_delete=django.db.models.deletion.CASCADE,
                    related_name="findings",
                    to="netbox_vuln_manager.vulnerability",
                )),
                ("source", models.ForeignKey(
                    on_delete=django.db.models.deletion.PROTECT,
                    related_name="findings",
                    to="netbox_vuln_manager.vulnerabilitysource",
                )),
                ("asset_type", models.ForeignKey(
                    blank=True,
                    null=True,
                    on_delete=django.db.models.deletion.SET_NULL,
                    related_name="+",
                    to="contenttypes.contenttype",
                )),
                ("tags", taggit.managers.TaggableManager(
                    help_text="A comma-separated list of tags.",
                    through="extras.TaggedItem",
                    to="extras.Tag",
                    verbose_name="Tags",
                )),
            ],
            options={"ordering": ["-last_seen", "status"], "verbose_name": "Vulnerability Finding", "verbose_name_plural": "Vulnerability Findings"},
        ),
        # ----------------------------------------------------------------
        # RiskScore
        # ----------------------------------------------------------------
        migrations.CreateModel(
            name="RiskScore",
            fields=[
                ("id", models.BigAutoField(auto_created=True, primary_key=True, serialize=False)),
                ("assessed_at", models.DateTimeField(auto_now_add=True)),
                ("base_score", models.DecimalField(blank=True, decimal_places=1, max_digits=4, null=True)),
                ("temporal_score", models.DecimalField(blank=True, decimal_places=1, max_digits=4, null=True)),
                ("environmental_score", models.DecimalField(blank=True, decimal_places=1, max_digits=4, null=True)),
                ("calculated_score", models.DecimalField(decimal_places=1, max_digits=4)),
                ("factors", models.JSONField(blank=True, default=dict)),
                ("finding", models.ForeignKey(
                    on_delete=django.db.models.deletion.CASCADE,
                    related_name="risk_scores",
                    to="netbox_vuln_manager.vulnerabilityfinding",
                )),
            ],
            options={"ordering": ["-assessed_at"], "verbose_name": "Risk Score", "verbose_name_plural": "Risk Scores"},
        ),
        # ----------------------------------------------------------------
        # SyncLog
        # ----------------------------------------------------------------
        migrations.CreateModel(
            name="SyncLog",
            fields=[
                ("id", models.BigAutoField(auto_created=True, primary_key=True, serialize=False)),
                ("started_at", models.DateTimeField(auto_now_add=True)),
                ("completed_at", models.DateTimeField(blank=True, null=True)),
                ("status", models.CharField(
                    choices=[("running", "Running"), ("success", "Success"), ("partial", "Partial"), ("failed", "Failed")],
                    default="running",
                    max_length=16,
                )),
                ("message", models.TextField(blank=True)),
                ("records_processed", models.PositiveIntegerField(default=0)),
                ("records_created", models.PositiveIntegerField(default=0)),
                ("records_updated", models.PositiveIntegerField(default=0)),
                ("records_failed", models.PositiveIntegerField(default=0)),
                ("assets_created", models.PositiveIntegerField(default=0)),
                ("source", models.ForeignKey(
                    on_delete=django.db.models.deletion.CASCADE,
                    related_name="sync_logs",
                    to="netbox_vuln_manager.vulnerabilitysource",
                )),
            ],
            options={"ordering": ["-started_at"], "verbose_name": "Sync Log", "verbose_name_plural": "Sync Logs"},
        ),
        # ----------------------------------------------------------------
        # Indexes
        # ----------------------------------------------------------------
        migrations.AddIndex(
            model_name="vulnerabilityfinding",
            index=models.Index(fields=["asset_type", "asset_id"], name="nvmgr_finding_asset_idx"),
        ),
        migrations.AddIndex(
            model_name="vulnerabilityfinding",
            index=models.Index(fields=["status", "severity"], name="nvmgr_finding_status_sev_idx"),
        ),
        migrations.AddIndex(
            model_name="vulnerabilityfinding",
            index=models.Index(fields=["last_seen"], name="nvmgr_finding_last_seen_idx"),
        ),
    ]
