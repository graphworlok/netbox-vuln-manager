from netbox.api.serializers import NetBoxModelSerializer
from rest_framework import serializers

from ..models import Vulnerability, VulnerabilityFinding, VulnerabilitySource
from ..choices import SeverityChoices, FindingStatusChoices


class VulnerabilitySerializer(NetBoxModelSerializer):
    severity = serializers.ChoiceField(choices=SeverityChoices)
    best_cvss_score = serializers.ReadOnlyField()
    finding_count = serializers.SerializerMethodField()

    class Meta:
        model = Vulnerability
        fields = [
            "id",
            "url",
            "display",
            "cve_id",
            "title",
            "description",
            "severity",
            "cvss_v2_score",
            "cvss_v3_score",
            "cvss_v3_vector",
            "cwe_id",
            "affected_vendor",
            "affected_product",
            "affected_versions",
            "published_date",
            "modified_date",
            "references",
            "best_cvss_score",
            "finding_count",
            "tags",
            "custom_fields",
            "created",
            "last_updated",
        ]

    def get_finding_count(self, obj):
        return obj.findings.count()


class VulnerabilitySourceSerializer(NetBoxModelSerializer):
    # Never expose credentials in API responses
    safe_config = serializers.ReadOnlyField()
    finding_count = serializers.SerializerMethodField()

    class Meta:
        model = VulnerabilitySource
        fields = [
            "id",
            "url",
            "display",
            "name",
            "source_type",
            "enabled",
            "description",
            "auto_create_assets",
            "asset_match_strategy",
            "min_severity",
            "safe_config",
            "last_sync_at",
            "last_sync_status",
            "last_sync_message",
            "finding_count",
            "tags",
            "custom_fields",
            "created",
            "last_updated",
        ]

    def get_finding_count(self, obj):
        return obj.findings.count()


class VulnerabilityFindingSerializer(NetBoxModelSerializer):
    vulnerability = VulnerabilitySerializer(nested=True)
    source = VulnerabilitySourceSerializer(nested=True)
    status = serializers.ChoiceField(choices=FindingStatusChoices)
    severity = serializers.ChoiceField(choices=SeverityChoices)

    class Meta:
        model = VulnerabilityFinding
        fields = [
            "id",
            "url",
            "display",
            "vulnerability",
            "source",
            "asset_hostname",
            "asset_ip",
            "external_id",
            "status",
            "severity",
            "first_seen",
            "last_seen",
            "exploitability",
            "remediation",
            "notes",
            "tags",
            "custom_fields",
            "created",
            "last_updated",
        ]
