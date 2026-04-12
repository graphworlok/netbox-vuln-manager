import django_filters
from django.db.models import Q
from netbox.filtersets import NetBoxModelFilterSet

from .models import Vulnerability, VulnerabilityFinding, VulnerabilitySource
from .choices import SeverityChoices, FindingStatusChoices, SourceTypeChoices


class VulnerabilityFilterSet(NetBoxModelFilterSet):
    q = django_filters.CharFilter(method="search", label="Search")
    severity = django_filters.MultipleChoiceFilter(choices=SeverityChoices)
    has_cve = django_filters.BooleanFilter(
        field_name="cve_id",
        lookup_expr="isnull",
        exclude=True,
        label="Has CVE ID",
    )
    cvss_v3_min = django_filters.NumberFilter(field_name="cvss_v3_score", lookup_expr="gte")
    cvss_v3_max = django_filters.NumberFilter(field_name="cvss_v3_score", lookup_expr="lte")

    class Meta:
        model = Vulnerability
        fields = [
            "q",
            "cve_id",
            "severity",
            "has_cve",
            "cvss_v3_min",
            "cvss_v3_max",
            "affected_vendor",
            "affected_product",
        ]

    def search(self, queryset, name, value):
        return queryset.filter(
            Q(cve_id__icontains=value)
            | Q(title__icontains=value)
            | Q(description__icontains=value)
            | Q(affected_vendor__icontains=value)
            | Q(affected_product__icontains=value)
        )


class VulnerabilityFindingFilterSet(NetBoxModelFilterSet):
    q = django_filters.CharFilter(method="search", label="Search")
    status = django_filters.MultipleChoiceFilter(choices=FindingStatusChoices)
    severity = django_filters.MultipleChoiceFilter(choices=SeverityChoices)
    source_id = django_filters.ModelMultipleChoiceFilter(
        queryset=VulnerabilitySource.objects.all(),
        field_name="source",
        label="Source",
    )
    vulnerability_id = django_filters.ModelMultipleChoiceFilter(
        queryset=Vulnerability.objects.all(),
        field_name="vulnerability",
        label="Vulnerability",
    )
    asset_ip = django_filters.CharFilter(lookup_expr="icontains")
    asset_hostname = django_filters.CharFilter(lookup_expr="icontains")
    last_seen_after = django_filters.DateFilter(field_name="last_seen", lookup_expr="gte")
    last_seen_before = django_filters.DateFilter(field_name="last_seen", lookup_expr="lte")

    class Meta:
        model = VulnerabilityFinding
        fields = [
            "q",
            "status",
            "severity",
            "source_id",
            "vulnerability_id",
            "asset_ip",
            "asset_hostname",
            "last_seen_after",
            "last_seen_before",
        ]

    def search(self, queryset, name, value):
        return queryset.filter(
            Q(vulnerability__cve_id__icontains=value)
            | Q(vulnerability__title__icontains=value)
            | Q(asset_hostname__icontains=value)
            | Q(asset_ip__icontains=value)
            | Q(external_id__icontains=value)
        )


class VulnerabilitySourceFilterSet(NetBoxModelFilterSet):
    q = django_filters.CharFilter(method="search", label="Search")
    source_type = django_filters.MultipleChoiceFilter(choices=SourceTypeChoices)
    enabled = django_filters.BooleanFilter()

    class Meta:
        model = VulnerabilitySource
        fields = ["q", "source_type", "enabled"]

    def search(self, queryset, name, value):
        return queryset.filter(
            Q(name__icontains=value) | Q(description__icontains=value)
        )
