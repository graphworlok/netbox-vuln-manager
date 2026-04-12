from django import forms
from netbox.forms import NetBoxModelForm, NetBoxModelFilterSetForm
from utilities.forms.fields import DynamicModelChoiceField, DynamicModelMultipleChoiceField, TagFilterField

from ..models import VulnerabilityFinding, Vulnerability, VulnerabilitySource
from ..choices import FindingStatusChoices, SeverityChoices


class VulnerabilityFindingForm(NetBoxModelForm):
    vulnerability = DynamicModelChoiceField(queryset=Vulnerability.objects.all())
    source = DynamicModelChoiceField(queryset=VulnerabilitySource.objects.all())

    class Meta:
        model = VulnerabilityFinding
        fields = [
            "vulnerability",
            "source",
            "status",
            "severity",
            "asset_hostname",
            "asset_ip",
            "external_id",
            "first_seen",
            "last_seen",
            "exploitability",
            "remediation",
            "notes",
            "tags",
        ]
        widgets = {
            "first_seen": forms.DateTimeInput(attrs={"type": "datetime-local"}),
            "last_seen": forms.DateTimeInput(attrs={"type": "datetime-local"}),
            "remediation": forms.Textarea(attrs={"rows": 3}),
            "notes": forms.Textarea(attrs={"rows": 3}),
        }


class VulnerabilityFindingFilterForm(NetBoxModelFilterSetForm):
    model = VulnerabilityFinding
    q = forms.CharField(required=False, label="Search")
    status = forms.MultipleChoiceField(
        choices=FindingStatusChoices,
        required=False,
        widget=forms.SelectMultiple(attrs={"size": 5}),
    )
    severity = forms.MultipleChoiceField(
        choices=SeverityChoices,
        required=False,
        widget=forms.SelectMultiple(attrs={"size": 6}),
    )
    source_id = DynamicModelMultipleChoiceField(
        queryset=VulnerabilitySource.objects.all(),
        required=False,
        label="Source",
    )
    asset_hostname = forms.CharField(required=False)
    asset_ip = forms.GenericIPAddressField(required=False, label="Asset IP")
    last_seen_after = forms.DateField(
        required=False,
        label="Last seen after",
        widget=forms.DateInput(attrs={"type": "date"}),
    )
    last_seen_before = forms.DateField(
        required=False,
        label="Last seen before",
        widget=forms.DateInput(attrs={"type": "date"}),
    )
    tag = TagFilterField(model)
