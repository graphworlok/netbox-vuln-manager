from django import forms
from netbox.forms import NetBoxModelForm, NetBoxModelFilterSetForm
from utilities.forms.fields import TagFilterField

from ..models import VulnerabilitySource
from ..choices import SourceTypeChoices, AssetMatchStrategyChoices


class VulnerabilitySourceForm(NetBoxModelForm):
    """
    Form for creating/editing a VulnerabilitySource.

    The ``config`` field is rendered as a JSON textarea.  Per-source config
    help text is injected via JavaScript in the template.
    """

    config = forms.JSONField(
        widget=forms.Textarea(attrs={"rows": 12, "class": "font-monospace"}),
        help_text=(
            "Source-specific configuration as JSON. "
            "See documentation for required keys per source type."
        ),
    )

    class Meta:
        model = VulnerabilitySource
        fields = [
            "name",
            "source_type",
            "enabled",
            "description",
            "auto_create_assets",
            "asset_match_strategy",
            "min_severity",
            "config",
            "tags",
        ]
        widgets = {
            "description": forms.Textarea(attrs={"rows": 2}),
        }

    def clean_config(self):
        source_type = self.cleaned_data.get("source_type")
        config = self.cleaned_data.get("config") or {}

        if source_type == "crowdstrike":
            _require_keys(config, ["client_id", "client_secret"], self)
        elif source_type == "securityscorecard":
            _require_keys(config, ["api_key", "domain"], self)
        elif source_type == "csv":
            if not config.get("file_path") and not config.get("csv_content"):
                raise forms.ValidationError(
                    "CSV source requires either 'file_path' or 'csv_content' in config."
                )

        return config


def _require_keys(config: dict, keys: list[str], form):
    missing = [k for k in keys if not config.get(k)]
    if missing:
        raise forms.ValidationError(
            f"Missing required config keys: {', '.join(missing)}"
        )


class VulnerabilitySourceFilterForm(NetBoxModelFilterSetForm):
    model = VulnerabilitySource
    q = forms.CharField(required=False, label="Search")
    source_type = forms.MultipleChoiceField(
        choices=SourceTypeChoices,
        required=False,
        widget=forms.SelectMultiple(attrs={"size": 3}),
    )
    enabled = forms.NullBooleanField(required=False)
    tag = TagFilterField(model)
