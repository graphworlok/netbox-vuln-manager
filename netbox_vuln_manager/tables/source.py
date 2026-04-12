import django_tables2 as tables
from netbox.tables import NetBoxTable, ChoiceFieldColumn, BooleanColumn, columns

from ..models import VulnerabilitySource


class VulnerabilitySourceTable(NetBoxTable):
    name = tables.Column(linkify=True)
    source_type = ChoiceFieldColumn()
    enabled = BooleanColumn()
    auto_create_assets = BooleanColumn()
    last_sync_status = ChoiceFieldColumn()
    finding_count = tables.Column(verbose_name="Findings", orderable=False)
    actions = columns.ActionsColumn(actions=("edit", "delete", "sync"))

    class Meta(NetBoxTable.Meta):
        model = VulnerabilitySource
        fields = (
            "pk",
            "name",
            "source_type",
            "enabled",
            "auto_create_assets",
            "asset_match_strategy",
            "last_sync_at",
            "last_sync_status",
            "finding_count",
            "actions",
        )
        default_columns = (
            "name",
            "source_type",
            "enabled",
            "last_sync_at",
            "last_sync_status",
            "finding_count",
            "actions",
        )

    def render_finding_count(self, record):
        return record.findings.count()
