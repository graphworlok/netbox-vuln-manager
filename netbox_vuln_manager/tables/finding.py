import django_tables2 as tables
from netbox.tables import NetBoxTable, ChoiceFieldColumn, columns

from ..models import VulnerabilityFinding


class VulnerabilityFindingTable(NetBoxTable):
    vulnerability = tables.Column(linkify=True)
    source = tables.Column(linkify=True)
    status = ChoiceFieldColumn()
    severity = ChoiceFieldColumn()
    asset = tables.Column(
        verbose_name="Asset",
        accessor="asset_hostname",
        orderable=False,
    )
    asset_ip = tables.Column(verbose_name="IP")
    last_seen = tables.DateTimeColumn()
    first_seen = tables.DateTimeColumn()
    actions = columns.ActionsColumn(actions=("edit", "delete"))

    class Meta(NetBoxTable.Meta):
        model = VulnerabilityFinding
        fields = (
            "pk",
            "vulnerability",
            "source",
            "asset",
            "asset_ip",
            "status",
            "severity",
            "exploitability",
            "first_seen",
            "last_seen",
            "tags",
            "actions",
        )
        default_columns = (
            "vulnerability",
            "asset",
            "asset_ip",
            "status",
            "severity",
            "last_seen",
            "actions",
        )

    def render_asset(self, record):
        # Prefer the linked NetBox object name, fall back to denormalised hostname
        if record.asset:
            return str(record.asset)
        return record.asset_hostname or record.asset_ip or "—"
