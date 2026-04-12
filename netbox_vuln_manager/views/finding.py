from netbox.views import generic

from ..models import VulnerabilityFinding
from ..forms import VulnerabilityFindingForm, VulnerabilityFindingFilterForm
from ..filtersets import VulnerabilityFindingFilterSet
from ..tables import VulnerabilityFindingTable


class VulnerabilityFindingListView(generic.ObjectListView):
    queryset = VulnerabilityFinding.objects.select_related(
        "vulnerability", "source"
    ).prefetch_related("tags")
    table = VulnerabilityFindingTable
    filterset = VulnerabilityFindingFilterSet
    filterset_form = VulnerabilityFindingFilterForm
    template_name = "netbox_vuln_manager/finding_list.html"


class VulnerabilityFindingView(generic.ObjectView):
    queryset = VulnerabilityFinding.objects.select_related(
        "vulnerability", "source"
    ).prefetch_related("tags", "risk_scores")
    template_name = "netbox_vuln_manager/finding.html"

    def get_extra_context(self, request, instance):
        return {
            "risk_history": instance.risk_scores.order_by("-assessed_at")[:10],
        }


class VulnerabilityFindingEditView(generic.ObjectEditView):
    queryset = VulnerabilityFinding.objects.all()
    form = VulnerabilityFindingForm


class VulnerabilityFindingDeleteView(generic.ObjectDeleteView):
    queryset = VulnerabilityFinding.objects.all()
