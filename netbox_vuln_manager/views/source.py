import logging

from django.contrib import messages
from django.http import HttpResponseRedirect
from django.urls import reverse
from django.views import View
from django.contrib.auth.mixins import PermissionRequiredMixin
from netbox.views import generic

from ..models import VulnerabilitySource
from ..forms import VulnerabilitySourceForm, VulnerabilitySourceFilterForm
from ..filtersets import VulnerabilitySourceFilterSet
from ..tables import VulnerabilitySourceTable

logger = logging.getLogger(__name__)


class VulnerabilitySourceListView(generic.ObjectListView):
    queryset = VulnerabilitySource.objects.prefetch_related("tags")
    table = VulnerabilitySourceTable
    filterset = VulnerabilitySourceFilterSet
    filterset_form = VulnerabilitySourceFilterForm
    template_name = "netbox_vuln_manager/source_list.html"


class VulnerabilitySourceView(generic.ObjectView):
    queryset = VulnerabilitySource.objects.prefetch_related("tags", "sync_logs")
    template_name = "netbox_vuln_manager/source.html"

    def get_extra_context(self, request, instance):
        from ..tables import VulnerabilityFindingTable
        from ..models import SyncLog
        import django_tables2 as tables

        findings_table = VulnerabilityFindingTable(
            instance.findings.select_related("vulnerability").order_by("-last_seen")[:25]
        )
        recent_logs = instance.sync_logs.order_by("-started_at")[:10]
        return {
            "findings_table": findings_table,
            "recent_logs": recent_logs,
            "safe_config": instance.safe_config,
        }


class VulnerabilitySourceEditView(generic.ObjectEditView):
    queryset = VulnerabilitySource.objects.all()
    form = VulnerabilitySourceForm


class VulnerabilitySourceDeleteView(generic.ObjectDeleteView):
    queryset = VulnerabilitySource.objects.all()


class VulnerabilitySourceSyncView(PermissionRequiredMixin, View):
    """
    Trigger an immediate synchronisation for a VulnerabilitySource.

    This runs synchronously (blocking the HTTP request) and is intended for
    manual one-off syncs from the UI.  For scheduled/automated syncs use the
    ``sync_vulnerabilities`` management command or a Celery task.
    """

    permission_required = "netbox_vuln_manager.sync_vulnerabilitysource"

    def post(self, request, pk):
        source = VulnerabilitySource.objects.get(pk=pk)

        try:
            from ..management.commands.sync_vulnerabilities import run_sync
            log = run_sync(source)
            messages.success(
                request,
                f"Sync of '{source.name}' complete: "
                f"{log.records_created} created, {log.records_updated} updated, "
                f"{log.records_failed} failed.",
            )
        except Exception as exc:
            logger.exception("Manual sync of %s failed", source)
            messages.error(request, f"Sync failed: {exc}")

        return HttpResponseRedirect(
            reverse("plugins:netbox_vuln_manager:vulnerabilitysource", args=[pk])
        )
