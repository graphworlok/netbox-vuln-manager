from netbox.api.viewsets import NetBoxModelViewSet
from rest_framework.decorators import action
from rest_framework.response import Response

from ..models import Vulnerability, VulnerabilityFinding, VulnerabilitySource
from ..filtersets import VulnerabilityFilterSet, VulnerabilityFindingFilterSet, VulnerabilitySourceFilterSet
from .serializers import VulnerabilitySerializer, VulnerabilityFindingSerializer, VulnerabilitySourceSerializer


class VulnerabilityViewSet(NetBoxModelViewSet):
    queryset = Vulnerability.objects.prefetch_related("tags")
    serializer_class = VulnerabilitySerializer
    filterset_class = VulnerabilityFilterSet


class VulnerabilityFindingViewSet(NetBoxModelViewSet):
    queryset = VulnerabilityFinding.objects.select_related(
        "vulnerability", "source"
    ).prefetch_related("tags")
    serializer_class = VulnerabilityFindingSerializer
    filterset_class = VulnerabilityFindingFilterSet


class VulnerabilitySourceViewSet(NetBoxModelViewSet):
    queryset = VulnerabilitySource.objects.prefetch_related("tags")
    serializer_class = VulnerabilitySourceSerializer
    filterset_class = VulnerabilitySourceFilterSet

    @action(detail=True, methods=["post"], url_path="sync")
    def sync(self, request, pk=None):
        """Trigger an immediate sync for this source via the REST API."""
        source = self.get_object()
        try:
            from ..management.commands.sync_vulnerabilities import run_sync
            log = run_sync(source)
            return Response(
                {
                    "status": log.status,
                    "records_processed": log.records_processed,
                    "records_created": log.records_created,
                    "records_updated": log.records_updated,
                    "records_failed": log.records_failed,
                    "assets_created": log.assets_created,
                    "message": log.message,
                }
            )
        except Exception as exc:
            return Response({"error": str(exc)}, status=500)
