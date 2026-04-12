from netbox.api.routers import NetBoxRouter
from . import views

router = NetBoxRouter()
router.register("vulnerabilities", views.VulnerabilityViewSet)
router.register("findings", views.VulnerabilityFindingViewSet)
router.register("sources", views.VulnerabilitySourceViewSet)

urlpatterns = router.urls
