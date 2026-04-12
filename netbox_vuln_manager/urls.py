from django.urls import path
from . import views

urlpatterns = [
    # Vulnerabilities
    path("vulnerabilities/", views.VulnerabilityListView.as_view(), name="vulnerability_list"),
    path("vulnerabilities/add/", views.VulnerabilityEditView.as_view(), name="vulnerability_add"),
    path("vulnerabilities/<int:pk>/", views.VulnerabilityView.as_view(), name="vulnerability"),
    path("vulnerabilities/<int:pk>/edit/", views.VulnerabilityEditView.as_view(), name="vulnerability_edit"),
    path("vulnerabilities/<int:pk>/delete/", views.VulnerabilityDeleteView.as_view(), name="vulnerability_delete"),

    # Findings
    path("findings/", views.VulnerabilityFindingListView.as_view(), name="vulnerabilityfinding_list"),
    path("findings/add/", views.VulnerabilityFindingEditView.as_view(), name="vulnerabilityfinding_add"),
    path("findings/<int:pk>/", views.VulnerabilityFindingView.as_view(), name="vulnerabilityfinding"),
    path("findings/<int:pk>/edit/", views.VulnerabilityFindingEditView.as_view(), name="vulnerabilityfinding_edit"),
    path("findings/<int:pk>/delete/", views.VulnerabilityFindingDeleteView.as_view(), name="vulnerabilityfinding_delete"),

    # Sources
    path("sources/", views.VulnerabilitySourceListView.as_view(), name="vulnerabilitysource_list"),
    path("sources/add/", views.VulnerabilitySourceEditView.as_view(), name="vulnerabilitysource_add"),
    path("sources/<int:pk>/", views.VulnerabilitySourceView.as_view(), name="vulnerabilitysource"),
    path("sources/<int:pk>/edit/", views.VulnerabilitySourceEditView.as_view(), name="vulnerabilitysource_edit"),
    path("sources/<int:pk>/delete/", views.VulnerabilitySourceDeleteView.as_view(), name="vulnerabilitysource_delete"),
    path("sources/<int:pk>/sync/", views.VulnerabilitySourceSyncView.as_view(), name="vulnerabilitysource_sync"),
]
