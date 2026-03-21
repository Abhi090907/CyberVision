from django.urls import path
from apps.scanner.api.views import ScanAPIView, ScanDetailAPIView


urlpatterns = [
    path("scan/", ScanAPIView.as_view(), name="scan-create"),
    path("scan/<int:scan_id>/", ScanDetailAPIView.as_view(), name="scan-detail"),
]
