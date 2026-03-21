from django.urls import path
from apps.attack.api.views import AttackDetailAPIView, AttackRunAPIView


urlpatterns = [
    path("run/", AttackRunAPIView.as_view(), name="attack-run"),
    path("<int:attack_id>/", AttackDetailAPIView.as_view(), name="attack-detail"),
]
