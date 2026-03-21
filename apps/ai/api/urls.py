from django.urls import path
from apps.ai.api.views import AIRecommendationsAPIView


urlpatterns = [
    path("recommendations/", AIRecommendationsAPIView.as_view(), name="ai-recommendations"),
]
