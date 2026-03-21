from rest_framework import status
from rest_framework.response import Response
from rest_framework.views import APIView

from apps.ai.api.serializers import AIReportSerializer
from apps.ai.services import AIRecommendationService


class AIRecommendationsAPIView(APIView):
    def get(self, request):
        raw_scan_id = request.query_params.get("scan_result_id")
        scan_result_id = int(raw_scan_id) if raw_scan_id and raw_scan_id.isdigit() else None
        report = AIRecommendationService.get_or_create_recommendation(scan_result_id=scan_result_id)
        return Response(AIReportSerializer(report).data, status=status.HTTP_200_OK)
