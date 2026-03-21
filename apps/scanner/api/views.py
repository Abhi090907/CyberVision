from rest_framework import status
from rest_framework.exceptions import NotFound, ValidationError
from rest_framework.response import Response
from rest_framework.views import APIView

from apps.scanner.models import ScanResult
from apps.scanner.api.serializers import (
    ScanCreatedSerializer,
    ScanDetailSerializer,
    ScanRequestSerializer,
    VulnerabilitySerializer,
)
from apps.scanner.services import ScanService


class ScanAPIView(APIView):
    def post(self, request):
        serializer = ScanRequestSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        try:
            scan = ScanService.start_scan(
                target=serializer.validated_data["url"],
                scan_type=serializer.validated_data.get("scan_type", "full"),
            )
        except ValueError as exc:
            raise ValidationError(str(exc)) from exc

        response_data = ScanCreatedSerializer({"scan_id": scan.id}).data
        return Response(response_data, status=status.HTTP_201_CREATED)


class ScanDetailAPIView(APIView):
    def get(self, request, scan_id: int):
        try:
            scan = ScanService.get_scan_by_id(scan_id=scan_id)
        except ScanResult.DoesNotExist as exc:
            raise NotFound("Scan not found") from exc

        zap_alerts = scan.raw_output.get("zap_alerts", []) if isinstance(scan.raw_output, dict) else []
        summary = (
            scan.raw_output.get("summary", "")
            if isinstance(scan.raw_output, dict)
            else ""
        )
        response_payload = {
            "url": scan.target,
            "risk_score": scan.risk_score,
            "vulnerabilities": VulnerabilitySerializer(scan.vulnerabilities.all(), many=True).data,
            "zap_alerts": zap_alerts,
            "summary": summary,
        }
        output = ScanDetailSerializer(response_payload)
        return Response(output.data, status=status.HTTP_200_OK)
