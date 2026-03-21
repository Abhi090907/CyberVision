from rest_framework import serializers
from apps.scanner.models import ScanResult, Vulnerability


class VulnerabilitySerializer(serializers.ModelSerializer):
    class Meta:
        model = Vulnerability
        fields = [
            "id",
            "title",
            "severity",
            "description",
            "cvss_score",
            "remediation",
            "created_at",
        ]


class ScanRequestSerializer(serializers.Serializer):
    url = serializers.URLField()
    scan_type = serializers.CharField(max_length=64, default="full", required=False)


class ScanCreatedSerializer(serializers.Serializer):
    scan_id = serializers.IntegerField()


class ScanDetailSerializer(serializers.Serializer):
    url = serializers.CharField()
    risk_score = serializers.FloatField()
    vulnerabilities = VulnerabilitySerializer(many=True)
    zap_alerts = serializers.JSONField()
    summary = serializers.CharField()


class ScanResultModelSerializer(serializers.ModelSerializer):
    class Meta:
        model = ScanResult
        fields = ["id", "target", "scan_type", "status", "risk_score", "raw_output", "created_at"]
