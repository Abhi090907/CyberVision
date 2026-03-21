from rest_framework import serializers
from apps.ai.models import AIReport


class AIReportSerializer(serializers.ModelSerializer):
    class Meta:
        model = AIReport
        fields = [
            "id",
            "scan_result",
            "model_name",
            "summary",
            "recommendations",
            "confidence",
            "created_at",
            "updated_at",
        ]


class AIRecommendationRequestSerializer(serializers.Serializer):
    scan_result_id = serializers.IntegerField(required=False)
