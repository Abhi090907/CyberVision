from rest_framework import serializers
from apps.attack.models import AttackLog, AttackSession


class RunAttackSerializer(serializers.Serializer):
    scan_id = serializers.IntegerField()
    scenario = serializers.CharField(max_length=128, default="controlled_validation")
    intensity = serializers.IntegerField(required=False, min_value=1, max_value=3, default=1)


class AttackLogSerializer(serializers.ModelSerializer):
    class Meta:
        model = AttackLog
        fields = [
            "id",
            "attack_session",
            "scan_result",
            "attack_type",
            "payload",
            "response_status",
            "validated",
            "scenario",
            "status",
            "result",
            "notes",
            "created_at",
            "updated_at",
        ]


class AttackSessionSerializer(serializers.ModelSerializer):
    logs = AttackLogSerializer(many=True, read_only=True)

    class Meta:
        model = AttackSession
        fields = [
            "id",
            "scan_result",
            "target",
            "scenario",
            "status",
            "steps",
            "results",
            "validation_results",
            "summary",
            "risk_update",
            "logs",
            "created_at",
            "updated_at",
        ]
