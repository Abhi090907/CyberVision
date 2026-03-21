from rest_framework import status
from rest_framework.exceptions import NotFound, ValidationError
from rest_framework.response import Response
from rest_framework.views import APIView

from apps.attack.api.serializers import AttackSessionSerializer, RunAttackSerializer
from apps.attack.models import AttackSession
from apps.attack.services import AttackService


class AttackRunAPIView(APIView):
    def post(self, request):
        serializer = RunAttackSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        try:
            session = AttackService.trigger_simulation(
                scan_result_id=serializer.validated_data["scan_id"],
                scenario=serializer.validated_data.get("scenario", "controlled_validation"),
                intensity=serializer.validated_data.get("intensity", 1),
            )
        except ValueError as exc:
            raise ValidationError(str(exc)) from exc
        return Response({"attack_id": session.id}, status=status.HTTP_201_CREATED)


class AttackDetailAPIView(APIView):
    def get(self, request, attack_id: int):
        try:
            session = AttackService.get_attack_session(attack_id)
        except AttackSession.DoesNotExist as exc:
            raise NotFound("Attack session not found") from exc
        return Response(AttackSessionSerializer(session).data, status=status.HTTP_200_OK)
