from django.db import models
from apps.core.models import TimeStampedModel
from apps.scanner.models import ScanResult


class AttackSession(TimeStampedModel):
    scan_result = models.ForeignKey(
        ScanResult,
        on_delete=models.CASCADE,
        related_name="attack_sessions",
    )
    target = models.CharField(max_length=512, db_index=True)
    scenario = models.CharField(max_length=128, default="controlled_validation")
    status = models.CharField(max_length=32, default="running")
    steps = models.JSONField(default=list, blank=True)
    results = models.JSONField(default=list, blank=True)
    validation_results = models.JSONField(default=list, blank=True)
    summary = models.TextField(blank=True)
    risk_update = models.CharField(max_length=64, blank=True)

    def __str__(self) -> str:
        return f"AttackSession #{self.id} [{self.status}]"


class AttackLog(TimeStampedModel):
    attack_session = models.ForeignKey(
        AttackSession,
        on_delete=models.CASCADE,
        null=True,
        blank=True,
        related_name="logs",
    )
    scan_result = models.ForeignKey(
        ScanResult,
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name="attack_logs",
    )
    attack_type = models.CharField(max_length=64, default="generic")
    payload = models.JSONField(default=dict, blank=True)
    response_status = models.IntegerField(default=0)
    validated = models.BooleanField(default=False)
    scenario = models.CharField(max_length=128, default="red_team_baseline")
    status = models.CharField(max_length=32, default="completed")
    result = models.JSONField(default=dict, blank=True)
    notes = models.TextField(blank=True)

    def __str__(self) -> str:
        return f"{self.scenario} [{self.status}]"
