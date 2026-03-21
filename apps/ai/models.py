from django.db import models
from apps.core.models import TimeStampedModel
from apps.scanner.models import ScanResult


class AIReport(TimeStampedModel):
    scan_result = models.ForeignKey(
        ScanResult,
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name="ai_reports",
    )
    model_name = models.CharField(max_length=128, default="cybervisionx-guardian-v1")
    summary = models.TextField()
    recommendations = models.JSONField(default=list, blank=True)
    confidence = models.FloatField(default=0.0)

    def __str__(self) -> str:
        return f"AIReport #{self.id} ({self.model_name})"
