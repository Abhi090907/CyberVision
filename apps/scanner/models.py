from django.db import models
from apps.core.models import TimeStampedModel


class ScanResult(TimeStampedModel):
    target = models.CharField(max_length=255, db_index=True)
    scan_type = models.CharField(max_length=64, default="full")
    status = models.CharField(max_length=32, default="queued")
    risk_score = models.FloatField(default=0.0)
    raw_output = models.JSONField(default=dict, blank=True)

    def __str__(self) -> str:
        return f"{self.target} [{self.status}]"


class Vulnerability(TimeStampedModel):
    scan_result = models.ForeignKey(
        ScanResult,
        on_delete=models.CASCADE,
        related_name="vulnerabilities",
    )
    title = models.CharField(max_length=255)
    severity = models.CharField(max_length=16, db_index=True)
    description = models.TextField()
    cvss_score = models.FloatField(default=0.0)
    remediation = models.TextField(blank=True)

    def __str__(self) -> str:
        return f"{self.title} ({self.severity})"
