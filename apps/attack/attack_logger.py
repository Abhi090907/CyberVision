from __future__ import annotations

from typing import Any

from apps.attack.models import AttackLog, AttackSession
from apps.scanner.models import ScanResult


def log_attack_event(
    *,
    attack_session: AttackSession,
    scan_result: ScanResult,
    attack_type: str,
    payload: dict[str, Any],
    response_status: int,
    status: str,
    validated: bool,
    result: dict[str, Any],
    notes: str = "",
) -> AttackLog:
    return AttackLog.objects.create(
        attack_session=attack_session,
        scan_result=scan_result,
        attack_type=attack_type,
        payload=payload,
        response_status=response_status,
        validated=validated,
        scenario=attack_session.scenario,
        status=status,
        result=result,
        notes=notes,
    )
