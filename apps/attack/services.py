from __future__ import annotations

from typing import Any

from apps.attack.attack_logger import log_attack_event
from apps.attack.attack_simulator import correlate_with_zap, run_safe_attacks, run_zap_active_validation
from apps.attack.models import AttackLog, AttackSession
from apps.scanner.models import ScanResult


class AttackService:
    @staticmethod
    def _determine_validation(vulnerability: dict[str, Any], attacks: list[dict[str, Any]]) -> str:
        title = str(vulnerability.get("title", "")).lower()
        severity = str(vulnerability.get("severity", "")).lower()
        has_validated = any(item.get("validated") for item in attacks)
        if "cookie" in title or "session" in title:
            return "confirmed" if any(a["type"] == "session_testing" and a["validated"] for a in attacks) else "potential"
        if "xss" in title or "sql" in title or "injection" in title:
            return "confirmed" if any(a["type"] == "input_fuzzing" and a["validated"] for a in attacks) else "potential"
        if "login" in title or "brute" in title:
            return "confirmed" if any(a["type"] == "brute_force" and a["validated"] for a in attacks) else "potential"
        if severity in {"critical", "high"} and not has_validated:
            return "potential"
        return "false_positive" if not has_validated else "potential"

    @staticmethod
    def run_attack_simulation(scan_data: dict, intensity: int = 1) -> dict:
        target = str(scan_data.get("target") or scan_data.get("url") or "").strip()
        if not target:
            raise ValueError("scan_data must include target URL")

        local = run_safe_attacks(target, intensity=intensity)
        attacks = local["attacks"]
        zap_result = run_zap_active_validation(target)
        zap_alerts = zap_result.get("alerts", [])
        correlations = correlate_with_zap(attacks, zap_alerts if isinstance(zap_alerts, list) else [])

        vulnerabilities = scan_data.get("vulnerabilities", []) or []
        validations = []
        for vuln in vulnerabilities:
            verdict = AttackService._determine_validation(vuln, attacks)
            validations.append(
                {
                    "title": vuln.get("title", "Unknown vulnerability"),
                    "severity": vuln.get("severity", "medium"),
                    "validation": verdict,
                }
            )

        confirmed = sum(1 for item in validations if item["validation"] == "confirmed")
        potential = sum(1 for item in validations if item["validation"] == "potential")
        false_pos = sum(1 for item in validations if item["validation"] == "false_positive")
        summary = (
            f"Attack simulation complete: {confirmed} confirmed, "
            f"{potential} potential, {false_pos} false positive findings."
        )
        if confirmed >= 3:
            risk_update = "Critical"
        elif confirmed >= 1 or potential >= 3:
            risk_update = "High"
        elif potential >= 1:
            risk_update = "Medium"
        else:
            risk_update = "Low"

        return {
            "target": target,
            "attacks": attacks,
            "summary": summary,
            "risk_update": risk_update,
            "validation_results": validations,
            "zap_alerts": zap_alerts if isinstance(zap_alerts, list) else [],
            "correlation": correlations,
        }

    @staticmethod
    def trigger_simulation(scan_result_id: int | None, scenario: str, intensity: int = 1) -> AttackSession:
        scan_result = None
        if scan_result_id:
            scan_result = ScanResult.objects.filter(id=scan_result_id).first()
        if not scan_result:
            raise ValueError("Valid scan_result_id is required")

        scan_payload = {
            "target": scan_result.target,
            "vulnerabilities": [
                {
                    "title": item.title,
                    "description": item.description,
                    "severity": item.severity,
                    "cvss_score": item.cvss_score,
                }
                for item in scan_result.vulnerabilities.all()
            ],
            "zap_alerts": (
                scan_result.raw_output.get("zap_alerts", [])
                if isinstance(scan_result.raw_output, dict)
                else []
            ),
            "risk_score": scan_result.risk_score,
        }
        result = AttackService.run_attack_simulation(scan_payload, intensity=intensity)

        steps = [attack["type"] for attack in result["attacks"]]
        session = AttackSession.objects.create(
            scan_result=scan_result,
            target=scan_result.target,
            scenario=scenario,
            status="completed",
            steps=steps,
            results=result["attacks"],
            validation_results=result["validation_results"],
            summary=result["summary"],
            risk_update=result["risk_update"],
        )

        for attack in result["attacks"]:
            first_step = attack.get("steps", [{}])[0] if attack.get("steps") else {}
            payload = {"step": first_step}
            response_status = int(attack.get("response_status", 0) or 0)
            log_attack_event(
                attack_session=session,
                scan_result=scan_result,
                attack_type=attack["type"],
                payload=payload,
                response_status=response_status,
                status=attack["status"],
                validated=bool(attack["validated"]),
                result=attack,
                notes="Controlled attack simulation event.",
            )
        return session

    @staticmethod
    def get_attack_session(attack_id: int) -> AttackSession:
        return AttackSession.objects.prefetch_related("logs").get(id=attack_id)


def run_attack_simulation(scan_data: dict) -> dict:
    intensity = int(scan_data.get("intensity", 1) or 1)
    return AttackService.run_attack_simulation(scan_data=scan_data, intensity=intensity)
