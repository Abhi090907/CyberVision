from __future__ import annotations

import json
import os
import sys

import django


def main() -> int:
    if len(sys.argv) < 2:
        print("Usage: python run_scan.py https://example.com")
        return 2

    target_url = sys.argv[1].strip()
    os.environ.setdefault("DJANGO_SETTINGS_MODULE", "config.settings")
    django.setup()

    from apps.scanner.services import ScanService

    scan = ScanService.start_scan(target=target_url, scan_type="full")
    vulnerabilities = [
        {
            "title": item.title,
            "severity": item.severity,
            "description": item.description,
            "cvss_score": item.cvss_score,
        }
        for item in scan.vulnerabilities.all()
    ]
    result = {
        "scan_id": scan.id,
        "target": scan.target,
        "status": scan.status,
        "risk_score": scan.risk_score,
        "vulnerabilities": vulnerabilities,
        "zap_alerts": scan.raw_output.get("zap_alerts", []) if isinstance(scan.raw_output, dict) else [],
    }
    print(json.dumps(result, indent=2))

    has_high_or_critical = any(
        str(item.get("severity", "")).strip().lower() in {"high", "critical"} for item in vulnerabilities
    )
    if has_high_or_critical or scan.risk_score >= 50:
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
