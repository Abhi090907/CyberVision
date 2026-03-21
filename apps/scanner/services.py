from __future__ import annotations

import json
import os
import socket
import time
from typing import Any
from urllib.error import HTTPError, URLError
from urllib.parse import urlencode, urlparse
from urllib.request import Request, urlopen

from apps.scanner.models import ScanResult, Vulnerability


class ScanService:
    SEVERITY_WEIGHTS = {
        "critical": 30.0,
        "high": 20.0,
        "medium": 10.0,
        "low": 5.0,
    }

    @staticmethod
    def _normalize_url(url: str) -> str:
        parsed = urlparse(url.strip())
        if not parsed.scheme or not parsed.netloc:
            raise ValueError("Invalid URL. Provide an absolute URL like https://example.com")
        if parsed.scheme not in {"http", "https"}:
            raise ValueError("Only http and https URLs are supported")
        return parsed.geturl()

    @staticmethod
    def _fetch_headers(url: str, timeout: float = 10.0) -> dict[str, str]:
        request = Request(url=url, method="GET")
        try:
            with urlopen(request, timeout=timeout) as response:
                return {k.lower(): v for k, v in response.headers.items()}
        except HTTPError as exc:
            return {k.lower(): v for k, v in exc.headers.items()} if exc.headers else {}
        except (URLError, socket.timeout) as exc:
            raise RuntimeError(f"Request failed for {url}: {exc}") from exc

    @staticmethod
    def _build_finding(
        title: str,
        severity: str,
        description: str,
        remediation: str,
        cvss_score: float = 0.0,
    ) -> dict[str, Any]:
        return {
            "title": title,
            "severity": severity.lower(),
            "description": description,
            "remediation": remediation,
            "cvss_score": cvss_score,
        }

    @staticmethod
    def _analyze_headers(url: str, headers: dict[str, str]) -> list[dict[str, Any]]:
        findings: list[dict[str, Any]] = []
        required_headers = {
            "content-security-policy": (
                "Missing Content-Security-Policy",
                "high",
                "The Content-Security-Policy header is missing.",
                "Add a strict Content-Security-Policy policy.",
                7.5,
            ),
            "x-frame-options": (
                "Missing X-Frame-Options",
                "medium",
                "The X-Frame-Options header is missing.",
                "Set X-Frame-Options to DENY or SAMEORIGIN.",
                5.3,
            ),
            "strict-transport-security": (
                "Missing Strict-Transport-Security",
                "high",
                "Strict-Transport-Security header is missing.",
                "Enable HSTS with a long max-age and includeSubDomains.",
                7.0,
            ),
            "x-content-type-options": (
                "Missing X-Content-Type-Options",
                "medium",
                "X-Content-Type-Options header is missing.",
                "Set X-Content-Type-Options to nosniff.",
                4.8,
            ),
        }
        for key, values in required_headers.items():
            if key not in headers:
                findings.append(ScanService._build_finding(*values))

        # Basic OWASP checks
        if urlparse(url).scheme != "https":
            findings.append(
                ScanService._build_finding(
                    "Insecure Transport (HTTP)",
                    "high",
                    "Target URL uses HTTP instead of HTTPS.",
                    "Serve application over HTTPS and redirect all HTTP traffic.",
                    8.2,
                )
            )

        set_cookie_value = headers.get("set-cookie", "")
        cookie_lower = set_cookie_value.lower()
        if set_cookie_value and ("secure" not in cookie_lower or "httponly" not in cookie_lower):
            findings.append(
                ScanService._build_finding(
                    "Insecure Cookie Configuration",
                    "medium",
                    "Cookies may be missing Secure and/or HttpOnly flags.",
                    "Set Secure and HttpOnly flags for all session/auth cookies.",
                    6.1,
                )
            )

        if headers.get("server"):
            findings.append(
                ScanService._build_finding(
                    "Exposed Server Information",
                    "low",
                    "Server banner is exposed in the Server response header.",
                    "Hide or minimize server banner details.",
                    3.7,
                )
            )

        return findings

    @staticmethod
    def _severity_from_zap_risk(risk: str) -> str:
        normalized = risk.strip().lower()
        if normalized in {"critical", "high", "medium", "low"}:
            return normalized
        if normalized in {"informational", "info"}:
            return "low"
        return "medium"

    @staticmethod
    def _risk_score(findings: list[dict[str, Any]], zap_alerts: list[dict[str, Any]]) -> float:
        total = 0.0
        for finding in findings:
            total += ScanService.SEVERITY_WEIGHTS.get(finding.get("severity", "low"), 5.0)
        for alert in zap_alerts:
            severity = ScanService._severity_from_zap_risk(str(alert.get("risk", "medium")))
            total += ScanService.SEVERITY_WEIGHTS.get(severity, 5.0)
        return round(min(100.0, total), 2)

    @staticmethod
    def _summary(url: str, risk_score: float, findings_count: int, zap_count: int) -> str:
        if risk_score >= 75:
            posture = "Critical risk posture"
        elif risk_score >= 50:
            posture = "High risk posture"
        elif risk_score >= 25:
            posture = "Moderate risk posture"
        else:
            posture = "Low risk posture"
        return (
            f"{posture} for {url}. "
            f"Detected {findings_count} local findings and {zap_count} ZAP alerts."
        )

    @staticmethod
    def _zap_request(base_url: str, path: str, params: dict[str, Any], timeout: float) -> dict[str, Any]:
        query = urlencode(params)
        full_url = f"{base_url.rstrip('/')}/{path}?{query}"
        request = Request(url=full_url, method="GET")
        with urlopen(request, timeout=timeout) as response:
            payload = response.read().decode("utf-8")
            return json.loads(payload)

    @staticmethod
    def _poll_zap_progress(
        base_url: str,
        endpoint: str,
        scan_id: str,
        api_key: str,
        timeout: float,
        interval: float = 2.0,
    ) -> None:
        start = time.time()
        while True:
            if time.time() - start > timeout:
                raise TimeoutError(f"ZAP scan timed out for scan ID {scan_id}")
            result = ScanService._zap_request(
                base_url,
                endpoint,
                {"apikey": api_key, "scanId": scan_id},
                timeout=10.0,
            )
            status_value = str(result.get("status", "0"))
            if status_value.isdigit() and int(status_value) >= 100:
                return
            time.sleep(interval)

    @staticmethod
    def _run_zap_scan(url: str) -> tuple[list[dict[str, Any]], dict[str, Any]]:
        zap_url = os.getenv("ZAP_API_URL", "http://127.0.0.1:8080")
        api_key = os.getenv("ZAP_API_KEY", "")
        timeout = float(os.getenv("ZAP_SCAN_TIMEOUT", "180"))

        if not api_key:
            return [], {"enabled": False, "error": "Missing ZAP_API_KEY"}

        try:
            spider = ScanService._zap_request(
                zap_url,
                "JSON/spider/action/scan/",
                {"apikey": api_key, "url": url, "maxChildren": 10, "recurse": "true"},
                timeout=10.0,
            )
            spider_id = str(spider.get("scan", ""))
            if spider_id:
                ScanService._poll_zap_progress(
                    zap_url,
                    "JSON/spider/view/status/",
                    spider_id,
                    api_key,
                    timeout=timeout,
                )

            active = ScanService._zap_request(
                zap_url,
                "JSON/ascan/action/scan/",
                {
                    "apikey": api_key,
                    "url": url,
                    "recurse": "true",
                    "inScopeOnly": "false",
                },
                timeout=10.0,
            )
            active_id = str(active.get("scan", ""))
            if active_id:
                ScanService._poll_zap_progress(
                    zap_url,
                    "JSON/ascan/view/status/",
                    active_id,
                    api_key,
                    timeout=timeout,
                )

            alerts_response = ScanService._zap_request(
                zap_url,
                "JSON/core/view/alerts/",
                {"apikey": api_key, "baseurl": url, "start": 0, "count": 999},
                timeout=10.0,
            )
            alerts = alerts_response.get("alerts", [])
            if not isinstance(alerts, list):
                alerts = []
            return alerts, {
                "enabled": True,
                "spider_scan_id": spider_id,
                "active_scan_id": active_id,
            }
        except (URLError, HTTPError, TimeoutError, ValueError, json.JSONDecodeError) as exc:
            return [], {"enabled": True, "error": str(exc)}

    @staticmethod
    def start_scan(target: str, scan_type: str = "full") -> ScanResult:
        normalized_url = ScanService._normalize_url(target)
        scan = ScanResult.objects.create(
            target=normalized_url,
            scan_type=scan_type,
            status="running",
            risk_score=0.0,
            raw_output={},
        )
        try:
            headers = ScanService._fetch_headers(normalized_url)
            findings = ScanService._analyze_headers(normalized_url, headers)
            zap_alerts, zap_meta = ScanService._run_zap_scan(normalized_url)
            risk_score = ScanService._risk_score(findings=findings, zap_alerts=zap_alerts)

            for finding in findings:
                Vulnerability.objects.create(
                    scan_result=scan,
                    title=finding["title"],
                    severity=finding["severity"],
                    description=finding["description"],
                    cvss_score=float(finding.get("cvss_score", 0.0)),
                    remediation=finding["remediation"],
                )

            for alert in zap_alerts:
                severity = ScanService._severity_from_zap_risk(str(alert.get("risk", "medium")))
                title = str(alert.get("alert", "ZAP Alert"))
                description = str(alert.get("description", "Potential vulnerability found by ZAP."))
                solution = str(alert.get("solution", "Review and remediate according to security best practices."))
                score = float(alert.get("cvss", 0.0) or 0.0)
                Vulnerability.objects.create(
                    scan_result=scan,
                    title=title[:255],
                    severity=severity,
                    description=description,
                    cvss_score=score,
                    remediation=solution,
                )

            summary = ScanService._summary(
                normalized_url,
                risk_score,
                findings_count=len(findings),
                zap_count=len(zap_alerts),
            )
            scan.status = "completed"
            scan.risk_score = risk_score
            scan.raw_output = {
                "url": normalized_url,
                "risk_score": risk_score,
                "vulnerabilities": findings,
                "zap_alerts": zap_alerts,
                "summary": summary,
                "zap_meta": zap_meta,
                "headers": headers,
            }
            scan.save(update_fields=["status", "risk_score", "raw_output", "updated_at"])
        except Exception as exc:
            scan.status = "failed"
            scan.raw_output = {"error": str(exc), "url": normalized_url}
            scan.save(update_fields=["status", "raw_output", "updated_at"])
            raise
        return scan

    @staticmethod
    def get_scan_by_id(scan_id: int) -> ScanResult:
        return ScanResult.objects.prefetch_related("vulnerabilities").get(id=scan_id)
