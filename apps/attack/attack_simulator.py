from __future__ import annotations

import json
import os
import time
from typing import Any
from urllib import request
from urllib.error import HTTPError, URLError
from urllib.parse import urlencode

from apps.attack.fuzz_engine import run_input_fuzzing


def _http_get(url: str, timeout: float = 8.0) -> tuple[int, dict[str, str], str]:
    req = request.Request(url=url, method="GET")
    try:
        with request.urlopen(req, timeout=timeout) as resp:
            headers = {k.lower(): v for k, v in resp.headers.items()}
            body = resp.read(8192).decode("utf-8", errors="ignore")
            return int(resp.getcode() or 0), headers, body
    except HTTPError as exc:
        headers = {k.lower(): v for k, v in (exc.headers.items() if exc.headers else [])}
        body = exc.read(8192).decode("utf-8", errors="ignore")
        return int(exc.code or 0), headers, body
    except URLError:
        return 0, {}, ""


def _http_post(url: str, payload: dict[str, str], timeout: float = 8.0) -> tuple[int, str]:
    data = urlencode(payload).encode("utf-8")
    req = request.Request(url=url, method="POST", data=data)
    req.add_header("Content-Type", "application/x-www-form-urlencoded")
    try:
        with request.urlopen(req, timeout=timeout) as resp:
            body = resp.read(4096).decode("utf-8", errors="ignore")
            return int(resp.getcode() or 0), body
    except HTTPError as exc:
        body = exc.read(4096).decode("utf-8", errors="ignore")
        return int(exc.code or 0), body
    except URLError:
        return 0, ""


def simulate_brute_force(target_url: str, intensity: int = 1) -> dict[str, Any]:
    max_attempts = max(2, min(3 + intensity, 8))
    usernames = os.getenv("ATTACK_USERNAMES", "admin,test,user").split(",")
    passwords = os.getenv("ATTACK_PASSWORDS", "admin,123456,password").split(",")
    login_path = os.getenv("ATTACK_LOGIN_PATH", "/login")
    login_url = f"{target_url.rstrip('/')}{login_path}"

    attempts = 0
    success = False
    last_status = 0
    step_results = []
    for username in usernames:
        for password in passwords:
            if attempts >= max_attempts or success:
                break
            attempts += 1
            status, body = _http_post(login_url, {"username": username, "password": password})
            last_status = status
            maybe_success = status in {200, 302} and ("invalid" not in body.lower() and "error" not in body.lower())
            step_results.append(
                {
                    "username": username,
                    "password": "***",
                    "response_status": status,
                    "possible_success": maybe_success,
                }
            )
            success = maybe_success
        if attempts >= max_attempts or success:
            break

    return {
        "type": "brute_force",
        "status": "success" if success else "fail",
        "details": f"Executed {attempts} controlled attempts against login endpoint.",
        "validated": bool(success),
        "response_status": last_status,
        "steps": step_results,
    }


def simulate_session_testing(target_url: str) -> dict[str, Any]:
    status_a, headers_a, _ = _http_get(target_url)
    status_b, headers_b, _ = _http_get(target_url)
    cookie_a = headers_a.get("set-cookie", "")
    cookie_b = headers_b.get("set-cookie", "")

    insecure_flags = cookie_a and ("secure" not in cookie_a.lower() or "httponly" not in cookie_a.lower())
    reuse_possible = bool(cookie_a and cookie_b and cookie_a == cookie_b)
    validated = bool(insecure_flags or reuse_possible)

    return {
        "type": "session_testing",
        "status": "success" if validated else "fail",
        "details": "Checked session cookie reuse and secure cookie flags.",
        "validated": validated,
        "response_status": max(status_a, status_b),
        "steps": [
            {"check": "secure_cookie_flags", "result": not insecure_flags},
            {"check": "session_reuse", "result": not reuse_possible},
        ],
    }


def run_zap_active_validation(target_url: str) -> dict[str, Any]:
    zap_url = os.getenv("ZAP_API_URL", "http://127.0.0.1:8080").rstrip("/")
    api_key = os.getenv("ZAP_API_KEY", "").strip()
    timeout = float(os.getenv("ZAP_SCAN_TIMEOUT", "120"))
    if not api_key:
        return {"enabled": False, "alerts": [], "details": "Missing ZAP_API_KEY"}

    def zap_get(path: str, params: dict[str, Any]) -> dict[str, Any]:
        query = urlencode(params)
        full = f"{zap_url}/{path}?{query}"
        req = request.Request(url=full, method="GET")
        with request.urlopen(req, timeout=10.0) as resp:
            return json.loads(resp.read().decode("utf-8"))

    try:
        start_resp = zap_get(
            "JSON/ascan/action/scan/",
            {"apikey": api_key, "url": target_url, "recurse": "true", "inScopeOnly": "false"},
        )
        scan_id = str(start_resp.get("scan", ""))
        started = time.time()
        while scan_id:
            if time.time() - started > timeout:
                raise TimeoutError("ZAP active scan timeout")
            status_resp = zap_get("JSON/ascan/view/status/", {"apikey": api_key, "scanId": scan_id})
            status_str = str(status_resp.get("status", "0"))
            if status_str.isdigit() and int(status_str) >= 100:
                break
            time.sleep(2)
        alerts_resp = zap_get(
            "JSON/core/view/alerts/",
            {"apikey": api_key, "baseurl": target_url, "start": 0, "count": 999},
        )
        alerts = alerts_resp.get("alerts", [])
        if not isinstance(alerts, list):
            alerts = []
        return {"enabled": True, "alerts": alerts, "details": "ZAP validation completed"}
    except (URLError, HTTPError, ValueError, TimeoutError, json.JSONDecodeError) as exc:
        return {"enabled": True, "alerts": [], "details": f"ZAP validation failed: {exc}"}


def correlate_with_zap(local_attacks: list[dict[str, Any]], zap_alerts: list[dict[str, Any]]) -> list[dict[str, Any]]:
    alert_titles = {str(item.get("alert", "")).lower() for item in zap_alerts}
    correlated = []
    for attack in local_attacks:
        label = attack["type"].replace("_", " ")
        matched = any(label in alert for alert in alert_titles)
        correlated.append(
            {
                "attack_type": attack["type"],
                "validated_by_zap": matched,
                "local_validated": bool(attack.get("validated")),
                "status": "confirmed" if matched or attack.get("validated") else "potential",
            }
        )
    return correlated


def run_safe_attacks(target_url: str, intensity: int = 1) -> dict[str, Any]:
    brute = simulate_brute_force(target_url, intensity=intensity)
    fuzz_results = run_input_fuzzing(target_url, intensity=intensity)
    fuzz_abnormal = any(item["abnormal"] for item in fuzz_results)
    fuzz = {
        "type": "input_fuzzing",
        "status": "success" if fuzz_abnormal else "fail",
        "details": f"Executed {len(fuzz_results)} non-destructive payload probes.",
        "validated": fuzz_abnormal,
        "response_status": max((item["response_status"] for item in fuzz_results), default=0),
        "steps": fuzz_results,
    }
    session = simulate_session_testing(target_url)
    return {"attacks": [brute, fuzz, session], "fuzz_results": fuzz_results}
