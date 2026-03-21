from __future__ import annotations

import time
from typing import Any
from urllib import parse, request
from urllib.error import HTTPError, URLError
from urllib.parse import urlencode, urlparse


SQLI_PAYLOADS = [
    "' OR '1'='1",
    "'; WAITFOR DELAY '0:0:1'--",
    "admin' --",
]

XSS_PAYLOADS = [
    "<script>alert(1)</script>",
    "\" onmouseover=\"alert(1)",
    "<img src=x onerror=alert(1)>",
]


def _append_query_payload(url: str, param: str, value: str) -> str:
    parsed = urlparse(url)
    query = parse.parse_qs(parsed.query, keep_blank_values=True)
    query[param] = [value]
    encoded = urlencode(query, doseq=True)
    return parsed._replace(query=encoded).geturl()


def _safe_get(url: str, timeout: float = 8.0) -> tuple[int, str, float]:
    start = time.time()
    try:
        req = request.Request(url=url, method="GET")
        with request.urlopen(req, timeout=timeout) as resp:
            body = resp.read(4096).decode("utf-8", errors="ignore")
            return int(resp.getcode() or 0), body, time.time() - start
    except HTTPError as exc:
        body = exc.read(4096).decode("utf-8", errors="ignore")
        return int(exc.code or 0), body, time.time() - start
    except URLError:
        return 0, "", time.time() - start


def run_input_fuzzing(target_url: str, intensity: int = 1) -> list[dict[str, Any]]:
    capped = max(1, min(intensity, 3))
    payloads = (SQLI_PAYLOADS[: capped + 1] + XSS_PAYLOADS[: capped + 1])[:8]
    findings: list[dict[str, Any]] = []
    error_markers = ["sql syntax", "database error", "exception", "traceback"]

    for payload in payloads:
        fuzzed_url = _append_query_payload(target_url, "q", payload)
        status, body, latency = _safe_get(fuzzed_url)
        body_lower = body.lower()
        abnormal = status >= 500 or any(marker in body_lower for marker in error_markers) or latency > 3.5
        findings.append(
            {
                "type": "input_fuzzing",
                "payload": payload,
                "url": fuzzed_url,
                "response_status": status,
                "latency_seconds": round(latency, 3),
                "abnormal": abnormal,
                "details": "Abnormal response detected" if abnormal else "No abnormal behavior detected",
            }
        )
    return findings
