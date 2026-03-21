from __future__ import annotations

import hashlib
import json
import os
import time
from pathlib import Path
from urllib import request
from urllib.error import HTTPError, URLError
from urllib.parse import urlparse

from selenium import webdriver
from selenium.common.exceptions import TimeoutException, WebDriverException
from selenium.webdriver.chrome.options import Options
from selenium.webdriver.chrome.service import Service as ChromeService
from selenium.webdriver.support.ui import WebDriverWait

from apps.ai.models import AIReport
from apps.ai.prompt_templates import SYSTEM_PROMPT, build_user_prompt
from apps.ai.vision_pipeline import run_vision_pipeline
from apps.scanner.models import ScanResult


class AIRecommendationService:
    @staticmethod
    def get_or_create_recommendation(scan_result_id: int | None = None) -> AIReport:
        scan = None
        if scan_result_id:
            scan = ScanResult.objects.filter(id=scan_result_id).first()
        if scan is None:
            scan = ScanResult.objects.order_by("-created_at").first()

        report = AIReport.objects.filter(scan_result=scan).order_by("-created_at").first()
        if report:
            return report

        return AIReport.objects.create(
            scan_result=scan,
            summary="Prioritize patching high-severity findings and enforce least privilege.",
            recommendations=[
                "Patch vulnerable dependencies within 24 hours.",
                "Enable runtime anomaly detection for robotics edge nodes.",
                "Add SAST/DAST gates to CI pipeline before deployment.",
            ],
            confidence=0.91,
        )


def _validate_url(url: str) -> str:
    parsed = urlparse(url.strip())
    if parsed.scheme not in {"http", "https"} or not parsed.netloc:
        raise ValueError("Invalid URL. Use absolute http/https URL.")
    return parsed.geturl()


def _ai_artifacts_dir() -> Path:
    return Path(__file__).resolve().parent / "artifacts"


def _cache_key(url: str) -> str:
    return hashlib.sha256(url.encode("utf-8")).hexdigest()[:20]


def _build_chrome_driver(timeout_seconds: int) -> webdriver.Chrome:
    options = Options()
    options.add_argument("--headless=new")
    options.add_argument("--disable-gpu")
    options.add_argument("--window-size=1920,1080")
    options.add_argument("--no-sandbox")
    options.add_argument("--disable-dev-shm-usage")
    options.add_argument("--ignore-certificate-errors")

    driver_path = os.getenv("CHROMEDRIVER_PATH")
    if driver_path:
        service = ChromeService(executable_path=driver_path)
        driver = webdriver.Chrome(service=service, options=options)
    else:
        driver = webdriver.Chrome(options=options)

    driver.set_page_load_timeout(timeout_seconds)
    return driver


def capture_screenshot(url: str) -> str:
    normalized_url = _validate_url(url)
    timeout_seconds = int(os.getenv("SCREENSHOT_TIMEOUT_SECONDS", "20"))
    cache_ttl = int(os.getenv("SCREENSHOT_CACHE_TTL_SECONDS", "300"))
    out_dir = _ai_artifacts_dir() / "screenshots"
    out_dir.mkdir(parents=True, exist_ok=True)

    cache_id = _cache_key(normalized_url)
    screenshot_path = out_dir / f"{cache_id}.png"

    # Optional caching keeps repeated scans stable and faster.
    if screenshot_path.exists():
        age_seconds = time.time() - screenshot_path.stat().st_mtime
        if age_seconds <= cache_ttl:
            return str(screenshot_path)

    driver = None
    try:
        driver = _build_chrome_driver(timeout_seconds=timeout_seconds)
        driver.get(normalized_url)
        WebDriverWait(driver, timeout_seconds).until(
            lambda d: d.execute_script("return document.readyState") == "complete"
        )
        success = driver.save_screenshot(str(screenshot_path))
        if not success:
            raise RuntimeError("Selenium failed to save screenshot.")
        return str(screenshot_path)
    except TimeoutException as exc:
        raise RuntimeError(f"Timed out loading page: {normalized_url}") from exc
    except WebDriverException as exc:
        raise RuntimeError(f"Selenium error while capturing screenshot: {exc}") from exc
    finally:
        if driver is not None:
            driver.quit()


def run_visual_analysis(url: str) -> dict:
    image_path = capture_screenshot(url)
    cache_id = _cache_key(_validate_url(url))
    annotated_path = str(_ai_artifacts_dir() / "annotated" / f"{cache_id}_annotated.png")
    return run_vision_pipeline(image_path=image_path, annotated_output_path=annotated_path)


def _severity_rank(severity: str) -> int:
    mapping = {"critical": 4, "high": 3, "medium": 2, "low": 1}
    return mapping.get(str(severity).strip().lower(), 1)


def _normalized_severity(severity: str) -> str:
    lower = str(severity).strip().lower()
    if lower in {"critical", "high", "medium", "low"}:
        return lower.capitalize()
    if lower in {"info", "informational"}:
        return "Low"
    return "Medium"


def _default_code_fix(issue_title: str, issue_desc: str) -> dict:
    combined = f"{issue_title} {issue_desc}".lower()
    if "content-security-policy" in combined or "csp" in combined:
        return {
            "language": "http",
            "example": "Content-Security-Policy: default-src 'self'; script-src 'self'; object-src 'none'; frame-ancestors 'none'; base-uri 'self';",
        }
    if "x-frame-options" in combined or "clickjacking" in combined:
        return {"language": "http", "example": "X-Frame-Options: DENY"}
    if "strict-transport-security" in combined or "hsts" in combined:
        return {
            "language": "http",
            "example": "Strict-Transport-Security: max-age=31536000; includeSubDomains; preload",
        }
    if "cookie" in combined:
        return {
            "language": "python",
            "example": "response.set_cookie('sessionid', value, secure=True, httponly=True, samesite='Lax')",
        }
    if "input" in combined or "xss" in combined or "phishing_ui" in combined:
        return {
            "language": "js",
            "example": "const clean = DOMPurify.sanitize(userInput); element.textContent = clean;",
        }
    return {
        "language": "python",
        "example": "import requests\nresp = requests.get(url, timeout=10, allow_redirects=False)\nresp.raise_for_status()",
    }


def _extract_raw_issues(scan_data: dict, vision_data: dict) -> list[dict]:
    vulnerabilities = scan_data.get("vulnerabilities", []) or []
    zap_alerts = scan_data.get("zap_alerts", []) or []
    detections = vision_data.get("detections", []) or []

    issues: list[dict] = []
    for item in vulnerabilities:
        issues.append(
            {
                "title": str(item.get("title", "Scanner Vulnerability")),
                "description": str(item.get("description", "Vulnerability detected.")),
                "severity": _normalized_severity(item.get("severity", "Medium")),
                "exploitability": float(item.get("cvss_score", 5.0) or 5.0) / 10.0,
                "source": "scanner",
            }
        )
    for alert in zap_alerts:
        title = str(alert.get("alert", "ZAP Alert"))
        description = str(alert.get("description", "Potential weakness detected by ZAP."))
        risk = alert.get("risk") or alert.get("riskdesc") or "Medium"
        severity = _normalized_severity(str(risk).split()[0])
        cvss = alert.get("cvss", 6.0)
        try:
            exploitability = float(cvss or 6.0) / 10.0
        except (TypeError, ValueError):
            exploitability = 0.6
        issues.append(
            {
                "title": title,
                "description": description,
                "severity": severity,
                "exploitability": max(0.0, min(1.0, exploitability)),
                "source": "zap",
            }
        )
    for det in detections:
        det_type = str(det.get("type", "visual_anomaly"))
        conf = float(det.get("confidence", 0.5) or 0.5)
        severity = "High" if conf >= 0.8 else "Medium" if conf >= 0.6 else "Low"
        issues.append(
            {
                "title": f"Visual anomaly: {det_type}",
                "description": f"Computer vision flagged {det_type} with confidence {conf:.2f}.",
                "severity": severity,
                "exploitability": max(0.0, min(1.0, conf)),
                "source": "vision",
            }
        )
    return issues


def _dedupe_and_group(issues: list[dict]) -> list[dict]:
    grouped: dict[str, dict] = {}
    for issue in issues:
        key = f"{issue['title'].strip().lower()}::{issue['source']}"
        if key not in grouped:
            grouped[key] = dict(issue)
            grouped[key]["count"] = 1
            continue
        existing = grouped[key]
        existing["count"] += 1
        if _severity_rank(issue["severity"]) > _severity_rank(existing["severity"]):
            existing["severity"] = issue["severity"]
        existing["exploitability"] = max(float(existing["exploitability"]), float(issue["exploitability"]))
    return list(grouped.values())


def _prioritize(issues: list[dict]) -> list[dict]:
    for issue in issues:
        sev_score = _severity_rank(issue["severity"]) * 10.0
        exp_score = float(issue.get("exploitability", 0.5)) * 10.0
        issue["priority_score"] = round(sev_score + exp_score, 4)
    return sorted(issues, key=lambda x: x["priority_score"], reverse=True)


def _json_request(url: str, payload: dict, headers: dict) -> dict:
    data = json.dumps(payload).encode("utf-8")
    req = request.Request(url=url, data=data, headers=headers, method="POST")
    with request.urlopen(req, timeout=45) as resp:
        body = resp.read().decode("utf-8")
        return json.loads(body)


def call_llm(prompt: str) -> str:
    provider = os.getenv("AI_LLM_PROVIDER", "openai").strip().lower()
    if provider == "openai":
        api_key = os.getenv("OPENAI_API_KEY", "").strip()
        model = os.getenv("OPENAI_MODEL", "gpt-4o-mini").strip()
        if not api_key:
            raise RuntimeError("OPENAI_API_KEY is not configured")
        payload = {
            "model": model,
            "temperature": 0.1,
            "response_format": {"type": "json_object"},
            "messages": [
                {"role": "system", "content": SYSTEM_PROMPT},
                {"role": "user", "content": prompt},
            ],
        }
        response = _json_request(
            "https://api.openai.com/v1/chat/completions",
            payload,
            {"Content-Type": "application/json", "Authorization": f"Bearer {api_key}"},
        )
        return str(response["choices"][0]["message"]["content"])

    if provider == "cohere":
        api_key = os.getenv("COHERE_API_KEY", "").strip()
        model = os.getenv("COHERE_MODEL", "command-r").strip()
        if not api_key:
            raise RuntimeError("COHERE_API_KEY is not configured")
        payload = {
            "model": model,
            "temperature": 0.1,
            "message": f"{SYSTEM_PROMPT}\n\n{prompt}",
        }
        response = _json_request(
            "https://api.cohere.com/v1/chat",
            payload,
            {"Content-Type": "application/json", "Authorization": f"Bearer {api_key}"},
        )
        return str(response.get("text", ""))

    raise RuntimeError("Unsupported AI_LLM_PROVIDER. Use 'openai' or 'cohere'.")


def _fallback_report(prioritized_issues: list[dict], scan_data: dict) -> dict:
    issues = []
    for issue in prioritized_issues[:10]:
        fix_steps = [
            "Verify vulnerability details and affected endpoints.",
            "Apply remediation in staging and run regression/security tests.",
            "Deploy fix with monitoring and rollback plan.",
        ]
        issues.append(
            {
                "title": issue["title"],
                "description": issue["description"],
                "severity": issue["severity"],
                "reasoning": (
                    f"Prioritized due to severity {issue['severity']} and exploitability "
                    f"{float(issue.get('exploitability', 0.5)):.2f}."
                ),
                "fix_steps": fix_steps,
                "code_fix": _default_code_fix(issue["title"], issue["description"]),
            }
        )
    risk_score = float(scan_data.get("risk_score", 0.0) or 0.0)
    if risk_score >= 75:
        overall = "Critical"
    elif risk_score >= 50:
        overall = "High"
    elif risk_score >= 25:
        overall = "Medium"
    else:
        overall = "Low"
    return {
        "summary": f"Generated {len(issues)} prioritized security issues for remediation.",
        "overall_risk": overall,
        "issues": issues,
        "priority_order": [item["title"] for item in issues],
    }


def _validate_and_normalize_report(data: dict, fallback: dict) -> dict:
    required_top = {"summary", "overall_risk", "issues", "priority_order"}
    if not isinstance(data, dict) or set(data.keys()) != required_top:
        return fallback
    if not isinstance(data.get("issues"), list) or not isinstance(data.get("priority_order"), list):
        return fallback

    clean_issues = []
    for item in data["issues"]:
        if not isinstance(item, dict):
            continue
        expected = {"title", "description", "severity", "reasoning", "fix_steps", "code_fix"}
        if set(item.keys()) != expected:
            continue
        code_fix = item.get("code_fix", {})
        if not isinstance(code_fix, dict) or set(code_fix.keys()) != {"language", "example"}:
            continue
        fix_steps = item.get("fix_steps")
        if not isinstance(fix_steps, list):
            continue
        clean_issues.append(
            {
                "title": str(item["title"]),
                "description": str(item["description"]),
                "severity": _normalized_severity(item["severity"]),
                "reasoning": str(item["reasoning"]),
                "fix_steps": [str(step) for step in fix_steps],
                "code_fix": {
                    "language": str(code_fix["language"]).lower(),
                    "example": str(code_fix["example"]),
                },
            }
        )
    if not clean_issues:
        return fallback

    normalized = {
        "summary": str(data["summary"]),
        "overall_risk": _normalized_severity(data["overall_risk"]),
        "issues": clean_issues,
        "priority_order": [str(x) for x in data["priority_order"]],
    }
    issue_titles = {item["title"] for item in clean_issues}
    if any(title not in issue_titles for title in normalized["priority_order"]):
        normalized["priority_order"] = [item["title"] for item in clean_issues]
    return normalized


def _extract_json_from_text(text: str) -> dict:
    text = text.strip()
    start = text.find("{")
    end = text.rfind("}")
    if start < 0 or end < 0 or end <= start:
        raise ValueError("LLM response did not contain JSON object.")
    return json.loads(text[start : end + 1])


def _advice_cache_path(cache_key: str) -> Path:
    out_dir = _ai_artifacts_dir() / "advisor_cache"
    out_dir.mkdir(parents=True, exist_ok=True)
    return out_dir / f"{cache_key}.json"


def generate_security_report(scan_data: dict, vision_data: dict) -> dict:
    raw_issues = _extract_raw_issues(scan_data=scan_data, vision_data=vision_data)
    grouped = _dedupe_and_group(raw_issues)
    prioritized = _prioritize(grouped)

    normalized_inputs = {
        "risk_score": float(scan_data.get("risk_score", 0.0) or 0.0),
        "issues_for_reasoning": [
            {
                "title": item["title"],
                "description": item["description"],
                "severity": item["severity"],
                "exploitability": item["exploitability"],
                "source": item["source"],
                "priority_score": item["priority_score"],
            }
            for item in prioritized
        ],
    }

    cache_seed = json.dumps(
        {"scan": scan_data, "vision": vision_data, "normalized": normalized_inputs},
        sort_keys=True,
        ensure_ascii=True,
    )
    cache_id = hashlib.sha256(cache_seed.encode("utf-8")).hexdigest()
    cache_ttl = int(os.getenv("AI_REPORT_CACHE_TTL_SECONDS", "300"))
    cache_path = _advice_cache_path(cache_id)
    if cache_path.exists():
        age = time.time() - cache_path.stat().st_mtime
        if age <= cache_ttl:
            try:
                return json.loads(cache_path.read_text(encoding="utf-8"))
            except (OSError, json.JSONDecodeError):
                pass

    fallback = _fallback_report(prioritized, scan_data)
    prompt = build_user_prompt(scan_data=scan_data, vision_data=vision_data, normalized_inputs=normalized_inputs)

    try:
        llm_text = call_llm(prompt)
        llm_json = _extract_json_from_text(llm_text)
        final_report = _validate_and_normalize_report(llm_json, fallback)
    except (RuntimeError, ValueError, HTTPError, URLError, json.JSONDecodeError):
        final_report = fallback

    try:
        cache_path.write_text(json.dumps(final_report, ensure_ascii=True), encoding="utf-8")
    except OSError:
        pass
    return final_report
