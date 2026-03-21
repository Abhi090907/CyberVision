from __future__ import annotations

import json


SYSTEM_PROMPT = """You are CyberVision X AI Security Advisor.
Return ONLY valid JSON with the exact schema requested.
Do not add markdown, prose, code fences, or extra keys.
Use deterministic, concise, and security-focused language.
Every issue must include actionable fix_steps and realistic code_fix examples."""


OUTPUT_FORMAT_INSTRUCTIONS = """Return JSON with exactly these top-level keys:
{
  "summary": "string",
  "overall_risk": "Critical | High | Medium | Low",
  "issues": [
    {
      "title": "string",
      "description": "string",
      "severity": "Critical | High | Medium | Low",
      "reasoning": "string",
      "fix_steps": ["string", "..."],
      "code_fix": {
        "language": "python/js/http",
        "example": "string"
      }
    }
  ],
  "priority_order": ["issue title 1", "issue title 2"]
}
Constraints:
- No missing keys.
- No extra keys.
- priority_order must list issue titles in descending priority.
- code_fix.example must be practical and directly usable."""


def build_user_prompt(scan_data: dict, vision_data: dict, normalized_inputs: dict) -> str:
    payload = {
        "scan_data": scan_data,
        "vision_data": vision_data,
        "normalized_inputs": normalized_inputs,
    }
    compact = json.dumps(payload, separators=(",", ":"), ensure_ascii=True)
    return (
        "Analyze the provided cybersecurity scan and computer-vision evidence.\n"
        "Generate a production-grade security advisor report with prioritized remediation "
        "and code-level fixes.\n\n"
        f"{OUTPUT_FORMAT_INSTRUCTIONS}\n\n"
        f"INPUT_JSON:{compact}"
    )
