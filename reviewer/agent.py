from __future__ import annotations

import json
from dataclasses import dataclass
from hashlib import sha256
from typing import Any

from llm import ask_llm


@dataclass
class Finding:
    finding_type: str
    severity: str
    confidence: float
    file: str
    hunk: str
    message: str
    suggestion: str
    fingerprint: str


def review_file(file_name: str, diff: str, rules: str) -> list[Finding]:
    prompt = f"""
You are reviewing a pull request diff for one file.

Rules:
{rules}

File:
{file_name}

Diff:
{diff}

Return JSON only using this exact schema:
{{
  "findings": [
    {{
      "type": "bug|security|performance|maintainability|testing",
      "severity": "low|medium|high|critical",
      "confidence": 0.0,
      "hunk": "short location context",
      "message": "what is wrong and why it matters",
      "suggestion": "specific fix recommendation"
    }}
  ]
}}

Constraints:
- Focus on concrete issues from this diff only.
- Avoid style-only comments.
- Keep findings concise.
- If no actionable issue, return: {{"findings":[]}}
"""
    raw = ask_llm(prompt)
    parsed = _safe_parse_json(raw)
    results: list[Finding] = []
    for item in parsed.get("findings", []):
        finding_type = str(item.get("type", "maintainability")).strip().lower()
        severity = str(item.get("severity", "low")).strip().lower()
        confidence = _clamp_confidence(item.get("confidence", 0))
        hunk = str(item.get("hunk", "")).strip()
        message = str(item.get("message", "")).strip()
        suggestion = str(item.get("suggestion", "")).strip()
        fingerprint = _fingerprint(file_name, hunk, message, suggestion)

        if not message:
            continue

        results.append(
            Finding(
                finding_type=finding_type,
                severity=severity,
                confidence=confidence,
                file=file_name,
                hunk=hunk,
                message=message,
                suggestion=suggestion,
                fingerprint=fingerprint,
            )
        )
    return results


def final_summary(findings: list[Finding]) -> str:
    if not findings:
        return "No high-confidence issues found. Human review is still recommended."
    counts: dict[str, int] = {}
    for finding in findings:
        counts[finding.severity] = counts.get(finding.severity, 0) + 1
    ordered = ["critical", "high", "medium", "low"]
    parts = [f"{level}: {counts[level]}" for level in ordered if level in counts]
    return "Findings by severity -> " + ", ".join(parts)


def dedupe_findings(findings: list[Finding]) -> list[Finding]:
    seen: set[str] = set()
    output: list[Finding] = []
    for finding in findings:
        if finding.fingerprint in seen:
            continue
        seen.add(finding.fingerprint)
        output.append(finding)
    return output


def _safe_parse_json(text: str) -> dict[str, Any]:
    try:
        return json.loads(text)
    except json.JSONDecodeError:
        pass

    stripped = text.strip()
    if "```" in stripped:
        chunks = stripped.split("```")
        for chunk in chunks:
            candidate = chunk.strip()
            if candidate.startswith("json"):
                candidate = candidate[4:].strip()
            try:
                return json.loads(candidate)
            except json.JSONDecodeError:
                continue
    return {"findings": []}


def _clamp_confidence(value: Any) -> float:
    try:
        num = float(value)
    except (ValueError, TypeError):
        return 0.0
    return max(0.0, min(1.0, num))


def _fingerprint(file_name: str, hunk: str, message: str, suggestion: str) -> str:
    data = f"{file_name}|{hunk}|{message}|{suggestion}"
    return sha256(data.encode("utf-8")).hexdigest()
