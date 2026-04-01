from __future__ import annotations

import argparse
import json
import re
from hashlib import sha256
from pathlib import Path

from agent import Finding, dedupe_findings, final_summary, review_file
from parser import split_diff


SEVERITY_RANK = {"low": 1, "medium": 2, "high": 3, "critical": 4}


def main() -> None:
    parser = argparse.ArgumentParser(description="AI PR reviewer")
    parser.add_argument("--diff-file", default="diff.txt")
    parser.add_argument("--pep8-file", default="pep8.txt")
    parser.add_argument("--rules-file", default="reviewer/rules.txt")
    parser.add_argument("--out-json", default="review.json")
    parser.add_argument("--out-md", default="review.md")
    parser.add_argument("--skip-ai", action="store_true")
    parser.add_argument("--min-confidence", type=float, default=0.65)
    parser.add_argument(
        "--min-severity",
        choices=["low", "medium", "high", "critical"],
        default="medium",
    )
    args = parser.parse_args()

    diff_text = Path(args.diff_file).read_text(encoding="utf-8") if Path(args.diff_file).exists() else ""
    rules_text = Path(args.rules_file).read_text(encoding="utf-8")
    diff_files = split_diff(diff_text)

    all_findings = []
    all_findings.extend(load_pep8_findings(args.pep8_file))
    if not args.skip_ai:
        for diff_file in diff_files:
            findings = review_file(diff_file.path, diff_file.patch, rules_text)
            all_findings.extend(findings)

    unique_findings = dedupe_findings(all_findings)
    filtered = [
        f
        for f in unique_findings
        if f.confidence >= args.min_confidence
        and SEVERITY_RANK.get(f.severity, 0) >= SEVERITY_RANK[args.min_severity]
    ]
    filtered.sort(
        key=lambda f: (
            SEVERITY_RANK.get(f.severity, 0),
            f.confidence,
        ),
        reverse=True,
    )
    reviewed_files = sorted({df.path for df in diff_files})
    file_statuses = build_file_statuses(reviewed_files, filtered)
    overall_status = derive_overall_status(file_statuses)

    result = {
        "summary": final_summary(filtered),
        "overall_status": overall_status,
        "total_findings": len(filtered),
        "file_statuses": file_statuses,
        "findings": [
            {
                "type": f.finding_type,
                "severity": f.severity,
                "confidence": f.confidence,
                "file": f.file,
                "line": f.line,
                "hunk": f.hunk,
                "message": f.message,
                "suggestion": f.suggestion,
                "fingerprint": f.fingerprint,
            }
            for f in filtered
        ],
    }

    Path(args.out_json).write_text(json.dumps(result, indent=2), encoding="utf-8")
    Path(args.out_md).write_text(render_markdown(result), encoding="utf-8")


def render_markdown(result: dict) -> str:
    overall_status = result.get("overall_status", "unknown")
    file_statuses = result.get("file_statuses", [])
    lines = [
        "<!-- ai-pr-reviewer -->",
        "## AI PR Review",
        "",
        f"- Overall status: **{overall_status}**",
        f"- {result.get('summary', '')}",
        f"- Total findings: {result.get('total_findings', 0)}",
        "",
    ]

    if file_statuses:
        lines.extend(
            [
                "### File Status",
                "",
                "| File | Status | Findings | Highest Severity |",
                "| --- | --- | ---: | --- |",
            ]
        )
        for item in file_statuses:
            lines.append(
                f"| `{item['file']}` | {item['status']} | {item['findings_count']} | {item['highest_severity']} |"
            )
        lines.append("")

    findings = result.get("findings", [])
    if not findings:
        lines.append("No actionable findings above current thresholds.")
        return "\n".join(lines).strip() + "\n"

    lines.extend(
        [
            "### Findings Table",
            "",
            "| File | Type | Severity | Confidence | Line | Issue |",
            "| --- | --- | --- | ---: | ---: | --- |",
        ]
    )
    for finding in findings:
        issue = (finding["message"] or "").replace("\n", " ").replace("|", "\\|")
        lines.append(
            f"| `{finding['file']}` | {finding['type']} | {finding['severity']} | "
            f"{finding['confidence']} | {finding.get('line') or ''} | {issue} |"
        )
    lines.append("")

    lines.append("### Detailed Findings")
    lines.append("")
    for finding in findings:
        lines.extend(
            [
                f"### `{finding['file']}`",
                f"- Type: {finding['type']}",
                f"- Severity: {finding['severity']}",
                f"- Confidence: {finding['confidence']}",
                f"- Line: {finding.get('line') or 'n/a'}",
                f"- Hunk: {finding['hunk'] or 'n/a'}",
                f"- Issue: {finding['message']}",
                f"- Suggestion: {finding['suggestion'] or 'n/a'}",
                "",
            ]
        )
    return "\n".join(lines).strip() + "\n"


def build_file_statuses(reviewed_files: list[str], findings: list[Finding]) -> list[dict]:
    by_file: dict[str, list[Finding]] = {path: [] for path in reviewed_files}
    for finding in findings:
        by_file.setdefault(finding.file, []).append(finding)

    statuses = []
    for path in sorted(by_file.keys()):
        file_findings = by_file[path]
        if not file_findings:
            statuses.append(
                {
                    "file": path,
                    "status": "good",
                    "findings_count": 0,
                    "highest_severity": "none",
                }
            )
            continue

        highest = max(file_findings, key=lambda item: SEVERITY_RANK.get(item.severity, 0)).severity
        status = severity_to_status(highest)
        statuses.append(
            {
                "file": path,
                "status": status,
                "findings_count": len(file_findings),
                "highest_severity": highest,
            }
        )
    return statuses


def severity_to_status(severity: str) -> str:
    rank = SEVERITY_RANK.get(severity, 0)
    if rank >= SEVERITY_RANK["high"]:
        return "blocking"
    if rank >= SEVERITY_RANK["medium"]:
        return "needs_attention"
    return "minor"


def derive_overall_status(file_statuses: list[dict]) -> str:
    if any(item.get("status") == "blocking" for item in file_statuses):
        return "blocking"
    if any(item.get("status") == "needs_attention" for item in file_statuses):
        return "needs_attention"
    if any(item.get("status") == "minor" for item in file_statuses):
        return "minor"
    return "good"


def load_pep8_findings(path: str) -> list[Finding]:
    pep8_path = Path(path)
    if not pep8_path.exists():
        return []

    findings: list[Finding] = []
    pattern = re.compile(r"^(.*?):(\d+):(\d+):\s*([A-Z]\d+)\s+(.*)$")
    for raw_line in pep8_path.read_text(encoding="utf-8").splitlines():
        line = raw_line.strip()
        if not line:
            continue
        match = pattern.match(line)
        if not match:
            continue
        file_name, line_no, col_no, code, message = match.groups()
        hunk = f"line {line_no}:{col_no} ({code})"
        suggestion = "Update this line to satisfy the reported pycodestyle rule."
        findings.append(
            Finding(
                finding_type="pep8",
                severity="medium",
                confidence=1.0,
                file=file_name,
                line=int(line_no),
                hunk=hunk,
                message=f"PEP-8 {code}: {message}",
                suggestion=suggestion,
                fingerprint=_pep8_fingerprint(file_name, line_no, col_no, code, message),
            )
        )
    return findings


def _pep8_fingerprint(file_name: str, line_no: str, col_no: str, code: str, message: str) -> str:
    payload = f"{file_name}|{line_no}|{col_no}|{code}|{message}"
    return sha256(payload.encode("utf-8")).hexdigest()


if __name__ == "__main__":
    main()
