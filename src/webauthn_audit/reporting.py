from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from . import __version__
from .models import AuditResult, Finding, Policy, Severity


def finding_dict(finding: Finding) -> dict[str, Any]:
    return {
        "ruleId": finding.rule.id,
        "title": finding.rule.title,
        "severity": finding.rule.severity.name.lower(),
        "message": finding.message,
        "location": {"artifact": finding.location.artifact, "pointer": finding.location.pointer},
        "evidence": finding.evidence,
        "remediation": finding.rule.remediation,
        "references": [{"title": ref.title, "url": ref.url} for ref in finding.rule.references],
        "fingerprint": finding.fingerprint(),
    }


def report_dict(result: AuditResult, policy: Policy) -> dict[str, Any]:
    findings = result.active(policy)
    counts = {severity.name.lower(): 0 for severity in Severity}
    for finding in findings:
        counts[finding.rule.severity.name.lower()] += 1
    return {
        "schemaVersion": "1.0",
        "tool": {"name": "webauthn-audit", "version": __version__},
        "profile": policy.profile,
        "artifacts": result.artifacts,
        "summary": {"total": len(findings), "bySeverity": counts},
        "observations": result.observations,
        "findings": [finding_dict(finding) for finding in findings],
    }


def render_text(result: AuditResult, policy: Policy, *, color: bool = False) -> str:
    findings = result.active(policy)
    colors = {
        Severity.CRITICAL: "\033[1;31m",
        Severity.HIGH: "\033[31m",
        Severity.MEDIUM: "\033[33m",
        Severity.LOW: "\033[36m",
        Severity.INFO: "\033[2m",
    }
    reset = "\033[0m"
    lines = [
        f"webauthn-audit {__version__} · profile {policy.profile} · "
        f"{len(result.artifacts)} artifact(s)"
    ]
    for finding in findings:
        label = finding.rule.severity.name
        if color:
            label = f"{colors[finding.rule.severity]}{label}{reset}"
        lines.extend(
            (
                "",
                f"{label:>8}  {finding.rule.id}  {finding.rule.title}",
                f"          {finding.location.artifact}{finding.location.pointer}",
                f"          {finding.message}",
                f"          fix: {finding.rule.remediation}",
            )
        )
    if not findings:
        lines.append("\nNo findings.")
    counts = {severity: sum(f.rule.severity == severity for f in findings) for severity in Severity}
    lines.append(
        "\nSummary: "
        + ", ".join(
            f"{counts[item]} {item.name.lower()}"
            for item in reversed(list(Severity))
            if counts[item]
        )
        if findings
        else "Summary: clean"
    )
    return "\n".join(lines) + "\n"


def render_json(result: AuditResult, policy: Policy) -> str:
    return json.dumps(report_dict(result, policy), indent=2, sort_keys=True) + "\n"


def render_sarif(result: AuditResult, policy: Policy) -> str:
    findings = result.active(policy)
    rules = {finding.rule.id: finding.rule for finding in findings}
    payload = {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "webauthn-audit",
                        "version": __version__,
                        "informationUri": "https://github.com/Liam-G/webauthn-audit",
                        "rules": [
                            {
                                "id": rule.id,
                                "name": rule.title.replace(" ", ""),
                                "shortDescription": {"text": rule.title},
                                "fullDescription": {"text": rule.description},
                                "help": {"text": rule.remediation, "markdown": rule.remediation},
                                "helpUri": rule.references[0].url,
                                "properties": {
                                    "tags": list(rule.tags),
                                    "security-severity": str(_score(rule.severity)),
                                },
                            }
                            for rule in rules.values()
                        ],
                    }
                },
                "results": [
                    {
                        "ruleId": finding.rule.id,
                        "level": _sarif_level(finding.rule.severity),
                        "message": {"text": finding.message},
                        "locations": [
                            {
                                "physicalLocation": {
                                    "artifactLocation": {"uri": finding.location.artifact},
                                    "region": {"startLine": 1},
                                },
                                "logicalLocations": [
                                    {"fullyQualifiedName": finding.location.pointer or "/"}
                                ],
                            }
                        ],
                        "partialFingerprints": {"primaryLocationLineHash": finding.fingerprint()},
                        "properties": {
                            "jsonPointer": finding.location.pointer,
                            "severity": finding.rule.severity.name.lower(),
                            "evidence": finding.evidence,
                        },
                    }
                    for finding in findings
                ],
            }
        ],
    }
    return json.dumps(payload, indent=2, sort_keys=True) + "\n"


def _sarif_level(severity: Severity) -> str:
    if severity >= Severity.HIGH:
        return "error"
    if severity >= Severity.MEDIUM:
        return "warning"
    return "note"


def _score(severity: Severity) -> float:
    return {
        Severity.CRITICAL: 9.5,
        Severity.HIGH: 8.0,
        Severity.MEDIUM: 5.5,
        Severity.LOW: 3.0,
        Severity.INFO: 0.0,
    }[severity]


def baseline_fingerprints(path: Path) -> set[str]:
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
        findings = data["findings"]
        if not isinstance(findings, list):
            raise TypeError
        return {
            item["fingerprint"]
            for item in findings
            if isinstance(item, dict) and isinstance(item.get("fingerprint"), str)
        }
    except (OSError, UnicodeDecodeError, json.JSONDecodeError, KeyError, TypeError) as exc:
        raise ValueError(
            f"cannot load baseline {path}: invalid webauthn-audit JSON report"
        ) from exc


def apply_baseline(result: AuditResult, fingerprints: set[str]) -> AuditResult:
    return AuditResult(
        artifacts=result.artifacts,
        findings=[
            finding for finding in result.findings if finding.fingerprint() not in fingerprints
        ],
        observations=result.observations,
    )
