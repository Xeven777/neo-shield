"""Normalization of scanner output into NeoShield findings.

Everything here is pure: it takes parsed JSON and returns findings. Scanner
output is untrusted, so text is clipped and secret material is never copied.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Literal

Severity = Literal["critical", "high", "medium", "low", "informational"]
Confidence = Literal["low", "medium", "high"]

SEVERITY_RANK: dict[str, int] = {
    "critical": 5,
    "high": 4,
    "medium": 3,
    "low": 2,
    "informational": 1,
}

MAX_TITLE = 300
MAX_TEXT = 4000
MAX_EVIDENCE_STRING = 500
MAX_REFERENCES = 10


@dataclass(slots=True)
class Finding:
    source_tool: str
    source_rule_id: str | None
    stable_key: str
    title: str
    description: str
    category: str
    severity: Severity
    source: Literal["github", "domain", "wazuh", "network", "aws"] = "github"
    confidence: Confidence | None = None
    cve_id: str | None = None
    cvss_score: float | None = None
    remediation: str | None = None
    references: list[str] = field(default_factory=list)
    file_path: str | None = None
    package_name: str | None = None
    package_version: str | None = None
    fixed_version: str | None = None
    evidence: dict[str, Any] = field(default_factory=dict)


def clip(value: object, limit: int = MAX_TEXT) -> str:
    text = str(value or "").replace("\x00", "").strip()
    return text[:limit]


def normalize_severity(value: object, default: Severity = "medium") -> Severity:
    candidate = str(value or "").strip().lower()
    if candidate in SEVERITY_RANK:
        return candidate  # type: ignore[return-value]
    if candidate in {"moderate"}:
        return "medium"
    if candidate in {"info", "unknown", "none"}:
        return "informational"
    return default


def _as_float(value: object) -> float | None:
    try:
        number = float(value)  # type: ignore[arg-type]
    except (TypeError, ValueError):
        return None
    if number < 0 or number > 10:
        return None
    return round(number, 1)


def _dedupe(values: list[str]) -> list[str]:
    seen: set[str] = set()
    result: list[str] = []
    for value in values:
        if value and value not in seen:
            seen.add(value)
            result.append(value)
    return result[:MAX_REFERENCES]


def _safe_value(item: Any, depth: int) -> object:
    if isinstance(item, str):
        return clip(item, MAX_EVIDENCE_STRING)
    if isinstance(item, (int, float, bool)) or item is None:
        return item
    if isinstance(item, dict) and depth > 0:
        return safe_evidence(item, depth=depth - 1)
    if isinstance(item, list):
        result: list[object] = []
        for entry in item[:10]:
            if isinstance(entry, str):
                result.append(clip(entry, MAX_EVIDENCE_STRING))
            elif isinstance(entry, (int, float, bool)) or entry is None:
                result.append(entry)
            elif isinstance(entry, dict) and depth > 0:
                result.append(safe_evidence(entry, depth=depth - 1))
        return result
    return None


def safe_evidence(value: dict[str, Any], *, depth: int = 2) -> dict[str, Any]:
    """Bound and clip evidence objects so a report cannot bloat the database."""
    result: dict[str, Any] = {}
    for key, item in list(value.items())[:20]:
        if key.lower() in {
            "secret",
            "match",
            "raw",
            "token",
            "password",
            "full_log",
            "fullLog",
        }:
            continue
        cleaned = _safe_value(item, depth)
        if cleaned is not None:
            result[key] = cleaned
    return result


def parse_gitleaks(payload: object) -> list[Finding]:
    """Parse `gitleaks detect --report-format json` output.

    `Secret` and `Match` are deliberately never read: only the rule, location
    and fingerprint are persisted.
    """
    if isinstance(payload, dict):
        entries = payload.get("findings") or payload.get("Findings") or []
    elif isinstance(payload, list):
        entries = payload
    else:
        entries = []

    findings: list[Finding] = []
    for entry in entries:
        if not isinstance(entry, dict):
            continue

        rule_id = clip(
            entry.get("RuleID") or entry.get("RuleId") or "unknown-rule", 120
        )
        file_path = clip(entry.get("File") or entry.get("file") or "unknown", 400)
        start_line = entry.get("StartLine") or entry.get("startLine") or 0
        description = clip(
            entry.get("Description") or f"Potential secret matched rule {rule_id}",
            MAX_TEXT,
        )

        findings.append(
            Finding(
                source_tool="gitleaks",
                source_rule_id=rule_id,
                stable_key=f"gitleaks|{rule_id}|{file_path}|{start_line}",
                title=clip(description, MAX_TITLE),
                description=(
                    f"{description}. Detected in {file_path}"
                    + (f" at line {start_line}" if start_line else "")
                    + ". The secret value was redacted and is not stored."
                ),
                category="secret",
                severity="high",
                confidence="high",
                file_path=file_path,
                evidence=safe_evidence(
                    {
                        "rule": rule_id,
                        "line": start_line,
                        "fingerprint": entry.get("Fingerprint"),
                        "entropy": entry.get("Entropy"),
                        "commit": clip(entry.get("Commit"), 40) or None,
                        "author": clip(entry.get("Author"), 120) or None,
                    }
                ),
            )
        )

    return findings


def _osv_cvss(vulnerability: dict[str, Any]) -> float | None:
    severities = vulnerability.get("severity") or []
    if isinstance(severities, list):
        for entry in severities:
            if isinstance(entry, dict):
                score = _as_float(entry.get("score"))
                if score is not None:
                    return score
    return None


def _osv_database_severity(vulnerability: dict[str, Any]) -> object:
    database_specific = vulnerability.get("database_specific")
    if isinstance(database_specific, dict):
        if database_specific.get("severity"):
            return database_specific["severity"]

    affected = vulnerability.get("affected") or []
    if isinstance(affected, list):
        for entry in affected:
            if isinstance(entry, dict) and isinstance(
                entry.get("database_specific"), dict
            ):
                severity = entry["database_specific"].get("severity")
                if severity:
                    return severity
    return None


def _osv_fixed_version(vulnerability: dict[str, Any]) -> str | None:
    affected = vulnerability.get("affected") or []
    if not isinstance(affected, list):
        return None
    for entry in affected:
        if not isinstance(entry, dict):
            continue
        ranges = entry.get("ranges") or []
        if not isinstance(ranges, list):
            continue
        for version_range in ranges:
            if not isinstance(version_range, dict):
                continue
            for event in version_range.get("events") or []:
                if isinstance(event, dict) and event.get("fixed"):
                    return clip(event["fixed"], 120)
    return None


def parse_osv(payload: object) -> list[Finding]:
    """Parse OSV-Scanner JSON for lockfile/package findings."""
    if not isinstance(payload, dict):
        return []

    findings: list[Finding] = []
    results = payload.get("results") or []
    if not isinstance(results, list):
        return []

    for result in results:
        if not isinstance(result, dict):
            continue
        source = result.get("source") or {}
        source_path = (
            clip(source.get("path"), 400) if isinstance(source, dict) else ""
        )
        packages = result.get("packages") or []
        if not isinstance(packages, list):
            continue

        for package_entry in packages:
            if not isinstance(package_entry, dict):
                continue
            package = package_entry.get("package") or {}
            if not isinstance(package, dict):
                package = {}
            name = clip(package.get("name") or "unknown-package", 200)
            version = clip(package.get("version") or "", 120) or None
            ecosystem = clip(package.get("ecosystem") or "", 80) or None

            vulnerabilities = package_entry.get("vulnerabilities") or []
            if not isinstance(vulnerabilities, list):
                continue

            for vulnerability in vulnerabilities:
                if not isinstance(vulnerability, dict):
                    continue

                vuln_id = clip(vulnerability.get("id") or "OSV-UNKNOWN", 120)
                aliases = [
                    clip(alias, 120)
                    for alias in (vulnerability.get("aliases") or [])
                    if isinstance(alias, str)
                ]
                cve_id = next(
                    (alias for alias in aliases if alias.startswith("CVE-")), None
                )
                fixed = _osv_fixed_version(vulnerability)
                summary = clip(
                    vulnerability.get("summary") or vuln_id, MAX_TITLE
                )
                details = clip(vulnerability.get("details") or summary)

                references = [
                    clip(reference.get("url"), 500)
                    for reference in (vulnerability.get("references") or [])
                    if isinstance(reference, dict)
                    and isinstance(reference.get("url"), str)
                ]

                findings.append(
                    Finding(
                        source_tool="osv-scanner",
                        source_rule_id=vuln_id,
                        stable_key=f"osv|{name}|{version or 'unknown'}|{vuln_id}",
                        title=summary,
                        description=(
                            f"{details}\n\nPackage: {name}"
                            + (f"@{version}" if version else "")
                            + (f" ({ecosystem})" if ecosystem else "")
                            + (f"\nManifest: {source_path}" if source_path else "")
                        ),
                        category="dependency",
                        severity=normalize_severity(
                            _osv_database_severity(vulnerability), "medium"
                        ),
                        confidence="high",
                        cve_id=cve_id,
                        cvss_score=_osv_cvss(vulnerability),
                        remediation=(
                            f"Upgrade {name} to {fixed} or later." if fixed else None
                        ),
                        references=_dedupe(references),
                        file_path=source_path or None,
                        package_name=name,
                        package_version=version,
                        fixed_version=fixed,
                        evidence=safe_evidence(
                            {
                                "ecosystem": ecosystem,
                                "manifest": source_path or None,
                                "aliases": aliases,
                            }
                        ),
                    )
                )

    return findings


def _trivy_cvss(vulnerability: dict[str, Any]) -> float | None:
    cvss = vulnerability.get("CVSS")
    if not isinstance(cvss, dict):
        return None

    scores: list[float] = []
    for value in cvss.values():
        if isinstance(value, dict):
            score = _as_float(value.get("V3Score") or value.get("Score"))
            if score is not None:
                scores.append(score)
    return max(scores) if scores else None


def parse_trivy(payload: object) -> list[Finding]:
    """Parse `trivy fs --format json` vulnerabilities and misconfigurations."""
    if not isinstance(payload, dict):
        return []

    findings: list[Finding] = []
    results = payload.get("Results") or []
    if not isinstance(results, list):
        return []

    for result in results:
        if not isinstance(result, dict):
            continue
        target = clip(result.get("Target") or "repository", 400)

        for vulnerability in result.get("Vulnerabilities") or []:
            if not isinstance(vulnerability, dict):
                continue
            vuln_id = clip(
                vulnerability.get("VulnerabilityID") or "TRIVY-UNKNOWN", 120
            )
            package_name = clip(
                vulnerability.get("PkgName") or "unknown-package", 200
            )
            installed = clip(vulnerability.get("InstalledVersion") or "", 120)
            fixed = clip(vulnerability.get("FixedVersion") or "", 120) or None
            title = clip(
                vulnerability.get("Title") or vuln_id, MAX_TITLE
            )
            description = clip(vulnerability.get("Description") or title)
            primary_url = clip(vulnerability.get("PrimaryURL") or "", 500)
            references = [
                clip(reference, 500)
                for reference in (vulnerability.get("References") or [])
                if isinstance(reference, str)
            ]

            findings.append(
                Finding(
                    source_tool="trivy",
                    source_rule_id=vuln_id,
                    stable_key=f"trivy:vuln|{target}|{vuln_id}|{package_name}",
                    title=title,
                    description=(
                        f"{description}\n\nPackage: {package_name}"
                        + (f"@{installed}" if installed else "")
                        + f"\nTarget: {target}"
                    ),
                    category="dependency",
                    severity=normalize_severity(
                        vulnerability.get("Severity"), "medium"
                    ),
                    confidence="high",
                    cve_id=vuln_id if vuln_id.startswith("CVE-") else None,
                    cvss_score=_trivy_cvss(vulnerability),
                    remediation=(
                        f"Upgrade {package_name} to {fixed} or later."
                        if fixed
                        else None
                    ),
                    references=_dedupe(
                        ([primary_url] if primary_url else []) + references
                    ),
                    file_path=target,
                    package_name=package_name,
                    package_version=installed or None,
                    fixed_version=fixed,
                    evidence=safe_evidence(
                        {
                            "target": target,
                            "class": result.get("Class"),
                            "type": result.get("Type"),
                        }
                    ),
                )
            )

        for misconfiguration in result.get("Misconfigurations") or []:
            if not isinstance(misconfiguration, dict):
                continue
            rule_id = clip(
                misconfiguration.get("ID")
                or misconfiguration.get("AVDID")
                or "MISCONFIG",
                120,
            )
            title = clip(misconfiguration.get("Title") or rule_id, MAX_TITLE)
            description = clip(
                misconfiguration.get("Description") or title
            )
            message = clip(misconfiguration.get("Message") or "", 1000)
            resolution = clip(misconfiguration.get("Resolution") or "", 1000)
            cause = misconfiguration.get("CauseMetadata") or {}
            start_line = cause.get("StartLine") if isinstance(cause, dict) else None

            findings.append(
                Finding(
                    source_tool="trivy",
                    source_rule_id=rule_id,
                    stable_key=f"trivy:misconfig|{target}|{rule_id}",
                    title=title,
                    description=(
                        f"{description}\n\nTarget: {target}"
                        + (f"\n{message}" if message else "")
                    ),
                    category="misconfiguration",
                    severity=normalize_severity(
                        misconfiguration.get("Severity"), "medium"
                    ),
                    confidence="medium",
                    remediation=resolution or None,
                    references=_dedupe(
                        [
                            clip(reference, 500)
                            for reference in (
                                misconfiguration.get("References") or []
                            )
                            if isinstance(reference, str)
                        ]
                    ),
                    file_path=target,
                    evidence=safe_evidence(
                        {
                            "target": target,
                            "line": start_line,
                            "message": message or None,
                        }
                    ),
                )
            )

        for secret in result.get("Secrets") or []:
            if not isinstance(secret, dict):
                continue
            rule_id = clip(secret.get("RuleID") or "trivy-secret", 120)
            title = clip(secret.get("Title") or rule_id, MAX_TITLE)
            start_line = secret.get("StartLine") or 0

            findings.append(
                Finding(
                    source_tool="trivy",
                    source_rule_id=rule_id,
                    stable_key=f"trivy:secret|{target}|{rule_id}|{start_line}",
                    title=title,
                    description=(
                        f"{title}. Detected in {target}"
                        + (f" at line {start_line}" if start_line else "")
                        + ". The secret value was redacted and is not stored."
                    ),
                    category="secret",
                    severity=normalize_severity(
                        secret.get("Severity"), "high"
                    ),
                    confidence="high",
                    file_path=target,
                    evidence=safe_evidence(
                        {"target": target, "line": start_line, "rule": rule_id}
                    ),
                )
            )

    return findings
