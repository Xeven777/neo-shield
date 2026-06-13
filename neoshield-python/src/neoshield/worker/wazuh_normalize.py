"""Normalize Wazuh alerts and agent inventory into NeoShield findings/events.

Wazuh rule levels are 0-15. We map them to NeoShield severities and only turn
the selected use cases into findings; every alert above the ingestion threshold
is still stored as a security event so the timeline is complete.

Nothing from `full_log` or other raw fields is persisted. Evidence is an
allowlist of bounded values (agent, rule, decoder, location, network tuple, FIM
path, vulnerability, SCA and audit context).
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Any

from neoshield.worker.normalize import (
    Finding,
    Severity,
    clip,
    safe_evidence,
)
from neoshield.worker.wazuh_client import parse_wazuh_timestamp

# Categories that become findings. `system` alerts are event-only to keep the
# finding feed focused on the selected Phase 2 use cases.
FINDING_CATEGORIES = {
    "authentication",
    "file_integrity",
    "malware",
    "vulnerability",
    "agent_health",
    "configuration",
    "audit",
}


@dataclass(slots=True)
class AgentInfo:
    agent_id: str
    name: str
    ip_address: str | None = None
    os_name: str | None = None
    os_version: str | None = None
    os_platform: str | None = None
    architecture: str | None = None
    version: str | None = None
    status: str = "unknown"
    last_seen: datetime | None = None


@dataclass(slots=True)
class WazuhAlert:
    external_id: str
    event_time: datetime
    rule_id: str | None
    rule_level: int
    severity: Severity
    category: str
    title: str
    description: str
    agent_id: str
    agent_name: str
    agent_ip: str | None
    source_ip: str | None
    evidence: dict[str, Any] = field(default_factory=dict)
    finding: Finding | None = None
    agent_status: str | None = None


def severity_from_level(level: int) -> Severity:
    if level >= 12:
        return "critical"
    if level >= 10:
        return "high"
    if level >= 7:
        return "medium"
    if level >= 4:
        return "low"
    return "informational"


def _dict(value: object) -> dict[str, Any]:
    return value if isinstance(value, dict) else {}


def _text(value: object, limit: int = 300) -> str:
    if value is None:
        return ""
    return clip(value, limit)


def _int(value: object) -> int | None:
    try:
        return int(value)  # type: ignore[arg-type]
    except (TypeError, ValueError):
        return None


def _groups(rule: dict[str, Any]) -> list[str]:
    groups = rule.get("groups")
    if not isinstance(groups, list):
        return []
    return [str(group)[:80] for group in groups if isinstance(group, str)]


def classify_alert(
    *, groups: list[str], rule_id: str | None, description: str
) -> str:
    group_set = {group.lower() for group in groups}
    lowered = description.lower()

    if "syscheck" in group_set or "fim" in group_set:
        return "file_integrity"
    if group_set & {"virustotal", "malware", "rootcheck", "virus"}:
        return "malware"
    if group_set & {"vulnerability-detector", "vulnerability", "vuln"}:
        return "vulnerability"
    if "sca" in group_set:
        return "configuration"
    if group_set & {"audit", "auditd"}:
        return "audit"
    if "wazuh" in group_set:
        numeric = _int(rule_id)
        if numeric is not None and 500 <= numeric <= 514:
            return "agent_health"
    if group_set & {"authentication_failed", "authentication_failures"}:
        return "authentication"
    if "authentication" in group_set and (
        "fail" in lowered or "invalid" in lowered or "denied" in lowered
    ):
        return "authentication"
    if any(
        phrase in lowered
        for phrase in (
            "failed password",
            "failed login",
            "authentication failure",
            "invalid user",
            "brute force",
        )
    ):
        return "authentication"
    return "system"


def agent_status_from_alert(
    *, rule_id: str | None, description: str
) -> str | None:
    numeric = _int(rule_id)
    if numeric is None or not 500 <= numeric <= 514:
        return None

    lowered = description.lower()
    if "disconnected" in lowered or "stopped" in lowered:
        return "disconnected"
    if "pending" in lowered:
        return "pending"
    if "never" in lowered and "connected" in lowered:
        return "never_connected"
    if "started" in lowered or "connected" in lowered or "active" in lowered:
        return "active"
    return None


def _vulnerability_context(source: dict[str, Any]) -> dict[str, Any]:
    candidates = [
        _dict(source.get("vulnerability")),
        _dict(_dict(source.get("data")).get("vulnerability")),
    ]
    for candidate in candidates:
        if candidate:
            return candidate
    return {}


def _syscheck_context(source: dict[str, Any]) -> dict[str, Any]:
    return _dict(source.get("syscheck"))


def _sca_context(source: dict[str, Any]) -> dict[str, Any]:
    sca = _dict(_dict(source.get("data")).get("sca"))
    return _dict(sca.get("check")) if isinstance(sca.get("check"), dict) else sca


def _audit_context(source: dict[str, Any]) -> dict[str, Any]:
    return _dict(_dict(source.get("data")).get("audit"))


def _malware_context(source: dict[str, Any]) -> dict[str, Any]:
    data = _dict(source.get("data"))
    virustotal = _dict(data.get("virustotal"))
    return {
        "file": _text(data.get("file") or source.get("file"), 400),
        "malware": _text(virustotal.get("malware"), 200),
        "permalink": _text(virustotal.get("permalink"), 500),
        "md5": _text(data.get("md5"), 64),
        "sha1": _text(data.get("sha1"), 64),
    }


def _stable_key(alert: WazuhAlert, source: dict[str, Any]) -> str:
    data = _dict(source.get("data"))
    agent = alert.agent_id or "unknown"
    rule = alert.rule_id or "unknown"

    if alert.category == "authentication":
        source_ip = _text(data.get("srcip"), 100) or "unknown-source"
        user = _text(data.get("dstuser") or data.get("srcuser"), 100) or "unknown-user"
        return f"wazuh|auth|{agent}|{rule}|{source_ip}|{user}"

    if alert.category == "file_integrity":
        syscheck = _syscheck_context(source)
        path = _text(syscheck.get("path"), 400) or "unknown-path"
        event = _text(syscheck.get("event"), 40) or "change"
        return f"wazuh|fim|{agent}|{event}|{path}"

    if alert.category == "malware":
        context = _malware_context(source)
        fingerprint = (
            context.get("sha1")
            or context.get("md5")
            or context.get("file")
            or rule
        )
        return f"wazuh|malware|{agent}|{rule}|{fingerprint}"

    if alert.category == "vulnerability":
        vulnerability = _vulnerability_context(source)
        cve = _text(vulnerability.get("cve"), 40) or rule
        package = _text(vulnerability.get("package"), 200) or "unknown-package"
        version = _text(vulnerability.get("version"), 100) or "unknown-version"
        return f"wazuh|vuln|{agent}|{cve}|{package}|{version}"

    if alert.category == "configuration":
        check = _sca_context(source)
        check_id = _text(check.get("id"), 120) or rule
        return f"wazuh|sca|{agent}|{check_id}"

    if alert.category == "audit":
        audit = _audit_context(source)
        command = (
            _text(audit.get("command"), 300)
            or _text(audit.get("exe"), 300)
            or rule
        )
        return f"wazuh|audit|{agent}|{rule}|{command}"

    if alert.category == "agent_health":
        status = alert.agent_status or "state"
        return f"wazuh|agent|{agent}|{status}"

    return f"wazuh|{alert.category}|{agent}|{rule}"


def _remediation(category: str) -> str:
    return {
        "authentication": (
            "Review the source address and the affected account. Check SSH/PAM "
            "logs, lock or block the source if it is unexpected, and confirm "
            "whether the activity was authorized."
        ),
        "file_integrity": (
            "Confirm the file change with the system owner. If it was not "
            "planned, compare it with version control or a known-good backup "
            "and investigate the account that made the change."
        ),
        "malware": (
            "Isolate the endpoint from the network, collect the file for "
            "analysis, and follow your malware response runbook. Do not execute "
            "the file on another host."
        ),
        "vulnerability": (
            "Patch or upgrade the affected package, then re-run the endpoint "
            "vulnerability check to confirm the fix."
        ),
        "agent_health": (
            "Check that the Wazuh agent service is running, that the manager is "
            "reachable on the private network, and that the agent key is valid."
        ),
        "configuration": (
            "Review the failing configuration check with the system owner and "
            "apply the recommended hardening step."
        ),
        "audit": (
            "Review the audited command and the account that ran it. Confirm it "
            "was expected and document the change."
        ),
    }.get(
        category,
        "Review the Wazuh alert and confirm whether the activity was authorized.",
    )


def _title_and_description(
    alert: WazuhAlert,
    *,
    rule_description: str,
    source: dict[str, Any],
) -> tuple[str, str]:
    data = _dict(source.get("data"))
    title = clip(rule_description or "Wazuh alert", 300)
    parts = [
        f"{rule_description or title}.",
        f"Agent {alert.agent_name} ({alert.agent_id}) reported rule "
        f"{alert.rule_id or 'unknown'} at level {alert.rule_level}.",
    ]

    if alert.category == "authentication":
        user = _text(data.get("dstuser") or data.get("srcuser"), 100)
        if user:
            parts.append(f"Account: {user}.")
    if alert.source_ip:
        parts.append(f"Source address: {alert.source_ip}.")
    if alert.category == "file_integrity":
        syscheck = _syscheck_context(source)
        path = _text(syscheck.get("path"), 400)
        event = _text(syscheck.get("event"), 40)
        if path:
            parts.append(f"Path: {path}" + (f" ({event})." if event else "."))
    if alert.category == "vulnerability":
        vulnerability = _vulnerability_context(source)
        cve = _text(vulnerability.get("cve"), 40)
        package = _text(vulnerability.get("package"), 200)
        version = _text(vulnerability.get("version"), 100)
        if cve:
            parts.append(f"Advisory: {cve}.")
        if package:
            parts.append(
                f"Package: {package}" + (f" {version}." if version else ".")
            )
    if alert.category == "configuration":
        check = _sca_context(source)
        check_title = _text(check.get("title"), 200)
        if check_title:
            parts.append(f"Check: {check_title}.")
    if alert.category == "audit":
        audit = _audit_context(source)
        command = _text(audit.get("command") or audit.get("exe"), 300)
        if command:
            parts.append(f"Command: {command}.")

    location = _text(source.get("location"), 300)
    if location:
        parts.append(f"Log location: {location}.")

    return title, clip(" ".join(parts), 4000)


def normalize_alert(
    hit: dict[str, Any],
    *,
    min_level: int = 5,
) -> WazuhAlert | None:
    source = _dict(hit.get("_source")) or hit
    rule = _dict(source.get("rule"))
    agent = _dict(source.get("agent"))
    data = _dict(source.get("data"))

    level = _int(rule.get("level")) or 0
    if level < max(0, min_level):
        return None

    agent_id = _text(agent.get("id"), 40)
    agent_name = _text(agent.get("name"), 200) or "unknown-agent"
    # Agent 000 is the manager itself. It is not an enrolled endpoint.
    if not agent_id or agent_id == "000":
        return None

    event_time = (
        parse_wazuh_timestamp(source.get("timestamp"))
        or parse_wazuh_timestamp(source.get("@timestamp"))
        or datetime.now(UTC)
    )
    rule_id = _text(rule.get("id"), 40) or None
    rule_description = _text(rule.get("description"), 300)
    groups = _groups(rule)
    category = classify_alert(
        groups=groups,
        rule_id=rule_id,
        description=rule_description,
    )
    severity = severity_from_level(level)
    agent_status = (
        agent_status_from_alert(rule_id=rule_id, description=rule_description)
        if category == "agent_health"
        else None
    )

    external_id = _text(hit.get("_id"), 200)
    if not external_id:
        seed = "|".join(
            [
                _text(hit.get("_index"), 100),
                event_time.isoformat(),
                agent_id,
                rule_id or "",
                _text(data.get("srcip"), 100),
                rule_description,
            ]
        )
        external_id = hashlib.sha256(seed.encode("utf-8")).hexdigest()[:40]

    evidence: dict[str, Any] = {
        "agent": {
            "id": agent_id,
            "name": agent_name,
            "ip": _text(agent.get("ip"), 100) or None,
        },
        "rule": {
            "id": rule_id,
            "level": level,
            "groups": groups[:10],
            "description": rule_description,
        },
        "decoder": _text(_dict(source.get("decoder")).get("name"), 120) or None,
        "location": _text(source.get("location"), 300) or None,
        "source": {
            "ip": _text(data.get("srcip"), 100) or None,
            "port": _text(data.get("srcport"), 20) or None,
            "user": _text(data.get("dstuser") or data.get("srcuser"), 100)
            or None,
        },
        "destination": {
            "ip": _text(data.get("dstip"), 100) or None,
            "port": _text(data.get("dstport"), 20) or None,
            "user": _text(data.get("dstuser"), 100) or None,
        },
    }

    if category == "file_integrity":
        syscheck = _syscheck_context(source)
        evidence["file"] = {
            "path": _text(syscheck.get("path"), 400) or None,
            "event": _text(syscheck.get("event"), 40) or None,
            "mode": _text(syscheck.get("mode"), 40) or None,
        }
    elif category == "vulnerability":
        vulnerability = _vulnerability_context(source)
        evidence["vulnerability"] = {
            "cve": _text(vulnerability.get("cve"), 40) or None,
            "package": _text(vulnerability.get("package"), 200) or None,
            "version": _text(vulnerability.get("version"), 100) or None,
            "severity": _text(vulnerability.get("severity"), 40) or None,
            "status": _text(vulnerability.get("status"), 40) or None,
            "reference": _text(vulnerability.get("reference"), 500) or None,
        }
    elif category == "configuration":
        check = _sca_context(source)
        evidence["sca"] = {
            "id": _text(check.get("id"), 120) or None,
            "title": _text(check.get("title"), 200) or None,
            "result": _text(check.get("result"), 80) or None,
            "policy": _text(check.get("policy"), 200) or None,
        }
    elif category == "audit":
        audit = _audit_context(source)
        evidence["audit"] = {
            "command": _text(audit.get("command"), 300) or None,
            "exe": _text(audit.get("exe"), 300) or None,
            "type": _text(audit.get("type"), 40) or None,
            "key": _text(audit.get("key"), 120) or None,
        }
    elif category == "malware":
        evidence["malware"] = _malware_context(source)

    alert = WazuhAlert(
        external_id=external_id,
        event_time=event_time,
        rule_id=rule_id,
        rule_level=level,
        severity=severity,
        category=category,
        title="",
        description="",
        agent_id=agent_id,
        agent_name=agent_name,
        agent_ip=_text(agent.get("ip"), 100) or None,
        source_ip=_text(data.get("srcip"), 100) or None,
        evidence=safe_evidence(evidence),
        agent_status=agent_status,
    )
    title, description = _title_and_description(
        alert, rule_description=rule_description, source=source
    )
    alert.title = title
    alert.description = description

    if category not in FINDING_CATEGORIES:
        return alert

    vulnerability = _vulnerability_context(source)
    cve = _text(vulnerability.get("cve"), 40) or None
    syscheck_path = _text(_syscheck_context(source).get("path"), 400) or None
    package_name = _text(vulnerability.get("package"), 200) or None
    package_version = _text(vulnerability.get("version"), 100) or None

    alert.finding = Finding(
        source="wazuh",
        source_tool="wazuh",
        source_rule_id=rule_id,
        stable_key=_stable_key(alert, source),
        title=title,
        description=description,
        category=category,
        severity=severity,
        confidence="high"
        if category in {"malware", "vulnerability"}
        else "medium",
        cve_id=cve if cve and cve.startswith("CVE-") else None,
        remediation=_remediation(category),
        references=(
            [_text(vulnerability.get("reference"), 500)]
            if _text(vulnerability.get("reference"), 500)
            else []
        ),
        file_path=syscheck_path if category == "file_integrity" else None,
        package_name=package_name if category == "vulnerability" else None,
        package_version=(
            package_version if category == "vulnerability" else None
        ),
        evidence=alert.evidence,
    )
    return alert


def normalize_agent(entry: dict[str, Any]) -> AgentInfo | None:
    agent_id = _text(entry.get("id"), 40)
    if not agent_id or agent_id == "000":
        return None

    os_data = _dict(entry.get("os"))
    status = _text(entry.get("status"), 40).lower() or "unknown"

    return AgentInfo(
        agent_id=agent_id,
        name=_text(entry.get("name"), 200) or f"wazuh-agent-{agent_id}",
        ip_address=_text(entry.get("ip"), 100) or None,
        os_name=_text(os_data.get("name"), 120) or None,
        os_version=_text(os_data.get("version"), 120) or None,
        os_platform=_text(os_data.get("platform"), 120) or None,
        architecture=_text(os_data.get("arch"), 80) or None,
        version=_text(entry.get("version"), 80) or None,
        status=status,
        last_seen=parse_wazuh_timestamp(entry.get("lastKeepAlive")),
    )


def agent_disconnected_finding(agent: AgentInfo) -> Finding | None:
    if agent.status in {"active", "unknown", ""}:
        return None

    severity: Severity = "medium" if agent.status == "disconnected" else "low"
    return Finding(
        source="wazuh",
        source_tool="wazuh",
        source_rule_id="agent-health",
        stable_key="wazuh|agent|disconnected",
        title=f"Wazuh agent {agent.name} is {agent.status.replace('_', ' ')}",
        description=(
            f"Agent {agent.name} ({agent.agent_id}) is reported as "
            f"{agent.status}. Events from this endpoint may be missing until "
            "the agent reconnects."
        ),
        category="agent_health",
        severity=severity,
        confidence="high",
        remediation=_remediation("agent_health"),
        evidence=safe_evidence(
            {
                "agentId": agent.agent_id,
                "agentName": agent.name,
                "status": agent.status,
                "lastSeen": (
                    agent.last_seen.isoformat() if agent.last_seen else None
                ),
                "agentVersion": agent.version,
            }
        ),
    )
