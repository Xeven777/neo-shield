from __future__ import annotations

from datetime import UTC, datetime

from neoshield.worker.wazuh_normalize import (
    agent_disconnected_finding,
    classify_alert,
    normalize_agent,
    normalize_alert,
    severity_from_level,
)


def alert(**overrides):
    source = {
        "timestamp": "2026-11-13T10:02:03.456+0000",
        "rule": {
            "id": "5710",
            "level": 10,
            "description": "sshd: Attempt to login using a non-existent user",
            "groups": ["syslog", "sshd", "authentication_failed"],
        },
        "agent": {"id": "001", "name": "lab-linux", "ip": "10.0.0.21"},
        "manager": {"name": "wazuh-manager"},
        "decoder": {"name": "sshd"},
        "location": "/var/log/auth.log",
        "data": {
            "srcip": "203.0.113.50",
            "srcport": "54321",
            "dstuser": "root",
        },
        "full_log": (
            "Nov 13 10:02:03 lab sshd[1]: Failed password for invalid user root"
        ),
    }
    source.update(overrides)
    return {
        "_id": "alert-1",
        "_index": "wazuh-alerts-4.x-2026.11.13",
        "_source": source,
    }


def test_severity_mapping() -> None:
    assert severity_from_level(15) == "critical"
    assert severity_from_level(12) == "critical"
    assert severity_from_level(10) == "high"
    assert severity_from_level(7) == "medium"
    assert severity_from_level(4) == "low"
    assert severity_from_level(1) == "informational"


def test_failed_authentication_becomes_finding() -> None:
    normalized = normalize_alert(alert(), min_level=5)

    assert normalized is not None
    assert normalized.category == "authentication"
    assert normalized.severity == "high"
    assert normalized.source_ip == "203.0.113.50"
    assert normalized.finding is not None
    assert normalized.finding.source == "wazuh"
    assert "203.0.113.50" in normalized.finding.stable_key
    assert "root" in normalized.finding.stable_key
    assert normalized.finding.remediation
    assert "Failed password" not in str(normalized.finding.evidence)
    assert "full_log" not in normalized.finding.evidence


def test_file_integrity_finding_uses_path() -> None:
    payload = alert(
        rule={
            "id": "550",
            "level": 7,
            "description": "Integrity checksum changed.",
            "groups": ["ossec", "syscheck"],
        },
        syscheck={
            "path": "/etc/ssh/sshd_config",
            "event": "modified",
            "mode": "real-time",
        },
    )
    normalized = normalize_alert(payload, min_level=5)

    assert normalized is not None
    assert normalized.category == "file_integrity"
    assert normalized.finding is not None
    assert normalized.finding.file_path == "/etc/ssh/sshd_config"
    assert "modified" in normalized.finding.stable_key


def test_malware_is_critical() -> None:
    payload = alert(
        rule={
            "id": "87105",
            "level": 15,
            "description": "Malware detected by VirusTotal",
            "groups": ["virustotal", "malware"],
        },
        data={"virustotal": {"malware": "Eicar-Test-Signature"}},
    )
    normalized = normalize_alert(payload, min_level=5)

    assert normalized is not None
    assert normalized.finding is not None
    assert normalized.finding.severity == "critical"
    assert normalized.finding.category == "malware"


def test_low_level_and_manager_alerts_are_skipped() -> None:
    assert (
        normalize_alert(alert(rule={"id": "1", "level": 3}), min_level=5) is None
    )
    assert (
        normalize_alert(
            alert(agent={"id": "000", "name": "manager"}), min_level=5
        )
        is None
    )


def test_system_alert_is_event_only() -> None:
    normalized = normalize_alert(
        alert(
            rule={
                "id": "1002",
                "level": 5,
                "description": "Unknown problem somewhere in the system",
                "groups": ["syslog"],
            }
        ),
        min_level=5,
    )

    assert normalized is not None
    assert normalized.category == "system"
    assert normalized.finding is None


def test_classification_order() -> None:
    assert classify_alert(
        groups=["syscheck"], rule_id="550", description="changed"
    ) == "file_integrity"
    assert classify_alert(
        groups=["authentication_failed"], rule_id="5710", description="failed"
    ) == "authentication"
    assert classify_alert(
        groups=["wazuh"], rule_id="503", description="Agent disconnected"
    ) == "agent_health"


def test_agent_inventory_and_disconnect_finding() -> None:
    agent = normalize_agent(
        {
            "id": "002",
            "name": "win-lab",
            "ip": "10.0.0.22",
            "status": "disconnected",
            "version": "Wazuh v4.9.2",
            "lastKeepAlive": "2026-11-13T10:00:00Z",
            "os": {
                "name": "Microsoft Windows 11",
                "version": "10.0",
                "platform": "windows",
            },
        }
    )

    assert agent is not None
    assert agent.agent_id == "002"
    assert agent.status == "disconnected"
    assert agent.os_name == "Microsoft Windows 11"
    assert agent.last_seen == datetime(2026, 11, 13, 10, 0, tzinfo=UTC)

    finding = agent_disconnected_finding(agent)
    assert finding is not None
    assert finding.stable_key == "wazuh|agent|disconnected"
    assert finding.severity == "medium"


def test_active_agent_has_no_disconnect_finding() -> None:
    agent = normalize_agent({"id": "001", "name": "lab-linux", "status": "active"})
    assert agent is not None
    assert agent_disconnected_finding(agent) is None


def test_manager_agent_is_ignored_by_inventory() -> None:
    assert normalize_agent({"id": "000", "name": "manager"}) is None
