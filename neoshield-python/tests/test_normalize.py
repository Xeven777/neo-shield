from __future__ import annotations

import dataclasses

from neoshield.worker.normalize import (
    normalize_severity,
    parse_gitleaks,
    parse_osv,
    parse_trivy,
)

GITLEAKS_PAYLOAD = [
    {
        "RuleID": "github-pat",
        "Description": "GitHub Personal Access Token",
        "File": "src/config.py",
        "StartLine": 12,
        "EndLine": 12,
        "StartColumn": 5,
        "EndColumn": 60,
        "Secret": "ghp_supersecretvaluethatmustneverbepersisted",
        "Match": "token = 'ghp_supersecretvaluethatmustneverbepersisted'",
        "Entropy": 5.2,
        "Commit": "1234567890abcdef1234567890abcdef12345678",
        "Author": "dev",
        "Fingerprint": "1234567890abcdef:src/config.py:github-pat:12",
    }
]


OSV_PAYLOAD = {
    "results": [
        {
            "source": {"path": "requirements.txt", "type": "lockfile"},
            "packages": [
                {
                    "package": {
                        "name": "requests",
                        "version": "2.19.0",
                        "ecosystem": "PyPI",
                    },
                    "vulnerabilities": [
                        {
                            "id": "GHSA-xxxx-yyyy-zzzz",
                            "summary": "Requests vulnerable to credential leak",
                            "details": "Long details about the issue.",
                            "aliases": ["CVE-2018-18074"],
                            "severity": [
                                {"type": "CVSS_V3", "score": "7.5"}
                            ],
                            "affected": [
                                {
                                    "ranges": [
                                        {
                                            "events": [
                                                {"introduced": "0"},
                                                {"fixed": "2.20.0"},
                                            ]
                                        }
                                    ]
                                }
                            ],
                            "references": [
                                {"type": "ADVISORY", "url": "https://osv.dev/GHSA-xxxx-yyyy-zzzz"}
                            ],
                        }
                    ],
                }
            ],
        }
    ]
}


TRIVY_PAYLOAD = {
    "Results": [
        {
            "Target": "package-lock.json",
            "Class": "lang-pkgs",
            "Type": "npm",
            "Vulnerabilities": [
                {
                    "VulnerabilityID": "CVE-2024-0001",
                    "PkgName": "lodash",
                    "InstalledVersion": "4.17.15",
                    "FixedVersion": "4.17.21",
                    "Severity": "CRITICAL",
                    "Title": "Prototype pollution in lodash",
                    "Description": "Lodash allows prototype pollution.",
                    "PrimaryURL": "https://avd.aquasec.com/nvd/cve-2024-0001",
                    "References": ["https://example.com/advisory"],
                    "CVSS": {"nvd": {"V3Score": 9.8}},
                }
            ],
            "Misconfigurations": [
                {
                    "ID": "DS002",
                    "Title": "Image user should not be root",
                    "Description": "Running as root is discouraged.",
                    "Severity": "HIGH",
                    "Resolution": "Add a USER instruction.",
                    "References": ["https://avd.aquasec.com/misconfig/ds002"],
                    "CauseMetadata": {"StartLine": 3},
                }
            ],
        }
    ]
}


def test_gitleaks_normalization_never_stores_the_secret() -> None:
    findings = parse_gitleaks(GITLEAKS_PAYLOAD)

    assert len(findings) == 1
    finding = findings[0]
    assert finding.source_tool == "gitleaks"
    assert finding.source_rule_id == "github-pat"
    assert finding.file_path == "src/config.py"
    assert finding.severity == "high"
    assert finding.stable_key == "gitleaks|github-pat|src/config.py|12"

    serialized = repr(dataclasses.asdict(finding))
    assert "ghp_supersecretvaluethatmustneverbepersisted" not in serialized
    assert "token =" not in serialized


def test_osv_normalization_extracts_fixed_version_and_cve() -> None:
    findings = parse_osv(OSV_PAYLOAD)

    assert len(findings) == 1
    finding = findings[0]
    assert finding.source_tool == "osv-scanner"
    assert finding.package_name == "requests"
    assert finding.package_version == "2.19.0"
    assert finding.fixed_version == "2.20.0"
    assert finding.cve_id == "CVE-2018-18074"
    assert finding.cvss_score == 7.5
    assert finding.severity == "medium"
    assert finding.stable_key == "osv|requests|2.19.0|GHSA-xxxx-yyyy-zzzz"


def test_trivy_normalization_handles_vulnerabilities_and_misconfigurations() -> None:
    findings = parse_trivy(TRIVY_PAYLOAD)

    assert len(findings) == 2

    vulnerability = next(item for item in findings if item.category == "dependency")
    assert vulnerability.cve_id == "CVE-2024-0001"
    assert vulnerability.fixed_version == "4.17.21"
    assert vulnerability.severity == "critical"
    assert vulnerability.cvss_score == 9.8

    misconfiguration = next(
        item for item in findings if item.category == "misconfiguration"
    )
    assert misconfiguration.severity == "high"
    assert misconfiguration.remediation == "Add a USER instruction."
    assert misconfiguration.file_path == "package-lock.json"


def test_severity_mapping_is_conservative() -> None:
    assert normalize_severity("MODERATE") == "medium"
    assert normalize_severity("UNKNOWN") == "informational"
    assert normalize_severity(None, "low") == "low"
