from __future__ import annotations

from datetime import UTC, datetime, timedelta

from neoshield.worker.domain_checks import (
    DnsSnapshot,
    HttpSnapshot,
    TlsSnapshot,
    evaluate_dns,
    evaluate_domain,
    evaluate_http,
    evaluate_tls,
    is_public_ip,
)

NOW = datetime(2026, 11, 13, tzinfo=UTC)

CLEAN_HEADERS = {
    "strict-transport-security": "max-age=31536000; includeSubDomains",
    "content-security-policy": "default-src 'self'; frame-ancestors 'none'",
    "x-content-type-options": "nosniff",
    "x-frame-options": "DENY",
    "referrer-policy": "strict-origin-when-cross-origin",
    "permissions-policy": "camera=(), microphone=()",
}


def keys(findings) -> set[str]:
    return {finding.stable_key for finding in findings}


def test_public_ip_guard_rejects_internal_and_reserved_ranges() -> None:
    assert is_public_ip("8.8.8.8")
    assert is_public_ip("2606:4700:4700::1111")

    for address in (
        "127.0.0.1",
        "10.1.2.3",
        "192.168.1.10",
        "172.16.0.1",
        "169.254.169.254",
        "100.64.0.1",
        "0.0.0.0",
        "::1",
        "fd00::1",
        "fe80::1",
        "not-an-ip",
    ):
        assert not is_public_ip(address), address


def test_unresolvable_domain_is_a_single_high_finding() -> None:
    findings = evaluate_domain(
        dns=DnsSnapshot(),
        tls=TlsSnapshot(error="domain did not resolve"),
        http=HttpSnapshot(https_error="domain did not resolve"),
        now=NOW,
    )

    assert keys(findings) == {"domain|dns|unresolvable"}
    assert findings[0].severity == "high"
    assert findings[0].source == "domain"


def test_missing_spf_and_dmarc_are_reported() -> None:
    findings = evaluate_dns(
        DnsSnapshot(
            a=["93.184.216.34"],
            dmarc=["v=DMARC1; p=reject; rua=mailto:dmarc@example.com"],
        )
    )

    found = keys(findings)
    assert "domain|dns|spf-missing" in found
    assert "domain|dns|dmarc-missing" not in found
    assert "domain|dns|caa-missing" in found


def test_multiple_spf_and_monitoring_dmarc() -> None:
    findings = evaluate_dns(
        DnsSnapshot(
            a=["93.184.216.34"],
            spf=["v=spf1 include:a.example -all", "v=spf1 include:b.example -all"],
            dmarc=["v=DMARC1; p=none"],
            caa=['0 issue "letsencrypt.org"'],
        )
    )

    found = keys(findings)
    assert "domain|dns|spf-multiple" in found
    assert "domain|dns|dmarc-none" in found
    assert "domain|dns|caa-missing" not in found


def test_tls_expiry_protocol_and_validation() -> None:
    expired = evaluate_tls(
        TlsSnapshot(
            ok=True,
            verified=True,
            not_after=NOW - timedelta(days=2),
            protocol="TLSv1.2",
        ),
        now=NOW,
    )
    assert "domain|tls|expired" in keys(expired)

    soon = evaluate_tls(
        TlsSnapshot(
            ok=True,
            verified=True,
            not_after=NOW + timedelta(days=10),
            protocol="TLSv1.3",
        ),
        now=NOW,
    )
    assert keys(soon) == {"domain|tls|expiring-soon"}

    weak = evaluate_tls(
        TlsSnapshot(
            ok=True,
            verified=False,
            error="certificate verify failed",
            not_after=NOW + timedelta(days=200),
            protocol="TLSv1",
        ),
        now=NOW,
    )
    found = keys(weak)
    assert "domain|tls|invalid-certificate" in found
    assert "domain|tls|weak-protocol" in found
    assert "domain|tls|expiring-soon" not in found


def test_unreachable_tls_is_reported_once() -> None:
    findings = evaluate_tls(TlsSnapshot(error="connection refused"), now=NOW)

    assert keys(findings) == {"domain|tls|unreachable"}
    assert findings[0].severity == "high"


def test_missing_security_headers() -> None:
    findings = evaluate_http(
        HttpSnapshot(
            https_ok=True,
            https_status=200,
            http_ok=True,
            http_status=301,
            http_location="https://example.com/",
            final_url="https://example.com/",
            headers={},
        )
    )

    found = keys(findings)
    assert {
        "domain|header|hsts",
        "domain|header|csp",
        "domain|header|x-content-type-options",
        "domain|header|x-frame-options",
        "domain|header|referrer-policy",
        "domain|header|permissions-policy",
    } <= found


def test_present_headers_produce_no_header_findings() -> None:
    findings = evaluate_http(
        HttpSnapshot(
            https_ok=True,
            https_status=200,
            http_ok=True,
            http_status=308,
            http_location="https://example.com/",
            final_url="https://example.com/",
            headers=dict(CLEAN_HEADERS),
        )
    )

    assert findings == []


def test_csp_frame_ancestors_replaces_x_frame_options() -> None:
    headers = dict(CLEAN_HEADERS)
    headers.pop("x-frame-options")

    findings = evaluate_http(
        HttpSnapshot(
            https_ok=True,
            https_status=200,
            http_ok=False,
            final_url="https://example.com/",
            headers=headers,
        )
    )

    assert "domain|header|x-frame-options" not in keys(findings)


def test_http_without_https_redirect_and_https_unavailable() -> None:
    downgrade = evaluate_http(
        HttpSnapshot(
            https_ok=True,
            https_status=200,
            http_ok=True,
            http_status=200,
            http_location=None,
            final_url="https://example.com/",
            headers=dict(CLEAN_HEADERS),
        )
    )
    assert keys(downgrade) == {"domain|http|no-https-redirect"}

    unavailable = evaluate_http(
        HttpSnapshot(https_ok=False, https_error="connection refused")
    )
    assert keys(unavailable) == {"domain|http|https-unavailable"}


def test_https_redirecting_to_http_is_reported() -> None:
    findings = evaluate_http(
        HttpSnapshot(
            https_ok=True,
            https_status=200,
            http_ok=False,
            final_url="http://example.com/",
            headers=dict(CLEAN_HEADERS),
        )
    )

    assert "domain|http|https-redirects-to-http" in keys(findings)


def test_server_version_disclosure_is_informational() -> None:
    headers = dict(CLEAN_HEADERS)
    headers["server"] = "nginx/1.24.0"

    findings = evaluate_http(
        HttpSnapshot(
            https_ok=True,
            https_status=200,
            http_ok=False,
            final_url="https://example.com/",
            headers=headers,
        )
    )

    assert keys(findings) == {"domain|header|server-version"}
    assert findings[0].severity == "informational"


def test_clean_domain_produces_no_findings() -> None:
    findings = evaluate_domain(
        dns=DnsSnapshot(
            a=["93.184.216.34"],
            spf=["v=spf1 -all"],
            dmarc=["v=DMARC1; p=reject"],
            caa=['0 issue "letsencrypt.org"'],
        ),
        tls=TlsSnapshot(
            ok=True,
            verified=True,
            not_after=NOW + timedelta(days=200),
            protocol="TLSv1.3",
        ),
        http=HttpSnapshot(
            https_ok=True,
            https_status=200,
            http_ok=True,
            http_status=308,
            http_location="https://example.com/",
            final_url="https://example.com/",
            headers=dict(CLEAN_HEADERS),
        ),
        now=NOW,
    )

    assert findings == []
