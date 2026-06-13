"""Pure evaluation of domain observations into NeoShield findings.

Collection lives in :mod:`neoshield.worker.domain`; this module holds no network
code so the checks and their severity mapping can be tested deterministically.
"""

from __future__ import annotations

import ipaddress
import re
from dataclasses import dataclass, field
from datetime import UTC, datetime
from urllib.parse import urljoin

from neoshield.worker.normalize import Finding, clip, safe_evidence

SOURCE_DNS = "dns"
SOURCE_TLS = "tls"
SOURCE_HTTP = "http"

_SHARED_ADDRESS_SPACE = ipaddress.ip_network("100.64.0.0/10")
_DMARC_POLICY = re.compile(r"(?:^|;)\s*p\s*=\s*([a-z]+)", re.IGNORECASE)


@dataclass(slots=True)
class DnsSnapshot:
    a: list[str] = field(default_factory=list)
    aaaa: list[str] = field(default_factory=list)
    ns: list[str] = field(default_factory=list)
    mx: list[str] = field(default_factory=list)
    txt: list[str] = field(default_factory=list)
    spf: list[str] = field(default_factory=list)
    dmarc: list[str] = field(default_factory=list)
    caa: list[str] = field(default_factory=list)
    error: str | None = None

    @property
    def resolved(self) -> bool:
        return bool(self.a or self.aaaa)

    def addresses(self) -> list[str]:
        return [*self.a, *self.aaaa]


@dataclass(slots=True)
class TlsSnapshot:
    ok: bool = False
    verified: bool = False
    error: str | None = None
    issuer: str | None = None
    subject: str | None = None
    not_after: datetime | None = None
    days_remaining: int | None = None
    protocol: str | None = None
    cipher: str | None = None


@dataclass(slots=True)
class HttpSnapshot:
    https_ok: bool = False
    https_status: int | None = None
    https_error: str | None = None
    http_ok: bool = False
    http_status: int | None = None
    http_location: str | None = None
    http_error: str | None = None
    final_url: str | None = None
    redirect_chain: list[str] = field(default_factory=list)
    headers: dict[str, str] = field(default_factory=dict)


def is_public_ip(value: str) -> bool:
    """Reject addresses a hosted scanner must never connect to (SSRF guard)."""
    try:
        address = ipaddress.ip_address(value)
    except ValueError:
        return False

    if isinstance(address, ipaddress.IPv6Address) and address.ipv4_mapped:
        address = address.ipv4_mapped

    if isinstance(address, ipaddress.IPv4Address) and (
        address in _SHARED_ADDRESS_SPACE
    ):
        return False

    return not (
        address.is_private
        or address.is_loopback
        or address.is_link_local
        or address.is_multicast
        or address.is_reserved
        or address.is_unspecified
    )


def _finding(
    *,
    source_tool: str,
    key: str,
    title: str,
    description: str,
    category: str,
    severity: str,
    confidence: str,
    remediation: str | None = None,
    evidence: dict[str, object] | None = None,
) -> Finding:
    return Finding(
        source="domain",
        source_tool=source_tool,
        source_rule_id=key,
        stable_key=f"domain|{key}",
        title=clip(title, 300),
        description=clip(description),
        category=category,
        severity=severity,  # type: ignore[arg-type]
        confidence=confidence,  # type: ignore[arg-type]
        remediation=remediation,
        evidence=safe_evidence(evidence or {}),
    )


def evaluate_dns(snapshot: DnsSnapshot) -> list[Finding]:
    findings: list[Finding] = []

    if not snapshot.resolved:
        findings.append(
            _finding(
                source_tool=SOURCE_DNS,
                key="dns|unresolvable",
                title="Domain does not resolve",
                description=(
                    "No A or AAAA records were returned. A domain that does not "
                    "resolve cannot serve traffic and may indicate an expired "
                    "registration, a deleted zone or broken DNS hosting."
                ),
                category="dns",
                severity="high",
                confidence="high",
                remediation="Restore the zone and publish an A/AAAA record.",
                evidence={"ns": snapshot.ns},
            )
        )
        return findings

    if not snapshot.spf:
        findings.append(
            _finding(
                source_tool=SOURCE_DNS,
                key="dns|spf-missing",
                title="No SPF record",
                description=(
                    "No TXT record starting with v=spf1 was found. Without SPF, "
                    "receivers cannot tell whether a host is authorized to send "
                    "mail for this domain, which weakens spoofing protection."
                ),
                category="dns",
                severity="medium",
                confidence="high",
                remediation="Publish one SPF TXT record ending in -all.",
                evidence={"txtRecords": len(snapshot.txt)},
            )
        )
    elif len(snapshot.spf) > 1:
        findings.append(
            _finding(
                source_tool=SOURCE_DNS,
                key="dns|spf-multiple",
                title="Multiple SPF records",
                description=(
                    "More than one SPF record was found. Receivers treat multiple "
                    "SPF records as a permanent error, so the domain has no "
                    "effective sender policy."
                ),
                category="dns",
                severity="medium",
                confidence="high",
                remediation="Merge the SPF mechanisms into a single TXT record.",
                evidence={"spfRecords": snapshot.spf},
            )
        )

    if not snapshot.dmarc:
        findings.append(
            _finding(
                source_tool=SOURCE_DNS,
                key="dns|dmarc-missing",
                title="No DMARC record",
                description=(
                    "No TXT record was found at _dmarc.<domain>. DMARC ties SPF "
                    "and DKIM to the visible From: domain and tells receivers "
                    "what to do with failing mail."
                ),
                category="dns",
                severity="medium",
                confidence="high",
                remediation="Publish a _dmarc TXT record starting with v=DMARC1.",
            )
        )
    else:
        policy = _dmarc_policy(snapshot.dmarc[0])
        if policy == "none":
            findings.append(
                _finding(
                    source_tool=SOURCE_DNS,
                    key="dns|dmarc-none",
                    title="DMARC policy is monitoring only",
                    description=(
                        "The DMARC record uses p=none, so receivers report "
                        "failures but still deliver or quarantine as they see fit. "
                        "Spoofed mail is not actively rejected."
                    ),
                    category="dns",
                    severity="low",
                    confidence="high",
                    remediation="Move to p=quarantine or p=reject.",
                    evidence={"policy": policy},
                )
            )

    if not snapshot.caa:
        findings.append(
            _finding(
                source_tool=SOURCE_DNS,
                key="dns|caa-missing",
                title="No CAA record",
                description=(
                    "Without Certification Authority Authorization, any public "
                    "certificate authority may issue a certificate for this "
                    "domain."
                ),
                category="dns",
                severity="low",
                confidence="high",
                remediation="Publish CAA records naming the CAs you actually use.",
            )
        )

    return findings


def _dmarc_policy(record: str) -> str | None:
    match = _DMARC_POLICY.search(record)
    return match.group(1).lower() if match else None


def evaluate_tls(
    snapshot: TlsSnapshot, *, warn_days: int = 30, now: datetime | None = None
) -> list[Finding]:
    findings: list[Finding] = []
    current = now or datetime.now(UTC)

    if not snapshot.ok:
        findings.append(
            _finding(
                source_tool=SOURCE_TLS,
                key="tls|unreachable",
                title="TLS endpoint is unreachable",
                description=(
                    "A TLS connection to port 443 failed. Visitors cannot "
                    "establish a secure session, and the failure may indicate an "
                    "expired certificate, a firewall change or a stopped service."
                ),
                category="tls",
                severity="high",
                confidence="medium",
                remediation="Check the listener on port 443 and the certificate chain.",
                evidence={"error": snapshot.error},
            )
        )
        return findings

    evidence = {
        "issuer": snapshot.issuer,
        "subject": snapshot.subject,
        "protocol": snapshot.protocol,
        "cipher": snapshot.cipher,
        "notAfter": snapshot.not_after.isoformat() if snapshot.not_after else None,
    }

    if not snapshot.verified:
        findings.append(
            _finding(
                source_tool=SOURCE_TLS,
                key="tls|invalid-certificate",
                title="Certificate failed validation",
                description=(
                    "The presented certificate did not validate against the "
                    "system trust store for this hostname."
                    + (f" {snapshot.error}" if snapshot.error else "")
                ),
                category="tls",
                severity="high",
                confidence="high",
                remediation="Use a trusted certificate valid for this hostname.",
                evidence=evidence,
            )
        )

    if snapshot.not_after is not None:
        remaining = (snapshot.not_after - current).days
        if remaining < 0:
            findings.append(
                _finding(
                    source_tool=SOURCE_TLS,
                    key="tls|expired",
                    title="Certificate has expired",
                    description=(
                        f"The certificate expired {abs(remaining)} day(s) ago. "
                        "Browsers block the site with a full-page warning."
                    ),
                    category="tls",
                    severity="high",
                    confidence="high",
                    remediation="Renew and deploy the certificate.",
                    evidence=evidence,
                )
            )
        elif remaining <= warn_days:
            findings.append(
                _finding(
                    source_tool=SOURCE_TLS,
                    key="tls|expiring-soon",
                    title="Certificate expires soon",
                    description=(
                        f"The certificate expires in {remaining} day(s). Renewal "
                        "should be automated to avoid an outage."
                    ),
                    category="tls",
                    severity="medium",
                    confidence="high",
                    remediation="Renew the certificate or confirm auto-renewal.",
                    evidence=evidence,
                )
            )

    weak_protocols = {"TLSv1", "TLSv1.1", "SSLv2", "SSLv3"}
    if snapshot.protocol in weak_protocols:
        findings.append(
            _finding(
                source_tool=SOURCE_TLS,
                key="tls|weak-protocol",
                title="Obsolete TLS version negotiated",
                description=(
                    f"The server negotiated {snapshot.protocol}. TLS 1.0 and 1.1 "
                    "are deprecated and fail modern compliance baselines."
                ),
                category="tls",
                severity="high",
                confidence="high",
                remediation="Disable TLS 1.0/1.1 and require TLS 1.2 or newer.",
                evidence=evidence,
            )
        )

    return findings


def evaluate_http(snapshot: HttpSnapshot) -> list[Finding]:
    findings: list[Finding] = []

    if not snapshot.https_ok:
        findings.append(
            _finding(
                source_tool=SOURCE_HTTP,
                key="http|https-unavailable",
                title="HTTPS is not available",
                description=(
                    "An HTTPS request to the domain failed"
                    + (f": {snapshot.https_error}" if snapshot.https_error else ".")
                    + " Traffic sent to this site cannot be protected in transit."
                ),
                category="http",
                severity="high",
                confidence="medium",
                remediation="Serve the site over HTTPS with a valid certificate.",
                evidence={"error": snapshot.https_error},
            )
        )
        return findings

    if snapshot.https_status is not None and snapshot.https_status >= 500:
        findings.append(
            _finding(
                source_tool=SOURCE_HTTP,
                key="http|server-error",
                title="Site returns a server error",
                description=(
                    f"The HTTPS homepage returned HTTP {snapshot.https_status}. "
                    "Availability problems can hide or mimic security controls."
                ),
                category="http",
                severity="low",
                confidence="high",
                remediation="Check the application and upstream proxy logs.",
                evidence={"status": snapshot.https_status},
            )
        )

    final_url = (snapshot.final_url or "").strip().lower()
    if final_url.startswith("http://"):
        findings.append(
            _finding(
                source_tool=SOURCE_HTTP,
                key="http|https-redirects-to-http",
                title="HTTPS redirects back to plain HTTP",
                description=(
                    "The HTTPS endpoint redirected the request to a non-HTTPS "
                    "URL. Encryption is dropped part-way through the navigation."
                ),
                category="http",
                severity="medium",
                confidence="high",
                remediation="Redirect to the canonical https:// URL only.",
                evidence={"finalUrl": snapshot.final_url},
            )
        )

    if snapshot.http_ok:
        raw_location = (snapshot.http_location or "").strip()
        location = (
            urljoin("http://placeholder.invalid/", raw_location)
            if raw_location
            else ""
        )
        if not location.lower().startswith("https://"):
            findings.append(
                _finding(
                    source_tool=SOURCE_HTTP,
                    key="http|no-https-redirect",
                    title="Plain HTTP does not redirect to HTTPS",
                    description=(
                        "A request to http:// reached the site without being "
                        "redirected to an https:// URL. Users and credentials can "
                        "travel in clear text on the first request."
                    ),
                    category="http",
                    severity="medium",
                    confidence="high",
                    remediation="Redirect every HTTP request to HTTPS.",
                    evidence={
                        "status": snapshot.http_status,
                        "location": location or None,
                    },
                )
            )

    findings.extend(_evaluate_headers(snapshot.headers))
    return findings


def _evaluate_headers(headers: dict[str, str]) -> list[Finding]:
    findings: list[Finding] = []
    csp = headers.get("content-security-policy")
    frame_ancestors = bool(csp and "frame-ancestors" in csp.lower())

    hsts = headers.get("strict-transport-security")
    if not hsts:
        findings.append(
            _finding(
                source_tool=SOURCE_HTTP,
                key="header|hsts",
                title="Missing Strict-Transport-Security",
                description=(
                    "The response does not send HSTS. Without it a browser may "
                    "still attempt plain HTTP on a later visit, exposing the "
                    "first request to interception."
                ),
                category="headers",
                severity="medium",
                confidence="high",
                remediation="Send HSTS with a max-age of at least one year.",
            )
        )
    elif re.search(r"max-age\s*=\s*0(?:[;\s]|$)", hsts, re.IGNORECASE):
        findings.append(
            _finding(
                source_tool=SOURCE_HTTP,
                key="header|hsts-disabled",
                title="HSTS is disabled",
                description=(
                    "Strict-Transport-Security is present with max-age=0, which "
                    "tells browsers to forget the HTTPS-only policy."
                ),
                category="headers",
                severity="medium",
                confidence="high",
                remediation="Set a positive max-age (for example 31536000).",
                evidence={"header": hsts},
            )
        )

    if not csp:
        findings.append(
            _finding(
                source_tool=SOURCE_HTTP,
                key="header|csp",
                title="Missing Content-Security-Policy",
                description=(
                    "No Content-Security-Policy header was returned. CSP is the "
                    "main browser control that limits injected and third-party "
                    "script execution."
                ),
                category="headers",
                severity="medium",
                confidence="medium",
                remediation="Publish a CSP limiting script and frame sources.",
            )
        )

    xcto = headers.get("x-content-type-options")
    if not xcto or xcto.strip().lower() != "nosniff":
        findings.append(
            _finding(
                source_tool=SOURCE_HTTP,
                key="header|x-content-type-options",
                title="Missing X-Content-Type-Options: nosniff",
                description=(
                    "Browsers may sniff content types when this header is absent, "
                    "which can turn an uploaded file into executable script."
                ),
                category="headers",
                severity="low",
                confidence="high",
                remediation="Send X-Content-Type-Options: nosniff on every response.",
                evidence={"header": xcto},
            )
        )

    if not headers.get("x-frame-options") and not frame_ancestors:
        findings.append(
            _finding(
                source_tool=SOURCE_HTTP,
                key="header|x-frame-options",
                title="Clickjacking protection is missing",
                description=(
                    "Neither X-Frame-Options nor a CSP frame-ancestors directive "
                    "was found, so the site can be framed by another origin."
                ),
                category="headers",
                severity="low",
                confidence="high",
                remediation="Send X-Frame-Options or CSP frame-ancestors.",
            )
        )

    if not headers.get("referrer-policy"):
        findings.append(
            _finding(
                source_tool=SOURCE_HTTP,
                key="header|referrer-policy",
                title="Missing Referrer-Policy",
                description=(
                    "Without Referrer-Policy, full URLs (including query strings) "
                    "may leak to third-party sites through the Referer header."
                ),
                category="headers",
                severity="low",
                confidence="high",
                remediation="Send Referrer-Policy: strict-origin-when-cross-origin.",
            )
        )

    if not headers.get("permissions-policy"):
        findings.append(
            _finding(
                source_tool=SOURCE_HTTP,
                key="header|permissions-policy",
                title="Missing Permissions-Policy",
                description=(
                    "Permissions-Policy is not set, so powerful browser features "
                    "(camera, microphone, geolocation) are not explicitly denied "
                    "to embedded content."
                ),
                category="headers",
                severity="informational",
                confidence="medium",
                remediation="Send a Permissions-Policy for unused features.",
            )
        )

    server = headers.get("server")
    if server and re.search(r"\d+\.\d+", server):
        findings.append(
            _finding(
                source_tool=SOURCE_HTTP,
                key="header|server-version",
                title="Server header discloses a version",
                description=(
                    f"The Server header advertises product versions ({server}). "
                    "Attackers use this to match known vulnerabilities."
                ),
                category="headers",
                severity="informational",
                confidence="high",
                remediation="Return a generic Server header or omit it.",
                evidence={"server": server},
            )
        )

    return findings


def evaluate_domain(
    *,
    dns: DnsSnapshot,
    tls: TlsSnapshot,
    http: HttpSnapshot,
    cert_warning_days: int = 30,
    now: datetime | None = None,
) -> list[Finding]:
    findings = evaluate_dns(dns)
    if not dns.resolved:
        return findings

    findings.extend(evaluate_tls(tls, warn_days=cert_warning_days, now=now))
    findings.extend(evaluate_http(http))

    # One row per stable key even if two checks happen to produce the same key.
    unique: dict[str, Finding] = {}
    for finding in findings:
        unique.setdefault(finding.stable_key, finding)
    return list(unique.values())
