"""Network collection for domain checks.

Only public addresses are contacted. Every hostname (the target and each
redirect hop) is resolved first and rejected if any answer is private, loopback,
link-local, reserved or shared address space. TLS is pinned to the validated
address with SNI, so a second DNS answer cannot move the connection.
"""

from __future__ import annotations

import asyncio
import logging
import socket
import ssl
from dataclasses import asdict
from datetime import UTC, datetime
from typing import Any
from urllib.parse import urljoin, urlparse

import dns.asyncresolver
import dns.exception
import dns.resolver
import httpx

from neoshield.config import Settings
from neoshield.worker.domain_checks import (
    DnsSnapshot,
    HttpSnapshot,
    TlsSnapshot,
    evaluate_domain,
    is_public_ip,
)
from neoshield.worker.normalize import Finding, clip, safe_evidence

logger = logging.getLogger(__name__)

USER_AGENT = "NeoShield-DomainCheck/0.1 (+https://github.com/neoshield)"


class DomainCheckError(RuntimeError):
    """A transient collection error. The job may be retried."""


class DomainBlockedError(RuntimeError):
    """The target resolves to an address a hosted scanner must not contact."""


def _resolver(timeout: float) -> dns.asyncresolver.Resolver:
    resolver = dns.asyncresolver.Resolver()
    resolver.timeout = timeout
    resolver.lifetime = timeout
    return resolver


async def _lookup(
    resolver: dns.asyncresolver.Resolver, name: str, rdtype: str
) -> tuple[list[Any], str | None]:
    try:
        answer = await resolver.resolve(name, rdtype, raise_on_no_answer=False)
    except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer):
        return [], None
    except dns.exception.DNSException as error:
        return [], clip(error, 200)

    if answer.rrset is None:
        return [], None
    return list(answer.rrset), None


def _txt_value(record: Any) -> str:
    strings = getattr(record, "strings", [])
    return clip(b"".join(strings).decode("utf-8", "replace"), 400)


def _mx_value(record: Any) -> str:
    exchange = getattr(record, "exchange", "")
    preference = getattr(record, "preference", 0)
    return f"{preference} {str(exchange).rstrip('.')}"


def _caa_value(record: Any) -> str:
    tag = getattr(record, "tag", b"")
    value = getattr(record, "value", b"")
    flags = getattr(record, "flags", 0)
    if isinstance(tag, bytes):
        tag = tag.decode("utf-8", "replace")
    if isinstance(value, bytes):
        value = value.decode("utf-8", "replace")
    return clip(f'{flags} {tag} "{value}"', 300)


async def collect_dns(domain: str, timeout: float) -> DnsSnapshot:
    resolver = _resolver(timeout)

    a, aaaa, ns, mx, txt, caa = await asyncio.gather(
        _lookup(resolver, domain, "A"),
        _lookup(resolver, domain, "AAAA"),
        _lookup(resolver, domain, "NS"),
        _lookup(resolver, domain, "MX"),
        _lookup(resolver, domain, "TXT"),
        _lookup(resolver, domain, "CAA"),
    )

    a_records, a_error = a
    aaaa_records, aaaa_error = aaaa
    ns_records, ns_error = ns
    mx_records, mx_error = mx
    txt_records, txt_error = txt
    caa_records, caa_error = caa

    # NXDOMAIN/NoAnswer are meaningful observations; a resolver timeout or
    # SERVFAIL is transient and must not be reported as a missing record.
    transient = next(
        (
            error
            for error in (a_error, aaaa_error, ns_error, mx_error, txt_error, caa_error)
            if error
        ),
        None,
    )

    txt_values = [_txt_value(record) for record in txt_records]
    spf = [value for value in txt_values if value.lower().startswith("v=spf1")]

    dmarc_records, dmarc_error = await _lookup(resolver, f"_dmarc.{domain}", "TXT")
    dmarc = [
        value
        for value in (_txt_value(record) for record in dmarc_records)
        if value.lower().startswith("v=dmarc1")
    ]
    if dmarc_error and not transient:
        transient = dmarc_error

    return DnsSnapshot(
        a=[str(record) for record in a_records],
        aaaa=[str(record) for record in aaaa_records],
        ns=[str(record).rstrip(".") for record in ns_records],
        mx=[_mx_value(record) for record in mx_records],
        txt=txt_values[:20],
        spf=spf[:5],
        dmarc=dmarc[:5],
        caa=[_caa_value(record) for record in caa_records],
        error=transient,
    )


def _cert_name(parts: object) -> str | None:
    if not isinstance(parts, (tuple, list)):
        return None
    values: list[str] = []
    for group in parts:
        if not isinstance(group, (tuple, list)):
            continue
        for pair in group:
            if isinstance(pair, (tuple, list)) and len(pair) == 2:
                values.append(f"{pair[0]}={pair[1]}")
    return clip(", ".join(values), 300) or None


async def _handshake(
    host: str,
    address: str,
    timeout: float,
    context: ssl.SSLContext,
    *,
    verified: bool,
) -> TlsSnapshot:
    reader, writer = await asyncio.wait_for(
        asyncio.open_connection(
            address,
            443,
            ssl=context,
            server_hostname=host,
            ssl_handshake_timeout=timeout,
        ),
        timeout=timeout,
    )
    del reader

    try:
        ssl_object = writer.get_extra_info("ssl_object")
        if ssl_object is None:
            return TlsSnapshot(error="TLS handshake completed without a socket")

        certificate = ssl_object.getpeercert() or {}
        not_after: datetime | None = None
        raw_expiry = certificate.get("notAfter")
        if isinstance(raw_expiry, str):
            try:
                not_after = datetime.fromtimestamp(
                    ssl.cert_time_to_seconds(raw_expiry), UTC
                )
            except ValueError:
                not_after = None

        days_remaining = (
            (not_after - datetime.now(UTC)).days if not_after is not None else None
        )
        cipher = ssl_object.cipher()

        return TlsSnapshot(
            ok=True,
            verified=verified,
            issuer=_cert_name(certificate.get("issuer")),
            subject=_cert_name(certificate.get("subject")),
            not_after=not_after,
            days_remaining=days_remaining,
            protocol=ssl_object.version(),
            cipher=cipher[0] if cipher else None,
        )
    finally:
        writer.close()
        try:
            await writer.wait_closed()
        except (OSError, ssl.SSLError):
            pass


async def collect_tls(host: str, address: str, timeout: float) -> TlsSnapshot:
    context = ssl.create_default_context()

    try:
        return await _handshake(host, address, timeout, context, verified=True)
    except ssl.SSLCertVerificationError as error:
        insecure = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        insecure.check_hostname = False
        insecure.verify_mode = ssl.CERT_NONE
        try:
            snapshot = await _handshake(
                host, address, timeout, insecure, verified=False
            )
        except (OSError, TimeoutError, ssl.SSLError) as retry_error:
            return TlsSnapshot(error=clip(f"{error} ({retry_error})", 300))
        snapshot.error = clip(error, 300)
        return snapshot
    except (OSError, TimeoutError, ssl.SSLError) as error:
        return TlsSnapshot(error=clip(error, 300))


async def _resolve_public(host: str, timeout: float) -> list[str]:
    try:
        infos = await asyncio.wait_for(
            asyncio.get_running_loop().getaddrinfo(host, None, type=socket.SOCK_STREAM),
            timeout=timeout,
        )
    except (OSError, TimeoutError) as error:
        raise DomainCheckError(f"could not resolve {host}: {error}") from error

    addresses = sorted({info[4][0] for info in infos})
    blocked = [address for address in addresses if not is_public_ip(address)]
    if blocked:
        raise DomainBlockedError(
            f"{host} resolves to a non-public address ({blocked[0]}); scan refused"
        )
    if not addresses:
        raise DomainCheckError(f"{host} did not resolve to an address")
    return addresses


async def _follow(
    client: httpx.AsyncClient,
    url: str,
    *,
    timeout: float,
    max_redirects: int,
) -> tuple[httpx.Response | None, list[str], str | None, str | None]:
    """Follow redirects manually so every hop is SSRF-checked.

    Returns (response, redirect chain, final url, error).
    """
    chain: list[str] = []
    current = url

    for _ in range(max_redirects + 1):
        host = urlparse(current).hostname
        if not host:
            return None, chain, current, "redirect target has no hostname"
        await _resolve_public(host, timeout)

        try:
            response = await client.get(current)
        except httpx.HTTPError as error:
            return None, chain, current, clip(error, 300)

        location = response.headers.get("location")
        if response.status_code not in {301, 302, 303, 307, 308} or not location:
            return response, chain, current, None

        following = urljoin(current, location)
        chain.append(f"{response.status_code} {following}")
        if len(chain) > max_redirects:
            return None, chain, current, "too many redirects"
        current = following

    return None, chain, current, "too many redirects"


async def collect_http(domain: str, timeout: float, max_redirects: int) -> HttpSnapshot:
    headers = {
        "User-Agent": USER_AGENT,
        "Accept": "text/html,application/xhtml+xml",
    }
    snapshot = HttpSnapshot()

    async with httpx.AsyncClient(
        timeout=httpx.Timeout(timeout),
        follow_redirects=False,
        verify=True,
        trust_env=False,
        headers=headers,
    ) as client:
        https_response, chain, final_url, https_error = await _follow(
            client,
            f"https://{domain}/",
            timeout=timeout,
            max_redirects=max_redirects,
        )
        snapshot.redirect_chain = chain[:max_redirects]
        snapshot.final_url = final_url
        snapshot.https_error = https_error

        if https_response is not None:
            snapshot.https_ok = True
            snapshot.https_status = https_response.status_code
            snapshot.headers = {
                str(key).lower(): clip(value, 500)
                for key, value in https_response.headers.items()
                if str(key).lower()
                in {
                    "strict-transport-security",
                    "content-security-policy",
                    "x-content-type-options",
                    "x-frame-options",
                    "referrer-policy",
                    "permissions-policy",
                    "server",
                }
            }

        try:
            http_response = await client.get(f"http://{domain}/")
        except httpx.HTTPError as error:
            snapshot.http_error = clip(error, 300)
        else:
            snapshot.http_ok = True
            snapshot.http_status = http_response.status_code
            snapshot.http_location = (
                clip(http_response.headers.get("location"), 500) or None
            )

    return snapshot


def _snapshot(domain: str, dns: DnsSnapshot, tls: TlsSnapshot, http: HttpSnapshot):
    dns_data = asdict(dns)
    tls_data = asdict(tls)
    tls_data["notAfter"] = tls.not_after.isoformat() if tls.not_after else None
    tls_data.pop("not_after", None)

    http_data = asdict(http)
    http_data["headers"] = safe_evidence(http.headers)

    return {
        "provider": "domain",
        "domain": domain,
        "addresses": dns.addresses(),
        "dns": dns_data,
        "tls": tls_data,
        "http": http_data,
    }


async def check_domain(
    domain: str, settings: Settings
) -> tuple[list[Finding], dict[str, object]]:
    timeout = settings.domain_timeout_seconds

    dns_snapshot = await collect_dns(domain, timeout)
    if dns_snapshot.error:
        raise DomainCheckError(f"DNS lookup failed: {dns_snapshot.error}")

    addresses = dns_snapshot.addresses()
    blocked = [address for address in addresses if not is_public_ip(address)]
    if blocked:
        raise DomainBlockedError(
            f"{domain} resolves to a non-public address ({blocked[0]}); scan refused"
        )

    if dns_snapshot.resolved:
        address = addresses[0]
        tls_snapshot, http_snapshot = await asyncio.gather(
            collect_tls(domain, address, timeout),
            collect_http(domain, timeout, settings.domain_max_redirects),
        )
    else:
        tls_snapshot = TlsSnapshot(error="domain did not resolve")
        http_snapshot = HttpSnapshot(
            https_error="domain did not resolve",
            http_error="domain did not resolve",
        )

    findings = evaluate_domain(
        dns=dns_snapshot,
        tls=tls_snapshot,
        http=http_snapshot,
        cert_warning_days=settings.domain_certificate_warning_days,
    )

    logger.info(
        "domain checks for %s: %s findings (%s)",
        domain,
        len(findings),
        ", ".join(finding.source_tool for finding in findings) or "clean",
    )

    return findings, _snapshot(domain, dns_snapshot, tls_snapshot, http_snapshot)
