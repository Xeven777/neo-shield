"""Authorized, conservative Nmap discovery.

Safety properties enforced here, regardless of what the asset config says:

* IPv4 only, at most a /24 (256 addresses) by default.
* Only RFC1918 and CGNAT address space is accepted; public ranges are refused.
* Two fixed profiles: host discovery, or host discovery plus limited service
  detection on an explicit port list. No NSE scripts, OS detection, brute force,
  exploitation or aggressive timing.
* No shell: Nmap is executed as an argv list with a hard timeout and a bounded
  output size.

The web UI records the exact scope confirmation; this module re-validates the
scope and the worker refuses scans whose authorization record is missing.
"""

from __future__ import annotations

import asyncio
import ipaddress
import logging
import shutil
from dataclasses import dataclass, field
from typing import Any
from xml.etree.ElementTree import ParseError as XmlParseError

from defusedxml import ElementTree

from neoshield.config import Settings
from neoshield.worker.normalize import Finding, Severity, clip, safe_evidence

logger = logging.getLogger(__name__)

ALLOWED_NETWORKS = (
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
    ipaddress.ip_network("100.64.0.0/10"),
)

RISKY_PORTS: dict[int, tuple[Severity, str]] = {
    21: ("high", "FTP transmits credentials and data in clear text"),
    22: ("medium", "SSH is a remote-administration entry point"),
    23: ("critical", "Telnet is unencrypted remote administration"),
    445: ("high", "SMB exposes file sharing and a large attack surface"),
    1433: ("high", "Microsoft SQL Server is reachable from the network"),
    1521: ("high", "Oracle database listener is reachable from the network"),
    2049: ("high", "NFS exports may be reachable from the network"),
    2375: ("critical", "The Docker daemon API is unauthenticated"),
    3306: ("high", "MySQL is reachable from the network"),
    3389: ("high", "RDP is a remote-administration entry point"),
    5432: ("high", "PostgreSQL is reachable from the network"),
    5900: ("high", "VNC is a remote-administration entry point"),
    6379: ("high", "Redis is reachable and may be unauthenticated"),
    9200: ("high", "Elasticsearch/OpenSearch is reachable from the network"),
    11211: ("high", "Memcached is reachable and may be unauthenticated"),
    27017: ("high", "MongoDB is reachable and may be unauthenticated"),
}

PORT_NAMES = {
    21: "ftp",
    22: "ssh",
    23: "telnet",
    25: "smtp",
    53: "dns",
    80: "http",
    110: "pop3",
    143: "imap",
    443: "https",
    445: "smb",
    993: "imaps",
    995: "pop3s",
    1433: "mssql",
    1521: "oracle",
    2049: "nfs",
    2375: "docker",
    3306: "mysql",
    3389: "rdp",
    5432: "postgresql",
    5900: "vnc",
    6379: "redis",
    8080: "http-alt",
    8443: "https-alt",
    9200: "elasticsearch",
    11211: "memcached",
    27017: "mongodb",
}


class NetworkScopeError(ValueError):
    """The requested scope is outside the authorized scanner policy."""


class NetworkScanError(RuntimeError):
    """Nmap could not be executed or returned unusable output."""


@dataclass(slots=True)
class ServiceObservation:
    port: int
    protocol: str = "tcp"
    service: str | None = None
    product: str | None = None
    version: str | None = None
    extra_info: str | None = None
    cpe: str | None = None


@dataclass(slots=True)
class HostObservation:
    address: str
    hostname: str | None = None
    mac_address: str | None = None
    vendor: str | None = None
    services: list[ServiceObservation] = field(default_factory=list)


@dataclass(slots=True)
class ScanOutcome:
    hosts: list[HostObservation]
    findings: list[Finding]
    snapshot: dict[str, Any]


def validate_scope(cidr: str, settings: Settings) -> ipaddress.IPv4Network:
    candidate = (cidr or "").strip()
    if not candidate:
        raise NetworkScopeError("A CIDR range is required")

    try:
        network = ipaddress.ip_network(candidate, strict=False)
    except ValueError as error:
        raise NetworkScopeError("The CIDR range is not valid") from error

    if not isinstance(network, ipaddress.IPv4Network):
        raise NetworkScopeError("Only IPv4 ranges are supported")

    if network.prefixlen < settings.network_max_prefix_length:
        raise NetworkScopeError(
            f"The range is too large; the smallest allowed network is "
            f"/{settings.network_max_prefix_length}"
        )

    if network.num_addresses > settings.network_max_hosts:
        raise NetworkScopeError(
            f"The range contains more than {settings.network_max_hosts} addresses"
        )

    if network.is_loopback or network.is_multicast or network.is_link_local:
        raise NetworkScopeError(
            "Loopback, multicast and link-local ranges are not allowed"
        )

    allowed = any(network.subnet_of(entry) for entry in ALLOWED_NETWORKS)
    if not allowed and not settings.network_allow_public:
        raise NetworkScopeError(
            "Only private RFC1918 or CGNAT ranges may be scanned"
        )

    if network.is_unspecified or network.is_reserved:
        raise NetworkScopeError("Reserved ranges are not allowed")

    return network


def estimated_hosts(network: ipaddress.IPv4Network) -> int:
    return max(0, network.num_addresses - 2)


def nmap_binary(settings: Settings) -> str:
    configured = settings.nmap_path
    path = shutil.which(configured) if configured else shutil.which("nmap")
    if configured and not path:
        raise NetworkScanError(f"Nmap was not found at {configured}")
    if not path:
        raise NetworkScanError(
            "Nmap is not installed on this worker; install nmap or set "
            "NEOSHIELD_NMAP_PATH"
        )
    return path


async def _run_nmap(
    arguments: list[str], *, timeout: float, max_output: int
) -> bytes:
    logger.info("running nmap with %s argument(s)", len(arguments))
    process = await asyncio.create_subprocess_exec(
        *arguments,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
    )
    try:
        stdout, stderr = await asyncio.wait_for(
            process.communicate(), timeout=timeout
        )
    except TimeoutError as error:
        process.kill()
        await process.wait()
        raise NetworkScanError("Nmap exceeded the scan timeout") from error

    if len(stdout) + len(stderr) > max_output:
        raise NetworkScanError("Nmap output exceeded the configured size limit")

    if process.returncode != 0:
        detail = clip(stderr.decode("utf-8", "replace"), 300)
        raise NetworkScanError(
            f"Nmap exited with status {process.returncode}"
            + (f": {detail}" if detail else "")
        )

    return stdout


def _pick_address(
    host: ElementTree.Element,
) -> tuple[str | None, str | None, str | None]:
    address: str | None = None
    mac: str | None = None
    vendor: str | None = None
    for entry in host.findall("address"):
        addrtype = entry.get("addrtype")
        if addrtype == "ipv4" and address is None:
            address = entry.get("addr")
        elif addrtype == "mac" and mac is None:
            mac = entry.get("addr")
            vendor = entry.get("vendor")
    return address, mac, vendor


def _pick_hostname(host: ElementTree.Element) -> str | None:
    for entry in host.findall("hostnames/hostname"):
        name = entry.get("name")
        if name and name != "?":
            return clip(name, 253)
    return None


def parse_nmap_xml(xml: bytes, *, max_hosts: int = 1024) -> list[HostObservation]:
    if not xml.strip():
        raise NetworkScanError("Nmap returned no XML output")
    try:
        root = ElementTree.fromstring(xml)
    except (XmlParseError, ValueError) as error:
        raise NetworkScanError("Nmap returned malformed XML") from error

    observations: list[HostObservation] = []
    for host in root.findall("host")[:max_hosts]:
        status = host.find("status")
        if status is None or status.get("state") != "up":
            continue

        address, mac, vendor = _pick_address(host)
        if not address:
            continue

        observation = HostObservation(
            address=address,
            hostname=_pick_hostname(host),
            mac_address=mac,
            vendor=clip(vendor, 120) if vendor else None,
        )

        for port in host.findall("ports/port")[:2048]:
            state = port.find("state")
            if state is None or state.get("state") != "open":
                continue
            number = port.get("portid")
            try:
                port_number = int(number or 0)
            except ValueError:
                continue
            if port_number <= 0 or port_number > 65535:
                continue

            service = port.find("service")
            cpe = None
            extra = None
            name = None
            product = None
            version = None
            if service is not None:
                name = clip(service.get("name"), 80) or None
                product = clip(service.get("product"), 200) or None
                version = clip(service.get("version"), 120) or None
                extra = clip(service.get("extrainfo"), 200) or None
                cpe_entry = service.find("cpe")
                if cpe_entry is not None and cpe_entry.text:
                    cpe = clip(cpe_entry.text, 300)

            observation.services.append(
                ServiceObservation(
                    port=port_number,
                    protocol=clip(port.get("protocol"), 10) or "tcp",
                    service=name,
                    product=product,
                    version=version,
                    extra_info=extra,
                    cpe=cpe,
                )
            )

        observations.append(observation)

    return observations


def _host_finding(
    host: HostObservation, *, network: str, profile: str
) -> Finding:
    open_ports = ", ".join(
        f"{service.port}/{service.protocol}"
        for service in host.services[:20]
    )
    return Finding(
        source="network",
        source_tool="nmap",
        source_rule_id="nmap-host-discovered",
        stable_key=f"network|host|{host.address}",
        title=f"Host discovered: {host.address}",
        description=(
            f"Nmap discovered {host.address}"
            + (f" ({host.hostname})" if host.hostname else "")
            + f" while scanning the authorized range {network}."
            + (f" Open ports: {open_ports}." if open_ports else "")
        ),
        category="network_host",
        severity="informational",
        confidence="high",
        remediation=(
            "Confirm this host is expected on the network. Remove it or "
            "segment it if it is unauthorized."
        ),
        evidence=safe_evidence(
            {
                "address": host.address,
                "hostname": host.hostname,
                "macAddress": host.mac_address,
                "vendor": host.vendor,
                "scope": network,
                "profile": profile,
                "openPorts": [
                    f"{service.port}/{service.protocol}"
                    for service in host.services[:20]
                ],
            }
        ),
    )


def _service_finding(
    host: HostObservation,
    service: ServiceObservation,
    *,
    network: str,
    profile: str,
) -> Finding | None:
    risk = RISKY_PORTS.get(service.port)
    if risk is None:
        return None
    severity, reason = risk
    label = service.service or PORT_NAMES.get(service.port, "service")
    product = " ".join(
        part for part in [service.product, service.version] if part
    )

    return Finding(
        source="network",
        source_tool="nmap",
        source_rule_id=f"nmap-port-{service.port}",
        stable_key=(
            f"network|port|{host.address}|{service.port}|{service.protocol}"
        ),
        title=(
            f"Exposed service: {service.port}/{service.protocol} "
            f"({label}) on {host.address}"
        ),
        description=(
            f"{reason}. Nmap observed {label}"
            + (f" ({product})" if product else "")
            + f" listening on {service.port}/{service.protocol} at "
            f"{host.address}"
            + (f" ({host.hostname})" if host.hostname else "")
            + f" during an authorized scan of {network}."
        ),
        category="exposed_service",
        severity=severity,
        confidence="high" if product else "medium",
        remediation=(
            f"Restrict port {service.port}/{service.protocol} to a management "
            "network or VPN with host and network firewalls. Disable the "
            "service if it is not required."
        ),
        evidence=safe_evidence(
            {
                "address": host.address,
                "hostname": host.hostname,
                "macAddress": host.mac_address,
                "vendor": host.vendor,
                "port": service.port,
                "protocol": service.protocol,
                "service": service.service,
                "product": service.product,
                "version": service.version,
                "extraInfo": service.extra_info,
                "cpe": service.cpe,
                "scope": network,
                "profile": profile,
            }
        ),
    )


def build_findings(
    hosts: list[HostObservation], *, network: str, profile: str
) -> list[Finding]:
    findings: list[Finding] = []
    for host in hosts:
        findings.append(_host_finding(host, network=network, profile=profile))
        for service in host.services:
            finding = _service_finding(
                host, service, network=network, profile=profile
            )
            if finding is not None:
                findings.append(finding)
    return findings


async def scan_network(
    cidr: str, profile: str, settings: Settings
) -> ScanOutcome:
    network = validate_scope(cidr, settings)
    binary = nmap_binary(settings)
    scope = str(network)
    ports = settings.network_ports
    max_output = settings.network_max_output_bytes

    discovery = await _run_nmap(
        [
            binary,
            "-sn",
            "-PE",
            "-PS22,80,443",
            "--max-retries",
            "2",
            "--host-timeout",
            "20s",
            "--max-rate",
            "500",
            "-oX",
            "-",
            scope,
        ],
        timeout=settings.network_scan_timeout_seconds,
        max_output=max_output,
    )
    hosts = parse_nmap_xml(discovery)

    scanned = 0
    skipped = 0
    scanned_addresses: list[str] = []
    nmap_version: str | None = None
    try:
        root = ElementTree.fromstring(discovery)
        nmap_version = root.get("version")
    except (XmlParseError, ValueError):
        nmap_version = None

    if profile == "services":
        for host in hosts:
            if scanned >= settings.network_max_service_hosts:
                skipped = len(hosts) - scanned
                break
            output = await _run_nmap(
                [
                    binary,
                    "-sV",
                    "--version-light",
                    "-Pn",
                    "-n",
                    "-T3",
                    "--max-retries",
                    "2",
                    "--host-timeout",
                    f"{settings.network_host_timeout_seconds}s",
                    "--max-rate",
                    "300",
                    "-p",
                    ports,
                    "-oX",
                    "-",
                    host.address,
                ],
                timeout=settings.network_scan_timeout_seconds,
                max_output=max_output,
            )
            parsed = parse_nmap_xml(output, max_hosts=1)
            if parsed:
                host.services = parsed[0].services
            scanned += 1
            scanned_addresses.append(host.address)

    findings = build_findings(hosts, network=scope, profile=profile)
    snapshot = {
        "provider": "network",
        "cidr": scope,
        "profile": profile,
        "ports": ports,
        "nmapVersion": nmap_version,
        "hostsFound": len(hosts),
        "servicesFound": sum(len(host.services) for host in hosts),
        "hostsServiceScanned": scanned,
        "hostsServiceScanSkipped": skipped,
        "serviceScanComplete": profile == "services" and skipped == 0,
        "serviceScannedAddresses": scanned_addresses,
        "authorized": True,
    }

    logger.info(
        "network scan %s (%s): %s hosts, %s services, %s findings",
        scope,
        profile,
        len(hosts),
        snapshot["servicesFound"],
        len(findings),
    )

    return ScanOutcome(hosts=hosts, findings=findings, snapshot=snapshot)
