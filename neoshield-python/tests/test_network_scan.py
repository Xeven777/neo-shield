from __future__ import annotations

import pytest

from neoshield.config import Settings
from neoshield.worker.network_scan import (
    NetworkScopeError,
    build_findings,
    estimated_hosts,
    parse_nmap_xml,
    validate_scope,
)

NMAP_XML = b"""<?xml version="1.0" encoding="UTF-8"?>
<nmaprun scanner="nmap" args="nmap -sV" start="1763028000" version="7.94">
  <host>
    <status state="up" reason="arp-response"/>
    <address addr="10.10.10.5" addrtype="ipv4"/>
    <address addr="AA:BB:CC:DD:EE:FF" addrtype="mac" vendor="Example Corp"/>
    <hostnames>
      <hostname name="lab-host.lan" type="PTR"/>
    </hostnames>
    <ports>
      <port protocol="tcp" portid="22">
        <state state="open" reason="syn-ack"/>
        <service name="ssh" product="OpenSSH" version="9.6p1" extrainfo="Ubuntu"/>
      </port>
      <port protocol="tcp" portid="8080">
        <state state="open" reason="syn-ack"/>
        <service name="http-proxy"/>
      </port>
      <port protocol="tcp" portid="443">
        <state state="closed" reason="reset"/>
      </port>
    </ports>
  </host>
  <host>
    <status state="down"/>
    <address addr="10.10.10.6" addrtype="ipv4"/>
  </host>
</nmaprun>
"""


def settings() -> Settings:
    return Settings(
        network_max_prefix_length=24,
        network_max_hosts=256,
        network_allow_public=False,
    )


def test_scope_accepts_private_and_normalizes_host_bits() -> None:
    network = validate_scope("192.168.1.7/24", settings())
    assert str(network) == "192.168.1.0/24"
    assert estimated_hosts(network) == 254


@pytest.mark.parametrize(
    "cidr",
    [
        "8.8.8.0/24",
        "0.0.0.0/0",
        "192.168.0.0/16",
        "127.0.0.0/24",
        "169.254.1.0/24",
        "2001:db8::/120",
        "",
        "not-a-cidr",
    ],
)
def test_scope_rejects_unsafe_ranges(cidr: str) -> None:
    with pytest.raises(NetworkScopeError):
        validate_scope(cidr, settings())


def test_scope_accepts_cgnat_and_smaller_networks() -> None:
    assert str(validate_scope("100.64.10.0/24", settings())) == "100.64.10.0/24"
    assert str(validate_scope("192.168.1.0/25", settings())) == "192.168.1.0/25"


def test_parse_nmap_xml_keeps_open_services_only() -> None:
    hosts = parse_nmap_xml(NMAP_XML)

    assert len(hosts) == 1
    host = hosts[0]
    assert host.address == "10.10.10.5"
    assert host.hostname == "lab-host.lan"
    assert host.mac_address == "AA:BB:CC:DD:EE:FF"
    assert host.vendor == "Example Corp"
    assert [service.port for service in host.services] == [22, 8080]
    assert host.services[0].product == "OpenSSH"
    assert host.services[0].version == "9.6p1"


def test_findings_cover_risky_ports_only() -> None:
    hosts = parse_nmap_xml(NMAP_XML)
    findings = build_findings(hosts, network="10.10.10.0/24", profile="services")

    keys = {finding.stable_key: finding for finding in findings}
    assert "network|host|10.10.10.5" in keys
    assert "network|port|10.10.10.5|22|tcp" in keys
    assert "network|port|10.10.10.5|8080|tcp" not in keys

    ssh = keys["network|port|10.10.10.5|22|tcp"]
    assert ssh.severity == "medium"
    assert ssh.source == "network"
    assert ssh.source_tool == "nmap"
    assert ssh.category == "exposed_service"
    assert ssh.evidence["product"] == "OpenSSH"

    host_finding = keys["network|host|10.10.10.5"]
    assert host_finding.severity == "informational"
