"""Nmap output parser — converts XML and greppable output to structured data.

Supports both nmap XML (-oX) and greppable (-oG) formats, as well as plain
text output fallback.
"""

from __future__ import annotations

import logging
import re
import xml.etree.ElementTree as ET
from dataclasses import dataclass, field
from typing import Any

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Data classes
# ---------------------------------------------------------------------------


@dataclass
class NmapService:
    """Single discovered service on a host."""

    port: int
    protocol: str = "tcp"
    state: str = "open"
    service_name: str = ""
    product: str = ""
    version: str = ""
    extra_info: str = ""
    cpe: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "port": self.port,
            "protocol": self.protocol,
            "state": self.state,
            "service": self.service_name,
            "product": self.product,
            "version": self.version,
            "extra_info": self.extra_info,
            "cpe": self.cpe,
        }


@dataclass
class NmapHost:
    """Single host discovered by nmap."""

    ip: str
    hostname: str = ""
    state: str = "up"
    services: list[NmapService] = field(default_factory=list)
    os_matches: list[str] = field(default_factory=list)

    @property
    def open_ports(self) -> list[int]:
        return [s.port for s in self.services if s.state == "open"]

    def to_dict(self) -> dict[str, Any]:
        return {
            "ip": self.ip,
            "hostname": self.hostname,
            "state": self.state,
            "services": [s.to_dict() for s in self.services],
            "os_matches": self.os_matches,
            "open_ports": self.open_ports,
        }


@dataclass
class NmapResult:
    """Complete nmap scan result."""

    hosts: list[NmapHost] = field(default_factory=list)
    scan_info: dict[str, Any] = field(default_factory=dict)
    raw_command: str = ""

    @property
    def total_hosts(self) -> int:
        return len(self.hosts)

    @property
    def total_open_ports(self) -> int:
        return sum(len(h.open_ports) for h in self.hosts)

    def to_dict(self) -> dict[str, Any]:
        return {
            "hosts": [h.to_dict() for h in self.hosts],
            "scan_info": self.scan_info,
            "raw_command": self.raw_command,
            "summary": {
                "total_hosts": self.total_hosts,
                "total_open_ports": self.total_open_ports,
                "hosts_up": sum(1 for h in self.hosts if h.state == "up"),
            },
        }

    def to_summary(self) -> str:
        """Generate a human-readable summary for the LLM agent."""
        lines = [
            f"Nmap scan: {self.total_hosts} host(s), {self.total_open_ports} open port(s)",
        ]
        for host in self.hosts:
            ports_str = ", ".join(
                f"{s.port}/{s.protocol} ({s.service_name or '?'})"
                for s in host.services
                if s.state == "open"
            )
            name = host.hostname or host.ip
            lines.append(f"  {name} [{host.state}] — {ports_str or 'no open ports'}")
        return "\n".join(lines)


# ---------------------------------------------------------------------------
# Parsers
# ---------------------------------------------------------------------------


def parse_nmap_xml(xml_content: str) -> NmapResult:
    """Parse nmap XML output (-oX) into structured NmapResult.

    Parameters
    ----------
    xml_content:
        Raw XML string from nmap -oX output.

    Returns
    -------
    Parsed NmapResult with hosts and services.
    """
    result = NmapResult()

    try:
        root = ET.fromstring(xml_content)
    except ET.ParseError as exc:
        logger.error("Failed to parse nmap XML: %s", exc)
        return result

    # Scan info
    result.raw_command = root.get("args", "")
    scan_info_el = root.find("scaninfo")
    if scan_info_el is not None:
        result.scan_info = {
            "type": scan_info_el.get("type", ""),
            "protocol": scan_info_el.get("protocol", ""),
            "services": scan_info_el.get("services", ""),
        }

    # Hosts
    for host_el in root.findall("host"):
        # Address
        addr_el = host_el.find("address")
        if addr_el is None:
            continue
        ip = addr_el.get("addr", "")

        # Status
        status_el = host_el.find("status")
        state = status_el.get("state", "up") if status_el is not None else "up"

        # Hostname
        hostname = ""
        hostnames_el = host_el.find("hostnames")
        if hostnames_el is not None:
            hn_el = hostnames_el.find("hostname")
            if hn_el is not None:
                hostname = hn_el.get("name", "")

        host = NmapHost(ip=ip, hostname=hostname, state=state)

        # Ports / services
        ports_el = host_el.find("ports")
        if ports_el is not None:
            for port_el in ports_el.findall("port"):
                port_num = int(port_el.get("portid", "0"))
                protocol = port_el.get("protocol", "tcp")

                state_el = port_el.find("state")
                port_state = state_el.get("state", "unknown") if state_el is not None else "unknown"

                svc_el = port_el.find("service")
                svc = NmapService(
                    port=port_num,
                    protocol=protocol,
                    state=port_state,
                )
                if svc_el is not None:
                    svc.service_name = svc_el.get("name", "")
                    svc.product = svc_el.get("product", "")
                    svc.version = svc_el.get("version", "")
                    svc.extra_info = svc_el.get("extrainfo", "")
                    cpe_el = svc_el.find("cpe")
                    if cpe_el is not None and cpe_el.text:
                        svc.cpe = cpe_el.text

                host.services.append(svc)

        # OS detection
        os_el = host_el.find("os")
        if os_el is not None:
            for match_el in os_el.findall("osmatch"):
                os_name = match_el.get("name", "")
                accuracy = match_el.get("accuracy", "")
                if os_name:
                    host.os_matches.append(f"{os_name} ({accuracy}%)")

        result.hosts.append(host)

    logger.info(
        "Parsed nmap XML: %d hosts, %d open ports",
        result.total_hosts,
        result.total_open_ports,
    )
    return result


def parse_nmap_text(text_output: str) -> NmapResult:
    """Parse plain text nmap output (fallback when XML is not available).

    This is a best-effort parser using regex patterns.
    """
    result = NmapResult()

    # Match "Nmap scan report for <host> (<ip>)" or "Nmap scan report for <ip>"
    host_pattern = re.compile(
        r"Nmap scan report for (?:(\S+)\s+\((\d+\.\d+\.\d+\.\d+)\)|(\d+\.\d+\.\d+\.\d+))"
    )
    port_pattern = re.compile(
        r"^(\d+)/(tcp|udp)\s+(open|closed|filtered)\s+(\S+)(?:\s+(.*))?$",
        re.MULTILINE,
    )

    current_host: NmapHost | None = None

    for line in text_output.splitlines():
        host_match = host_pattern.search(line)
        if host_match:
            if current_host is not None:
                result.hosts.append(current_host)
            hostname = host_match.group(1) or ""
            ip = host_match.group(2) or host_match.group(3) or ""
            current_host = NmapHost(ip=ip, hostname=hostname)
            continue

        if current_host is not None:
            port_match = port_pattern.match(line.strip())
            if port_match:
                svc = NmapService(
                    port=int(port_match.group(1)),
                    protocol=port_match.group(2),
                    state=port_match.group(3),
                    service_name=port_match.group(4) or "",
                    product=port_match.group(5) or "",
                )
                current_host.services.append(svc)

    if current_host is not None:
        result.hosts.append(current_host)

    logger.info(
        "Parsed nmap text: %d hosts, %d open ports",
        result.total_hosts,
        result.total_open_ports,
    )
    return result


def parse_nmap(output: str) -> NmapResult:
    """Auto-detect format and parse nmap output."""
    stripped = output.strip()
    if stripped.startswith("<?xml") or stripped.startswith("<nmaprun"):
        return parse_nmap_xml(stripped)
    return parse_nmap_text(stripped)
