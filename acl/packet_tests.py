"""Packet behavior checks for the ACL scenario.

Packet testing is topology-dependent in SONiC VS. This module provides an
explicit command path but reports "skip" unless a caller supplies reachable
interfaces and destination information.
"""

from __future__ import annotations

from dataclasses import dataclass


@dataclass
class PacketResult:
    name: str
    status: str
    detail: str


def run_packet_checks(dst_ip: str | None = None, iface: str | None = None) -> list[PacketResult]:
    if not dst_ip or not iface:
        return [
            PacketResult("packet tcp/443", "skip", "requires --dst-ip and --iface for this VS topology"),
            PacketResult("packet tcp/80", "skip", "requires --dst-ip and --iface for this VS topology"),
        ]

    try:
        from scapy.all import IP, TCP, sr1  # type: ignore
    except ImportError:
        return [
            PacketResult("packet tcp/443", "skip", "scapy is not installed"),
            PacketResult("packet tcp/80", "skip", "scapy is not installed"),
        ]

    results: list[PacketResult] = []
    for port, expected in [(443, "dropped"), (80, "permitted")]:
        pkt = IP(dst=dst_ip) / TCP(dport=port, flags="S")
        response = sr1(pkt, iface=iface, timeout=2, verbose=False)
        observed = "dropped" if response is None else "permitted"
        status = "pass" if observed == expected else "fail"
        results.append(PacketResult(f"packet tcp/{port}", status, observed))
    return results

