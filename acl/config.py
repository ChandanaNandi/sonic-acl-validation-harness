"""Static configuration for the ACL validation scenario."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[1]


@dataclass(frozen=True)
class SonicTarget:
    container: str = "sonic-vs-acl"
    image: str = "docker-sonic-vs-fixed:latest"


@dataclass(frozen=True)
class AclScenario:
    table_name: str = "DATAACL"
    rule_name: str = "drop_https"
    bind_port: str = "Ethernet4"
    stage: str = "INGRESS"
    table_type: str = "L3"
    priority: str = "100"
    action: str = "DROP"
    packet_action: str = "DROP"
    l4_dst_port: str = "443"
    protocol: str = "6"

    @property
    def table_key(self) -> str:
        return f"ACL_TABLE|{self.table_name}"

    @property
    def rule_key(self) -> str:
        return f"ACL_RULE|{self.table_name}|{self.rule_name}"


TARGET = SonicTarget()
SCENARIO = AclScenario()

