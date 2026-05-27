"""Database checks for SONiC ACL state.

The checks are intentionally conservative. CONFIG_DB is the source of truth for
this demo. APP_DB and ASIC_DB are reported only when visible in the SONiC VS
container because not every VS image exposes useful SAI ACL objects.
"""

from __future__ import annotations

import json
import re
import subprocess
from ast import literal_eval
from dataclasses import dataclass, field
from typing import Any

from acl.config import AclScenario, TARGET


@dataclass
class Check:
    name: str
    status: str
    detail: str = ""


@dataclass
class ValidationReport:
    checks: list[Check] = field(default_factory=list)

    def add(self, name: str, ok: bool | None, detail: str = "") -> None:
        if ok is None:
            status = "skip"
        else:
            status = "pass" if ok else "fail"
        self.checks.append(Check(name, status, detail))

    @property
    def passed(self) -> bool:
        return all(check.status in {"pass", "skip"} for check in self.checks)

    def text(self) -> str:
        lines = []
        for check in self.checks:
            suffix = f": {check.detail}" if check.detail else ""
            lines.append(f"{check.name}: {check.status}{suffix}")
        lines.append(f"verdict: {'pass' if self.passed else 'fail'}")
        return "\n".join(lines)


def run_in_container(args: list[str], check: bool = False) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        ["docker", "exec", TARGET.container, *args],
        text=True,
        capture_output=True,
        check=check,
    )


def sonic_db_cli(db: str, args: list[str]) -> subprocess.CompletedProcess[str]:
    return run_in_container(["sonic-db-cli", db, *args])


def key_exists(db: str, key: str) -> bool:
    result = sonic_db_cli(db, ["EXISTS", key])
    return result.returncode == 0 and result.stdout.strip() == "1"


def hgetall(db: str, key: str) -> dict[str, str]:
    result = sonic_db_cli(db, ["HGETALL", key])
    if result.returncode != 0:
        return {}
    return parse_hgetall_output(result.stdout)


def parse_hgetall_output(output: str) -> dict[str, str]:
    stripped = output.strip()
    if stripped.startswith("{") and stripped.endswith("}"):
        try:
            parsed = literal_eval(stripped)
        except (SyntaxError, ValueError):
            parsed = None
        if isinstance(parsed, dict):
            return {str(key): str(value) for key, value in parsed.items()}

    lines = [parse_redis_line(line.strip()) for line in output.splitlines() if line.strip()]
    lines = [line for line in lines if line is not None]
    return dict(zip(lines[0::2], lines[1::2], strict=False))


def parse_redis_line(line: str) -> str | None:
    numbered = re.match(r"^\d+\)\s+(.*)$", line)
    if numbered:
        line = numbered.group(1)
    if line.startswith('"') and line.endswith('"'):
        try:
            return json.loads(line)
        except json.JSONDecodeError:
            return line[1:-1]
    return line


def keys(db: str, pattern: str) -> list[str]:
    result = sonic_db_cli(db, ["KEYS", pattern])
    if result.returncode != 0:
        return []
    return [line.strip() for line in result.stdout.splitlines() if line.strip()]


def parse_config_value(value: str | None) -> Any:
    if value is None:
        return None
    try:
        return json.loads(value)
    except json.JSONDecodeError:
        return value


def parse_port_list(value: str | None) -> list[str] | None:
    """Interpret a CONFIG_DB port-list field across the serializations SONiC uses.

    Returns the parsed port list, or None if the value is a plain scalar.
    SONiC images variously serialize ACL_TABLE.ports as a JSON list
    (`["Ethernet4"]`), comma-separated (`Ethernet0,Ethernet4`), or
    `@`-separated (`Ethernet0@Ethernet4`).
    """

    if value is None:
        return None
    parsed = parse_config_value(value)
    if isinstance(parsed, list):
        return [str(item).strip() for item in parsed]
    for separator in (",", "@"):
        if separator in value:
            return [token.strip() for token in value.split(separator) if token.strip()]
    return None


def field_matches(value: str | None, expected: str) -> bool:
    as_list = parse_port_list(value)
    if as_list is not None:
        return as_list == [expected]
    return value.strip() == expected if value is not None else False


def first_present(mapping: dict[str, str], names: list[str]) -> str | None:
    for name in names:
        if name in mapping:
            return mapping[name]
    return None


def evaluate_config_db_state(
    scenario: AclScenario,
    table: dict[str, str],
    rule: dict[str, str],
) -> ValidationReport:
    """Pure evaluation: given the table and rule hashes, build the report.

    Separated from Redis I/O so fault cases are unit-testable without docker.
    SONiC stores priority under PRIORITY in CONFIG_DB; we accept both casings
    because some sonic-cfggen paths normalize the key.
    """

    report = ValidationReport()
    rule_label = f"CONFIG_DB ACL_RULE {scenario.rule_name}"
    priority = rule.get("PRIORITY", rule.get("priority"))
    ports = first_present(table, ["ports", "ports@"])

    report.add("CONFIG_DB ACL_TABLE", bool(table), "present" if table else "missing")
    report.add(rule_label, bool(rule), "present" if rule else "missing")
    report.add("port_binding", field_matches(ports, scenario.bind_port), ports or "missing")
    report.add("stage", table.get("stage") == scenario.stage, table.get("stage", "missing"))
    report.add("type", table.get("type") == scenario.table_type, table.get("type", "missing"))
    report.add("priority", priority == scenario.priority, priority or "missing")
    report.add(
        "IP_PROTOCOL",
        rule.get("IP_PROTOCOL") == scenario.protocol,
        rule.get("IP_PROTOCOL", "missing"),
    )
    report.add("L4_DST_PORT", rule.get("L4_DST_PORT") == scenario.l4_dst_port, rule.get("L4_DST_PORT", "missing"))
    report.add(
        "PACKET_ACTION",
        rule.get("PACKET_ACTION") == scenario.packet_action,
        rule.get("PACKET_ACTION", "missing"),
    )
    return report


def config_db_validate(scenario: AclScenario) -> ValidationReport:
    table = hgetall("CONFIG_DB", scenario.table_key)
    rule = hgetall("CONFIG_DB", scenario.rule_key)
    return evaluate_config_db_state(scenario, table, rule)


def app_db_observe(scenario: AclScenario, report: ValidationReport) -> None:
    matching = keys("APPL_DB", f"*{scenario.table_name}*")
    if matching:
        report.add("APP_DB ACL state", True, ", ".join(matching[:5]))
    else:
        report.add("APP_DB ACL state", None, "not visible in this VS image")


def asic_db_observe(report: ValidationReport) -> None:
    acl_tables = keys("ASIC_DB", "ASIC_STATE:SAI_OBJECT_TYPE_ACL_TABLE*")
    acl_entries = keys("ASIC_DB", "ASIC_STATE:SAI_OBJECT_TYPE_ACL_ENTRY*")
    if acl_tables or acl_entries:
        detail = f"tables={len(acl_tables)} entries={len(acl_entries)}"
        report.add("ASIC_DB SAI ACL objects", True, detail)
    else:
        report.add("ASIC_DB SAI ACL objects", None, "not visible or not materialized in this VS image")


def strip_sai_mask(value: str | None) -> str | None:
    """Drop the `&mask:0x...` suffix SAI uses for ternary ACL match fields."""

    if value is None:
        return None
    return value.split("&mask:", 1)[0]


def expected_sai_action(scenario: AclScenario) -> str:
    return f"SAI_PACKET_ACTION_{scenario.packet_action}"


def evaluate_asic_acl_entry_attrs(
    scenario: AclScenario, attrs: dict[str, str]
) -> ValidationReport:
    """Pure check of one ASIC_DB ACL_ENTRY's SAI attributes against the scenario.

    Tolerates the `value&mask:0xff` shape SAI emits for ternary fields by
    stripping the mask before comparing.
    """

    report = ValidationReport()

    priority = attrs.get("SAI_ACL_ENTRY_ATTR_PRIORITY")
    l4_raw = attrs.get("SAI_ACL_ENTRY_ATTR_FIELD_L4_DST_PORT")
    proto_raw = attrs.get("SAI_ACL_ENTRY_ATTR_FIELD_IP_PROTOCOL")
    action = attrs.get("SAI_ACL_ENTRY_ATTR_ACTION_PACKET_ACTION")

    report.add("SAI priority", priority == scenario.priority, priority or "missing")
    report.add(
        "SAI L4_DST_PORT",
        strip_sai_mask(l4_raw) == scenario.l4_dst_port,
        l4_raw or "missing",
    )
    report.add(
        "SAI IP_PROTOCOL",
        strip_sai_mask(proto_raw) == scenario.protocol,
        proto_raw or "missing",
    )
    report.add(
        "SAI PACKET_ACTION",
        action == expected_sai_action(scenario),
        action or "missing",
    )
    return report


def compute_asic_entry_delta(pre: list[str], post: list[str]) -> list[str]:
    """ACL_ENTRY keys present after apply but not before. Order-preserving."""

    seen = set(pre)
    return [key for key in post if key not in seen]


def find_scenario_entry(
    scenario: AclScenario, candidates: dict[str, dict[str, str]]
) -> str | None:
    """Return the candidate key whose attrs match the scenario fingerprint."""

    for key, attrs in candidates.items():
        if evaluate_asic_acl_entry_attrs(scenario, attrs).passed:
            return key
    return None


def validate_acl_state(scenario: AclScenario) -> ValidationReport:
    report = config_db_validate(scenario)
    app_db_observe(scenario, report)
    asic_db_observe(report)
    return report


def evaluate_cleanup_state(
    rule_present: bool,
    table_present: bool,
    stale_app_keys: list[str],
) -> ValidationReport:
    """Pure evaluation of post-cleanup state for unit testing."""

    report = ValidationReport()
    report.add("cleanup CONFIG_DB ACL_RULE", not rule_present, "removed" if not rule_present else "stale")
    report.add("cleanup CONFIG_DB ACL_TABLE", not table_present, "removed" if not table_present else "stale")
    report.add(
        "cleanup APP_DB stale ACL state",
        not stale_app_keys,
        ", ".join(stale_app_keys[:5]) or "none visible",
    )
    return report


def validate_cleanup(scenario: AclScenario) -> ValidationReport:
    return evaluate_cleanup_state(
        rule_present=key_exists("CONFIG_DB", scenario.rule_key),
        table_present=key_exists("CONFIG_DB", scenario.table_key),
        stale_app_keys=keys("APPL_DB", f"*{scenario.table_name}*"),
    )


def render_acl_json(scenario: AclScenario) -> str:
    policy_desc = (
        f"{scenario.packet_action.lower()} TCP destination port "
        f"{scenario.l4_dst_port} on {scenario.bind_port}"
    )
    acl_config: dict[str, Any] = {
        "ACL_TABLE": {
            scenario.table_name: {
                "policy_desc": policy_desc,
                "type": scenario.table_type,
                "ports": [scenario.bind_port],
                "stage": scenario.stage,
            }
        },
        "ACL_RULE": {
            f"{scenario.table_name}|{scenario.rule_name}": {
                "PRIORITY": scenario.priority,
                "PACKET_ACTION": scenario.packet_action,
                "IP_PROTOCOL": scenario.protocol,
                "L4_DST_PORT": scenario.l4_dst_port,
            }
        },
    }
    return json.dumps(acl_config, indent=2, sort_keys=True)
