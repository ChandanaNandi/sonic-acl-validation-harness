#!/usr/bin/env python3
"""CLI entry point for the SONiC ACL validation harness."""

from __future__ import annotations

import argparse
import subprocess
import sys
import tempfile
from pathlib import Path

if __package__ in (None, ""):
    sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from acl.config import SCENARIO, TARGET
from acl.db_checks import (
    compute_asic_entry_delta,
    config_db_validate,
    find_scenario_entry,
    hgetall,
    keys,
    render_acl_json,
    run_in_container,
    validate_acl_state,
    validate_cleanup,
)
from acl.packet_tests import run_packet_checks


ASIC_ACL_ENTRY_PATTERN = "ASIC_STATE:SAI_OBJECT_TYPE_ACL_ENTRY*"
SAI_ATTRS_OF_INTEREST = (
    "SAI_ACL_ENTRY_ATTR_PRIORITY",
    "SAI_ACL_ENTRY_ATTR_FIELD_L4_DST_PORT",
    "SAI_ACL_ENTRY_ATTR_FIELD_IP_PROTOCOL",
    "SAI_ACL_ENTRY_ATTR_ACTION_PACKET_ACTION",
)


def docker_available() -> bool:
    result = subprocess.run(["docker", "ps"], text=True, capture_output=True)
    return result.returncode == 0


def container_running() -> bool:
    result = subprocess.run(
        ["docker", "inspect", "-f", "{{.State.Running}}", TARGET.container],
        text=True,
        capture_output=True,
    )
    return result.returncode == 0 and result.stdout.strip() == "true"


def require_container() -> None:
    if not docker_available():
        raise SystemExit("docker is not available or not running")
    if not container_running():
        raise SystemExit(f"container {TARGET.container} is not running; run scripts/bringup.sh first")


def copy_to_container(src: Path, dst: str) -> None:
    subprocess.run(["docker", "cp", str(src), f"{TARGET.container}:{dst}"], check=True)


def _do_apply() -> int:
    acl_json = render_acl_json(SCENARIO)
    with tempfile.NamedTemporaryFile("w", suffix=".json", delete=False) as tmp:
        tmp.write(acl_json)
        tmp_path = Path(tmp.name)
    try:
        copy_to_container(tmp_path, "/tmp/acl_drop_https.json")
        result = run_in_container(["sonic-cfggen", "-j", "/tmp/acl_drop_https.json", "--write-to-db"])
    finally:
        tmp_path.unlink(missing_ok=True)
    if result.returncode != 0:
        sys.stderr.write(result.stderr)
        return result.returncode
    return 0


def _do_cleanup() -> int:
    commands = [
        ["sonic-db-cli", "CONFIG_DB", "DEL", SCENARIO.rule_key],
        ["sonic-db-cli", "CONFIG_DB", "DEL", SCENARIO.table_key],
    ]
    for command in commands:
        result = run_in_container(command)
        if result.returncode != 0:
            sys.stderr.write(result.stderr)
            return result.returncode
    return 0


def apply_acl(_: argparse.Namespace) -> int:
    require_container()
    rc = _do_apply()
    if rc == 0:
        print("apply: pass")
    return rc


def cleanup_acl(_: argparse.Namespace) -> int:
    require_container()
    rc = _do_cleanup()
    if rc != 0:
        return rc
    print(validate_cleanup(SCENARIO).text())
    return 0


def validate(args: argparse.Namespace) -> int:
    require_container()
    report = validate_acl_state(SCENARIO)
    for pkt in run_packet_checks(args.dst_ip, args.iface):
        report.add(pkt.name, None if pkt.status == "skip" else pkt.status == "pass", pkt.detail)
    print(report.text())
    return 0 if report.passed else 1


def status(_: argparse.Namespace) -> int:
    require_container()
    print(validate_acl_state(SCENARIO).text())
    return 0


def _emit_flow_report(
    pre_count: int,
    config_report,
    matched_oid: str | None,
    matched_attrs: dict[str, str] | None,
    cleanup_ok: bool,
    removed_after_cleanup: bool | None,
) -> bool:
    """Print the flow report in the documented layout and return overall pass."""

    print(f"baseline ACL_ENTRY keys: {pre_count}")
    print("apply: pass")

    for check in config_report.checks:
        suffix = f": {check.detail}" if check.detail else ""
        print(f"{check.name}: {check.status}{suffix}")

    if matched_oid:
        print(f"ASIC_DB SAI ACL entry delta: pass: {matched_oid}")
        assert matched_attrs is not None
        for attr in SAI_ATTRS_OF_INTEREST:
            print(f"  {attr}: {matched_attrs.get(attr, 'missing')}")
    else:
        print("ASIC_DB SAI ACL entry delta: fail: no new entry matches scenario fingerprint")

    print(f"cleanup: {'pass' if cleanup_ok else 'fail'}")

    if removed_after_cleanup is None:
        removal_line = "ASIC_DB scenario entry removed: skip: no scenario entry to track"
    elif removed_after_cleanup:
        removal_line = "ASIC_DB scenario entry removed: pass"
    else:
        removal_line = "ASIC_DB scenario entry removed: fail: still present in ASIC_DB"
    print(removal_line)

    overall = (
        config_report.passed
        and matched_oid is not None
        and cleanup_ok
        and removed_after_cleanup is True
    )
    print(f"verdict: {'pass' if overall else 'fail'}")
    return overall


def flow(_: argparse.Namespace) -> int:
    """Baseline-capture -> apply -> validate (with ASIC delta) -> cleanup -> verify-removed."""

    require_container()

    pre_keys = keys("ASIC_DB", ASIC_ACL_ENTRY_PATTERN)

    rc = _do_apply()
    if rc != 0:
        return rc

    config_report = None
    matched_oid = None
    matched_attrs = None
    cleanup_ok = False
    try:
        config_report = config_db_validate(SCENARIO)

        post_keys = keys("ASIC_DB", ASIC_ACL_ENTRY_PATTERN)
        new_keys = compute_asic_entry_delta(pre_keys, post_keys)
        candidates = {key: hgetall("ASIC_DB", key) for key in new_keys}
        matched_oid = find_scenario_entry(SCENARIO, candidates)
        matched_attrs = candidates.get(matched_oid) if matched_oid else None
    finally:
        cleanup_ok = _do_cleanup() == 0

    assert config_report is not None

    if matched_oid is None:
        removed = None
    else:
        final_keys = keys("ASIC_DB", ASIC_ACL_ENTRY_PATTERN)
        removed = matched_oid not in final_keys

    overall = _emit_flow_report(
        pre_count=len(pre_keys),
        config_report=config_report,
        matched_oid=matched_oid,
        matched_attrs=matched_attrs,
        cleanup_ok=cleanup_ok,
        removed_after_cleanup=removed,
    )
    return 0 if overall else 1


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Validate ACL state in SONiC VS")
    sub = parser.add_subparsers(dest="command", required=True)

    apply_parser = sub.add_parser("apply", help="apply ACL scenario")
    apply_parser.add_argument("--rule", default=SCENARIO.rule_name, choices=[SCENARIO.rule_name])
    apply_parser.set_defaults(func=apply_acl)

    validate_parser = sub.add_parser("validate", help="validate DB and optional packet behavior")
    validate_parser.add_argument("--dst-ip", help="destination IP for optional Scapy checks")
    validate_parser.add_argument("--iface", help="host interface for optional Scapy checks")
    validate_parser.set_defaults(func=validate)

    cleanup_parser = sub.add_parser("cleanup", help="remove ACL scenario")
    cleanup_parser.set_defaults(func=cleanup_acl)

    status_parser = sub.add_parser("status", help="show current ACL state")
    status_parser.set_defaults(func=status)

    flow_parser = sub.add_parser(
        "flow",
        help="baseline ASIC_DB, apply, validate with SAI delta, cleanup, verify removed",
    )
    flow_parser.set_defaults(func=flow)
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    raise SystemExit(main())
