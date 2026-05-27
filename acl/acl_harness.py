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
from acl.db_checks import render_acl_json, run_in_container, validate_acl_state, validate_cleanup
from acl.packet_tests import run_packet_checks


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


def apply_acl(_: argparse.Namespace) -> int:
    require_container()
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
    print("apply: pass")
    return 0


def cleanup_acl(_: argparse.Namespace) -> int:
    require_container()
    commands = [
        ["sonic-db-cli", "CONFIG_DB", "DEL", SCENARIO.rule_key],
        ["sonic-db-cli", "CONFIG_DB", "DEL", SCENARIO.table_key],
    ]
    for command in commands:
        result = run_in_container(command)
        if result.returncode != 0:
            sys.stderr.write(result.stderr)
            return result.returncode
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
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    raise SystemExit(main())

