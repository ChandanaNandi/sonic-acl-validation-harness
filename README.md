# SONiC ACL State Validation Harness

Python validation harness for a focused SONiC VS ACL scenario. It applies an
ACL table and rule, validates SONiC database state, optionally checks packet
behavior, and documents where CONFIG_DB, APP_DB, ASIC_DB, and SAI visibility
begin and end.

This is a SONiC / ACL / SAI-concepts project, not an AI project. Deterministic
Python validation is the source of truth.

## Scenario

- Container image: `docker-sonic-vs-fixed:latest`
- Container name: `sonic-vs-acl`
- ACL table: `DATAACL`
- Bound interface: `Ethernet4`
- Rule: `drop_https`
- Match: TCP destination port `443`
- Action: `DROP`
- Priority: `100`

## State Flow

```text
ACL intent
  -> CONFIG_DB ACL_TABLE / ACL_RULE
  -> APP_DB / orchagent translation if visible
  -> ASIC_DB / SAI ACL objects if visible
  -> packet behavior if the VS topology supports traffic injection
```

## Quickstart

```bash
cd /Users/nandichandana/sonic-acl-validation-harness

./scripts/bringup.sh
python3 -m acl.acl_harness apply --rule drop_https
python3 -m acl.acl_harness validate
python3 -m acl.acl_harness status
python3 -m acl.acl_harness cleanup
```

Direct-script invocation is also supported:

```bash
python3 acl/acl_harness.py apply --rule drop_https
python3 acl/acl_harness.py validate
python3 acl/acl_harness.py status
python3 acl/acl_harness.py cleanup
```

End-to-end flow with ASIC_DB delta validation (apply -> validate -> cleanup
in one command):

```bash
python3 -m acl.acl_harness flow
```

`flow` captures the baseline ACL_ENTRY keys in ASIC_DB before applying, then
identifies the scenario's entry by matching SAI attributes (priority,
`L4_DST_PORT`, `IP_PROTOCOL`, `PACKET_ACTION`), and finally verifies that
*that specific* entry disappears after cleanup. Pre-existing ACL table objects
are left alone.

To run the deterministic tests without docker:

```bash
python3 -m pytest -q
```

Packet checks are optional and require a reachable test path:

```bash
python3 -m acl.acl_harness validate --dst-ip 192.0.2.10 --iface veth0
```

## Expected Output Shape

`validate` output against `docker-sonic-vs-fixed:latest` after `apply`. APP_DB
ACL state is not visible in this VS image and is reported as `skip`. ASIC_DB
SAI ACL objects are visible and pass:

```text
CONFIG_DB ACL_TABLE: pass: present
CONFIG_DB ACL_RULE drop_https: pass: present
port_binding: pass: Ethernet4
stage: pass: INGRESS
type: pass: L3
priority: pass: 100
IP_PROTOCOL: pass: 6
L4_DST_PORT: pass: 443
PACKET_ACTION: pass: DROP
APP_DB ACL state: skip: not visible in this VS image
ASIC_DB SAI ACL objects: pass: tables=4 entries=1
packet tcp/443: skip: requires --dst-ip and --iface for this VS topology
packet tcp/80: skip: requires --dst-ip and --iface for this VS topology
verdict: pass
```

`flow` output, which adds ASIC_DB delta validation (identifies the scenario's
ACL entry by SAI attribute fingerprint and verifies that specific entry
disappears after cleanup):

```text
baseline ACL_ENTRY keys: 0
apply: pass
CONFIG_DB ACL_TABLE: pass: present
CONFIG_DB ACL_RULE drop_https: pass: present
port_binding: pass: Ethernet4
stage: pass: INGRESS
type: pass: L3
priority: pass: 100
IP_PROTOCOL: pass: 6
L4_DST_PORT: pass: 443
PACKET_ACTION: pass: DROP
ASIC_DB SAI ACL entry delta: pass: ASIC_STATE:SAI_OBJECT_TYPE_ACL_ENTRY:oid:0x80000000005e8
  SAI_ACL_ENTRY_ATTR_PRIORITY: 100
  SAI_ACL_ENTRY_ATTR_FIELD_L4_DST_PORT: 443&mask:0xffff
  SAI_ACL_ENTRY_ATTR_FIELD_IP_PROTOCOL: 6&mask:0xff
  SAI_ACL_ENTRY_ATTR_ACTION_PACKET_ACTION: SAI_PACKET_ACTION_DROP
cleanup: pass
ASIC_DB scenario entry removed: pass
verdict: pass
```

This is software-visible SAI object translation in SONiC VS, not proof of
hardware-backed ASIC enforcement.

## Helper Scripts

- `scripts/bringup.sh`: starts `sonic-vs-acl`
- `scripts/apply_acl.sh`: applies the ACL scenario
- `scripts/cleanup_acl.sh`: removes the ACL scenario
- `scripts/show_state.sh`: prints CONFIG_DB, APP_DB, and ASIC_DB ACL keys

## Fault Cases Covered

Deterministic fault-case coverage lives in `tests/`:

- missing ACL rule (`tests/test_acl_config.py::test_fault_missing_rule_fails_verdict`)
- wrong interface binding (`tests/test_acl_config.py::test_fault_wrong_port_binding_fails_verdict`)
- wrong table type (`tests/test_acl_config.py::test_fault_wrong_table_type_fails_verdict`)
- wrong priority (`tests/test_acl_config.py::test_fault_wrong_priority_fails_verdict`)
- wrong IP protocol (`tests/test_acl_config.py::test_fault_wrong_ip_protocol_fails_verdict`)
- wrong packet action (`tests/test_acl_config.py::test_fault_wrong_action_fails_verdict`)
- stale CONFIG_DB rule after cleanup (`tests/test_acl_cleanup.py::test_fault_stale_rule_after_cleanup_fails_verdict`)
- stale CONFIG_DB table after cleanup (`tests/test_acl_cleanup.py::test_fault_stale_table_after_cleanup_fails_verdict`)
- stale APP_DB state after cleanup (`tests/test_acl_cleanup.py::test_fault_stale_app_db_state_after_cleanup_fails_verdict`)

These exercise the pure evaluators (`evaluate_config_db_state` and
`evaluate_cleanup_state`) so they run without docker.

## Limitations

This project does not claim hardware-backed SAI validation. ASIC_DB keys inside
SONiC VS are useful evidence of software-visible SAI object translation only
when they are present. If ASIC_DB ACL objects are not visible, the harness marks
that check as skipped and documents the limitation.

Packet behavior is also topology-dependent. The harness can run Scapy probes
when a valid interface and destination are supplied, but it does not fabricate a
pass/fail result when no packet path is available.

## Role Relevance

The project maps to Cisco / SONiC / open networking roles by showing practical
work with ACL configuration, SONiC database inspection, orchagent and SAI
translation boundaries, deterministic Python validation, and honest treatment
of virtual-switch limitations.
