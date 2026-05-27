# Findings

## Initial Scope

The first version validates the ACL configuration path and cleanup behavior for
a single rule:

- table: `DATAACL`
- bind port: `Ethernet4`
- rule: `drop_https`
- action: drop TCP destination port `443`

## Deterministic Checks

The deterministic checks are:

- CONFIG_DB table exists
- CONFIG_DB rule exists
- interface binding is `Ethernet4`
- ACL table type is `L3`
- rule priority is `100`
- IP protocol is `6` for TCP
- rule action is `DROP`
- cleanup removes both ACL rule and table keys

## Conditional Checks

APP_DB, ASIC_DB, and packet behavior are environment-dependent in SONiC VS.
The harness reports these as observed, skipped, or failed based on what is
actually visible at runtime.

## Current Limitation

The project does not claim hardware SAI validation. ASIC_DB visibility in a VS
container is useful for understanding SONiC-to-SAI object translation, but it is
not evidence that a physical ASIC installed or enforced the rule.

## Local SONiC VS Observation

Run date: 2026-05-27

Image and container:

- image: `docker-sonic-vs-fixed:latest`
- container: `sonic-vs-acl`

Observed CONFIG_DB shape after apply:

```text
ACL_TABLE|DATAACL
{'policy_desc': 'drop TCP destination port 443 on Ethernet4', 'ports@': 'Ethernet4', 'stage': 'INGRESS', 'type': 'L3'}

ACL_RULE|DATAACL|drop_https
{'IP_PROTOCOL': '6', 'L4_DST_PORT': '443', 'PACKET_ACTION': 'DROP', 'PRIORITY': '100'}
```

Observed APP_DB state:

- no `DATAACL` keys were visible in APP_DB for this image.

Observed ASIC_DB state after apply:

```text
ASIC_STATE:SAI_OBJECT_TYPE_ACL_ENTRY:oid:0x80000000005e3
```

The ACL entry attributes showed:

```text
SAI_ACL_ENTRY_ATTR_PRIORITY: 100
SAI_ACL_ENTRY_ATTR_FIELD_L4_DST_PORT: 443&mask:0xffff
SAI_ACL_ENTRY_ATTR_FIELD_IP_PROTOCOL: 6&mask:0xff
SAI_ACL_ENTRY_ATTR_ACTION_PACKET_ACTION: SAI_PACKET_ACTION_DROP
```

## SAI Attribute Mapping

Each CONFIG_DB field for the rule mapped one-to-one to a SAI ACL entry
attribute observed in ASIC_DB during this run:

| CONFIG_DB field (ACL_RULE) | SAI attribute                              | Observed value          |
| -------------------------- | ------------------------------------------ | ----------------------- |
| `PRIORITY: 100`            | `SAI_ACL_ENTRY_ATTR_PRIORITY`              | `100`                   |
| `L4_DST_PORT: 443`         | `SAI_ACL_ENTRY_ATTR_FIELD_L4_DST_PORT`     | `443&mask:0xffff`       |
| `IP_PROTOCOL: 6`           | `SAI_ACL_ENTRY_ATTR_FIELD_IP_PROTOCOL`     | `6&mask:0xff`           |
| `PACKET_ACTION: DROP`      | `SAI_ACL_ENTRY_ATTR_ACTION_PACKET_ACTION`  | `SAI_PACKET_ACTION_DROP`|

The `&mask:...` suffix on the field attributes reflects SAI's ternary
match model: each field carries a value and a bitmask. `0xffff` on the L4
destination port and `0xff` on the IP protocol indicate exact match on
the full field width. The action attribute is a SAI enum rather than a
masked field, so no mask is reported.

This mapping is the practical evidence that SONiC orchagent translated
the CONFIG_DB intent into SAI ACL objects in this image. It is not
evidence of hardware enforcement; ASIC_DB inside SONiC VS is a
software-visible database, not a real ASIC.

After cleanup:

- `ACL_TABLE|DATAACL` was removed from CONFIG_DB.
- `ACL_RULE|DATAACL|drop_https` was removed from CONFIG_DB.
- no `DATAACL` APP_DB keys were visible.
- the applied ASIC_DB ACL entry was removed.
- a baseline `SAI_OBJECT_TYPE_ACL_TABLE` object remained, which appears to be image/default state rather than this scenario's rule.
