# SONiC ACL State Flow

This project validates a single ACL scenario:

```text
intent: drop TCP destination port 443 on Ethernet4
  -> CONFIG_DB ACL_TABLE and ACL_RULE
  -> orchagent translates desired state
  -> APP_DB state if exposed by the image
  -> ASIC_DB SAI ACL objects if materialized and visible
  -> packet behavior if the local VS topology supports traffic injection
```

## CONFIG_DB

The harness writes this intended state through `sonic-cfggen --write-to-db`:

- `ACL_TABLE|DATAACL`
- `ACL_RULE|DATAACL|drop_https`
- table type: `L3`
- bound port: `Ethernet4`
- stage: `INGRESS`
- priority: `100`
- packet action: `DROP`
- IP protocol: `6` for TCP
- L4 destination port: `443`

CONFIG_DB validation is deterministic and is the source of truth for this first
version.

## APP_DB

SONiC ACL orchagent behavior depends on the image and services running inside
the VS container. The harness searches APP_DB for ACL keys matching `DATAACL`.
If it finds translated state, it reports the keys. If not, the check is marked
`skip` rather than `fail`.

## ASIC_DB and SAI Boundary

ASIC_DB may expose keys such as:

- `ASIC_STATE:SAI_OBJECT_TYPE_ACL_TABLE:*`
- `ASIC_STATE:SAI_OBJECT_TYPE_ACL_ENTRY:*`

In SONiC VS, these objects are software-visible database artifacts, not proof
of hardware-backed forwarding. This project reports their presence only as
conditional SAI object visibility.

## Packet Behavior

The packet check is optional because SONiC VS wiring differs by environment.
When `--dst-ip` and `--iface` are provided, Scapy sends TCP SYN probes:

- TCP/443 should be dropped
- TCP/80 should be permitted

Without a known reachable dataplane path, packet checks are marked `skip`.

