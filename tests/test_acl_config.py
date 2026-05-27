import json

from acl.config import SCENARIO
from acl.db_checks import evaluate_config_db_state, field_matches, parse_hgetall_output, render_acl_json


def _good_table() -> dict[str, str]:
    return {
        "policy_desc": "drop TCP destination port 443 on Ethernet4",
        "type": "L3",
        "ports": '["Ethernet4"]',
        "stage": "INGRESS",
    }


def _good_rule() -> dict[str, str]:
    return {
        "PRIORITY": "100",
        "PACKET_ACTION": "DROP",
        "IP_PROTOCOL": "6",
        "L4_DST_PORT": "443",
    }


def test_acl_config_contains_expected_table_binding():
    payload = json.loads(render_acl_json(SCENARIO))

    table = payload["ACL_TABLE"]["DATAACL"]

    assert table["type"] == "L3"
    assert table["stage"] == "INGRESS"
    assert table["ports"] == ["Ethernet4"]


def test_acl_config_contains_drop_https_rule():
    payload = json.loads(render_acl_json(SCENARIO))

    rule = payload["ACL_RULE"]["DATAACL|drop_https"]

    assert rule["PRIORITY"] == "100"
    assert rule["PACKET_ACTION"] == "DROP"
    assert rule["IP_PROTOCOL"] == "6"
    assert rule["L4_DST_PORT"] == "443"


def test_port_binding_accepts_sonic_serialized_list():
    assert field_matches('["Ethernet4"]', "Ethernet4")
    assert field_matches("Ethernet4", "Ethernet4")
    assert not field_matches('["Ethernet8"]', "Ethernet4")


def test_port_binding_accepts_comma_separated_form():
    assert field_matches("Ethernet4,", "Ethernet4")
    assert field_matches(" Ethernet4 ", "Ethernet4")
    assert not field_matches("Ethernet0,Ethernet4", "Ethernet4")
    assert not field_matches("Ethernet4,Ethernet8", "Ethernet4")


def test_port_binding_accepts_at_separated_form():
    assert field_matches("Ethernet4@", "Ethernet4")
    assert not field_matches("Ethernet0@Ethernet4", "Ethernet4")
    assert not field_matches("Ethernet4@Ethernet8", "Ethernet4")


def test_hgetall_parser_accepts_raw_line_pairs():
    output = 'ports\n["Ethernet4"]\nstage\nINGRESS\n'

    assert parse_hgetall_output(output) == {"ports": '["Ethernet4"]', "stage": "INGRESS"}


def test_hgetall_parser_accepts_redis_numbered_lines():
    output = '1) "ports"\n2) "[\\"Ethernet4\\"]"\n3) "stage"\n4) "INGRESS"\n'

    assert parse_hgetall_output(output) == {"ports": '["Ethernet4"]', "stage": "INGRESS"}


def test_hgetall_parser_accepts_python_dict_shape_from_sonic_db_cli():
    output = "{'policy_desc': 'drop TCP destination port 443 on Ethernet4', 'ports@': 'Ethernet4', 'stage': 'INGRESS'}\n"

    assert parse_hgetall_output(output) == {
        "policy_desc": "drop TCP destination port 443 on Ethernet4",
        "ports@": "Ethernet4",
        "stage": "INGRESS",
    }


def test_evaluate_passes_on_good_state():
    report = evaluate_config_db_state(SCENARIO, _good_table(), _good_rule())
    assert report.passed
    statuses = {c.name: c.status for c in report.checks}
    assert statuses["CONFIG_DB ACL_TABLE"] == "pass"
    assert statuses["CONFIG_DB ACL_RULE drop_https"] == "pass"
    assert statuses["port_binding"] == "pass"
    assert statuses["type"] == "pass"
    assert statuses["priority"] == "pass"
    assert statuses["IP_PROTOCOL"] == "pass"
    assert statuses["L4_DST_PORT"] == "pass"
    assert statuses["PACKET_ACTION"] == "pass"


def test_evaluate_accepts_ports_at_field_from_sonic_db_cli():
    table = _good_table()
    table.pop("ports")
    table["ports@"] = "Ethernet4"

    report = evaluate_config_db_state(SCENARIO, table, _good_rule())

    assert report.passed
    statuses = {c.name: c.status for c in report.checks}
    assert statuses["port_binding"] == "pass"


def test_fault_missing_rule_fails_verdict():
    report = evaluate_config_db_state(SCENARIO, _good_table(), {})
    assert not report.passed
    statuses = {c.name: c.status for c in report.checks}
    assert statuses["CONFIG_DB ACL_RULE drop_https"] == "fail"


def test_fault_wrong_port_binding_fails_verdict():
    table = _good_table() | {"ports": '["Ethernet8"]'}
    report = evaluate_config_db_state(SCENARIO, table, _good_rule())
    assert not report.passed
    statuses = {c.name: c.status for c in report.checks}
    assert statuses["port_binding"] == "fail"


def test_fault_wrong_priority_fails_verdict():
    rule = _good_rule() | {"PRIORITY": "50"}
    report = evaluate_config_db_state(SCENARIO, _good_table(), rule)
    assert not report.passed
    statuses = {c.name: c.status for c in report.checks}
    assert statuses["priority"] == "fail"


def test_fault_wrong_action_fails_verdict():
    rule = _good_rule() | {"PACKET_ACTION": "FORWARD"}
    report = evaluate_config_db_state(SCENARIO, _good_table(), rule)
    assert not report.passed
    statuses = {c.name: c.status for c in report.checks}
    assert statuses["PACKET_ACTION"] == "fail"


def test_fault_wrong_table_type_fails_verdict():
    table = _good_table() | {"type": "MIRROR"}
    report = evaluate_config_db_state(SCENARIO, table, _good_rule())
    assert not report.passed
    statuses = {c.name: c.status for c in report.checks}
    assert statuses["type"] == "fail"


def test_fault_wrong_ip_protocol_fails_verdict():
    rule = _good_rule() | {"IP_PROTOCOL": "17"}
    report = evaluate_config_db_state(SCENARIO, _good_table(), rule)
    assert not report.passed
    statuses = {c.name: c.status for c in report.checks}
    assert statuses["IP_PROTOCOL"] == "fail"
