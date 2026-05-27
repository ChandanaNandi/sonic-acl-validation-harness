from acl.config import SCENARIO
from acl.db_checks import (
    compute_asic_entry_delta,
    evaluate_asic_acl_entry_attrs,
    expected_sai_action,
    find_scenario_entry,
    strip_sai_mask,
)


def _good_attrs() -> dict[str, str]:
    return {
        "SAI_ACL_ENTRY_ATTR_PRIORITY": "100",
        "SAI_ACL_ENTRY_ATTR_FIELD_L4_DST_PORT": "443&mask:0xffff",
        "SAI_ACL_ENTRY_ATTR_FIELD_IP_PROTOCOL": "6&mask:0xff",
        "SAI_ACL_ENTRY_ATTR_ACTION_PACKET_ACTION": "SAI_PACKET_ACTION_DROP",
    }


def test_strip_sai_mask_handles_present_and_absent_mask():
    assert strip_sai_mask("443&mask:0xffff") == "443"
    assert strip_sai_mask("6&mask:0xff") == "6"
    assert strip_sai_mask("443") == "443"
    assert strip_sai_mask(None) is None


def test_expected_sai_action_derives_from_scenario():
    assert expected_sai_action(SCENARIO) == "SAI_PACKET_ACTION_DROP"


def test_evaluate_asic_attrs_passes_on_live_observed_values():
    report = evaluate_asic_acl_entry_attrs(SCENARIO, _good_attrs())
    assert report.passed
    statuses = {c.name: c.status for c in report.checks}
    assert statuses["SAI priority"] == "pass"
    assert statuses["SAI L4_DST_PORT"] == "pass"
    assert statuses["SAI IP_PROTOCOL"] == "pass"
    assert statuses["SAI PACKET_ACTION"] == "pass"


def test_evaluate_asic_attrs_passes_when_mask_suffix_absent():
    attrs = _good_attrs() | {
        "SAI_ACL_ENTRY_ATTR_FIELD_L4_DST_PORT": "443",
        "SAI_ACL_ENTRY_ATTR_FIELD_IP_PROTOCOL": "6",
    }
    assert evaluate_asic_acl_entry_attrs(SCENARIO, attrs).passed


def test_fault_wrong_sai_priority_fails():
    attrs = _good_attrs() | {"SAI_ACL_ENTRY_ATTR_PRIORITY": "50"}
    report = evaluate_asic_acl_entry_attrs(SCENARIO, attrs)
    assert not report.passed
    statuses = {c.name: c.status for c in report.checks}
    assert statuses["SAI priority"] == "fail"


def test_fault_wrong_sai_l4_dst_port_fails():
    attrs = _good_attrs() | {"SAI_ACL_ENTRY_ATTR_FIELD_L4_DST_PORT": "80&mask:0xffff"}
    report = evaluate_asic_acl_entry_attrs(SCENARIO, attrs)
    assert not report.passed
    statuses = {c.name: c.status for c in report.checks}
    assert statuses["SAI L4_DST_PORT"] == "fail"


def test_fault_wrong_sai_ip_protocol_fails():
    attrs = _good_attrs() | {"SAI_ACL_ENTRY_ATTR_FIELD_IP_PROTOCOL": "17&mask:0xff"}
    report = evaluate_asic_acl_entry_attrs(SCENARIO, attrs)
    assert not report.passed
    statuses = {c.name: c.status for c in report.checks}
    assert statuses["SAI IP_PROTOCOL"] == "fail"


def test_fault_wrong_sai_packet_action_fails():
    attrs = _good_attrs() | {"SAI_ACL_ENTRY_ATTR_ACTION_PACKET_ACTION": "SAI_PACKET_ACTION_FORWARD"}
    report = evaluate_asic_acl_entry_attrs(SCENARIO, attrs)
    assert not report.passed
    statuses = {c.name: c.status for c in report.checks}
    assert statuses["SAI PACKET_ACTION"] == "fail"


def test_fault_missing_sai_attrs_fail_with_missing_detail():
    report = evaluate_asic_acl_entry_attrs(SCENARIO, {})
    assert not report.passed
    details = {c.name: c.detail for c in report.checks}
    assert details["SAI priority"] == "missing"
    assert details["SAI L4_DST_PORT"] == "missing"
    assert details["SAI IP_PROTOCOL"] == "missing"
    assert details["SAI PACKET_ACTION"] == "missing"


def test_compute_asic_entry_delta_returns_only_new_keys():
    pre = ["ASIC_STATE:SAI_OBJECT_TYPE_ACL_ENTRY:oid:0xAAA"]
    post = [
        "ASIC_STATE:SAI_OBJECT_TYPE_ACL_ENTRY:oid:0xAAA",
        "ASIC_STATE:SAI_OBJECT_TYPE_ACL_ENTRY:oid:0xBBB",
    ]
    assert compute_asic_entry_delta(pre, post) == [
        "ASIC_STATE:SAI_OBJECT_TYPE_ACL_ENTRY:oid:0xBBB"
    ]


def test_compute_asic_entry_delta_empty_when_no_new_keys():
    pre = ["ASIC_STATE:SAI_OBJECT_TYPE_ACL_ENTRY:oid:0xAAA"]
    post = list(pre)
    assert compute_asic_entry_delta(pre, post) == []


def test_find_scenario_entry_returns_matching_key():
    other = {
        "SAI_ACL_ENTRY_ATTR_PRIORITY": "9999",
        "SAI_ACL_ENTRY_ATTR_FIELD_L4_DST_PORT": "22&mask:0xffff",
        "SAI_ACL_ENTRY_ATTR_FIELD_IP_PROTOCOL": "6&mask:0xff",
        "SAI_ACL_ENTRY_ATTR_ACTION_PACKET_ACTION": "SAI_PACKET_ACTION_FORWARD",
    }
    candidates = {"oid:0xAAA": other, "oid:0xBBB": _good_attrs()}
    assert find_scenario_entry(SCENARIO, candidates) == "oid:0xBBB"


def test_find_scenario_entry_returns_none_when_no_match():
    other = {
        "SAI_ACL_ENTRY_ATTR_PRIORITY": "9999",
        "SAI_ACL_ENTRY_ATTR_FIELD_L4_DST_PORT": "22&mask:0xffff",
        "SAI_ACL_ENTRY_ATTR_FIELD_IP_PROTOCOL": "6&mask:0xff",
        "SAI_ACL_ENTRY_ATTR_ACTION_PACKET_ACTION": "SAI_PACKET_ACTION_FORWARD",
    }
    candidates = {"oid:0xAAA": other}
    assert find_scenario_entry(SCENARIO, candidates) is None
