from acl.config import SCENARIO
from acl.db_checks import evaluate_cleanup_state


def test_scenario_keys_match_sonic_config_db_shape():
    assert SCENARIO.table_key == "ACL_TABLE|DATAACL"
    assert SCENARIO.rule_key == "ACL_RULE|DATAACL|drop_https"


def test_cleanup_order_removes_rule_before_table():
    cleanup_keys = [SCENARIO.rule_key, SCENARIO.table_key]

    assert cleanup_keys == ["ACL_RULE|DATAACL|drop_https", "ACL_TABLE|DATAACL"]


def test_cleanup_passes_when_state_is_fully_removed():
    report = evaluate_cleanup_state(rule_present=False, table_present=False, stale_app_keys=[])
    assert report.passed


def test_fault_stale_rule_after_cleanup_fails_verdict():
    report = evaluate_cleanup_state(rule_present=True, table_present=False, stale_app_keys=[])
    assert not report.passed
    statuses = {c.name: c.status for c in report.checks}
    assert statuses["cleanup CONFIG_DB ACL_RULE"] == "fail"


def test_fault_stale_table_after_cleanup_fails_verdict():
    report = evaluate_cleanup_state(rule_present=False, table_present=True, stale_app_keys=[])
    assert not report.passed
    statuses = {c.name: c.status for c in report.checks}
    assert statuses["cleanup CONFIG_DB ACL_TABLE"] == "fail"


def test_fault_stale_app_db_state_after_cleanup_fails_verdict():
    report = evaluate_cleanup_state(
        rule_present=False,
        table_present=False,
        stale_app_keys=["ACL_TABLE_TABLE:DATAACL"],
    )
    assert not report.passed
    statuses = {c.name: c.status for c in report.checks}
    assert statuses["cleanup APP_DB stale ACL state"] == "fail"
