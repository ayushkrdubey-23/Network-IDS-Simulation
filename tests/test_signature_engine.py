
"""
Tests for the Network IDS signature detection engine.
"""

import json

import pytest

from ids.signature_engine import (
    detect_record,
    load_rules,
    matches_rule,
)


def make_rule(
    rule_id="TEST-001",
    field="packet_count",
    operator="greater_than",
    threshold=100,
    enabled=True,
):
    """Return a valid signature rule."""

    return {
        "rule_id": rule_id,
        "name": "Test Signature Rule",
        "description": "A rule created for automated testing.",
        "field": field,
        "operator": operator,
        "threshold": threshold,
        "severity": "HIGH",
        "enabled": enabled,
    }


def write_rules(path, rules):
    """Save rules in the expected JSON structure."""

    with path.open("w", encoding="utf-8") as file:
        json.dump({"rules": rules}, file)


def test_load_rules_reads_valid_rules(tmp_path):
    path = tmp_path / "rules.json"
    rules = [make_rule()]

    write_rules(path, rules)

    loaded_rules = load_rules(path)

    assert len(loaded_rules) == 1
    assert loaded_rules[0]["rule_id"] == "TEST-001"


def test_load_rules_rejects_missing_rules_list(tmp_path):
    path = tmp_path / "rules.json"

    with path.open("w", encoding="utf-8") as file:
        json.dump({}, file)

    with pytest.raises(ValueError):
        load_rules(path)


def test_load_rules_rejects_duplicate_rule_ids(tmp_path):
    path = tmp_path / "rules.json"

    write_rules(
        path,
        [
            make_rule(rule_id="DUPLICATE"),
            make_rule(rule_id="DUPLICATE", field="byte_count"),
        ],
    )

    with pytest.raises(ValueError):
        load_rules(path)


@pytest.mark.parametrize(
    "missing_field",
    [
        "rule_id",
        "name",
        "description",
        "field",
        "operator",
        "threshold",
        "severity",
        "enabled",
    ],
)
def test_load_rules_rejects_missing_required_properties(
    tmp_path,
    missing_field,
):
    path = tmp_path / "rules.json"
    rule = make_rule()
    del rule[missing_field]

    write_rules(path, [rule])

    with pytest.raises(ValueError):
        load_rules(path)


def test_load_rules_rejects_unsupported_operator(tmp_path):
    path = tmp_path / "rules.json"
    rule = make_rule(operator="not_equal")

    write_rules(path, [rule])

    with pytest.raises(ValueError):
        load_rules(path)


def test_load_rules_rejects_non_boolean_enabled_value(tmp_path):
    path = tmp_path / "rules.json"
    rule = make_rule()
    rule["enabled"] = "yes"

    write_rules(path, [rule])

    with pytest.raises(ValueError):
        load_rules(path)


def test_load_rules_rejects_non_list_in_threshold(tmp_path):
    path = tmp_path / "rules.json"
    rule = make_rule(operator="in", threshold=443)

    write_rules(path, [rule])

    with pytest.raises(ValueError):
        load_rules(path)


@pytest.mark.parametrize(
    ("value", "operator", "threshold", "expected"),
    [
        (150, "greater_than", 100, True),
        (50, "greater_than", 100, False),
        (50, "less_than", 100, True),
        (150, "less_than", 100, False),
        ("TCP", "equals", "TCP", True),
        ("UDP", "equals", "TCP", False),
        (443, "in", [80, 443, 8080], True),
        (22, "in", [80, 443, 8080], False),
        ("invalid", "greater_than", 100, False),
    ],
)
def test_matches_rule(
    value,
    operator,
    threshold,
    expected,
):
    assert matches_rule(value, operator, threshold) is expected


def test_detect_record_returns_matching_rule():
    record = {
        "flow_id": "TEST-FLOW-001",
        "packet_count": 250,
    }
    rules = [make_rule(threshold=100)]

    alerts = detect_record(record, rules)

    assert len(alerts) == 1
    assert alerts[0]["rule_id"] == "TEST-001"


def test_detect_record_ignores_non_matching_rule():
    record = {
        "flow_id": "TEST-FLOW-002",
        "packet_count": 50,
    }
    rules = [make_rule(threshold=100)]

    alerts = detect_record(record, rules)

    assert alerts == []


def test_detect_record_ignores_disabled_rule():
    record = {
        "flow_id": "TEST-FLOW-003",
        "packet_count": 250,
    }
    rules = [make_rule(enabled=False)]

    alerts = detect_record(record, rules)

    assert alerts == []


def test_detect_record_ignores_rule_when_field_is_missing():
    record = {
        "flow_id": "TEST-FLOW-004",
        "byte_count": 5000,
    }
    rules = [make_rule(field="packet_count")]

    alerts = detect_record(record, rules)

    assert alerts == []


def test_detect_record_can_match_multiple_rules():
    record = {
        "flow_id": "TEST-FLOW-005",
        "packet_count": 250,
        "byte_count": 50000,
    }

    rules = [
        make_rule(
            rule_id="TEST-001",
            field="packet_count",
            threshold=100,
        ),
        make_rule(
            rule_id="TEST-002",
            field="byte_count",
            threshold=10000,
        ),
    ]

    alerts = detect_record(record, rules)

    assert len(alerts) == 2
    assert {alert["rule_id"] for alert in alerts} == {
        "TEST-001",
        "TEST-002",
    }
    