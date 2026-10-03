
"""
Tests for the Network IDS hybrid detection engine.
"""

import pandas as pd
import pytest

from ids.hybrid_engine import (
    aggregate_anomaly_alerts,
    aggregate_signature_alerts,
    calculate_anomaly_score,
    calculate_ml_score,
    calculate_risk_score,
    calculate_signature_score,
    classify_risk,
)


# --------------------------------------------------
# SIGNATURE SCORE TESTS
# --------------------------------------------------

def test_signature_score_is_zero_without_matched_rules():
    assert calculate_signature_score([]) == 0


def test_signature_score_for_low_severity():
    assert calculate_signature_score(
        [{"severity": "LOW"}]
    ) == 10


def test_signature_score_for_medium_severity():
    assert calculate_signature_score(
        [{"severity": "MEDIUM"}]
    ) == 20


def test_signature_score_for_high_severity():
    assert calculate_signature_score(
        [{"severity": "HIGH"}]
    ) == 30


def test_signature_score_for_critical_severity():
    assert calculate_signature_score(
        [{"severity": "CRITICAL"}]
    ) == 40


def test_signature_score_is_capped_at_40():
    score = calculate_signature_score(
        [
            {"severity": "CRITICAL"},
            {"severity": "CRITICAL"},
        ]
    )
    assert score == 40


# --------------------------------------------------
# ANOMALY SCORE TESTS
# --------------------------------------------------

def test_anomaly_score_for_low_severity():
    assert calculate_anomaly_score(
        {"severity": "LOW"}
    ) == 10


def test_anomaly_score_for_medium_severity():
    assert calculate_anomaly_score(
        {"severity": "MEDIUM"}
    ) == 18


def test_anomaly_score_for_high_severity():
    assert calculate_anomaly_score(
        {"severity": "HIGH"}
    ) == 25


def test_anomaly_score_is_zero_without_anomaly():
    assert calculate_anomaly_score(None) == 0


def test_anomaly_score_is_capped_at_25():
    assert calculate_anomaly_score(
        {"severity": "HIGH"}
    ) == 25


# --------------------------------------------------
# MACHINE LEARNING SCORE TESTS
# --------------------------------------------------

def test_ml_score_is_zero_without_predictions():
    assert calculate_ml_score({}) == 0


def test_ml_score_is_35_when_all_models_vote_positive():
    predictions = {
        "logistic_regression": 1,
        "random_forest": 1,
        "isolation_forest": 1,
    }

    assert calculate_ml_score(predictions) == 35


def test_ml_score_is_zero_when_all_models_vote_negative():
    predictions = {
        "logistic_regression": 0,
        "random_forest": 0,
        "isolation_forest": 0,
    }

    assert calculate_ml_score(predictions) == 0


def test_ml_score_uses_average_model_vote():
    predictions = {
        "logistic_regression": 1,
        "random_forest": 0,
        "isolation_forest": 1,
    }

    assert calculate_ml_score(predictions) == 23


# --------------------------------------------------
# HYBRID RISK SCORE TESTS
# --------------------------------------------------

def test_risk_score_combines_all_detection_sources():
    result = calculate_risk_score(
        matched_rules=[{"severity": "HIGH"}],
        anomaly={"severity": "MEDIUM"},
        ml_predictions={
            "logistic_regression": 1,
            "random_forest": 1,
            "isolation_forest": 1,
        },
    )

    assert result["signature_score"] == 30
    assert result["anomaly_score"] == 18
    assert result["ml_score"] == 35
    assert result["risk_score"] == 83


def test_risk_score_is_capped_at_100():
    result = calculate_risk_score(
        matched_rules=[
            {"severity": "CRITICAL"},
            {"severity": "CRITICAL"},
        ],
        anomaly={"severity": "HIGH"},
        ml_predictions={
            "logistic_regression": 1,
            "random_forest": 1,
            "isolation_forest": 1,
        },
    )

    assert result["risk_score"] == 100


def test_risk_score_is_zero_without_detection_evidence():
    result = calculate_risk_score(
        matched_rules=[],
        anomaly=None,
        ml_predictions={},
    )

    assert result["signature_score"] == 0
    assert result["anomaly_score"] == 0
    assert result["ml_score"] == 0
    assert result["risk_score"] == 0


# --------------------------------------------------
# RISK CLASSIFICATION TESTS
# --------------------------------------------------

@pytest.mark.parametrize(
    ("score", "expected"),
    [
        (0, "INFO"),
        (24, "INFO"),
        (25, "LOW"),
        (49, "LOW"),
        (50, "MEDIUM"),
        (74, "MEDIUM"),
        (75, "HIGH"),
        (100, "HIGH"),
    ],
)
def test_classify_risk(score, expected):
    assert classify_risk(score) == expected


# --------------------------------------------------
# SIGNATURE ALERT AGGREGATION TESTS
# --------------------------------------------------

def test_aggregate_signature_alerts_groups_by_flow():
    signatures = pd.DataFrame(
        [
            {
                "flow_id": "FLOW-001",
                "rule_id": "RULE-001",
                "rule_name": "High Packet Count",
                "severity": "HIGH",
            },
            {
                "flow_id": "FLOW-001",
                "rule_id": "RULE-002",
                "rule_name": "Unusual Port",
                "severity": "MEDIUM",
            },
            {
                "flow_id": "FLOW-002",
                "rule_id": "RULE-003",
                "rule_name": "High Byte Count",
                "severity": "LOW",
            },
        ]
    )

    result = aggregate_signature_alerts(signatures)

    assert len(result) == 2
    assert "FLOW-001" in result
    assert "FLOW-002" in result

    assert len(result["FLOW-001"]) == 2
    assert result["FLOW-001"][0]["rule_id"] == "RULE-001"
    assert result["FLOW-001"][0]["severity"] == "HIGH"


def test_aggregate_signature_alerts_returns_empty_for_no_alerts():
    signatures = pd.DataFrame()

    assert aggregate_signature_alerts(signatures) == {}


def test_aggregate_signature_alerts_rejects_missing_required_column():
    signatures = pd.DataFrame(
        [
            {
                "flow_id": "FLOW-001",
                "rule_id": "RULE-001",
            }
        ]
    )

    with pytest.raises(ValueError):
        aggregate_signature_alerts(signatures)


# --------------------------------------------------
# ANOMALY ALERT AGGREGATION TESTS
# --------------------------------------------------

def test_aggregate_anomaly_alerts_groups_by_flow():
    anomalies = pd.DataFrame(
        [
            {
                "flow_id": "FLOW-001",
                "severity": "HIGH",
                "highest_absolute_z_score": 4.5,
            },
            {
                "flow_id": "FLOW-002",
                "severity": "MEDIUM",
                "highest_absolute_z_score": 3.2,
            },
        ]
    )

    result = aggregate_anomaly_alerts(anomalies)

    assert len(result) == 2
    assert "FLOW-001" in result
    assert "FLOW-002" in result

    assert result["FLOW-001"]["severity"] == "HIGH"
    assert result["FLOW-001"]["highest_absolute_z_score"] == 4.5


def test_aggregate_anomaly_alerts_returns_empty_for_no_alerts():
    anomalies = pd.DataFrame()

    assert aggregate_anomaly_alerts(anomalies) == {}


def test_aggregate_anomaly_alerts_rejects_missing_required_column():
    anomalies = pd.DataFrame(
        [
            {
                "flow_id": "FLOW-001",
            }
        ]
    )

    with pytest.raises(ValueError):
        aggregate_anomaly_alerts(anomalies)