
"""
Automated tests for the Network IDS alert and incident service.
"""

import csv

import pytest

from backend.services import alert_service


# --------------------------------------------------
# ALERT RETRIEVAL TESTS
# --------------------------------------------------

def test_list_alerts_returns_all_seeded_alerts(database_with_alerts):
    alerts = alert_service.list_alerts()

    assert len(alerts) == 3


def test_list_alerts_filters_by_status(database_with_alerts):
    alert = database_with_alerts["alerts"][0]

    alert_service.update_alert_status(
        alert["id"],
        "INVESTIGATING",
    )

    results = alert_service.list_alerts(
        status="INVESTIGATING"
    )

    assert len(results) == 1
    assert results[0]["status"] == "INVESTIGATING"


def test_list_alerts_filters_by_risk_level(database_with_alerts):
    results = alert_service.list_alerts(
        risk_level="HIGH"
    )

    assert len(results) == 1
    assert results[0]["risk_level"] == "HIGH"


def test_list_alerts_supports_limit(database_with_alerts):
    results = alert_service.list_alerts(limit=1)

    assert len(results) == 1


def test_list_alerts_supports_offset(database_with_alerts):
    all_alerts = alert_service.list_alerts()

    results = alert_service.list_alerts(
        limit=1,
        offset=1,
    )

    assert len(results) == 1
    assert results[0]["id"] == all_alerts[1]["id"]


def test_get_alert_returns_existing_alert(database_with_alerts):
    alert = database_with_alerts["alerts"][0]

    result = alert_service.get_alert(alert["id"])

    assert result is not None
    assert result["id"] == alert["id"]


def test_get_alert_returns_none_for_missing_id(database_with_alerts):
    assert alert_service.get_alert(99999) is None


# --------------------------------------------------
# ALERT STATUS TESTS
# --------------------------------------------------

def test_update_alert_status_successfully(database_with_alerts):
    alert = database_with_alerts["alerts"][0]

    result = alert_service.update_alert_status(
        alert["id"],
        "RESOLVED",
    )

    updated = alert_service.get_alert(alert["id"])

    assert result is True
    assert updated["status"] == "RESOLVED"


def test_update_alert_status_saves_analyst_notes(database_with_alerts):
    alert = database_with_alerts["alerts"][0]

    notes = "Reviewed synthetic traffic record."

    alert_service.update_alert_status(
        alert["id"],
        "INVESTIGATING",
        notes,
    )

    updated = alert_service.get_alert(alert["id"])

    assert updated["analyst_notes"] == notes
    assert updated["status"] == "INVESTIGATING"


def test_update_status_without_notes_preserves_existing_notes(
    database_with_alerts,
):
    alert = database_with_alerts["alerts"][0]

    alert_service.update_alert_status(
        alert["id"],
        "INVESTIGATING",
        "Initial analyst review.",
    )

    alert_service.update_alert_status(
        alert["id"],
        "RESOLVED",
    )

    updated = alert_service.get_alert(alert["id"])

    assert updated["status"] == "RESOLVED"
    assert updated["analyst_notes"] == "Initial analyst review."


def test_update_alert_status_rejects_invalid_status(database_with_alerts):
    alert = database_with_alerts["alerts"][0]

    with pytest.raises(ValueError):
        alert_service.update_alert_status(
            alert["id"],
            "INVALID_STATUS",
        )


def test_update_alert_status_returns_false_for_missing_alert(
    database_with_alerts,
):
    result = alert_service.update_alert_status(
        99999,
        "RESOLVED",
    )

    assert result is False


# --------------------------------------------------
# INCIDENT MANAGEMENT TESTS
# --------------------------------------------------

def test_create_incident_returns_id(database_with_alerts):
    incident_id = alert_service.create_incident(
        "Synthetic Traffic Investigation",
        "Investigate a simulated high-risk traffic flow.",
        "HIGH",
    )

    assert isinstance(incident_id, int)
    assert incident_id > 0


@pytest.mark.parametrize(
    "severity",
    ["LOW", "MEDIUM", "HIGH", "CRITICAL"],
)
def test_create_incident_accepts_valid_severities(
    database_with_alerts,
    severity,
):
    incident_id = alert_service.create_incident(
        "Test Incident",
        "Testing valid severity.",
        severity,
    )

    assert incident_id > 0


def test_create_incident_rejects_invalid_severity(database_with_alerts):
    with pytest.raises(ValueError):
        alert_service.create_incident(
            "Invalid Incident",
            "Testing invalid severity.",
            "INFO",
        )


def test_link_alert_to_incident_successfully(database_with_alerts):
    alert = database_with_alerts["alerts"][0]

    incident_id = alert_service.create_incident(
        "Alert Investigation",
        "Linked synthetic alert.",
        "HIGH",
    )

    result = alert_service.link_alert_to_incident(
        incident_id,
        alert["id"],
    )

    assert result is True


def test_link_alert_to_incident_rejects_missing_incident(
    database_with_alerts,
):
    alert = database_with_alerts["alerts"][0]

    result = alert_service.link_alert_to_incident(
        99999,
        alert["id"],
    )

    assert result is False


def test_link_alert_to_incident_rejects_missing_alert(
    database_with_alerts,
):
    incident_id = alert_service.create_incident(
        "Alert Investigation",
        "Testing missing alert.",
        "MEDIUM",
    )

    result = alert_service.link_alert_to_incident(
        incident_id,
        99999,
    )

    assert result is False


def test_linking_same_alert_twice_is_safe(database_with_alerts):
    alert = database_with_alerts["alerts"][0]

    incident_id = alert_service.create_incident(
        "Duplicate Link Test",
        "Testing repeated link operation.",
        "LOW",
    )

    first_result = alert_service.link_alert_to_incident(
        incident_id,
        alert["id"],
    )

    second_result = alert_service.link_alert_to_incident(
        incident_id,
        alert["id"],
    )

    assert first_result is True
    assert second_result is True


# --------------------------------------------------
# ALERT STATISTICS TESTS
# --------------------------------------------------

def test_statistics_returns_total_alert_count(database_with_alerts):
    statistics = alert_service.get_alert_statistics()

    assert statistics["total_alerts"] == 3


def test_statistics_counts_flagged_alerts(database_with_alerts):
    statistics = alert_service.get_alert_statistics()

    # HIGH and MEDIUM are flagged.
    # INFO is not included.
    assert statistics["flagged_alerts"] == 2


def test_statistics_groups_alerts_by_risk(database_with_alerts):
    statistics = alert_service.get_alert_statistics()

    assert statistics["by_risk"]["HIGH"] == 1
    assert statistics["by_risk"]["MEDIUM"] == 1
    assert statistics["by_risk"]["INFO"] == 1


def test_statistics_groups_alerts_by_status(database_with_alerts):
    statistics = alert_service.get_alert_statistics()

    assert statistics["by_status"]["NEW"] == 3


# --------------------------------------------------
# CSV IMPORT TESTS
# --------------------------------------------------

def test_import_hybrid_alerts_rejects_missing_file(
    database_with_alerts,
    tmp_path,
):
    missing_file = tmp_path / "missing.csv"

    with pytest.raises(FileNotFoundError):
        alert_service.import_hybrid_alerts(missing_file)


def test_import_hybrid_alerts_rejects_missing_columns(
    database_with_alerts,
    tmp_path,
):
    csv_path = tmp_path / "invalid_columns.csv"

    with csv_path.open(
        "w",
        newline="",
        encoding="utf-8",
    ) as file:
        writer = csv.writer(file)
        writer.writerow(["flow_id", "risk_level"])
        writer.writerow(["FLOW-TEST", "HIGH"])

    with pytest.raises(ValueError):
        alert_service.import_hybrid_alerts(csv_path)


def test_import_hybrid_alerts_rejects_invalid_risk_level(
    database_with_alerts,
    tmp_path,
):
    csv_path = tmp_path / "invalid_risk.csv"

    fieldnames = [
        "flow_id",
        "timestamp",
        "source_ip",
        "destination_ip",
        "label",
        "scenario_type",
        "risk_score",
        "risk_level",
        "signature_matches",
        "is_anomaly",
    ]

    row = {
        "flow_id": "INVALID-RISK-001",
        "timestamp": "2026-10-03T11:00:00",
        "source_ip": "192.0.2.40",
        "destination_ip": "203.0.113.40",
        "label": "SUSPICIOUS",
        "scenario_type": "TEST",
        "risk_score": 80,
        "risk_level": "CRITICAL",
        "signature_matches": 1,
        "is_anomaly": "True",
    }

    with csv_path.open(
        "w",
        newline="",
        encoding="utf-8",
    ) as file:
        writer = csv.DictWriter(
            file,
            fieldnames=fieldnames,
        )
        writer.writeheader()
        writer.writerow(row)

    with pytest.raises(ValueError):
        alert_service.import_hybrid_alerts(csv_path)


def test_import_hybrid_alerts_rejects_invalid_label(
    database_with_alerts,
    tmp_path,
):
    csv_path = tmp_path / "invalid_label.csv"

    fieldnames = [
        "flow_id",
        "timestamp",
        "source_ip",
        "destination_ip",
        "label",
        "scenario_type",
        "risk_score",
        "risk_level",
        "signature_matches",
        "is_anomaly",
    ]

    row = {
        "flow_id": "INVALID-LABEL-001",
        "timestamp": "2026-10-03T11:00:00",
        "source_ip": "192.0.2.40",
        "destination_ip": "203.0.113.40",
        "label": "UNKNOWN",
        "scenario_type": "TEST",
        "risk_score": 80,
        "risk_level": "HIGH",
        "signature_matches": 1,
        "is_anomaly": "True",
    }

    with csv_path.open(
        "w",
        newline="",
        encoding="utf-8",
    ) as file:
        writer = csv.DictWriter(
            file,
            fieldnames=fieldnames,
        )
        writer.writeheader()
        writer.writerow(row)

    with pytest.raises(ValueError):
        alert_service.import_hybrid_alerts(csv_path)


def test_import_hybrid_alerts_rejects_out_of_range_score(
    database_with_alerts,
    tmp_path,
):
    csv_path = tmp_path / "invalid_score.csv"

    fieldnames = [
        "flow_id",
        "timestamp",
        "source_ip",
        "destination_ip",
        "label",
        "scenario_type",
        "risk_score",
        "risk_level",
        "signature_matches",
        "is_anomaly",
    ]

    row = {
        "flow_id": "INVALID-SCORE-001",
        "timestamp": "2026-10-03T11:00:00",
        "source_ip": "192.0.2.40",
        "destination_ip": "203.0.113.40",
        "label": "SUSPICIOUS",
        "scenario_type": "TEST",
        "risk_score": 120,
        "risk_level": "HIGH",
        "signature_matches": 1,
        "is_anomaly": "True",
    }

    with csv_path.open(
        "w",
        newline="",
        encoding="utf-8",
    ) as file:
        writer = csv.DictWriter(
            file,
            fieldnames=fieldnames,
        )
        writer.writeheader()
        writer.writerow(row)

    with pytest.raises(ValueError):
        alert_service.import_hybrid_alerts(csv_path)


def test_import_hybrid_alerts_updates_existing_flow(
    database_with_alerts,
    tmp_path,
):
    original_alert = database_with_alerts["alerts"][0]

    alert_service.update_alert_status(
        original_alert["id"],
        "INVESTIGATING",
        "Keep this analyst note.",
    )

    csv_path = tmp_path / "updated_alert.csv"

    fieldnames = [
        "flow_id",
        "timestamp",
        "source_ip",
        "destination_ip",
        "label",
        "scenario_type",
        "risk_score",
        "risk_level",
        "signature_matches",
        "is_anomaly",
    ]

    row = {
        "flow_id": original_alert["flow_id"],
        "timestamp": "2026-10-03T12:00:00",
        "source_ip": "192.0.2.10",
        "destination_ip": "203.0.113.10",
        "label": "SUSPICIOUS",
        "scenario_type": "UPDATED_TEST",
        "risk_score": 95,
        "risk_level": "HIGH",
        "signature_matches": 3,
        "is_anomaly": "True",
    }

    with csv_path.open(
        "w",
        newline="",
        encoding="utf-8",
    ) as file:
        writer = csv.DictWriter(
            file,
            fieldnames=fieldnames,
        )
        writer.writeheader()
        writer.writerow(row)

    imported_count = alert_service.import_hybrid_alerts(
        csv_path
    )

    updated_alert = alert_service.get_alert(
        original_alert["id"]
    )

    assert imported_count == 1
    assert updated_alert["risk_score"] == 95
    assert updated_alert["scenario_type"] == "UPDATED_TEST"

    # Importing an existing flow must preserve analyst workflow data.
    assert updated_alert["status"] == "INVESTIGATING"
    assert updated_alert["analyst_notes"] == "Keep this analyst note."
    