
"""
API tests for the Network IDS Simulation.

These tests use the temporary SQLite database provided
by the shared api_client fixture in conftest.py.
"""

import pytest


# ---------------------------------------------------------
# ROOT AND HEALTH ENDPOINT TESTS
# ---------------------------------------------------------

def test_root_endpoint(api_client):
    response = api_client.get("/")

    assert response.status_code == 200

    data = response.json()

    assert "message" in data
    assert data["documentation"] == "/docs"
    assert data["health"] == "/api/health"


def test_health_endpoint(api_client):
    response = api_client.get("/api/health")

    assert response.status_code == 200

    data = response.json()

    assert data["status"] == "healthy"
    assert data["project"] == "Network IDS Simulation"
    assert data["database"] == "connected"


# ---------------------------------------------------------
# ALERT LISTING TESTS
# ---------------------------------------------------------

def test_get_all_alerts(api_client):
    response = api_client.get("/api/alerts")

    assert response.status_code == 200

    alerts = response.json()

    assert isinstance(alerts, list)
    assert len(alerts) == 3


def test_filter_alerts_by_high_risk(api_client):
    response = api_client.get(
        "/api/alerts",
        params={"risk_level": "HIGH"},
    )

    assert response.status_code == 200

    alerts = response.json()

    assert len(alerts) == 1
    assert alerts[0]["risk_level"] == "HIGH"


def test_filter_alerts_by_medium_risk(api_client):
    response = api_client.get(
        "/api/alerts",
        params={"risk_level": "MEDIUM"},
    )

    assert response.status_code == 200

    alerts = response.json()

    assert len(alerts) == 1
    assert alerts[0]["risk_level"] == "MEDIUM"


def test_filter_alerts_by_info_risk(api_client):
    response = api_client.get(
        "/api/alerts",
        params={"risk_level": "INFO"},
    )

    assert response.status_code == 200

    alerts = response.json()

    assert len(alerts) == 1
    assert alerts[0]["risk_level"] == "INFO"


def test_filter_alerts_by_status(api_client):
    response = api_client.get(
        "/api/alerts",
        params={"status": "NEW"},
    )

    assert response.status_code == 200

    alerts = response.json()

    assert len(alerts) == 3

    for alert in alerts:
        assert alert["status"] == "NEW"


def test_alert_pagination_limit(api_client):
    response = api_client.get(
        "/api/alerts",
        params={"limit": 2},
    )

    assert response.status_code == 200
    assert len(response.json()) == 2


def test_alert_pagination_offset(api_client):
    response = api_client.get(
        "/api/alerts",
        params={
            "limit": 2,
            "offset": 1,
        },
    )

    assert response.status_code == 200
    assert len(response.json()) == 2


def test_alert_pagination_empty_result(api_client):
    response = api_client.get(
        "/api/alerts",
        params={
            "limit": 2,
            "offset": 10,
        },
    )

    assert response.status_code == 200
    assert response.json() == []


def test_invalid_alert_status_filter(api_client):
    response = api_client.get(
        "/api/alerts",
        params={"status": "INVALID"},
    )

    assert response.status_code == 422


def test_invalid_risk_level_filter(api_client):
    response = api_client.get(
        "/api/alerts",
        params={"risk_level": "CRITICAL"},
    )

    assert response.status_code == 422


def test_invalid_alert_limit(api_client):
    response = api_client.get(
        "/api/alerts",
        params={"limit": 0},
    )

    assert response.status_code == 422


def test_invalid_alert_offset(api_client):
    response = api_client.get(
        "/api/alerts",
        params={"offset": -1},
    )

    assert response.status_code == 422


# ---------------------------------------------------------
# GET ALERT BY ID TESTS
# ---------------------------------------------------------

def test_get_alert_by_id(api_client):
    response = api_client.get("/api/alerts/1")

    assert response.status_code == 200

    data = response.json()

    assert data["flow_id"] == "TEST-FLOW-001"
    assert data["risk_level"] == "HIGH"


def test_get_nonexistent_alert(api_client):
    response = api_client.get("/api/alerts/9999")

    assert response.status_code == 404
    assert response.json()["detail"] == "Alert not found"


# ---------------------------------------------------------
# STATISTICS TESTS
# ---------------------------------------------------------

def test_get_statistics(api_client):
    response = api_client.get("/api/statistics")

    assert response.status_code == 200

    data = response.json()

    assert data["total_alerts"] == 3
    assert data["flagged_alerts"] == 2
    assert "by_status" in data
    assert "by_risk" in data


# ---------------------------------------------------------
# UPDATE ALERT STATUS TESTS
# ---------------------------------------------------------

def test_update_alert_status(api_client):
    response = api_client.patch(
        "/api/alerts/1/status",
        json={
            "status": "INVESTIGATING",
            "analyst_notes": "Under investigation by analyst.",
        },
    )

    assert response.status_code == 200

    data = response.json()

    assert data["message"] == "Alert status updated successfully"
    assert data["alert"]["status"] == "INVESTIGATING"
    assert (
        data["alert"]["analyst_notes"]
        == "Under investigation by analyst."
    )


def test_update_alert_status_without_notes(api_client):
    response = api_client.patch(
        "/api/alerts/1/status",
        json={
            "status": "RESOLVED",
        },
    )

    assert response.status_code == 200

    data = response.json()

    assert data["alert"]["status"] == "RESOLVED"


def test_update_alert_with_invalid_status(api_client):
    response = api_client.patch(
        "/api/alerts/1/status",
        json={
            "status": "INVALID",
        },
    )

    assert response.status_code == 422


def test_update_nonexistent_alert(api_client):
    response = api_client.patch(
        "/api/alerts/9999/status",
        json={
            "status": "RESOLVED",
        },
    )

    assert response.status_code == 404


def test_update_alert_with_long_analyst_notes(api_client):
    response = api_client.patch(
        "/api/alerts/1/status",
        json={
            "status": "INVESTIGATING",
            "analyst_notes": "A" * 2001,
        },
    )

    assert response.status_code == 422


# ---------------------------------------------------------
# CREATE INCIDENT TESTS
# ---------------------------------------------------------

def test_create_incident(api_client):
    response = api_client.post(
        "/api/incidents",
        json={
            "incident_title": "Suspicious Traffic Investigation",
            "description": "Investigating suspicious simulated traffic.",
            "severity": "HIGH",
        },
    )

    assert response.status_code == 201

    data = response.json()

    assert data["incident_id"] > 0
    assert data["message"] == "Incident created successfully"


def test_create_incident_with_default_description(api_client):
    response = api_client.post(
        "/api/incidents",
        json={
            "incident_title": "Network Investigation",
            "severity": "MEDIUM",
        },
    )

    assert response.status_code == 201


def test_create_incident_with_short_title(api_client):
    response = api_client.post(
        "/api/incidents",
        json={
            "incident_title": "AB",
            "description": "Test description",
            "severity": "LOW",
        },
    )

    assert response.status_code == 422


def test_create_incident_with_invalid_severity(api_client):
    response = api_client.post(
        "/api/incidents",
        json={
            "incident_title": "Invalid Severity Incident",
            "description": "Testing invalid severity.",
            "severity": "INFO",
        },
    )

    assert response.status_code == 422


def test_create_incident_with_long_description(api_client):
    response = api_client.post(
        "/api/incidents",
        json={
            "incident_title": "Long Description Incident",
            "description": "A" * 2001,
            "severity": "HIGH",
        },
    )

    assert response.status_code == 422


def test_create_incident_without_severity(api_client):
    response = api_client.post(
        "/api/incidents",
        json={
            "incident_title": "Missing Severity Incident",
            "description": "Testing missing severity.",
        },
    )

    assert response.status_code == 422


# ---------------------------------------------------------
# LINK ALERT TO INCIDENT TESTS
# ---------------------------------------------------------

def test_link_alert_to_incident(api_client):
    incident_response = api_client.post(
        "/api/incidents",
        json={
            "incident_title": "Alert Linking Test",
            "description": "Testing alert and incident linking.",
            "severity": "HIGH",
        },
    )

    assert incident_response.status_code == 201

    incident_id = incident_response.json()["incident_id"]

    response = api_client.post(
        f"/api/incidents/{incident_id}/alerts/1"
    )

    assert response.status_code == 200

    data = response.json()

    assert data["message"] == "Alert linked to incident successfully"
    assert data["incident_id"] == incident_id
    assert data["alert_id"] == 1


def test_link_alert_to_nonexistent_incident(api_client):
    response = api_client.post(
        "/api/incidents/9999/alerts/1"
    )

    assert response.status_code == 404


def test_link_nonexistent_alert_to_incident(api_client):
    incident_response = api_client.post(
        "/api/incidents",
        json={
            "incident_title": "Missing Alert Test",
            "description": "Testing a missing alert.",
            "severity": "MEDIUM",
        },
    )

    assert incident_response.status_code == 201

    incident_id = incident_response.json()["incident_id"]

    response = api_client.post(
        f"/api/incidents/{incident_id}/alerts/9999"
    )

    assert response.status_code == 404
    