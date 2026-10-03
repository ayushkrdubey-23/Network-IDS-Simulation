
"""
Shared pytest fixtures for Network IDS Simulation.

All database tests use a temporary SQLite database.
The project's actual database is not modified.
"""

import csv

import pytest
from fastapi.testclient import TestClient

from backend.main import app
from backend.services import alert_service


@pytest.fixture
def database_with_alerts(tmp_path, monkeypatch):
    """Create an isolated database containing three sample alerts."""

    database_dir = tmp_path / "data"
    database_path = database_dir / "test_ids_database.db"

    monkeypatch.setattr(
        alert_service,
        "DATABASE_DIR",
        database_dir,
    )

    monkeypatch.setattr(
        alert_service,
        "DATABASE_PATH",
        database_path,
    )

    alert_service.initialize_database()

    csv_path = tmp_path / "sample_hybrid_alerts.csv"

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

    sample_alerts = [
        {
            "flow_id": "TEST-FLOW-001",
            "timestamp": "2026-10-03T10:00:00",
            "source_ip": "192.0.2.10",
            "destination_ip": "203.0.113.10",
            "label": "SUSPICIOUS",
            "scenario_type": "HIGH_CONNECTION_RATE",
            "risk_score": 85,
            "risk_level": "HIGH",
            "signature_matches": 2,
            "is_anomaly": "True",
        },
        {
            "flow_id": "TEST-FLOW-002",
            "timestamp": "2026-10-03T10:05:00",
            "source_ip": "192.0.2.20",
            "destination_ip": "203.0.113.20",
            "label": "SUSPICIOUS",
            "scenario_type": "UNUSUAL_PORT_ACTIVITY",
            "risk_score": 55,
            "risk_level": "MEDIUM",
            "signature_matches": 1,
            "is_anomaly": "False",
        },
        {
            "flow_id": "TEST-FLOW-003",
            "timestamp": "2026-10-03T10:10:00",
            "source_ip": "198.51.100.10",
            "destination_ip": "203.0.113.30",
            "label": "NORMAL",
            "scenario_type": "NORMAL_WEB",
            "risk_score": 10,
            "risk_level": "INFO",
            "signature_matches": 0,
            "is_anomaly": "False",
        },
    ]

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
        writer.writerows(sample_alerts)

    imported_count = alert_service.import_hybrid_alerts(
        csv_path
    )

    assert imported_count == 3

    return {
        "database_path": database_path,
        "alerts": alert_service.list_alerts(),
    }


@pytest.fixture
def api_client(database_with_alerts):
    """Provide a FastAPI test client using the temporary database."""

    with TestClient(app) as client:
        yield client
        