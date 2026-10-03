
"""
Network IDS Simulation
SQLite Alert and Incident Management Service

Author: Ayush Kumar Dubey
"""

import sqlite3
from pathlib import Path
from datetime import datetime, timezone
from contextlib import contextmanager


BASE_DIR = Path(__file__).resolve().parents[2]

DATABASE_DIR = BASE_DIR / "data"

DATABASE_PATH = DATABASE_DIR / "ids_database.db"


def get_connection():

    DATABASE_DIR.mkdir(
        parents=True,
        exist_ok=True
    )

    connection = sqlite3.connect(
        DATABASE_PATH,
        timeout=30
    )

    connection.row_factory = sqlite3.Row

    connection.execute("PRAGMA foreign_keys = ON")

    return connection


@contextmanager
def database_connection():

    connection = get_connection()

    try:
        yield connection
        connection.commit()

    except Exception:
        connection.rollback()
        raise

    finally:
        connection.close()


def initialize_database():

    with database_connection() as connection:

        connection.execute("""
            CREATE TABLE IF NOT EXISTS alerts (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                flow_id TEXT NOT NULL,
                timestamp TEXT NOT NULL,
                source_ip TEXT NOT NULL,
                destination_ip TEXT NOT NULL,
                label TEXT NOT NULL,
                scenario_type TEXT NOT NULL,
                risk_score INTEGER NOT NULL,
                risk_level TEXT NOT NULL,
                signature_matches INTEGER NOT NULL DEFAULT 0,
                is_anomaly INTEGER NOT NULL DEFAULT 0,
                status TEXT NOT NULL DEFAULT 'NEW',
                analyst_notes TEXT DEFAULT '',
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL,
                UNIQUE(flow_id)
            )
        """)

        connection.execute("""
            CREATE TABLE IF NOT EXISTS incidents (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                incident_title TEXT NOT NULL,
                description TEXT DEFAULT '',
                severity TEXT NOT NULL,
                status TEXT NOT NULL DEFAULT 'OPEN',
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL
            )
        """)

        connection.execute("""
            CREATE TABLE IF NOT EXISTS incident_alerts (
                incident_id INTEGER NOT NULL,
                alert_id INTEGER NOT NULL,
                PRIMARY KEY (incident_id, alert_id),
                FOREIGN KEY (incident_id)
                    REFERENCES incidents(id)
                    ON DELETE CASCADE,
                FOREIGN KEY (alert_id)
                    REFERENCES alerts(id)
                    ON DELETE CASCADE
            )
        """)

        connection.execute("""
            CREATE INDEX IF NOT EXISTS idx_alert_status
            ON alerts(status)
        """)

        connection.execute("""
            CREATE INDEX IF NOT EXISTS idx_alert_risk
            ON alerts(risk_level)
        """)

        connection.execute("""
            CREATE INDEX IF NOT EXISTS idx_alert_created
            ON alerts(created_at)
        """)


def import_hybrid_alerts(csv_path):

    csv_path = Path(csv_path)

    if not csv_path.exists():
        raise FileNotFoundError(
            f"Hybrid alert CSV not found: {csv_path}"
        )

    import csv

    imported_count = 0

    now = datetime.now(timezone.utc).isoformat()

    with csv_path.open(
        "r",
        newline="",
        encoding="utf-8"
    ) as file:

        reader = csv.DictReader(file)

        required = {
            "flow_id",
            "timestamp",
            "source_ip",
            "destination_ip",
            "label",
            "scenario_type",
            "risk_score",
            "risk_level",
            "signature_matches",
            "is_anomaly"
        }

        missing = required - set(reader.fieldnames or [])

        if missing:
            raise ValueError(
                f"Hybrid CSV missing columns: {sorted(missing)}"
            )

        with database_connection() as connection:

            for row in reader:

                if row["risk_level"] not in {
                    "INFO", "LOW", "MEDIUM", "HIGH"
                }:
                    raise ValueError(
                        f"Invalid risk level: {row['risk_level']}"
                    )

                if row["label"] not in {
                    "NORMAL", "SUSPICIOUS"
                }:
                    raise ValueError(
                        f"Invalid label: {row['label']}"
                    )

                risk_score = int(row["risk_score"])

                if not 0 <= risk_score <= 100:
                    raise ValueError(
                        "Risk score must be between 0 and 100."
                    )

                connection.execute("""
                    INSERT INTO alerts (
                        flow_id,
                        timestamp,
                        source_ip,
                        destination_ip,
                        label,
                        scenario_type,
                        risk_score,
                        risk_level,
                        signature_matches,
                        is_anomaly,
                        status,
                        created_at,
                        updated_at
                    )
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'NEW', ?, ?)
                    ON CONFLICT(flow_id) DO UPDATE SET
                        timestamp = excluded.timestamp,
                        source_ip = excluded.source_ip,
                        destination_ip = excluded.destination_ip,
                        label = excluded.label,
                        scenario_type = excluded.scenario_type,
                        risk_score = excluded.risk_score,
                        risk_level = excluded.risk_level,
                        signature_matches = excluded.signature_matches,
                        is_anomaly = excluded.is_anomaly,
                        updated_at = excluded.updated_at
                """, (
                    row["flow_id"],
                    row["timestamp"],
                    row["source_ip"],
                    row["destination_ip"],
                    row["label"],
                    row["scenario_type"],
                    risk_score,
                    row["risk_level"],
                    int(row["signature_matches"]),
                    int(
                        str(row["is_anomaly"]).lower()
                        in {"true", "1"}
                    ),
                    now,
                    now
                ))

                imported_count += 1

    return imported_count


def list_alerts(
    status=None,
    risk_level=None,
    limit=100,
    offset=0
):

    query = "SELECT * FROM alerts WHERE 1=1"

    parameters = []

    if status:
        query += " AND status = ?"
        parameters.append(status.upper())

    if risk_level:
        query += " AND risk_level = ?"
        parameters.append(risk_level.upper())

    query += " ORDER BY risk_score DESC, id DESC LIMIT ? OFFSET ?"

    parameters.extend([limit, offset])

    with database_connection() as connection:

        rows = connection.execute(
            query,
            parameters
        ).fetchall()

        return [dict(row) for row in rows]


def get_alert(alert_id):

    with database_connection() as connection:

        row = connection.execute("""
            SELECT * FROM alerts WHERE id = ?
        """, (alert_id,)).fetchone()

        return dict(row) if row else None


def update_alert_status(
    alert_id,
    status,
    analyst_notes=None
):

    allowed_statuses = {
        "NEW",
        "INVESTIGATING",
        "RESOLVED",
        "FALSE_POSITIVE"
    }

    status = status.upper()

    if status not in allowed_statuses:
        raise ValueError(
            f"Invalid alert status: {status}"
        )

    now = datetime.now(timezone.utc).isoformat()

    with database_connection() as connection:

        if analyst_notes is None:

            cursor = connection.execute("""
                UPDATE alerts
                SET status = ?, updated_at = ?
                WHERE id = ?
            """, (
                status,
                now,
                alert_id
            ))

        else:

            cursor = connection.execute("""
                UPDATE alerts
                SET status = ?,
                    analyst_notes = ?,
                    updated_at = ?
                WHERE id = ?
            """, (
                status,
                analyst_notes,
                now,
                alert_id
            ))

        return cursor.rowcount > 0


def create_incident(
    title,
    description,
    severity
):

    allowed_severities = {
        "LOW",
        "MEDIUM",
        "HIGH",
        "CRITICAL"
    }

    severity = severity.upper()

    if severity not in allowed_severities:
        raise ValueError(
            "Invalid incident severity."
        )

    now = datetime.now(timezone.utc).isoformat()

    with database_connection() as connection:

        cursor = connection.execute("""
            INSERT INTO incidents (
                incident_title,
                description,
                severity,
                status,
                created_at,
                updated_at
            )
            VALUES (?, ?, ?, 'OPEN', ?, ?)
        """, (
            title,
            description,
            severity,
            now,
            now
        ))

        return cursor.lastrowid


def link_alert_to_incident(
    incident_id,
    alert_id
):

    with database_connection() as connection:

        incident = connection.execute(
            "SELECT id FROM incidents WHERE id = ?",
            (incident_id,)
        ).fetchone()

        alert = connection.execute(
            "SELECT id FROM alerts WHERE id = ?",
            (alert_id,)
        ).fetchone()

        if incident is None or alert is None:
            return False

        connection.execute("""
            INSERT OR IGNORE INTO incident_alerts (
                incident_id,
                alert_id
            )
            VALUES (?, ?)
        """, (
            incident_id,
            alert_id
        ))

        return True


def get_alert_statistics():

    with database_connection() as connection:

        total = connection.execute(
            "SELECT COUNT(*) FROM alerts"
        ).fetchone()[0]

        by_status = connection.execute("""
            SELECT status, COUNT(*) AS count
            FROM alerts
            GROUP BY status
        """).fetchall()

        by_risk = connection.execute("""
            SELECT risk_level, COUNT(*) AS count
            FROM alerts
            GROUP BY risk_level
        """).fetchall()

        flagged = connection.execute("""
            SELECT COUNT(*) FROM alerts
            WHERE risk_level IN ('LOW', 'MEDIUM', 'HIGH')
        """).fetchone()[0]

        return {
            "total_alerts": total,
            "flagged_alerts": flagged,
            "by_status": {
                row["status"]: row["count"]
                for row in by_status
            },
            "by_risk": {
                row["risk_level"]: row["count"]
                for row in by_risk
            }
        }
    