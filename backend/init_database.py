
"""
Network IDS Simulation
Database Initialization and Hybrid Alert Import
"""

from pathlib import Path

from backend.services.alert_service import (
    initialize_database,
    import_hybrid_alerts,
)


BASE_DIR = Path(__file__).resolve().parent.parent

HYBRID_ALERTS_FILE = (
    BASE_DIR / "data" / "hybrid_alerts.csv"
)


def main():

    print("\nInitializing IDS database...")

    initialize_database()

    print("Database tables created successfully.")

    if HYBRID_ALERTS_FILE.exists():

        print("\nImporting hybrid alerts...")

        count = import_hybrid_alerts(
            HYBRID_ALERTS_FILE
        )

        print(
            f"Imported or updated {count} alert records."
        )

    else:

        print(
            "Hybrid alert CSV not found. "
            "Run the hybrid engine first."
        )

    print("\nDatabase initialization completed.")


if __name__ == "__main__":
    main()