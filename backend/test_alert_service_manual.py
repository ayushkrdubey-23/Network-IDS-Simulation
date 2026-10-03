
"""
Manual verification of IDS alert investigation functions.
"""

from backend.services.alert_service import (
    get_alert,
    list_alerts,
    update_alert_status,
    get_alert_statistics,
    create_incident,
    link_alert_to_incident,
)


def main():

    alerts = list_alerts(limit=5)

    print("\nFIRST FIVE ALERTS")

    for alert in alerts:

        print(
            alert["id"],
            alert["flow_id"],
            alert["risk_level"],
            alert["status"]
        )

    if not alerts:
        print("No alerts available for testing.")
        return

    first_alert = alerts[0]

    alert_id = first_alert["id"]

    print("\nUPDATING ALERT STATUS")

    updated = update_alert_status(
        alert_id,
        "INVESTIGATING",
        "Manual investigation started."
    )

    print(f"Update successful: {updated}")

    print("\nVERIFYING UPDATED ALERT")

    print(get_alert(alert_id))

    print("\nCREATING TEST INCIDENT")

    incident_id = create_incident(
        title="Synthetic IDS Investigation",
        description=(
            "Test incident created using "
            "synthetic network-flow alerts."
        ),
        severity="MEDIUM"
    )

    print(f"Incident ID: {incident_id}")

    linked = link_alert_to_incident(
        incident_id,
        alert_id
    )

    print(f"Alert linked: {linked}")

    print("\nALERT STATISTICS")

    print(get_alert_statistics())


if __name__ == "__main__":
    main()
    