
from typing import Literal

from fastapi import APIRouter, HTTPException, Query

from backend.models.schemas import (
    AlertStatusUpdate,
    IncidentCreate,
)
from backend.services.alert_service import (
    create_incident,
    get_alert,
    get_alert_statistics,
    import_hybrid_alerts,
    initialize_database,
    link_alert_to_incident,
    list_alerts,
    update_alert_status,
)


router = APIRouter(prefix="/api", tags=["Network IDS"])


@router.get("/health")
def health_check():
    try:
        initialize_database()
        get_alert_statistics()

        return {
            "status": "healthy",
            "project": "Network IDS Simulation",
            "database": "connected",
        }
    except Exception as error:
        raise HTTPException(
            status_code=503,
            detail=f"Database unavailable: {str(error)}",
        )


@router.get("/alerts")
def get_alerts(
    status: Literal[
        "NEW",
        "INVESTIGATING",
        "RESOLVED",
        "FALSE_POSITIVE",
    ] | None = None,
    risk_level: Literal[
        "INFO",
        "LOW",
        "MEDIUM",
        "HIGH",
    ] | None = None,
    limit: int = Query(default=100, ge=1, le=500),
    offset: int = Query(default=0, ge=0),
):
    try:
        return list_alerts(
            status=status,
            risk_level=risk_level,
            limit=limit,
            offset=offset,
        )
    except Exception as error:
        raise HTTPException(
            status_code=500,
            detail=f"Unable to retrieve alerts: {str(error)}",
        )


@router.get("/alerts/{alert_id}")
def get_alert_by_id(alert_id: int):
    alert = get_alert(alert_id)

    if alert is None:
        raise HTTPException(
            status_code=404,
            detail="Alert not found",
        )

    return alert


@router.get("/statistics")
def get_statistics():
    try:
        return get_alert_statistics()
    except Exception as error:
        raise HTTPException(
            status_code=500,
            detail=f"Unable to retrieve statistics: {str(error)}",
        )


@router.patch("/alerts/{alert_id}/status")
def change_alert_status(
    alert_id: int,
    payload: AlertStatusUpdate,
):
    updated = update_alert_status(
        alert_id=alert_id,
        status=payload.status,
        analyst_notes=payload.analyst_notes,
    )

    if not updated:
        raise HTTPException(
            status_code=404,
            detail="Alert not found or update failed",
        )

    return {
        "message": "Alert status updated successfully",
        "alert": get_alert(alert_id),
    }


@router.post("/incidents", status_code=201)
def add_incident(payload: IncidentCreate):
    try:
        incident_id = create_incident(
            title=payload.incident_title,
            description=payload.description,
            severity=payload.severity,
        )

        return {
            "incident_id": incident_id,
            "message": "Incident created successfully",
        }

    except ValueError as error:
        raise HTTPException(
            status_code=422,
            detail=str(error),
        )
    except Exception as error:
        raise HTTPException(
            status_code=500,
            detail=f"Unable to create incident: {str(error)}",
        )


@router.post("/incidents/{incident_id}/alerts/{alert_id}")
def attach_alert_to_incident(
    incident_id: int,
    alert_id: int,
):
    linked = link_alert_to_incident(
        incident_id=incident_id,
        alert_id=alert_id,
    )

    if not linked:
        raise HTTPException(
            status_code=404,
            detail="Incident or alert not found",
        )

    return {
        "message": "Alert linked to incident successfully",
        "incident_id": incident_id,
        "alert_id": alert_id,
    }