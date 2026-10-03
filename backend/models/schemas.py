
from typing import Literal

from pydantic import BaseModel, Field


AlertStatus = Literal[
    "NEW",
    "INVESTIGATING",
    "RESOLVED",
    "FALSE_POSITIVE",
]

RiskLevel = Literal[
    "INFO",
    "LOW",
    "MEDIUM",
    "HIGH",
]

IncidentSeverity = Literal[
    "LOW",
    "MEDIUM",
    "HIGH",
    "CRITICAL",
]


class AlertStatusUpdate(BaseModel):
    status: AlertStatus
    analyst_notes: str | None = Field(
        default=None,
        max_length=2000
    )


class IncidentCreate(BaseModel):
    incident_title: str = Field(
        min_length=3,
        max_length=200
    )
    description: str = Field(
        default="",
        max_length=2000
    )
    severity: IncidentSeverity


class MessageResponse(BaseModel):
    message: str


class IncidentCreateResponse(BaseModel):
    incident_id: int
    message: str


class HealthResponse(BaseModel):
    status: str
    project: str