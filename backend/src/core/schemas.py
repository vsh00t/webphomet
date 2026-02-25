"""Pydantic schemas for API request / response validation."""

from __future__ import annotations

import uuid
from datetime import datetime
from enum import Enum
from typing import Any

from pydantic import BaseModel, ConfigDict, Field, HttpUrl


# ---------------------------------------------------------------------------
# Enums (mirrors DB but kept separate for the API layer)
# ---------------------------------------------------------------------------


class SeverityLevel(str, Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class FindingStatusEnum(str, Enum):
    OPEN = "open"
    CONFIRMED = "confirmed"
    FALSE_POSITIVE = "false_positive"
    FIXED = "fixed"


class RunStatusEnum(str, Enum):
    PENDING = "pending"
    RUNNING = "running"
    SUCCESS = "success"
    FAILED = "failed"
    CANCELLED = "cancelled"


class SessionStatusEnum(str, Enum):
    CREATED = "created"
    RUNNING = "running"
    PAUSED = "paused"
    COMPLETED = "completed"
    FAILED = "failed"


# ---------------------------------------------------------------------------
# Endpoint Descriptor
# ---------------------------------------------------------------------------


class EndpointDescriptor(BaseModel):
    """Describes a discovered HTTP endpoint."""

    model_config = ConfigDict(from_attributes=True)

    url: HttpUrl
    method: str = "GET"
    params: dict[str, Any] | None = None
    headers: dict[str, str] | None = None
    auth_context_id: str | None = None
    source: str | None = Field(
        default=None,
        description="Tool or process that discovered this endpoint",
    )


# ---------------------------------------------------------------------------
# Finding
# ---------------------------------------------------------------------------


class FindingCreate(BaseModel):
    """Payload to create a new finding."""

    session_id: uuid.UUID
    vuln_type: str
    title: str
    description: str | None = None
    evidence: str | None = None
    impact: str | None = None
    likelihood: str | None = None
    severity: SeverityLevel
    poc: str | None = None
    recommendation: str | None = None
    references: dict[str, Any] | None = None


class FindingResponse(BaseModel):
    """Finding as returned by the API."""

    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    session_id: uuid.UUID
    vuln_type: str
    title: str
    description: str | None
    evidence: str | None
    impact: str | None
    likelihood: str | None
    severity: SeverityLevel
    status: FindingStatusEnum
    poc: str | None
    recommendation: str | None
    references: dict[str, Any] | None
    created_at: datetime


# ---------------------------------------------------------------------------
# Session
# ---------------------------------------------------------------------------


class SessionCreate(BaseModel):
    """Payload to create a new pentest session."""

    target_base_url: HttpUrl
    app_type: str | None = None
    scope: dict[str, Any] | None = None
    config: dict[str, Any] | None = None


class SessionUpdate(BaseModel):
    """Payload to partially update a pentest session."""

    status: SessionStatusEnum | None = None
    config: dict[str, Any] | None = None


class SessionResponse(BaseModel):
    """Pentest session as returned by the API."""

    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    target_base_url: str
    app_type: str | None
    scope: dict[str, Any] | None
    status: SessionStatusEnum
    config: dict[str, Any] | None
    created_at: datetime
    updated_at: datetime


# ---------------------------------------------------------------------------
# ToolRun
# ---------------------------------------------------------------------------


class ToolRunCreate(BaseModel):
    """Payload to create a tool run record."""

    session_id: uuid.UUID
    tool_name: str
    command: str
    args: dict[str, Any] | None = None


class ToolRunResponse(BaseModel):
    """Tool run as returned by the API."""

    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    session_id: uuid.UUID
    tool_name: str
    command: str
    args: dict[str, Any] | None
    status: RunStatusEnum
    stdout: str | None
    stderr: str | None
    exit_code: int | None
    started_at: datetime | None
    finished_at: datetime | None
