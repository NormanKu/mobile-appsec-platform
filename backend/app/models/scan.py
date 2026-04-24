from datetime import datetime
from typing import Any, Literal

from pydantic import BaseModel, Field

from app.models.report import NormalizedAnalysisReport, Platform

ScanJobStatus = Literal["queued", "running", "completed", "failed"]


class ScanJobError(BaseModel):
    code: str
    message: str
    status_code: int = Field(default=500, ge=400)
    details: dict[str, Any] = Field(default_factory=dict)


class ScanJobStatusResponse(BaseModel):
    job_id: str
    status: ScanJobStatus
    platform: Platform
    file_name: str
    created_at: datetime
    updated_at: datetime
    message: str | None = None
    report: NormalizedAnalysisReport | None = None
    error: ScanJobError | None = None
