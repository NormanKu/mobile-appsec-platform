from datetime import datetime
from typing import Literal

from pydantic import BaseModel, Field

from app.models.report import Platform, RiskLevel, Severity

ScanStatus = Literal["queued", "running", "completed", "failed"]


class Project(BaseModel):
    id: str
    name: str
    created_at: datetime


class ProjectCreate(BaseModel):
    name: str = Field(..., min_length=1, max_length=120)


class MobileApp(BaseModel):
    id: str
    project_id: str
    name: str
    platform: Platform
    created_at: datetime


class MobileAppCreate(BaseModel):
    name: str = Field(..., min_length=1, max_length=120)
    platform: Platform


class AppVersion(BaseModel):
    id: str
    app_id: str
    version_name: str | None = None
    build_identifier: str | None = None
    created_at: datetime


class AppVersionCreate(BaseModel):
    version_name: str | None = Field(default=None, max_length=120)
    build_identifier: str | None = Field(default=None, max_length=120)


class Scan(BaseModel):
    id: str
    app_version_id: str
    file_name: str
    file_extension: Literal[".apk", ".aab", ".ipa"]
    status: ScanStatus
    risk_level: RiskLevel
    score: int = Field(..., ge=0, le=100)
    error_code: str | None = None
    error_message: str | None = None
    started_at: datetime
    completed_at: datetime | None = None


class StoredFinding(BaseModel):
    id: str
    scan_id: str
    finding_key: str
    title: str
    severity: Severity
    category: str
    description: str
    recommendation: str
    source: str
    ordinal: int = Field(..., ge=0)


class RecentScan(BaseModel):
    id: str
    project_id: str
    project_name: str
    app_id: str
    app_name: str
    app_version_id: str
    version_name: str | None = None
    build_identifier: str | None = None
    file_name: str
    file_extension: Literal[".apk", ".aab", ".ipa"]
    platform: Platform
    status: ScanStatus
    risk_level: RiskLevel
    score: int = Field(..., ge=0, le=100)
    finding_count: int = Field(..., ge=0)
    error_code: str | None = None
    error_message: str | None = None
    started_at: datetime
    completed_at: datetime | None = None
