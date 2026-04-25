from typing import Literal

from pydantic import BaseModel, Field

from app.models.report import Finding, Severity

MatchConfidence = Literal["medium", "low"]


class ComparisonScanRef(BaseModel):
    scan_id: str
    app_id: str
    app_name: str
    app_version_id: str
    version_name: str | None = None
    build_identifier: str | None = None
    file_name: str


class SeverityChange(BaseModel):
    match_key: str
    baseline_severity: Severity
    target_severity: Severity
    baseline_finding: Finding
    target_finding: Finding


class UncertainMatch(BaseModel):
    confidence: MatchConfidence
    reason: str
    baseline_finding: Finding
    target_finding: Finding


class ComparisonSummary(BaseModel):
    new: int = Field(..., ge=0)
    resolved: int = Field(..., ge=0)
    unchanged: int = Field(..., ge=0)
    severity_changed: int = Field(..., ge=0)
    uncertain: int = Field(..., ge=0)


class ScanComparison(BaseModel):
    baseline_scan: ComparisonScanRef
    target_scan: ComparisonScanRef
    summary: ComparisonSummary
    new_findings: list[Finding]
    resolved_findings: list[Finding]
    unchanged_findings: list[Finding]
    severity_changes: list[SeverityChange]
    uncertain_matches: list[UncertainMatch]
    match_strategy: str
    limitations: list[str]
