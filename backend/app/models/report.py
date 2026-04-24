from datetime import datetime
from typing import Any, Literal

from pydantic import BaseModel, Field, model_validator

Severity = Literal["low", "medium", "high", "critical"]
RiskLevel = Literal["low", "medium", "high", "critical"]
Platform = Literal["android", "ios"]
ConfidenceLevel = Literal["confirmed", "heuristic", "informational"]
AnalysisStatus = Literal["complete", "warning", "partial"]
DiagnosticLevel = Literal["warning", "error"]


class Finding(BaseModel):
    id: str = Field(..., examples=["ANDROID-MANIFEST-001"])
    title: str = Field(..., examples=["Debuggable flag is enabled"])
    severity: Severity = Field(..., examples=["high"])
    category: str = Field(..., examples=["configuration"])
    description: str = Field(
        ..., examples=["android:debuggable is true in release manifest"]
    )
    recommendation: str = Field(
        ..., examples=["Set android:debuggable=false for release builds"]
    )
    source: str = Field(..., examples=["AndroidManifest.xml"])
    confidence_level: ConfidenceLevel = Field(
        default="heuristic", examples=["confirmed"]
    )
    evidence: list[str] = Field(
        default_factory=list, examples=[['android:debuggable="true"']]
    )
    detection_method: str | None = Field(default=None, examples=["manifest-inspection"])
    source_location: str | None = Field(default=None, examples=["AndroidManifest.xml"])


class Summary(BaseModel):
    total_findings: int = Field(..., ge=0)
    by_severity: dict[Severity, int] = Field(
        default_factory=lambda: {"low": 0, "medium": 0, "high": 0, "critical": 0}
    )
    by_platform: dict[Platform, int] = Field(default_factory=dict)


class CategorySummary(BaseModel):
    name: str
    count: int = Field(..., ge=0)
    max_severity: Severity


class Metadata(BaseModel):
    generated_at: datetime
    analyzer_version: str = Field(default="0.1.0-mvp")
    analysis_mode: Literal["static-placeholder"] = "static-placeholder"
    file_extension: Literal[".apk", ".aab", ".ipa"]


class ReportDiagnostic(BaseModel):
    level: DiagnosticLevel
    code: str = Field(..., examples=["ANDROID-JADX-SKIPPED"])
    message: str = Field(..., examples=["JADX analysis was skipped"])
    stage: str = Field(..., examples=["external-tool"])
    source: str = Field(..., examples=["jadx"])
    tool: str | None = Field(default=None, examples=["jadx"])
    recommendation: str | None = Field(
        default=None,
        examples=["Install jadx locally to enable Android code enrichment"],
    )
    details: dict[str, Any] = Field(default_factory=dict)


class NormalizedAnalysisReport(BaseModel):
    platform: Platform
    file_name: str
    risk_level: RiskLevel
    score: int = Field(..., ge=0, le=100)
    analysis_status: AnalysisStatus = "complete"
    summary: Summary
    findings: list[Finding] = Field(default_factory=list)
    categories: list[CategorySummary] = Field(default_factory=list)
    top_risks: list[Finding] = Field(default_factory=list)
    warnings: list[ReportDiagnostic] = Field(default_factory=list)
    errors: list[ReportDiagnostic] = Field(default_factory=list)
    metadata: Metadata

    @model_validator(mode="after")
    def validate_summary_counts(self) -> "NormalizedAnalysisReport":
        expected_total = len(self.findings)
        counted_total = sum(self.summary.by_severity.values())
        platform_total = sum(self.summary.by_platform.values())
        category_total = sum(category.count for category in self.categories)

        if self.summary.total_findings != expected_total:
            raise ValueError("summary.total_findings must equal number of findings")

        if counted_total != expected_total:
            raise ValueError("summary.by_severity counts must sum to total findings")

        if self.summary.by_platform and platform_total != expected_total:
            raise ValueError("summary.by_platform counts must sum to total findings")

        if category_total != expected_total:
            raise ValueError("categories counts must sum to total findings")

        return self


ANDROID_EXAMPLE_REPORT: dict = {
    "platform": "android",
    "file_name": "shopping-release.apk",
    "risk_level": "high",
    "score": 58,
    "analysis_status": "complete",
    "summary": {
        "total_findings": 1,
        "by_severity": {"low": 0, "medium": 0, "high": 1, "critical": 0},
        "by_platform": {"android": 1, "ios": 0},
    },
    "findings": [
        {
            "id": "ANDROID-MANIFEST-001",
            "title": "Debuggable flag is enabled",
            "severity": "high",
            "category": "configuration",
            "description": "android:debuggable is true in release manifest",
            "recommendation": "Set android:debuggable=false for release builds",
            "source": "AndroidManifest.xml",
            "confidence_level": "confirmed",
            "evidence": ['android:debuggable="true"'],
            "detection_method": "manifest-inspection",
            "source_location": "AndroidManifest.xml",
        }
    ],
    "categories": [
        {
            "name": "configuration",
            "count": 1,
            "max_severity": "high",
        }
    ],
    "top_risks": [
        {
            "id": "ANDROID-MANIFEST-001",
            "title": "Debuggable flag is enabled",
            "severity": "high",
            "category": "configuration",
            "description": "android:debuggable is true in release manifest",
            "recommendation": "Set android:debuggable=false for release builds",
            "source": "AndroidManifest.xml",
            "confidence_level": "confirmed",
            "evidence": ['android:debuggable="true"'],
            "detection_method": "manifest-inspection",
            "source_location": "AndroidManifest.xml",
        }
    ],
    "warnings": [],
    "errors": [],
    "metadata": {
        "generated_at": "2026-01-01T00:00:00Z",
        "analyzer_version": "0.1.0-mvp",
        "analysis_mode": "static-placeholder",
        "file_extension": ".apk",
    },
}

IOS_EXAMPLE_REPORT: dict = {
    "platform": "ios",
    "file_name": "shopping-release.ipa",
    "risk_level": "medium",
    "score": 76,
    "analysis_status": "complete",
    "summary": {
        "total_findings": 1,
        "by_severity": {"low": 0, "medium": 1, "high": 0, "critical": 0},
        "by_platform": {"android": 0, "ios": 1},
    },
    "findings": [
        {
            "id": "IOS-ENTITLEMENTS-001",
            "title": "Broad keychain access group",
            "severity": "medium",
            "category": "entitlements",
            "description": "Access group is broader than required",
            "recommendation": "Restrict keychain access groups to least privilege",
            "source": "Payload/App.app/Info.plist",
            "confidence_level": "heuristic",
            "evidence": ["keychain-access-groups count=4"],
            "detection_method": "entitlements-inspection",
            "source_location": "Payload/App.app/archived-expanded-entitlements.xcent",
        }
    ],
    "categories": [
        {
            "name": "entitlements",
            "count": 1,
            "max_severity": "medium",
        }
    ],
    "top_risks": [
        {
            "id": "IOS-ENTITLEMENTS-001",
            "title": "Broad keychain access group",
            "severity": "medium",
            "category": "entitlements",
            "description": "Access group is broader than required",
            "recommendation": "Restrict keychain access groups to least privilege",
            "source": "Payload/App.app/Info.plist",
            "confidence_level": "heuristic",
            "evidence": ["keychain-access-groups count=4"],
            "detection_method": "entitlements-inspection",
            "source_location": "Payload/App.app/archived-expanded-entitlements.xcent",
        }
    ],
    "warnings": [],
    "errors": [],
    "metadata": {
        "generated_at": "2026-01-01T00:00:00Z",
        "analyzer_version": "0.1.0-mvp",
        "analysis_mode": "static-placeholder",
        "file_extension": ".ipa",
    },
}
