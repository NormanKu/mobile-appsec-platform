from datetime import datetime
from typing import Literal

from pydantic import BaseModel, Field, model_validator

Severity = Literal["low", "medium", "high", "critical"]
RiskLevel = Literal["low", "medium", "high", "critical"]
Platform = Literal["android", "ios"]


class Finding(BaseModel):
    id: str = Field(..., examples=["ANDROID-MANIFEST-001"])
    title: str = Field(..., examples=["Debuggable flag is enabled"])
    severity: Severity = Field(..., examples=["high"])
    category: str = Field(..., examples=["configuration"])
    description: str = Field(..., examples=["android:debuggable is true in release manifest"])
    recommendation: str = Field(..., examples=["Set android:debuggable=false for release builds"])
    source: str = Field(..., examples=["AndroidManifest.xml"])


class Summary(BaseModel):
    total_findings: int = Field(..., ge=0)
    by_severity: dict[Severity, int] = Field(
        default_factory=lambda: {"low": 0, "medium": 0, "high": 0, "critical": 0}
    )


class CategorySummary(BaseModel):
    name: str
    count: int = Field(..., ge=0)
    max_severity: Severity


class Metadata(BaseModel):
    generated_at: datetime
    analyzer_version: str = Field(default="0.1.0-mvp")
    analysis_mode: Literal["static-placeholder"] = "static-placeholder"
    file_extension: Literal[".apk", ".aab", ".ipa"]


class NormalizedAnalysisReport(BaseModel):
    platform: Platform
    file_name: str
    risk_level: RiskLevel
    score: int = Field(..., ge=0, le=100)
    summary: Summary
    findings: list[Finding] = Field(default_factory=list)
    categories: list[CategorySummary] = Field(default_factory=list)
    metadata: Metadata

    @model_validator(mode="after")
    def validate_summary_counts(self) -> "NormalizedAnalysisReport":
        expected_total = len(self.findings)
        counted_total = sum(self.summary.by_severity.values())
        category_total = sum(category.count for category in self.categories)

        if self.summary.total_findings != expected_total:
            raise ValueError("summary.total_findings must equal number of findings")

        if counted_total != expected_total:
            raise ValueError("summary.by_severity counts must sum to total findings")

        if category_total != expected_total:
            raise ValueError("categories counts must sum to total findings")

        return self


ANDROID_EXAMPLE_REPORT: dict = {
    "platform": "android",
    "file_name": "shopping-release.apk",
    "risk_level": "high",
    "score": 58,
    "summary": {
        "total_findings": 1,
        "by_severity": {"low": 0, "medium": 0, "high": 1, "critical": 0},
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
        }
    ],
    "categories": [
        {
            "name": "configuration",
            "count": 1,
            "max_severity": "high",
        }
    ],
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
    "summary": {
        "total_findings": 1,
        "by_severity": {"low": 0, "medium": 1, "high": 0, "critical": 0},
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
        }
    ],
    "categories": [
        {
            "name": "entitlements",
            "count": 1,
            "max_severity": "medium",
        }
    ],
    "metadata": {
        "generated_at": "2026-01-01T00:00:00Z",
        "analyzer_version": "0.1.0-mvp",
        "analysis_mode": "static-placeholder",
        "file_extension": ".ipa",
    },
}
