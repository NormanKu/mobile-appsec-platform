import logging
import math
import re
from datetime import datetime, timezone

from analyzers.android.scanner import analyze_android_package
from analyzers.ios.scanner import analyze_ios_package

from app.errors.exceptions import UploadValidationError
from app.models.report import (
    CategorySummary,
    Metadata,
    NormalizedAnalysisReport,
    ReportDiagnostic,
    Summary,
)

logger = logging.getLogger(__name__)

_CONFIDENCE_PREFIX_RE = re.compile(
    r"^(Confirmed|Heuristic|Informational):\s*", re.IGNORECASE
)

RISK_RANK = {"low": 1, "medium": 2, "high": 3, "critical": 4}
CONFIDENCE_RANK = {"informational": 1, "heuristic": 2, "confirmed": 3}
SEVERITY_SCORE_PENALTY = {"low": 5, "medium": 12, "high": 22, "critical": 35}
CONFIDENCE_SCORE_MULTIPLIER = {
    "informational": 0.35,
    "heuristic": 0.7,
    "confirmed": 1.0,
}
MAX_TOP_RISKS = 3
INVALID_ARCHIVE_FINDING_IDS = {
    "ANDROID-ARCHIVE-001",
    "ANDROID-MANIFEST-404",
    "IOS-ARCHIVE-001",
    "IOS-PLIST-002",
    "IOS-PLIST-404",
}
ARCHIVE_LIMIT_FINDING_IDS = {"ANDROID-ARCHIVE-BOMB", "IOS-ARCHIVE-BOMB"}
DIAGNOSTIC_LEVELS = {"warning", "error"}


def _enrich_finding_sources(
    findings: list[dict[str, object]], platform: str
) -> list[dict[str, object]]:
    """Normalize finding metadata across all platforms.

    Ensures every finding has confidence_level, evidence, detection_method,
    and source_location. If the title contains a confidence prefix (e.g.
    "Heuristic: ..."), extract it into confidence_level and clean the title
    for consistent API output across iOS and Android.
    """
    default_source = "android-analyzer" if platform == "android" else "ios-analyzer"
    for finding in findings:
        source = str(finding.setdefault("source", default_source))

        # Extract confidence from title prefix if not explicitly set
        title = str(finding.get("title", ""))
        prefix_match = _CONFIDENCE_PREFIX_RE.match(title)
        if prefix_match:
            extracted_confidence = prefix_match.group(1).lower()
            finding.setdefault("confidence_level", extracted_confidence)
            finding["title"] = _CONFIDENCE_PREFIX_RE.sub("", title)
        else:
            finding.setdefault("confidence_level", "heuristic")

        finding.setdefault("evidence", [])
        finding.setdefault(
            "detection_method",
            _infer_detection_method(finding_id=str(finding["id"]), platform=platform),
        )
        if "source_location" not in finding or finding["source_location"] is None:
            finding["source_location"] = source if source != default_source else None
    return findings


def _infer_detection_method(finding_id: str, platform: str) -> str:
    if finding_id.endswith("ARCHIVE-001") or finding_id.endswith("ARCHIVE-BOMB"):
        return "zip-validation"
    if finding_id.endswith("FORMAT-001"):
        return "extension-validation"
    if finding_id.endswith("INPUT-001"):
        return "backend-input-validation"
    if finding_id.startswith("ANDROID-METADATA") or finding_id.startswith(
        "IOS-METADATA"
    ):
        return "archive-metadata-inspection"
    if finding_id.startswith("ANDROID-MANIFEST"):
        return "manifest-inspection"
    if finding_id.startswith("ANDROID-STRINGS") or finding_id.startswith("IOS-STRINGS"):
        return "archive-string-scan"
    if finding_id.startswith("ANDROID-JADX"):
        return "jadx-source-analysis"
    if finding_id.startswith("IOS-PLIST"):
        return "info-plist-inspection"
    if finding_id.startswith("IOS-ENTITLEMENTS"):
        return "entitlements-inspection"
    if finding_id.startswith("IOS-PAYLOAD") or finding_id.startswith("IOS-BINARY"):
        return "ipa-bundle-validation"
    return f"{platform}-static-analysis"


def _calculate_summary(findings: list[dict[str, object]], platform: str) -> Summary:
    by_severity = {"low": 0, "medium": 0, "high": 0, "critical": 0}
    for finding in findings:
        severity = finding["severity"]
        by_severity[severity] += 1

    by_platform = {"android": 0, "ios": 0}
    by_platform[platform] = len(findings)

    return Summary(
        total_findings=len(findings),
        by_severity=by_severity,
        by_platform=by_platform,
    )


def _calculate_categories(findings: list[dict[str, str]]) -> list[CategorySummary]:
    grouped: dict[str, dict[str, int | str]] = {}

    for finding in findings:
        category = finding["category"]
        severity = finding["severity"]
        if category not in grouped:
            grouped[category] = {"count": 0, "max_severity": severity}

        grouped[category]["count"] = int(grouped[category]["count"]) + 1
        if RISK_RANK[severity] > RISK_RANK[str(grouped[category]["max_severity"])]:
            grouped[category]["max_severity"] = severity

    return [
        CategorySummary(
            name=name, count=int(data["count"]), max_severity=str(data["max_severity"])
        )
        for name, data in sorted(grouped.items())
    ]


def _calculate_risk_level(findings: list[dict[str, str]]) -> str:
    if not findings:
        return "low"

    return _sort_findings_by_priority(findings)[0]["severity"]


def _calculate_finding_penalty(finding: dict[str, object]) -> int:
    severity = str(finding["severity"])
    confidence = str(finding.get("confidence_level", "heuristic"))
    base_penalty = SEVERITY_SCORE_PENALTY[severity]
    multiplier = CONFIDENCE_SCORE_MULTIPLIER.get(
        confidence, CONFIDENCE_SCORE_MULTIPLIER["heuristic"]
    )
    return max(1, math.floor(base_penalty * multiplier))


def _sort_findings_by_priority(
    findings: list[dict[str, object]],
) -> list[dict[str, object]]:
    return sorted(
        findings,
        key=lambda finding: (
            _calculate_finding_penalty(finding),
            RISK_RANK[str(finding["severity"])],
            CONFIDENCE_RANK[str(finding.get("confidence_level", "heuristic"))],
            len(finding.get("evidence", [])),
            str(finding["title"]),
        ),
        reverse=True,
    )


def _calculate_score(findings: list[dict[str, object]]) -> int:
    penalty = sum(_calculate_finding_penalty(finding) for finding in findings)
    return max(0, 100 - penalty)


def _calculate_top_risks(findings: list[dict[str, object]]) -> list[dict[str, object]]:
    prioritized_findings = _sort_findings_by_priority(findings)
    return [finding.copy() for finding in prioritized_findings[:MAX_TOP_RISKS]]


def _calculate_analysis_status(
    *,
    warnings: list[ReportDiagnostic],
    errors: list[ReportDiagnostic],
) -> str:
    if errors:
        return "partial"
    if warnings:
        return "warning"
    return "complete"


def _extract_report_diagnostics(
    findings: list[dict[str, object]],
) -> tuple[list[dict[str, object]], list[ReportDiagnostic], list[ReportDiagnostic]]:
    report_findings: list[dict[str, object]] = []
    warnings: list[ReportDiagnostic] = []
    errors: list[ReportDiagnostic] = []

    for finding in findings:
        level = str(finding.get("diagnostic_level", ""))
        if level not in DIAGNOSTIC_LEVELS:
            report_findings.append(finding)
            continue

        diagnostic = ReportDiagnostic(
            level=level,
            code=str(
                finding.get("diagnostic_code", finding.get("id", "ANALYSIS-DIAGNOSTIC"))
            ),
            message=str(
                finding.get(
                    "diagnostic_message",
                    finding.get("description", "Analysis diagnostic"),
                )
            ),
            stage=str(
                finding.get(
                    "diagnostic_stage", finding.get("detection_method", "analysis")
                )
            ),
            source=str(finding.get("source", "analysis")),
            tool=(
                str(finding["diagnostic_tool"])
                if finding.get("diagnostic_tool") is not None
                else None
            ),
            recommendation=(
                str(finding["recommendation"])
                if finding.get("recommendation") is not None
                else None
            ),
            details=dict(finding.get("diagnostic_details", {})),
        )
        if level == "warning":
            warnings.append(diagnostic)
        else:
            errors.append(diagnostic)

    return report_findings, warnings, errors


def _terminal_finding_to_diagnostic(
    finding: dict[str, object],
    *,
    file_name: str,
    platform: str,
) -> ReportDiagnostic:
    finding_id = str(finding["id"])
    status_code = 413 if finding_id in ARCHIVE_LIMIT_FINDING_IDS else 400
    code = (
        "ARCHIVE_LIMIT_EXCEEDED"
        if finding_id in ARCHIVE_LIMIT_FINDING_IDS
        else "INVALID_ARCHIVE"
    )
    return ReportDiagnostic(
        level="error",
        code=code,
        message=str(finding.get("title", "Package could not be fully analyzed")),
        stage=str(finding.get("detection_method", "archive-validation")),
        source=str(finding.get("source", "archive")),
        recommendation=str(
            finding.get(
                "recommendation", "Review the uploaded package and retry analysis"
            )
        ),
        details={
            "file_name": file_name,
            "platform": platform,
            "finding_id": finding_id,
            "status_code": status_code,
            "reason": str(finding.get("description", "")),
        },
    )


def _analysis_failed_error(
    *,
    file_name: str,
    platform: str,
    stage: str,
    reason: str,
) -> UploadValidationError:
    return UploadValidationError(
        code="ANALYSIS_FAILED",
        message="Static analysis could not be completed safely",
        status_code=500,
        details={
            "file_name": file_name,
            "platform": platform,
            "stage": stage,
            "reason": reason,
        },
    )


def _run_platform_analyzer(
    *,
    file_name: str,
    platform: str,
    analyzer,
    analyzer_kwargs: dict[str, object],
    allow_partial: bool,
) -> list[dict[str, object]]:
    try:
        return analyzer(**analyzer_kwargs)
    except UploadValidationError:
        raise
    except Exception as exc:
        logger.exception("Unexpected %s analyzer failure for %s", platform, file_name)
        if allow_partial:
            return [
                {
                    "id": f"{platform.upper()}-ANALYZER-FAILED",
                    "title": "Static analyzer failed before completing all checks",
                    "severity": "high",
                    "category": "analysis",
                    "description": f"{platform} analyzer raised an unexpected error",
                    "recommendation": "Review analyzer logs and retry with a known-good package before relying on this report",
                    "source": f"{platform}-analyzer",
                    "confidence_level": "informational",
                    "evidence": ["analyzer exception isolated"],
                    "detection_method": f"{platform}-static-analysis",
                    "source_location": None,
                    "diagnostic_level": "error",
                    "diagnostic_code": "ANALYZER_STEP_FAILED",
                    "diagnostic_message": "Static analyzer failed before completing all checks",
                    "diagnostic_stage": f"{platform}-analyzer",
                    "diagnostic_details": {
                        "file_name": file_name,
                        "platform": platform,
                        "reason": str(exc),
                    },
                }
            ]
        raise _analysis_failed_error(
            file_name=file_name,
            platform=platform,
            stage=f"{platform}-analyzer",
            reason="Analyzer raised an unexpected error",
        ) from exc


def _raise_for_terminal_findings(
    findings: list[dict[str, str]],
    file_name: str,
    platform: str,
    allow_partial: bool,
) -> None:
    for finding in findings:
        if finding["id"] in ARCHIVE_LIMIT_FINDING_IDS:
            if allow_partial:
                continue
            raise UploadValidationError(
                code="ARCHIVE_LIMIT_EXCEEDED",
                message="Uploaded archive exceeds safe extraction limits",
                status_code=413,
                details={
                    "file_name": file_name,
                    "platform": platform,
                    "finding_id": finding["id"],
                    "reason": finding["description"],
                    "source": finding["source"],
                },
            )

        if finding["id"] in INVALID_ARCHIVE_FINDING_IDS:
            if allow_partial:
                continue
            raise UploadValidationError(
                code="INVALID_ARCHIVE",
                message="Uploaded archive is invalid or missing required package metadata",
                status_code=400,
                details={
                    "file_name": file_name,
                    "platform": platform,
                    "finding_id": finding["id"],
                    "reason": finding["description"],
                    "source": finding["source"],
                },
            )


def build_normalized_report(
    file_name: str,
    platform: str,
    file_bytes: bytes | None = None,
    file_extension: str | None = None,
    max_zip_extracted_bytes: int | None = None,
    max_zip_files: int | None = None,
    max_text_file_size: int | None = None,
    max_text_files_scanned: int | None = None,
    allow_partial: bool = False,
) -> NormalizedAnalysisReport:
    try:
        if platform == "android":
            if file_bytes is None or file_extension is None:
                findings = [
                    {
                        "id": "ANDROID-INPUT-001",
                        "title": "Android analyzer received incomplete input",
                        "severity": "medium",
                        "category": "analysis",
                        "description": "Analyzer requires package bytes and extension for inspection",
                        "recommendation": "Pass uploaded archive bytes and extension to analyzer",
                        "source": "backend/report_builder",
                        "confidence_level": "informational",
                        "evidence": ["missing file_bytes or file_extension"],
                        "detection_method": "backend-input-validation",
                        "source_location": None,
                    }
                ]
                normalized_extension = ".apk"
            else:
                findings = _run_platform_analyzer(
                    file_name=file_name,
                    platform=platform,
                    analyzer=analyze_android_package,
                    allow_partial=allow_partial,
                    analyzer_kwargs={
                        "file_name": file_name,
                        "file_bytes": file_bytes,
                        "file_extension": file_extension,
                        "max_extracted_bytes": max_zip_extracted_bytes,
                        "max_files": max_zip_files,
                        "max_text_file_size": max_text_file_size,
                        "max_text_files_scanned": max_text_files_scanned,
                    },
                )
                normalized_extension = (
                    file_extension if file_extension in {".apk", ".aab"} else ".apk"
                )
        elif platform == "ios":
            if file_bytes is None or file_extension is None:
                findings = [
                    {
                        "id": "IOS-INPUT-001",
                        "title": "iOS analyzer received incomplete input",
                        "severity": "medium",
                        "category": "analysis",
                        "description": "Analyzer requires package bytes and extension for inspection",
                        "recommendation": "Pass uploaded archive bytes and extension to analyzer",
                        "source": "backend/report_builder",
                        "confidence_level": "informational",
                        "evidence": ["missing file_bytes or file_extension"],
                        "detection_method": "backend-input-validation",
                        "source_location": None,
                    }
                ]
                normalized_extension = ".ipa"
            else:
                findings = _run_platform_analyzer(
                    file_name=file_name,
                    platform=platform,
                    analyzer=analyze_ios_package,
                    allow_partial=allow_partial,
                    analyzer_kwargs={
                        "file_name": file_name,
                        "file_bytes": file_bytes,
                        "file_extension": file_extension,
                        "max_extracted_bytes": max_zip_extracted_bytes,
                        "max_files": max_zip_files,
                        "max_text_file_size": max_text_file_size,
                        "max_text_files_scanned": max_text_files_scanned,
                    },
                )
                normalized_extension = ".ipa"
        else:
            raise ValueError(f"Unsupported platform: {platform}")

        findings = _enrich_finding_sources(findings, platform)
        findings, warnings, errors = _extract_report_diagnostics(findings)
        _raise_for_terminal_findings(
            findings=findings,
            file_name=file_name,
            platform=platform,
            allow_partial=allow_partial,
        )
        if allow_partial:
            terminal_diagnostics = [
                _terminal_finding_to_diagnostic(
                    finding, file_name=file_name, platform=platform
                )
                for finding in findings
                if finding["id"] in INVALID_ARCHIVE_FINDING_IDS
                or finding["id"] in ARCHIVE_LIMIT_FINDING_IDS
            ]
            errors.extend(terminal_diagnostics)

        return NormalizedAnalysisReport(
            platform=platform,
            file_name=file_name,
            risk_level=_calculate_risk_level(findings),
            score=_calculate_score(findings),
            analysis_status=_calculate_analysis_status(
                warnings=warnings,
                errors=errors,
            ),
            summary=_calculate_summary(findings, platform),
            findings=findings,
            categories=_calculate_categories(findings),
            top_risks=_calculate_top_risks(findings),
            warnings=warnings,
            errors=errors,
            metadata=Metadata(
                generated_at=datetime.now(timezone.utc),
                file_extension=normalized_extension,
            ),
        )
    except UploadValidationError:
        raise
    except Exception as exc:
        logger.exception(
            "Unexpected report normalization failure for %s (%s)", file_name, platform
        )
        raise _analysis_failed_error(
            file_name=file_name,
            platform=platform,
            stage="report-normalization",
            reason="Unable to normalize analyzer output",
        ) from exc
