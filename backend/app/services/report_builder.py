import logging
import re
from datetime import datetime, timezone

from analyzers.android.scanner import analyze_android_package
from analyzers.ios.scanner import analyze_ios_package

from app.errors.exceptions import UploadValidationError
from app.models.report import CategorySummary, Metadata, NormalizedAnalysisReport, Summary

logger = logging.getLogger(__name__)

_CONFIDENCE_PREFIX_RE = re.compile(r"^(Confirmed|Heuristic|Informational):\s*", re.IGNORECASE)

RISK_RANK = {"low": 1, "medium": 2, "high": 3, "critical": 4}
SEVERITY_SCORE_PENALTY = {"low": 5, "medium": 12, "high": 22, "critical": 35}
INVALID_ARCHIVE_FINDING_IDS = {
    "ANDROID-ARCHIVE-001",
    "ANDROID-MANIFEST-404",
    "IOS-ARCHIVE-001",
    "IOS-PLIST-002",
    "IOS-PLIST-404",
}
ARCHIVE_LIMIT_FINDING_IDS = {"ANDROID-ARCHIVE-BOMB", "IOS-ARCHIVE-BOMB"}


def _enrich_finding_sources(findings: list[dict[str, object]], platform: str) -> list[dict[str, object]]:
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
        finding.setdefault("detection_method", _infer_detection_method(finding_id=str(finding["id"]), platform=platform))
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
    if finding_id.startswith("ANDROID-METADATA") or finding_id.startswith("IOS-METADATA"):
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


def _calculate_summary(findings: list[dict[str, str]]) -> Summary:
    by_severity = {"low": 0, "medium": 0, "high": 0, "critical": 0}
    for finding in findings:
        severity = finding["severity"]
        by_severity[severity] += 1

    return Summary(total_findings=len(findings), by_severity=by_severity)


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
        CategorySummary(name=name, count=int(data["count"]), max_severity=str(data["max_severity"]))
        for name, data in sorted(grouped.items())
    ]


def _calculate_risk_level(findings: list[dict[str, str]]) -> str:
    if not findings:
        return "low"

    return max(findings, key=lambda finding: RISK_RANK[finding["severity"]])["severity"]


def _calculate_score(findings: list[dict[str, str]]) -> int:
    penalty = sum(SEVERITY_SCORE_PENALTY[finding["severity"]] for finding in findings)
    return max(0, 100 - penalty)


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
) -> list[dict[str, object]]:
    try:
        return analyzer(**analyzer_kwargs)
    except UploadValidationError:
        raise
    except Exception as exc:
        logger.exception("Unexpected %s analyzer failure for %s", platform, file_name)
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
) -> None:
    for finding in findings:
        if finding["id"] in ARCHIVE_LIMIT_FINDING_IDS:
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
                normalized_extension = file_extension if file_extension in {".apk", ".aab"} else ".apk"
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
        _raise_for_terminal_findings(findings=findings, file_name=file_name, platform=platform)

        return NormalizedAnalysisReport(
            platform=platform,
            file_name=file_name,
            risk_level=_calculate_risk_level(findings),
            score=_calculate_score(findings),
            summary=_calculate_summary(findings),
            findings=findings,
            categories=_calculate_categories(findings),
            metadata=Metadata(
                generated_at=datetime.now(timezone.utc),
                file_extension=normalized_extension,
            ),
        )
    except UploadValidationError:
        raise
    except Exception as exc:
        logger.exception("Unexpected report normalization failure for %s (%s)", file_name, platform)
        raise _analysis_failed_error(
            file_name=file_name,
            platform=platform,
            stage="report-normalization",
            reason="Unable to normalize analyzer output",
        ) from exc
