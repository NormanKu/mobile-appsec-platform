from datetime import datetime, timezone

from analyzers.android.scanner import analyze_android_package
from analyzers.ios.scanner import analyze_ios_package

from app.errors.exceptions import UploadValidationError
from app.models.report import CategorySummary, Metadata, NormalizedAnalysisReport, Summary

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


def _enrich_finding_sources(findings: list[dict[str, str]], platform: str) -> list[dict[str, str]]:
    default_source = "android-analyzer" if platform == "android" else "ios-analyzer"
    for finding in findings:
        finding.setdefault("source", default_source)
    return findings


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
                }
            ]
            normalized_extension = ".apk"
        else:
            findings = analyze_android_package(
                file_name=file_name,
                file_bytes=file_bytes,
                file_extension=file_extension,
                max_extracted_bytes=max_zip_extracted_bytes,
                max_files=max_zip_files,
                max_text_file_size=max_text_file_size,
                max_text_files_scanned=max_text_files_scanned,
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
                }
            ]
            normalized_extension = ".ipa"
        else:
            findings = analyze_ios_package(
                file_name=file_name,
                file_bytes=file_bytes,
                file_extension=file_extension,
                max_extracted_bytes=max_zip_extracted_bytes,
                max_files=max_zip_files,
                max_text_file_size=max_text_file_size,
                max_text_files_scanned=max_text_files_scanned,
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
