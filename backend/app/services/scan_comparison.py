from __future__ import annotations

from contextlib import closing
from dataclasses import dataclass
import re
import sqlite3

from app.core.config import settings
from app.db.database import connect, initialize_database
from app.models.comparison import (
    ComparisonScanRef,
    ComparisonSummary,
    ScanComparison,
    SeverityChange,
    UncertainMatch,
)
from app.models.report import Finding, NormalizedAnalysisReport
from app.services.scan_history import ScanHistoryStore

MATCH_STRATEGY = (
    "Exact matches use finding id + category + source. Uncertain matches are only hints "
    "based on same id/category with changed source, or same title/category/source."
)
LIMITATIONS = [
    "Heuristic analyzer output can change when package contents or sampling order changes.",
    "A renamed rule, changed source path, or changed description can appear as new/resolved.",
    "Uncertain matches are not counted as exact matches; review them before treating them as regressions or fixes.",
]


class ScanComparisonError(Exception):
    def __init__(self, message: str, status_code: int = 400):
        super().__init__(message)
        self.status_code = status_code


@dataclass(frozen=True)
class _IndexedFinding:
    index: int
    finding: Finding
    key: str


def compare_scans(
    target_scan_id: str,
    baseline_scan_id: str,
    database_url: str | None = None,
) -> ScanComparison:
    db_url = database_url or settings.database_url
    initialize_database(db_url)

    baseline_ref = _get_scan_ref(baseline_scan_id, db_url)
    target_ref = _get_scan_ref(target_scan_id, db_url)

    if baseline_ref is None or target_ref is None:
        raise ScanComparisonError("Scan not found", status_code=404)
    if baseline_ref.app_id != target_ref.app_id:
        raise ScanComparisonError("Scans must belong to the same app")
    if baseline_ref.scan_id == target_ref.scan_id:
        raise ScanComparisonError("Choose two different scans for comparison")

    store = ScanHistoryStore(database_url=db_url)
    baseline_report = store.get_report(baseline_ref.scan_id)
    target_report = store.get_report(target_ref.scan_id)
    if baseline_report is None or target_report is None:
        baseline_scan = store.get_scan(baseline_ref.scan_id)
        target_scan = store.get_scan(target_ref.scan_id)
        if baseline_scan is not None and baseline_scan.status == "failed":
            raise ScanComparisonError(
                "Baseline scan failed and has no completed result", status_code=409
            )
        if target_scan is not None and target_scan.status == "failed":
            raise ScanComparisonError(
                "Target scan failed and has no completed result", status_code=409
            )
        raise ScanComparisonError("Scan result not found", status_code=404)

    return compare_reports(
        baseline_scan=baseline_ref,
        target_scan=target_ref,
        baseline_report=baseline_report,
        target_report=target_report,
    )


def compare_reports(
    baseline_scan: ComparisonScanRef,
    target_scan: ComparisonScanRef,
    baseline_report: NormalizedAnalysisReport,
    target_report: NormalizedAnalysisReport,
) -> ScanComparison:
    baseline_items = [
        _IndexedFinding(index=index, finding=finding, key=_exact_key(finding))
        for index, finding in enumerate(baseline_report.findings)
    ]
    target_items = [
        _IndexedFinding(index=index, finding=finding, key=_exact_key(finding))
        for index, finding in enumerate(target_report.findings)
    ]

    baseline_by_key: dict[str, list[_IndexedFinding]] = {}
    for item in baseline_items:
        baseline_by_key.setdefault(item.key, []).append(item)

    matched_baseline: set[int] = set()
    matched_target: set[int] = set()
    unchanged: list[Finding] = []
    severity_changes: list[SeverityChange] = []

    for target_item in target_items:
        candidates = baseline_by_key.get(target_item.key, [])
        candidate = next(
            (item for item in candidates if item.index not in matched_baseline), None
        )
        if candidate is None:
            continue

        matched_baseline.add(candidate.index)
        matched_target.add(target_item.index)

        if candidate.finding.severity == target_item.finding.severity:
            unchanged.append(target_item.finding)
        else:
            severity_changes.append(
                SeverityChange(
                    match_key=target_item.key,
                    baseline_severity=candidate.finding.severity,
                    target_severity=target_item.finding.severity,
                    baseline_finding=candidate.finding,
                    target_finding=target_item.finding,
                )
            )

    unmatched_baseline = [
        item for item in baseline_items if item.index not in matched_baseline
    ]
    unmatched_target = [
        item for item in target_items if item.index not in matched_target
    ]
    uncertain_matches = _find_uncertain_matches(unmatched_baseline, unmatched_target)

    return ScanComparison(
        baseline_scan=baseline_scan,
        target_scan=target_scan,
        summary=ComparisonSummary(
            new=len(unmatched_target),
            resolved=len(unmatched_baseline),
            unchanged=len(unchanged),
            severity_changed=len(severity_changes),
            uncertain=len(uncertain_matches),
        ),
        new_findings=[item.finding for item in unmatched_target],
        resolved_findings=[item.finding for item in unmatched_baseline],
        unchanged_findings=unchanged,
        severity_changes=severity_changes,
        uncertain_matches=uncertain_matches,
        match_strategy=MATCH_STRATEGY,
        limitations=LIMITATIONS,
    )


def _get_scan_ref(scan_id: str, database_url: str) -> ComparisonScanRef | None:
    with closing(connect(database_url)) as connection:
        row = connection.execute(
            """
            SELECT
                scans.id AS scan_id,
                mobile_apps.id AS app_id,
                mobile_apps.name AS app_name,
                app_versions.id AS app_version_id,
                app_versions.version_name,
                app_versions.build_identifier,
                COALESCE(scans.file_name, app_versions.file_name, '') AS file_name
            FROM scans
            JOIN app_versions ON app_versions.id = scans.app_version_id
            JOIN mobile_apps ON mobile_apps.id = app_versions.app_id
            WHERE scans.id = ?
            """,
            (scan_id,),
        ).fetchone()

    return _row_to_scan_ref(row) if row else None


def _row_to_scan_ref(row: sqlite3.Row) -> ComparisonScanRef:
    return ComparisonScanRef(
        scan_id=row["scan_id"],
        app_id=row["app_id"],
        app_name=row["app_name"],
        app_version_id=row["app_version_id"],
        version_name=row["version_name"],
        build_identifier=row["build_identifier"],
        file_name=row["file_name"],
    )


def _find_uncertain_matches(
    baseline_items: list[_IndexedFinding],
    target_items: list[_IndexedFinding],
) -> list[UncertainMatch]:
    candidates: list[tuple[int, str, str, _IndexedFinding, _IndexedFinding]] = []
    for baseline_item in baseline_items:
        for target_item in target_items:
            score, confidence, reason = _uncertain_match_score(
                baseline_item.finding,
                target_item.finding,
            )
            if score > 0 and confidence and reason:
                candidates.append(
                    (score, confidence, reason, baseline_item, target_item)
                )

    candidates.sort(key=lambda item: item[0], reverse=True)
    used_baseline: set[int] = set()
    used_target: set[int] = set()
    matches: list[UncertainMatch] = []

    for _, confidence, reason, baseline_item, target_item in candidates:
        if baseline_item.index in used_baseline or target_item.index in used_target:
            continue

        used_baseline.add(baseline_item.index)
        used_target.add(target_item.index)
        matches.append(
            UncertainMatch(
                confidence=confidence,
                reason=reason,
                baseline_finding=baseline_item.finding,
                target_finding=target_item.finding,
            )
        )

    return matches


def _uncertain_match_score(
    baseline: Finding,
    target: Finding,
) -> tuple[int, str | None, str | None]:
    same_id = _normalize(baseline.id) == _normalize(target.id)
    same_title = _normalize(baseline.title) == _normalize(target.title)
    same_category = _normalize(baseline.category) == _normalize(target.category)
    same_source = _normalize(baseline.source) == _normalize(target.source)

    if same_id and same_category:
        return (
            90,
            "medium",
            "same finding id and category, but source or context changed",
        )
    if same_title and same_category and same_source:
        return 80, "medium", "same title, category, and source, but rule id changed"
    if same_title and same_category:
        return 60, "low", "same title and category, but source or rule id changed"

    return 0, None, None


def _exact_key(finding: Finding) -> str:
    return "|".join(
        [
            _normalize(finding.id),
            _normalize(finding.category),
            _normalize(finding.source),
        ]
    )


def _normalize(value: str) -> str:
    return re.sub(r"\s+", " ", value.strip().lower())
