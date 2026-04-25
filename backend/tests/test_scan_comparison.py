from datetime import datetime, timezone

from fastapi.testclient import TestClient

from app.main import app
from app.models.comparison import ComparisonScanRef
from app.models.report import Finding, NormalizedAnalysisReport
from app.services.scan_comparison import compare_reports
from app.services.scan_history import ScanHistoryStore


def _finding(
    finding_id: str,
    title: str,
    severity: str,
    category: str,
    source: str,
) -> Finding:
    return Finding(
        id=finding_id,
        title=title,
        severity=severity,
        category=category,
        description=f"{title} description",
        recommendation=f"Fix {title}",
        source=source,
    )


def _report(file_name: str, findings: list[Finding]) -> NormalizedAnalysisReport:
    by_severity = {"low": 0, "medium": 0, "high": 0, "critical": 0}
    categories: dict[str, str] = {}
    rank = {"low": 1, "medium": 2, "high": 3, "critical": 4}

    for finding in findings:
        by_severity[finding.severity] += 1
        current = categories.get(finding.category)
        if current is None or rank[finding.severity] > rank[current]:
            categories[finding.category] = finding.severity

    return NormalizedAnalysisReport(
        platform="android",
        file_name=file_name,
        risk_level=max((finding.severity for finding in findings), key=lambda item: rank[item]),
        score=70,
        summary={"total_findings": len(findings), "by_severity": by_severity},
        findings=findings,
        categories=[
            {
                "name": category,
                "count": sum(1 for finding in findings if finding.category == category),
                "max_severity": severity,
            }
            for category, severity in categories.items()
        ],
        metadata={
            "generated_at": datetime.now(timezone.utc),
            "analyzer_version": "0.1.0-mvp",
            "analysis_mode": "static-placeholder",
            "file_extension": ".apk",
        },
    )


def _scan_ref(scan_id: str, app_version_id: str, file_name: str) -> ComparisonScanRef:
    return ComparisonScanRef(
        scan_id=scan_id,
        app_id="app-1",
        app_name="Wallet",
        app_version_id=app_version_id,
        version_name="1.0.0",
        build_identifier=None,
        file_name=file_name,
    )


def test_compare_reports_identifies_new_resolved_unchanged_severity_and_uncertain() -> None:
    baseline_report = _report(
        "wallet-1.apk",
        [
            _finding("RULE-A", "Debuggable flag", "high", "manifest", "AndroidManifest.xml"),
            _finding("RULE-B", "Cleartext traffic", "medium", "network", "AndroidManifest.xml"),
            _finding("RULE-C", "Old endpoint", "low", "strings", "assets/config.txt"),
            _finding("RULE-OLD", "Candidate token", "medium", "secrets", "assets/config.txt"),
        ],
    )
    target_report = _report(
        "wallet-2.apk",
        [
            _finding("RULE-A", "Debuggable flag", "high", "manifest", "AndroidManifest.xml"),
            _finding("RULE-B", "Cleartext traffic", "critical", "network", "AndroidManifest.xml"),
            _finding("RULE-D", "New endpoint", "medium", "strings", "assets/new-config.txt"),
            _finding("RULE-NEW", "Candidate token", "medium", "secrets", "assets/config.txt"),
        ],
    )

    comparison = compare_reports(
        baseline_scan=_scan_ref("baseline-scan", "version-1", "wallet-1.apk"),
        target_scan=_scan_ref("target-scan", "version-2", "wallet-2.apk"),
        baseline_report=baseline_report,
        target_report=target_report,
    )

    assert comparison.summary.unchanged == 1
    assert comparison.summary.severity_changed == 1
    assert comparison.summary.new == 2
    assert comparison.summary.resolved == 2
    assert comparison.summary.uncertain == 1
    assert comparison.severity_changes[0].baseline_severity == "medium"
    assert comparison.severity_changes[0].target_severity == "critical"
    assert comparison.uncertain_matches[0].confidence == "medium"


def test_compare_endpoint_requires_same_app_and_returns_diff() -> None:
    store = ScanHistoryStore()
    project = store.create_project("Payments")
    mobile_app = store.create_app(project.id, "Wallet", "android")
    version_one = store.create_app_version(mobile_app.id, "1.0.0", "100")
    version_two = store.create_app_version(mobile_app.id, "1.1.0", "110")

    baseline_scan = store.save_report(
        _report("wallet-1.apk", [_finding("RULE-A", "Debuggable flag", "high", "manifest", "manifest")]),
        project_id=project.id,
        app_id=mobile_app.id,
        app_version_id=version_one.id,
    )
    target_scan = store.save_report(
        _report(
            "wallet-2.apk",
            [
                _finding("RULE-A", "Debuggable flag", "medium", "manifest", "manifest"),
                _finding("RULE-B", "New endpoint", "medium", "strings", "assets/config.txt"),
            ],
        ),
        project_id=project.id,
        app_id=mobile_app.id,
        app_version_id=version_two.id,
    )

    with TestClient(app) as client:
        response = client.get(
            f"/api/v1/scans/{target_scan.id}/comparison",
            params={"baseline_scan_id": baseline_scan.id},
        )

    assert response.status_code == 200
    payload = response.json()
    assert payload["summary"]["severity_changed"] == 1
    assert payload["summary"]["new"] == 1
    assert payload["baseline_scan"]["app_id"] == mobile_app.id
    assert payload["target_scan"]["app_version_id"] == version_two.id
