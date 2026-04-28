from datetime import datetime, timezone

from fastapi.testclient import TestClient

from app.main import app
from app.models.report import Finding, NormalizedAnalysisReport
from app.services.policy_evaluator import evaluate_policy
from app.services.scan_history import ScanHistoryStore


def _finding(
    finding_id: str,
    severity: str,
    title: str = "Finding",
    description: str = "Description",
) -> Finding:
    return Finding(
        id=finding_id,
        title=title,
        severity=severity,
        category="policy-test",
        description=description,
        recommendation="Fix it",
        source="test",
    )


def _report(score: int, findings: list[Finding]) -> NormalizedAnalysisReport:
    by_severity = {"low": 0, "medium": 0, "high": 0, "critical": 0}
    for finding in findings:
        by_severity[finding.severity] += 1

    max_severity = "low"
    rank = {"low": 1, "medium": 2, "high": 3, "critical": 4}
    for finding in findings:
        if rank[finding.severity] > rank[max_severity]:
            max_severity = finding.severity

    return NormalizedAnalysisReport(
        platform="android",
        file_name="sample.apk",
        risk_level=max_severity,
        score=score,
        summary={"total_findings": len(findings), "by_severity": by_severity},
        findings=findings,
        categories=[
            {
                "name": "policy-test",
                "count": len(findings),
                "max_severity": max_severity,
            }
        ],
        metadata={
            "generated_at": datetime.now(timezone.utc),
            "analyzer_version": "0.1.0-mvp",
            "analysis_mode": "static-placeholder",
            "file_extension": ".apk",
        },
    )


def test_policy_fails_on_confirmed_critical_finding() -> None:
    evaluation = evaluate_policy(_report(95, [_finding("CRIT-1", "critical")]))

    assert evaluation.decision == "fail"
    assert evaluation.rules[0].status == "fail"
    assert evaluation.rules[0].finding_ids == ["CRIT-1"]


def test_policy_fails_when_score_is_below_threshold() -> None:
    evaluation = evaluate_policy(_report(64, []), min_score=70)

    assert evaluation.decision == "fail"
    assert evaluation.rules[1].status == "fail"


def test_policy_warns_on_heuristic_high_finding() -> None:
    evaluation = evaluate_policy(
        _report(
            95,
            [
                _finding(
                    "HIGH-HEURISTIC",
                    "high",
                    title="Heuristic: exported component",
                    description="Heuristic finding requires review",
                )
            ],
        )
    )

    assert evaluation.decision == "warn"
    assert evaluation.rules[2].status == "warn"
    assert evaluation.rules[2].finding_ids == ["HIGH-HEURISTIC"]


def test_policy_passes_when_rules_are_satisfied() -> None:
    evaluation = evaluate_policy(_report(90, [_finding("MED-1", "medium")]))

    assert evaluation.decision == "pass"
    assert all(rule.status == "pass" for rule in evaluation.rules)


def test_policy_endpoint_supports_ci_failure_status() -> None:
    store = ScanHistoryStore()
    report = _report(95, [_finding("CRIT-1", "critical")])
    scan = store.save_report(
        report, project_name="CI", app_name="Pipeline", version_name="1.0.0"
    )

    with TestClient(app) as client:
        response = client.get(
            f"/api/v1/scans/{scan.id}/policy",
            params={"fail_on_policy_failure": "true"},
        )

    assert response.status_code == 422
    assert response.json()["decision"] == "fail"
