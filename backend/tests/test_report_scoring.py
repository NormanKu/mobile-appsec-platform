from app.services.report_builder import (
    _calculate_risk_level,
    _calculate_score,
    _calculate_summary,
    _calculate_top_risks,
)


def _finding(
    *,
    finding_id: str,
    severity: str,
    confidence_level: str,
    category: str = "analysis",
) -> dict[str, object]:
    return {
        "id": finding_id,
        "title": finding_id,
        "severity": severity,
        "category": category,
        "description": f"{finding_id} description",
        "recommendation": "review",
        "source": "test",
        "confidence_level": confidence_level,
        "evidence": [finding_id],
    }


def test_score_uses_severity_and_confidence_weighting() -> None:
    confirmed_high = [
        _finding(
            finding_id="HIGH-CONFIRMED", severity="high", confidence_level="confirmed"
        )
    ]
    heuristic_high = [
        _finding(
            finding_id="HIGH-HEURISTIC", severity="high", confidence_level="heuristic"
        )
    ]
    informational_high = [
        _finding(
            finding_id="HIGH-INFORMATIONAL",
            severity="high",
            confidence_level="informational",
        )
    ]

    assert _calculate_score(confirmed_high) == 78
    assert _calculate_score(heuristic_high) == 85
    assert _calculate_score(informational_high) == 93


def test_summary_and_top_risks_follow_same_priority_model() -> None:
    findings = [
        _finding(
            finding_id="CRITICAL-INFORMATIONAL",
            severity="critical",
            confidence_level="informational",
        ),
        _finding(
            finding_id="HIGH-CONFIRMED", severity="high", confidence_level="confirmed"
        ),
        _finding(
            finding_id="LOW-HEURISTIC", severity="low", confidence_level="heuristic"
        ),
    ]

    summary = _calculate_summary(findings, "ios")
    top_risks = _calculate_top_risks(findings)

    assert summary.total_findings == 3
    assert summary.by_severity == {"low": 1, "medium": 0, "high": 1, "critical": 1}
    assert summary.by_platform == {"android": 0, "ios": 3}
    assert _calculate_risk_level(findings) == "high"
    assert [finding["id"] for finding in top_risks] == [
        "HIGH-CONFIRMED",
        "CRITICAL-INFORMATIONAL",
        "LOW-HEURISTIC",
    ]
