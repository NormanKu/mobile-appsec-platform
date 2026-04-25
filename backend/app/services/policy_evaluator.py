from __future__ import annotations

from app.core.config import settings
from app.models.report import Finding, NormalizedAnalysisReport, PolicyEvaluation, PolicyRuleResult

POLICY_LIMITATIONS = [
    "Policy decisions are release gates based on static scan output, not a complete security guarantee.",
    "Heuristic findings can be false positives and should be reviewed before being treated as confirmed defects.",
    "Confirmed means the finding is not labeled heuristic by the current analyzer output.",
]


def evaluate_policy(
    report: NormalizedAnalysisReport,
    min_score: int | None = None,
) -> PolicyEvaluation:
    threshold = _bounded_score(min_score if min_score is not None else settings.policy_min_score)
    rules = [
        _fail_on_critical_confirmed(report.findings),
        _fail_on_low_score(report.score, threshold),
        _warn_on_heuristic_high(report.findings),
    ]

    decision = "pass"
    if any(rule.status == "fail" for rule in rules):
        decision = "fail"
    elif any(rule.status == "warn" for rule in rules):
        decision = "warn"

    return PolicyEvaluation(
        decision=decision,
        min_score=threshold,
        rules=rules,
        limitations=POLICY_LIMITATIONS,
    )


def is_heuristic_finding(finding: Finding) -> bool:
    searchable = " ".join(
        [
            finding.id,
            finding.title,
            finding.description,
            finding.recommendation,
        ]
    ).lower()
    return "heuristic" in searchable


def _fail_on_critical_confirmed(findings: list[Finding]) -> PolicyRuleResult:
    finding_ids = [
        finding.id
        for finding in findings
        if finding.severity == "critical" and not is_heuristic_finding(finding)
    ]
    status = "fail" if finding_ids else "pass"
    message = (
        f"{len(finding_ids)} confirmed critical finding(s) block release"
        if finding_ids
        else "No confirmed critical findings found"
    )
    return PolicyRuleResult(
        id="fail-critical-confirmed",
        name="Fail on confirmed critical findings",
        status=status,
        message=message,
        finding_ids=finding_ids,
    )


def _fail_on_low_score(score: int, min_score: int) -> PolicyRuleResult:
    status = "fail" if score < min_score else "pass"
    message = (
        f"Score {score} is below required minimum {min_score}"
        if status == "fail"
        else f"Score {score} meets required minimum {min_score}"
    )
    return PolicyRuleResult(
        id="fail-score-threshold",
        name="Fail below score threshold",
        status=status,
        message=message,
    )


def _warn_on_heuristic_high(findings: list[Finding]) -> PolicyRuleResult:
    finding_ids = [
        finding.id
        for finding in findings
        if finding.severity == "high" and is_heuristic_finding(finding)
    ]
    status = "warn" if finding_ids else "pass"
    message = (
        f"{len(finding_ids)} heuristic high-severity finding(s) require review"
        if finding_ids
        else "No heuristic high-severity findings found"
    )
    return PolicyRuleResult(
        id="warn-high-heuristic",
        name="Warn on heuristic high-severity findings",
        status=status,
        message=message,
        finding_ids=finding_ids,
    )


def _bounded_score(value: int) -> int:
    return max(0, min(value, 100))
