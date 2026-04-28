from fastapi import APIRouter, Query
from fastapi.responses import JSONResponse

from app.models.comparison import ScanComparison
from app.models.error import ErrorResponse
from app.models.report import NormalizedAnalysisReport, PolicyEvaluation
from app.models.scan_history import RecentScan
from app.services.scan_comparison import ScanComparisonError, compare_scans
from app.services.policy_evaluator import evaluate_policy
from app.services.scan_history import ScanHistoryStore

router = APIRouter(prefix="/scans", tags=["scans"])


@router.get("", response_model=list[RecentScan])
def list_recent_scans(
    limit: int = Query(default=20, ge=1, le=100),
    app_id: str | None = None,
    app_version_id: str | None = None,
) -> list[RecentScan]:
    return ScanHistoryStore().list_recent_scans(
        limit=limit,
        app_id=app_id,
        app_version_id=app_version_id,
    )


@router.get(
    "/{scan_id}/comparison",
    response_model=ScanComparison,
    responses={
        400: {"model": ErrorResponse, "description": "Invalid comparison request"},
        404: {"model": ErrorResponse, "description": "Scan result not found"},
        409: {
            "model": ErrorResponse,
            "description": "Scan exists but has no completed result",
        },
    },
)
def compare_scan_to_baseline(
    scan_id: str, baseline_scan_id: str
) -> ScanComparison | JSONResponse:
    try:
        return compare_scans(target_scan_id=scan_id, baseline_scan_id=baseline_scan_id)
    except ScanComparisonError as exc:
        return JSONResponse(
            status_code=exc.status_code,
            content={
                "error": {
                    "code": "SCAN_COMPARISON_ERROR",
                    "message": str(exc),
                    "details": {
                        "scan_id": scan_id,
                        "baseline_scan_id": baseline_scan_id,
                    },
                }
            },
        )


@router.get(
    "/{scan_id}/policy",
    response_model=PolicyEvaluation,
    responses={
        404: {"model": ErrorResponse, "description": "Scan result not found"},
        409: {
            "model": ErrorResponse,
            "description": "Scan exists but has no completed result",
        },
        422: {"model": PolicyEvaluation, "description": "Policy gate failed"},
    },
)
def evaluate_scan_policy(
    scan_id: str,
    min_score: int = Query(default=70, ge=0, le=100),
    fail_on_policy_failure: bool = False,
) -> PolicyEvaluation | JSONResponse:
    report = ScanHistoryStore().get_report(scan_id)
    if report is None:
        scan = ScanHistoryStore().get_scan(scan_id)
        if scan is not None and scan.status == "failed":
            return JSONResponse(
                status_code=409,
                content={
                    "error": {
                        "code": "SCAN_FAILED",
                        "message": "Scan failed before a normalized report was produced",
                        "details": {
                            "scan_id": scan_id,
                            "error_code": scan.error_code,
                            "error_message": scan.error_message,
                        },
                    }
                },
            )
        return JSONResponse(
            status_code=404,
            content={
                "error": {
                    "code": "SCAN_NOT_FOUND",
                    "message": "No scan result exists for the requested id",
                    "details": {"scan_id": scan_id},
                }
            },
        )

    evaluation = evaluate_policy(report, min_score=min_score)
    status_code = (
        422 if fail_on_policy_failure and evaluation.decision == "fail" else 200
    )
    return JSONResponse(
        status_code=status_code, content=evaluation.model_dump(mode="json")
    )


@router.get(
    "/{scan_id}",
    response_model=NormalizedAnalysisReport,
    responses={
        404: {"model": ErrorResponse, "description": "Scan result not found"},
        409: {
            "model": ErrorResponse,
            "description": "Scan exists but has no completed result",
        },
    },
)
def get_scan_result(scan_id: str) -> NormalizedAnalysisReport | JSONResponse:
    store = ScanHistoryStore()
    report = store.get_report(scan_id)
    if report is None:
        scan = store.get_scan(scan_id)
        if scan is not None and scan.status == "failed":
            return JSONResponse(
                status_code=409,
                content={
                    "error": {
                        "code": "SCAN_FAILED",
                        "message": "Scan failed before a normalized report was produced",
                        "details": {
                            "scan_id": scan_id,
                            "error_code": scan.error_code,
                            "error_message": scan.error_message,
                        },
                    }
                },
            )
        return JSONResponse(
            status_code=404,
            content={
                "error": {
                    "code": "SCAN_NOT_FOUND",
                    "message": "No scan result exists for the requested id",
                    "details": {"scan_id": scan_id},
                }
            },
        )
    return report
