import logging
from concurrent.futures import Future, ThreadPoolExecutor
from dataclasses import dataclass
from datetime import datetime, timezone
from threading import Lock
from uuid import uuid4

from app.errors.exceptions import UploadValidationError
from app.models.report import NormalizedAnalysisReport
from app.models.scan import ScanJobError, ScanJobStatus, ScanJobStatusResponse
from app.services.report_builder import build_normalized_report

logger = logging.getLogger(__name__)


@dataclass(frozen=True)
class ScanJobInput:
    file_name: str
    platform: str
    file_bytes: bytes
    file_extension: str
    max_zip_extracted_bytes: int
    max_zip_files: int
    max_text_file_size: int
    max_text_files_scanned: int


@dataclass
class ScanJobRecord:
    job_id: str
    status: ScanJobStatus
    platform: str
    file_name: str
    created_at: datetime
    updated_at: datetime
    message: str | None = None
    report: NormalizedAnalysisReport | None = None
    error: ScanJobError | None = None

    def to_response(self) -> ScanJobStatusResponse:
        return ScanJobStatusResponse(
            job_id=self.job_id,
            status=self.status,
            platform=self.platform,
            file_name=self.file_name,
            created_at=self.created_at,
            updated_at=self.updated_at,
            message=self.message,
            report=self.report,
            error=self.error,
        )


def _utc_now() -> datetime:
    return datetime.now(timezone.utc)


class ScanJobStore:
    def __init__(self, max_workers: int = 2) -> None:
        self._executor = ThreadPoolExecutor(
            max_workers=max_workers,
            thread_name_prefix="appsec-scan",
        )
        self._jobs: dict[str, ScanJobRecord] = {}
        self._futures: dict[str, Future] = {}
        self._lock = Lock()

    def submit(self, scan_input: ScanJobInput) -> ScanJobStatusResponse:
        job_id = uuid4().hex
        now = _utc_now()
        record = ScanJobRecord(
            job_id=job_id,
            status="queued",
            platform=scan_input.platform,
            file_name=scan_input.file_name,
            created_at=now,
            updated_at=now,
            message="Scan queued",
        )

        with self._lock:
            self._jobs[job_id] = record

        future = self._executor.submit(self._run_job, job_id, scan_input)
        with self._lock:
            self._futures[job_id] = future

        return record.to_response()

    def get(self, job_id: str) -> ScanJobStatusResponse | None:
        with self._lock:
            record = self._jobs.get(job_id)
            if record is None:
                return None
            return record.to_response()

    def clear(self) -> None:
        with self._lock:
            for future in self._futures.values():
                future.cancel()
            self._jobs.clear()
            self._futures.clear()

    def _run_job(self, job_id: str, scan_input: ScanJobInput) -> None:
        self._update(
            job_id,
            status="running",
            message="Scan in progress",
            report=None,
            error=None,
        )

        try:
            report = build_normalized_report(
                file_name=scan_input.file_name,
                platform=scan_input.platform,
                file_bytes=scan_input.file_bytes,
                file_extension=scan_input.file_extension,
                max_zip_extracted_bytes=scan_input.max_zip_extracted_bytes,
                max_zip_files=scan_input.max_zip_files,
                max_text_file_size=scan_input.max_text_file_size,
                max_text_files_scanned=scan_input.max_text_files_scanned,
                allow_partial=True,
            )
        except UploadValidationError as exc:
            self._fail_with_upload_error(job_id, exc)
        except TimeoutError:
            logger.warning("Async analysis timed out for %s", scan_input.file_name)
            self._fail_with_upload_error(
                job_id,
                UploadValidationError(
                    code="ANALYSIS_TIMEOUT",
                    message="Static analysis timed out",
                    status_code=500,
                    details={
                        "file_name": scan_input.file_name,
                        "platform": scan_input.platform,
                        "stage": "scan-job",
                        "reason": "Analysis exceeded time limit",
                    },
                ),
            )
        except Exception as exc:
            logger.exception(
                "Async scan failed unexpectedly for %s: %s",
                scan_input.file_name,
                exc,
            )
            self._fail_with_upload_error(
                job_id,
                UploadValidationError(
                    code="ANALYSIS_FAILED",
                    message="Static analysis could not be completed safely",
                    status_code=500,
                    details={
                        "file_name": scan_input.file_name,
                        "platform": scan_input.platform,
                        "stage": "scan-job",
                        "reason": "Unexpected scan job failure",
                    },
                ),
            )
        else:
            message = "Scan completed"
            if report.analysis_status == "partial":
                message = "Partial analysis completed with errors"
            elif report.analysis_status == "warning":
                message = "Scan completed with warnings"

            self._update(
                job_id,
                status="completed",
                message=message,
                report=report,
                error=None,
            )

    def _fail_with_upload_error(
        self,
        job_id: str,
        exc: UploadValidationError,
    ) -> None:
        self._update(
            job_id,
            status="failed",
            message=exc.message,
            report=None,
            error=ScanJobError(
                code=exc.code,
                message=exc.message,
                status_code=exc.status_code,
                details=exc.details,
            ),
        )

    def _update(
        self,
        job_id: str,
        *,
        status: ScanJobStatus,
        message: str | None,
        report: NormalizedAnalysisReport | None,
        error: ScanJobError | None,
    ) -> None:
        with self._lock:
            record = self._jobs.get(job_id)
            if record is None:
                return

            record.status = status
            record.updated_at = _utc_now()
            record.message = message
            record.report = report
            record.error = error


scan_job_store = ScanJobStore()
