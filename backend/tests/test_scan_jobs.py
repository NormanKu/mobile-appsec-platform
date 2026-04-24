from io import BytesIO
from time import sleep
from zipfile import ZIP_DEFLATED, ZipFile

import pytest
from fastapi.testclient import TestClient

from app.main import app, limiter
from app.services.scan_jobs import scan_job_store

client = TestClient(app)


@pytest.fixture(autouse=True)
def reset_scan_jobs(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(limiter, "enabled", False)
    limiter.reset()
    scan_job_store.clear()
    yield
    scan_job_store.clear()


def _build_apk_payload() -> bytes:
    manifest = """
    <manifest package="com.example.app" xmlns:android="http://schemas.android.com/apk/res/android">
      <application android:debuggable="true" />
    </manifest>
    """
    buffer = BytesIO()
    with ZipFile(buffer, "w", compression=ZIP_DEFLATED) as archive:
        archive.writestr("AndroidManifest.xml", manifest)
        archive.writestr("assets/config.txt", "url=https://api.example.com")
    return buffer.getvalue()


def _wait_for_terminal_status(job_id: str) -> dict:
    for _ in range(100):
        response = client.get(f"/api/v1/scans/{job_id}")
        assert response.status_code == 200
        payload = response.json()
        if payload["status"] in {"completed", "failed"}:
            return payload
        sleep(0.01)

    pytest.fail(f"Scan job {job_id} did not reach a terminal status")


def test_scan_job_lifecycle_completes_with_normalized_report() -> None:
    response = client.post(
        "/api/v1/scans",
        files={
            "file": ("sample.apk", _build_apk_payload(), "application/octet-stream")
        },
    )

    assert response.status_code == 202
    accepted = response.json()
    assert accepted["job_id"]
    assert accepted["status"] in {"queued", "running", "completed"}
    assert accepted["platform"] == "android"
    assert accepted["file_name"] == "sample.apk"
    assert accepted["report"] is None or accepted["report"]["platform"] == "android"

    completed = _wait_for_terminal_status(accepted["job_id"])

    assert completed["status"] == "completed"
    assert completed["error"] is None
    assert completed["report"]["platform"] == "android"
    assert completed["report"]["file_name"] == "sample.apk"
    assert {
        "platform",
        "file_name",
        "risk_level",
        "score",
        "summary",
        "findings",
        "categories",
        "top_risks",
        "metadata",
    }.issubset(completed["report"].keys())


def test_scan_job_returns_partial_report_for_malformed_archive() -> None:
    response = client.post(
        "/api/v1/scans",
        files={"file": ("bad.apk", b"not-a-zip", "application/octet-stream")},
    )

    assert response.status_code == 202
    accepted = response.json()

    completed = _wait_for_terminal_status(accepted["job_id"])

    assert completed["status"] == "completed"
    assert completed["error"] is None
    assert completed["message"] == "Partial analysis completed with errors"
    assert completed["report"]["analysis_status"] == "partial"
    assert completed["report"]["errors"][0]["code"] == "INVALID_ARCHIVE"
    assert completed["report"]["errors"][0]["details"]["file_name"] == "bad.apk"


def test_scan_job_still_fails_for_unhandled_pipeline_exceptions(monkeypatch) -> None:
    monkeypatch.setattr(
        "app.services.scan_jobs.build_normalized_report",
        lambda **_: (_ for _ in ()).throw(RuntimeError("pipeline boom")),
    )

    response = client.post(
        "/api/v1/scans",
        files={
            "file": ("sample.apk", _build_apk_payload(), "application/octet-stream")
        },
    )

    assert response.status_code == 202
    accepted = response.json()

    failed = _wait_for_terminal_status(accepted["job_id"])

    assert failed["status"] == "failed"
    assert failed["report"] is None
    assert failed["error"]["code"] == "ANALYSIS_FAILED"
    assert failed["error"]["details"]["stage"] == "scan-job"


def test_scan_job_submission_still_rejects_unsupported_file_type() -> None:
    response = client.post(
        "/api/v1/scans",
        files={"file": ("notes.txt", b"placeholder", "text/plain")},
    )

    assert response.status_code == 400
    payload = response.json()
    assert payload["error"]["code"] == "INVALID_FILE_TYPE"


def test_scan_job_status_returns_404_for_unknown_job() -> None:
    response = client.get("/api/v1/scans/missing-job")

    assert response.status_code == 404
    payload = response.json()
    assert payload["error"]["code"] == "SCAN_JOB_NOT_FOUND"
    assert payload["error"]["details"]["job_id"] == "missing-job"
