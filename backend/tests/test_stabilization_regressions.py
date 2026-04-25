from __future__ import annotations

from contextlib import closing
from datetime import datetime, timezone
import json
import sqlite3

from fastapi.testclient import TestClient

from app.api.routes import upload as upload_route
from app.db.database import connect, initialize_database
from app.main import app
from app.models.report import NormalizedAnalysisReport
from app.services.scan_history import ScanHistoryStore


def _report() -> NormalizedAnalysisReport:
    return NormalizedAnalysisReport(
        platform="android",
        file_name="sample.apk",
        risk_level="high",
        score=73,
        summary={
            "total_findings": 1,
            "by_severity": {"low": 0, "medium": 0, "high": 1, "critical": 0},
        },
        findings=[
            {
                "id": "ANDROID-TEST-001",
                "title": "Debuggable release build",
                "severity": "high",
                "category": "manifest",
                "description": "android:debuggable is enabled",
                "recommendation": "Disable debugging in release builds",
                "source": "AndroidManifest.xml",
            }
        ],
        categories=[{"name": "manifest", "count": 1, "max_severity": "high"}],
        metadata={
            "generated_at": datetime.now(timezone.utc),
            "analyzer_version": "0.1.0-mvp",
            "analysis_mode": "static-placeholder",
            "file_extension": ".apk",
        },
    )


def test_initialize_database_migrates_legacy_schema_and_records_migrations(tmp_path) -> None:
    db_path = tmp_path / "legacy.sqlite3"
    db_url = f"sqlite:///{db_path}"
    connection = sqlite3.connect(db_path)
    try:
        connection.executescript(
            """
            CREATE TABLE projects (
                id TEXT PRIMARY KEY,
                name TEXT NOT NULL UNIQUE,
                created_at TEXT NOT NULL
            );
            CREATE TABLE mobile_apps (
                id TEXT PRIMARY KEY,
                project_id TEXT NOT NULL,
                name TEXT NOT NULL,
                platform TEXT NOT NULL,
                created_at TEXT NOT NULL
            );
            CREATE TABLE app_versions (
                id TEXT PRIMARY KEY,
                app_id TEXT NOT NULL,
                version_name TEXT,
                created_at TEXT NOT NULL
            );
            CREATE TABLE scans (
                id TEXT PRIMARY KEY,
                app_version_id TEXT NOT NULL,
                status TEXT NOT NULL,
                risk_level TEXT NOT NULL,
                score INTEGER NOT NULL,
                started_at TEXT NOT NULL,
                completed_at TEXT
            );
            CREATE TABLE scan_results (
                scan_id TEXT PRIMARY KEY,
                report_json TEXT NOT NULL,
                summary_json TEXT NOT NULL,
                created_at TEXT NOT NULL
            );
            CREATE TABLE findings (
                id TEXT PRIMARY KEY,
                scan_id TEXT NOT NULL,
                finding_key TEXT NOT NULL,
                title TEXT NOT NULL,
                severity TEXT NOT NULL,
                category TEXT NOT NULL,
                description TEXT NOT NULL,
                recommendation TEXT NOT NULL,
                source TEXT NOT NULL,
                ordinal INTEGER NOT NULL
            );
            """
        )
        connection.commit()
    finally:
        connection.close()

    initialize_database(db_url)
    initialize_database(db_url)

    with closing(connect(db_url)) as migrated:
        scan_columns = {row["name"] for row in migrated.execute("PRAGMA table_info(scans)").fetchall()}
        version_columns = {
            row["name"] for row in migrated.execute("PRAGMA table_info(app_versions)").fetchall()
        }
        migrations = migrated.execute("SELECT id FROM schema_migrations ORDER BY id").fetchall()

    assert {"file_name", "file_extension", "error_code", "error_message"}.issubset(scan_columns)
    assert {"build_identifier", "file_name", "file_extension"}.issubset(version_columns)
    assert [row["id"] for row in migrations] == [
        "001_app_version_build_metadata",
        "002_scan_package_metadata",
        "003_scan_failure_metadata",
    ]


def test_failed_scan_is_listed_and_report_endpoint_returns_recovery_error() -> None:
    store = ScanHistoryStore()
    failed_scan = store.save_failed_scan(
        file_name="broken.apk",
        file_extension=".apk",
        platform="android",
        error_code="SCAN_ANALYSIS_FAILED",
        error_message="tool crashed",
        project_name="Recovery",
        app_name="Wallet",
        version_name="1.0.0",
    )

    recent = store.list_recent_scans()
    with TestClient(app) as client:
        response = client.get(f"/api/v1/scans/{failed_scan.id}")

    assert recent[0].id == failed_scan.id
    assert recent[0].status == "failed"
    assert recent[0].error_code == "SCAN_ANALYSIS_FAILED"
    assert recent[0].finding_count == 0
    assert store.get_report(failed_scan.id) is None
    assert response.status_code == 409
    assert response.json()["error"]["code"] == "SCAN_FAILED"


def test_failed_scan_cannot_be_used_as_comparison_baseline() -> None:
    store = ScanHistoryStore()
    project = store.create_project("Comparison Recovery")
    mobile_app = store.create_app(project.id, "Wallet", "android")
    completed_version = store.create_app_version(mobile_app.id, "1.0.0", "100")
    failed_version = store.create_app_version(mobile_app.id, "1.1.0", "110")
    completed_scan = store.save_report(
        _report(),
        project_id=project.id,
        app_id=mobile_app.id,
        app_version_id=completed_version.id,
    )
    failed_scan = store.save_failed_scan(
        file_name="wallet-1.1.0.apk",
        file_extension=".apk",
        platform="android",
        error_code="SCAN_ANALYSIS_FAILED",
        error_message="tool crashed",
        project_id=project.id,
        app_id=mobile_app.id,
        app_version_id=failed_version.id,
    )

    with TestClient(app) as client:
        response = client.get(
            f"/api/v1/scans/{completed_scan.id}/comparison",
            params={"baseline_scan_id": failed_scan.id},
        )

    assert response.status_code == 409
    assert response.json()["error"]["code"] == "SCAN_COMPARISON_ERROR"


def test_upload_core_analysis_failure_persists_failed_scan(monkeypatch) -> None:
    def broken_report_builder(**_kwargs):
        raise RuntimeError("analyzer crashed")

    monkeypatch.setattr(upload_route, "build_normalized_report", broken_report_builder)

    with TestClient(app) as client:
        response = client.post(
            "/api/v1/upload",
            data={
                "project_name": "Recovery",
                "app_name": "Crashy",
                "version_name": "1.0.0",
            },
            files={"file": ("broken.apk", b"placeholder", "application/octet-stream")},
        )

    recent = ScanHistoryStore().list_recent_scans()
    failed_scan = next(scan for scan in recent if scan.file_name == "broken.apk")

    assert response.status_code == 500
    assert response.json()["error"]["code"] == "SCAN_ANALYSIS_FAILED"
    assert response.json()["error"]["details"]["scan_id"] == failed_scan.id
    assert failed_scan.status == "failed"
    assert failed_scan.error_message == "analyzer crashed"


def test_historical_report_payload_is_repaired_on_retrieval() -> None:
    store = ScanHistoryStore()
    scan = store.save_report(_report(), project_name="Legacy", app_name="Wallet", version_name="1.0.0")
    legacy_payload = _report().model_dump(mode="json")
    legacy_payload["summary"] = {
        "total_findings": 0,
        "by_severity": {"low": 0, "medium": 0, "high": 0, "critical": 0},
    }
    legacy_payload["categories"] = []
    legacy_payload["findings"][0].pop("source")

    with closing(connect()) as connection:
        with connection:
            connection.execute(
                "UPDATE scan_results SET report_json = ? WHERE scan_id = ?",
                (json.dumps(legacy_payload), scan.id),
            )

    retrieved = store.get_report(scan.id)

    assert retrieved is not None
    assert retrieved.findings[0].source == "historical/unknown-source"
    assert retrieved.summary.total_findings == 1
    assert retrieved.summary.by_severity["high"] == 1
    assert retrieved.categories[0].name == "manifest"
