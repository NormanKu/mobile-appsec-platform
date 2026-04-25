from datetime import datetime, timezone

from fastapi.testclient import TestClient

from app.main import app
from app.models.report import NormalizedAnalysisReport
from app.models.scan_history import AppVersion, MobileApp, Project, Scan, StoredFinding
from app.services.scan_history import ScanHistoryStore


def _build_report() -> NormalizedAnalysisReport:
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


def test_scan_history_domain_models_can_be_created() -> None:
    now = datetime.now(timezone.utc)

    project = Project(id="project-1", name="Default Project", created_at=now)
    mobile_app = MobileApp(
        id="app-1",
        project_id=project.id,
        name="sample",
        platform="android",
        created_at=now,
    )
    app_version = AppVersion(
        id="version-1",
        app_id=mobile_app.id,
        version_name="1.2.3",
        build_identifier="42",
        created_at=now,
    )
    scan = Scan(
        id="scan-1",
        app_version_id=app_version.id,
        file_name="sample.apk",
        file_extension=".apk",
        status="completed",
        risk_level="high",
        score=73,
        started_at=now,
        completed_at=now,
    )
    finding = StoredFinding(
        id="finding-1",
        scan_id=scan.id,
        finding_key="ANDROID-TEST-001",
        title="Debuggable release build",
        severity="high",
        category="manifest",
        description="android:debuggable is enabled",
        recommendation="Disable debugging in release builds",
        source="AndroidManifest.xml",
        ordinal=0,
    )

    assert project.name == "Default Project"
    assert mobile_app.project_id == project.id
    assert app_version.app_id == mobile_app.id
    assert app_version.build_identifier == "42"
    assert scan.app_version_id == app_version.id
    assert finding.scan_id == scan.id


def test_scan_history_store_persists_and_retrieves_report() -> None:
    store = ScanHistoryStore()
    report = _build_report()
    project = store.create_project("Payments")
    mobile_app = store.create_app(project.id, "Customer Wallet", "android")
    app_version = store.create_app_version(
        mobile_app.id,
        version_name="1.2.3",
        build_identifier="42",
    )

    scan = store.save_report(
        report,
        project_id=project.id,
        app_id=mobile_app.id,
        app_version_id=app_version.id,
    )
    recent_scans = store.list_recent_scans(app_id=mobile_app.id)
    version_scans = store.list_recent_scans(app_version_id=app_version.id)
    retrieved = store.get_report(scan.id)

    assert recent_scans[0].id == scan.id
    assert recent_scans[0].project_name == "Payments"
    assert recent_scans[0].app_name == "Customer Wallet"
    assert recent_scans[0].version_name == "1.2.3"
    assert recent_scans[0].build_identifier == "42"
    assert recent_scans[0].finding_count == 1
    assert version_scans[0].id == scan.id
    assert retrieved is not None
    assert retrieved.model_dump(mode="json") == report.model_dump(mode="json")


def test_scan_history_endpoints_create_context_and_retrieve_associated_scan() -> None:
    with TestClient(app) as client:
        project_response = client.post("/api/v1/projects", json={"name": "Retail"})
        project_id = project_response.json()["id"]

        app_response = client.post(
            f"/api/v1/projects/{project_id}/apps",
            json={"name": "Shopper", "platform": "android"},
        )
        app_id = app_response.json()["id"]

        version_response = client.post(
            f"/api/v1/apps/{app_id}/versions",
            json={"version_name": "2.0.0", "build_identifier": "200"},
        )
        version_id = version_response.json()["id"]

        upload_response = client.post(
            "/api/v1/upload",
            data={
                "project_id": project_id,
                "app_id": app_id,
                "app_version_id": version_id,
            },
            files={"file": ("sample.apk", b"placeholder", "application/octet-stream")},
        )
        list_response = client.get(f"/api/v1/scans?app_id={app_id}")
        version_list_response = client.get(f"/api/v1/scans?app_version_id={version_id}")

        assert upload_response.status_code == 200
        scans = list_response.json()
        scan_id = scans[0]["id"]
        get_response = client.get(f"/api/v1/scans/{scan_id}")

    assert list_response.status_code == 200
    assert scans[0]["finding_count"] == 1
    assert scans[0]["project_id"] == project_id
    assert scans[0]["app_id"] == app_id
    assert scans[0]["app_version_id"] == version_id
    assert scans[0]["version_name"] == "2.0.0"
    assert version_list_response.json()[0]["id"] == scan_id

    assert get_response.status_code == 200
    payload = get_response.json()
    assert payload["file_name"] == "sample.apk"
    assert payload["findings"][0]["id"] == "ANDROID-ARCHIVE-001"


def test_scan_history_endpoint_returns_404_for_missing_scan() -> None:
    with TestClient(app) as client:
        response = client.get("/api/v1/scans/missing-scan")

    assert response.status_code == 404
    assert response.json()["error"]["code"] == "SCAN_NOT_FOUND"
