from fastapi import APIRouter, HTTPException, status

from app.models.scan_history import (
    AppVersion,
    AppVersionCreate,
    MobileApp,
    MobileAppCreate,
    Project,
    ProjectCreate,
)
from app.services.scan_history import ScanHistoryStore

router = APIRouter(tags=["projects"])


@router.get("/projects", response_model=list[Project])
def list_projects() -> list[Project]:
    return ScanHistoryStore().list_projects()


@router.post("/projects", response_model=Project, status_code=status.HTTP_201_CREATED)
def create_project(payload: ProjectCreate) -> Project:
    try:
        return ScanHistoryStore().create_project(payload.name)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc


@router.get("/projects/{project_id}/apps", response_model=list[MobileApp])
def list_project_apps(project_id: str) -> list[MobileApp]:
    return ScanHistoryStore().list_apps(project_id)


@router.post(
    "/projects/{project_id}/apps",
    response_model=MobileApp,
    status_code=status.HTTP_201_CREATED,
)
def create_project_app(project_id: str, payload: MobileAppCreate) -> MobileApp:
    try:
        return ScanHistoryStore().create_app(project_id, payload.name, payload.platform)
    except ValueError as exc:
        status_code = 404 if "not found" in str(exc).lower() else 400
        raise HTTPException(status_code=status_code, detail=str(exc)) from exc


@router.get("/apps/{app_id}/versions", response_model=list[AppVersion])
def list_app_versions(app_id: str) -> list[AppVersion]:
    return ScanHistoryStore().list_app_versions(app_id)


@router.post(
    "/apps/{app_id}/versions",
    response_model=AppVersion,
    status_code=status.HTTP_201_CREATED,
)
def create_app_version(app_id: str, payload: AppVersionCreate) -> AppVersion:
    try:
        return ScanHistoryStore().create_app_version(
            app_id=app_id,
            version_name=payload.version_name,
            build_identifier=payload.build_identifier,
        )
    except ValueError as exc:
        status_code = 404 if "not found" in str(exc).lower() else 400
        raise HTTPException(status_code=status_code, detail=str(exc)) from exc
