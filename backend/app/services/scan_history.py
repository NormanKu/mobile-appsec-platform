from __future__ import annotations

from contextlib import closing
from datetime import datetime, timezone
import json
from pathlib import Path
import sqlite3
from uuid import uuid4

from app.core.config import settings
from app.db.database import connect, initialize_database
from app.models.report import NormalizedAnalysisReport, Platform
from app.models.scan_history import AppVersion, MobileApp, Project, RecentScan, Scan
from app.services.policy_evaluator import evaluate_policy

SEVERITY_RANK = {"low": 1, "medium": 2, "high": 3, "critical": 4}
SEVERITIES = ("low", "medium", "high", "critical")


class ScanHistoryStore:
    def __init__(
        self, database_url: str | None = None, default_project_name: str | None = None
    ):
        self.database_url = database_url or settings.database_url
        self.default_project_name = (
            default_project_name or settings.default_project_name
        )

    def list_projects(self) -> list[Project]:
        initialize_database(self.database_url)
        with closing(connect(self.database_url)) as connection:
            rows = connection.execute("SELECT * FROM projects ORDER BY name").fetchall()
        return [_row_to_project(row) for row in rows]

    def create_project(self, name: str) -> Project:
        initialize_database(self.database_url)
        now = _utc_now()
        project_name = _required_text(name, "project name")

        with closing(connect(self.database_url)) as connection:
            with connection:
                return self._get_or_create_project(connection, project_name, now)

    def list_apps(self, project_id: str) -> list[MobileApp]:
        initialize_database(self.database_url)
        with closing(connect(self.database_url)) as connection:
            rows = connection.execute(
                """
                SELECT * FROM mobile_apps
                WHERE project_id = ?
                ORDER BY platform, name
                """,
                (project_id,),
            ).fetchall()
        return [_row_to_mobile_app(row) for row in rows]

    def create_app(self, project_id: str, name: str, platform: Platform) -> MobileApp:
        initialize_database(self.database_url)
        now = _utc_now()
        app_name = _required_text(name, "app name")

        with closing(connect(self.database_url)) as connection:
            with connection:
                project = self._get_project(connection, project_id)
                if project is None:
                    raise ValueError("Project not found")
                return self._get_or_create_mobile_app(
                    connection,
                    project.id,
                    app_name,
                    platform,
                    now,
                )

    def list_app_versions(self, app_id: str) -> list[AppVersion]:
        initialize_database(self.database_url)
        with closing(connect(self.database_url)) as connection:
            rows = connection.execute(
                """
                SELECT * FROM app_versions
                WHERE app_id = ?
                ORDER BY created_at DESC
                """,
                (app_id,),
            ).fetchall()
        return [_row_to_app_version(row) for row in rows]

    def create_app_version(
        self,
        app_id: str,
        version_name: str | None = None,
        build_identifier: str | None = None,
    ) -> AppVersion:
        initialize_database(self.database_url)
        now = _utc_now()

        with closing(connect(self.database_url)) as connection:
            with connection:
                app = self._get_mobile_app(connection, app_id)
                if app is None:
                    raise ValueError("App not found")
                return self._get_or_create_app_version(
                    connection=connection,
                    app_id=app.id,
                    version_name=version_name,
                    build_identifier=build_identifier,
                    platform=app.platform,
                    now=now,
                )

    def save_report(
        self,
        report: NormalizedAnalysisReport,
        project_id: str | None = None,
        project_name: str | None = None,
        app_id: str | None = None,
        app_name: str | None = None,
        app_version_id: str | None = None,
        version_name: str | None = None,
        build_identifier: str | None = None,
    ) -> Scan:
        initialize_database(self.database_url)
        now = _utc_now()
        if report.policy is None:
            report.policy = evaluate_policy(report)

        with closing(connect(self.database_url)) as connection:
            with connection:
                project = self._resolve_project(
                    connection, project_id, project_name, now
                )
                mobile_app = self._resolve_mobile_app(
                    connection,
                    project,
                    report,
                    app_id,
                    app_name,
                    now,
                )
                app_version = self._resolve_app_version(
                    connection=connection,
                    app=mobile_app,
                    report=report,
                    app_version_id=app_version_id,
                    version_name=version_name,
                    build_identifier=build_identifier,
                    now=now,
                )
                scan = self._create_completed_scan(
                    connection, app_version.id, report, now
                )
                self._create_scan_result(connection, scan.id, report, now)
                self._create_findings(connection, scan.id, report)
                return scan

    def save_failed_scan(
        self,
        file_name: str,
        file_extension: str,
        platform: Platform,
        error_code: str,
        error_message: str,
        project_id: str | None = None,
        project_name: str | None = None,
        app_id: str | None = None,
        app_name: str | None = None,
        app_version_id: str | None = None,
        version_name: str | None = None,
        build_identifier: str | None = None,
    ) -> Scan:
        initialize_database(self.database_url)
        now = _utc_now()

        with closing(connect(self.database_url)) as connection:
            with connection:
                project = self._resolve_project(
                    connection, project_id, project_name, now
                )
                mobile_app = self._resolve_mobile_app_for_upload(
                    connection=connection,
                    project=project,
                    platform=platform,
                    file_name=file_name,
                    app_id=app_id,
                    app_name=app_name,
                    now=now,
                )
                app_version = self._resolve_app_version_for_upload(
                    connection=connection,
                    app=mobile_app,
                    file_name=file_name,
                    file_extension=file_extension,
                    app_version_id=app_version_id,
                    version_name=version_name,
                    build_identifier=build_identifier,
                    now=now,
                )
                return self._create_failed_scan(
                    connection=connection,
                    app_version_id=app_version.id,
                    file_name=file_name,
                    file_extension=file_extension,
                    error_code=error_code,
                    error_message=error_message,
                    now=now,
                )

    def list_recent_scans(
        self,
        limit: int = 20,
        app_id: str | None = None,
        app_version_id: str | None = None,
    ) -> list[RecentScan]:
        initialize_database(self.database_url)
        bounded_limit = max(1, min(limit, 100))

        filters = []
        params: list[str | int] = []
        if app_id:
            filters.append("mobile_apps.id = ?")
            params.append(app_id)
        if app_version_id:
            filters.append("app_versions.id = ?")
            params.append(app_version_id)

        where_clause = f"WHERE {' AND '.join(filters)}" if filters else ""
        params.append(bounded_limit)

        with closing(connect(self.database_url)) as connection:
            rows = connection.execute(
                f"""
                SELECT
                    scans.id,
                    projects.id AS project_id,
                    projects.name AS project_name,
                    mobile_apps.id AS app_id,
                    mobile_apps.name AS app_name,
                    app_versions.id AS app_version_id,
                    app_versions.version_name,
                    app_versions.build_identifier,
                    COALESCE(scans.file_name, app_versions.file_name, '') AS file_name,
                    COALESCE(
                        scans.file_extension,
                        app_versions.file_extension,
                        '.apk'
                    ) AS file_extension,
                    mobile_apps.platform,
                    scans.status,
                    scans.risk_level,
                    scans.score,
                    COUNT(findings.id) AS finding_count,
                    scans.error_code,
                    scans.error_message,
                    scans.started_at,
                    scans.completed_at
                FROM scans
                JOIN app_versions ON app_versions.id = scans.app_version_id
                JOIN mobile_apps ON mobile_apps.id = app_versions.app_id
                JOIN projects ON projects.id = mobile_apps.project_id
                LEFT JOIN findings ON findings.scan_id = scans.id
                {where_clause}
                GROUP BY scans.id
                ORDER BY COALESCE(scans.completed_at, scans.started_at) DESC
                LIMIT ?
                """,
                params,
            ).fetchall()

        return [_row_to_recent_scan(row) for row in rows]

    def get_scan(self, scan_id: str) -> Scan | None:
        initialize_database(self.database_url)
        with closing(connect(self.database_url)) as connection:
            row = connection.execute(
                "SELECT * FROM scans WHERE id = ?", (scan_id,)
            ).fetchone()
        return _row_to_scan(row) if row else None

    def get_report(self, scan_id: str) -> NormalizedAnalysisReport | None:
        initialize_database(self.database_url)
        with closing(connect(self.database_url)) as connection:
            row = connection.execute(
                "SELECT report_json FROM scan_results WHERE scan_id = ?",
                (scan_id,),
            ).fetchone()

        if row is None:
            return None

        payload = _repair_report_payload(json.loads(row["report_json"]))
        report = NormalizedAnalysisReport.model_validate(payload)
        if report.policy is None:
            report.policy = evaluate_policy(report)
        return report

    def _resolve_project(
        self,
        connection: sqlite3.Connection,
        project_id: str | None,
        project_name: str | None,
        now: datetime,
    ) -> Project:
        if project_id:
            project = self._get_project(connection, project_id)
            if project is None:
                raise ValueError("Project not found")
            return project

        return self._get_or_create_project(
            connection,
            _clean_text(project_name) or self.default_project_name,
            now,
        )

    def _resolve_mobile_app(
        self,
        connection: sqlite3.Connection,
        project: Project,
        report: NormalizedAnalysisReport,
        app_id: str | None,
        app_name: str | None,
        now: datetime,
    ) -> MobileApp:
        if app_id:
            mobile_app = self._get_mobile_app(connection, app_id)
            if mobile_app is None:
                raise ValueError("App not found")
            if mobile_app.project_id != project.id:
                raise ValueError("App does not belong to the selected project")
            if mobile_app.platform != report.platform:
                raise ValueError(
                    "Selected app platform does not match uploaded package"
                )
            return mobile_app

        resolved_name = (
            _clean_text(app_name) or Path(report.file_name).stem or report.file_name
        )
        return self._get_or_create_mobile_app(
            connection,
            project.id,
            resolved_name,
            report.platform,
            now,
        )

    def _resolve_mobile_app_for_upload(
        self,
        connection: sqlite3.Connection,
        project: Project,
        platform: Platform,
        file_name: str,
        app_id: str | None,
        app_name: str | None,
        now: datetime,
    ) -> MobileApp:
        if app_id:
            mobile_app = self._get_mobile_app(connection, app_id)
            if mobile_app is None:
                raise ValueError("App not found")
            if mobile_app.project_id != project.id:
                raise ValueError("App does not belong to the selected project")
            if mobile_app.platform != platform:
                raise ValueError(
                    "Selected app platform does not match uploaded package"
                )
            return mobile_app

        resolved_name = _clean_text(app_name) or Path(file_name).stem or file_name
        return self._get_or_create_mobile_app(
            connection,
            project.id,
            resolved_name,
            platform,
            now,
        )

    def _resolve_app_version(
        self,
        connection: sqlite3.Connection,
        app: MobileApp,
        report: NormalizedAnalysisReport,
        app_version_id: str | None,
        version_name: str | None,
        build_identifier: str | None,
        now: datetime,
    ) -> AppVersion:
        if app_version_id:
            app_version = self._get_app_version(connection, app_version_id)
            if app_version is None:
                raise ValueError("App version not found")
            if app_version.app_id != app.id:
                raise ValueError("App version does not belong to the selected app")
            return app_version

        return self._get_or_create_app_version(
            connection=connection,
            app_id=app.id,
            version_name=version_name,
            build_identifier=build_identifier,
            platform=app.platform,
            file_name=report.file_name,
            file_extension=report.metadata.file_extension,
            now=now,
        )

    def _resolve_app_version_for_upload(
        self,
        connection: sqlite3.Connection,
        app: MobileApp,
        file_name: str,
        file_extension: str,
        app_version_id: str | None,
        version_name: str | None,
        build_identifier: str | None,
        now: datetime,
    ) -> AppVersion:
        if app_version_id:
            app_version = self._get_app_version(connection, app_version_id)
            if app_version is None:
                raise ValueError("App version not found")
            if app_version.app_id != app.id:
                raise ValueError("App version does not belong to the selected app")
            return app_version

        return self._get_or_create_app_version(
            connection=connection,
            app_id=app.id,
            version_name=version_name,
            build_identifier=build_identifier,
            platform=app.platform,
            file_name=file_name,
            file_extension=file_extension,
            now=now,
        )

    def _get_project(
        self, connection: sqlite3.Connection, project_id: str
    ) -> Project | None:
        row = connection.execute(
            "SELECT * FROM projects WHERE id = ?", (project_id,)
        ).fetchone()
        return _row_to_project(row) if row else None

    def _get_or_create_project(
        self,
        connection: sqlite3.Connection,
        name: str,
        now: datetime,
    ) -> Project:
        connection.execute(
            """
            INSERT OR IGNORE INTO projects (id, name, created_at)
            VALUES (?, ?, ?)
            """,
            (_new_id(), name, _format_datetime(now)),
        )
        row = connection.execute(
            "SELECT * FROM projects WHERE name = ?", (name,)
        ).fetchone()
        return _row_to_project(row)

    def _get_mobile_app(
        self, connection: sqlite3.Connection, app_id: str
    ) -> MobileApp | None:
        row = connection.execute(
            "SELECT * FROM mobile_apps WHERE id = ?", (app_id,)
        ).fetchone()
        return _row_to_mobile_app(row) if row else None

    def _get_or_create_mobile_app(
        self,
        connection: sqlite3.Connection,
        project_id: str,
        name: str,
        platform: Platform,
        now: datetime,
    ) -> MobileApp:
        connection.execute(
            """
            INSERT OR IGNORE INTO mobile_apps (id, project_id, name, platform, created_at)
            VALUES (?, ?, ?, ?, ?)
            """,
            (_new_id(), project_id, name, platform, _format_datetime(now)),
        )
        row = connection.execute(
            """
            SELECT * FROM mobile_apps
            WHERE project_id = ? AND name = ? AND platform = ?
            """,
            (project_id, name, platform),
        ).fetchone()
        return _row_to_mobile_app(row)

    def _get_app_version(
        self,
        connection: sqlite3.Connection,
        app_version_id: str,
    ) -> AppVersion | None:
        row = connection.execute(
            "SELECT * FROM app_versions WHERE id = ?",
            (app_version_id,),
        ).fetchone()
        return _row_to_app_version(row) if row else None

    def _get_or_create_app_version(
        self,
        connection: sqlite3.Connection,
        app_id: str,
        version_name: str | None,
        build_identifier: str | None,
        platform: Platform,
        now: datetime,
        file_name: str | None = None,
        file_extension: str | None = None,
    ) -> AppVersion:
        resolved_version = _clean_text(version_name) or "Unspecified"
        resolved_build = _clean_text(build_identifier)
        lookup_build = resolved_build or ""

        row = connection.execute(
            """
            SELECT * FROM app_versions
            WHERE app_id = ?
              AND COALESCE(version_name, '') = ?
              AND COALESCE(build_identifier, '') = ?
            """,
            (app_id, resolved_version, lookup_build),
        ).fetchone()
        if row:
            return _row_to_app_version(row)

        app_version = AppVersion(
            id=_new_id(),
            app_id=app_id,
            version_name=resolved_version,
            build_identifier=resolved_build,
            created_at=now,
        )
        connection.execute(
            """
            INSERT INTO app_versions (
                id, app_id, version_name, build_identifier, file_name, file_extension, created_at
            )
            VALUES (?, ?, ?, ?, ?, ?, ?)
            """,
            (
                app_version.id,
                app_version.app_id,
                app_version.version_name,
                app_version.build_identifier,
                file_name or "",
                file_extension or _default_extension(platform),
                _format_datetime(app_version.created_at),
            ),
        )
        return app_version

    def _create_completed_scan(
        self,
        connection: sqlite3.Connection,
        app_version_id: str,
        report: NormalizedAnalysisReport,
        now: datetime,
    ) -> Scan:
        scan = Scan(
            id=_new_id(),
            app_version_id=app_version_id,
            file_name=report.file_name,
            file_extension=report.metadata.file_extension,
            status="completed",
            risk_level=report.risk_level,
            score=report.score,
            error_code=None,
            error_message=None,
            started_at=now,
            completed_at=now,
        )
        connection.execute(
            """
            INSERT INTO scans (
                id, app_version_id, file_name, file_extension, status,
                risk_level, score, error_code, error_message, started_at, completed_at
            )
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                scan.id,
                scan.app_version_id,
                scan.file_name,
                scan.file_extension,
                scan.status,
                scan.risk_level,
                scan.score,
                scan.error_code,
                scan.error_message,
                _format_datetime(scan.started_at),
                _format_datetime(scan.completed_at),
            ),
        )
        return scan

    def _create_failed_scan(
        self,
        connection: sqlite3.Connection,
        app_version_id: str,
        file_name: str,
        file_extension: str,
        error_code: str,
        error_message: str,
        now: datetime,
    ) -> Scan:
        scan = Scan(
            id=_new_id(),
            app_version_id=app_version_id,
            file_name=file_name,
            file_extension=file_extension,
            status="failed",
            risk_level="critical",
            score=0,
            error_code=error_code,
            error_message=error_message,
            started_at=now,
            completed_at=now,
        )
        connection.execute(
            """
            INSERT INTO scans (
                id, app_version_id, file_name, file_extension, status,
                risk_level, score, error_code, error_message, started_at, completed_at
            )
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                scan.id,
                scan.app_version_id,
                scan.file_name,
                scan.file_extension,
                scan.status,
                scan.risk_level,
                scan.score,
                scan.error_code,
                scan.error_message,
                _format_datetime(scan.started_at),
                _format_datetime(scan.completed_at),
            ),
        )
        return scan

    def _create_scan_result(
        self,
        connection: sqlite3.Connection,
        scan_id: str,
        report: NormalizedAnalysisReport,
        now: datetime,
    ) -> None:
        report_json = json.dumps(report.model_dump(mode="json"), sort_keys=True)
        summary_json = json.dumps(
            report.summary.model_dump(mode="json"), sort_keys=True
        )
        connection.execute(
            """
            INSERT INTO scan_results (scan_id, report_json, summary_json, created_at)
            VALUES (?, ?, ?, ?)
            """,
            (scan_id, report_json, summary_json, _format_datetime(now)),
        )

    def _create_findings(
        self,
        connection: sqlite3.Connection,
        scan_id: str,
        report: NormalizedAnalysisReport,
    ) -> None:
        rows = [
            (
                _new_id(),
                scan_id,
                finding.id,
                finding.title,
                finding.severity,
                finding.category,
                finding.description,
                finding.recommendation,
                finding.source,
                index,
            )
            for index, finding in enumerate(report.findings)
        ]
        connection.executemany(
            """
            INSERT INTO findings (
                id, scan_id, finding_key, title, severity, category,
                description, recommendation, source, ordinal
            )
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            rows,
        )


def _row_to_project(row: sqlite3.Row) -> Project:
    return Project(
        id=row["id"], name=row["name"], created_at=_parse_datetime(row["created_at"])
    )


def _row_to_mobile_app(row: sqlite3.Row) -> MobileApp:
    return MobileApp(
        id=row["id"],
        project_id=row["project_id"],
        name=row["name"],
        platform=row["platform"],
        created_at=_parse_datetime(row["created_at"]),
    )


def _row_to_app_version(row: sqlite3.Row) -> AppVersion:
    return AppVersion(
        id=row["id"],
        app_id=row["app_id"],
        version_name=row["version_name"],
        build_identifier=row["build_identifier"],
        created_at=_parse_datetime(row["created_at"]),
    )


def _row_to_scan(row: sqlite3.Row) -> Scan:
    return Scan(
        id=row["id"],
        app_version_id=row["app_version_id"],
        file_name=row["file_name"] or "",
        file_extension=row["file_extension"] or ".apk",
        status=row["status"],
        risk_level=row["risk_level"],
        score=row["score"],
        error_code=row["error_code"],
        error_message=row["error_message"],
        started_at=_parse_datetime(row["started_at"]),
        completed_at=_parse_optional_datetime(row["completed_at"]),
    )


def _row_to_recent_scan(row: sqlite3.Row) -> RecentScan:
    return RecentScan(
        id=row["id"],
        project_id=row["project_id"],
        project_name=row["project_name"],
        app_id=row["app_id"],
        app_name=row["app_name"],
        app_version_id=row["app_version_id"],
        version_name=row["version_name"],
        build_identifier=row["build_identifier"],
        file_name=row["file_name"],
        file_extension=row["file_extension"],
        platform=row["platform"],
        status=row["status"],
        risk_level=row["risk_level"],
        score=row["score"],
        finding_count=row["finding_count"],
        error_code=row["error_code"],
        error_message=row["error_message"],
        started_at=_parse_datetime(row["started_at"]),
        completed_at=_parse_optional_datetime(row["completed_at"]),
    )


def _new_id() -> str:
    return str(uuid4())


def _utc_now() -> datetime:
    return datetime.now(timezone.utc)


def _format_datetime(value: datetime | None) -> str | None:
    return value.isoformat() if value is not None else None


def _parse_datetime(value: str) -> datetime:
    return datetime.fromisoformat(value)


def _parse_optional_datetime(value: str | None) -> datetime | None:
    return _parse_datetime(value) if value else None


def _clean_text(value: str | None) -> str | None:
    if value is None:
        return None
    cleaned = value.strip()
    return cleaned or None


def _required_text(value: str, label: str) -> str:
    cleaned = _clean_text(value)
    if cleaned is None:
        raise ValueError(f"{label} is required")
    return cleaned


def _default_extension(platform: Platform) -> str:
    return ".ipa" if platform == "ios" else ".apk"


def _repair_report_payload(payload: dict) -> dict:
    if not isinstance(payload, dict):
        return payload

    findings = payload.get("findings")
    if not isinstance(findings, list):
        findings = []
    repaired_findings = []
    for finding in findings:
        if not isinstance(finding, dict):
            continue
        repaired = dict(finding)
        if not repaired.get("source"):
            repaired["source"] = "historical/unknown-source"
        repaired_findings.append(repaired)

    payload = dict(payload)
    payload["findings"] = repaired_findings
    payload["summary"] = _summary_payload(repaired_findings)
    payload["categories"] = _category_payload(repaired_findings)
    return payload


def _summary_payload(findings: list[dict]) -> dict:
    by_severity = {severity: 0 for severity in SEVERITIES}
    for finding in findings:
        severity = finding.get("severity")
        if severity in by_severity:
            by_severity[severity] += 1
    return {"total_findings": sum(by_severity.values()), "by_severity": by_severity}


def _category_payload(findings: list[dict]) -> list[dict]:
    grouped: dict[str, dict[str, int | str]] = {}
    for finding in findings:
        category = str(finding.get("category") or "uncategorized")
        severity = finding.get("severity")
        if severity not in SEVERITY_RANK:
            continue
        if category not in grouped:
            grouped[category] = {"count": 0, "max_severity": severity}
        grouped[category]["count"] = int(grouped[category]["count"]) + 1
        current = str(grouped[category]["max_severity"])
        if SEVERITY_RANK[severity] > SEVERITY_RANK[current]:
            grouped[category]["max_severity"] = severity

    return [
        {
            "name": category,
            "count": int(data["count"]),
            "max_severity": str(data["max_severity"]),
        }
        for category, data in sorted(grouped.items())
    ]
