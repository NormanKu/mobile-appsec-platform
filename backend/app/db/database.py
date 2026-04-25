from __future__ import annotations

from contextlib import closing
from datetime import datetime, timezone
from pathlib import Path
import sqlite3

from app.core.config import settings


SCHEMA_VERSION = 3

SCHEMA_STATEMENTS = [
    """
    CREATE TABLE IF NOT EXISTS schema_migrations (
        id TEXT PRIMARY KEY,
        description TEXT NOT NULL,
        applied_at TEXT NOT NULL
    )
    """,
    """
    CREATE TABLE IF NOT EXISTS projects (
        id TEXT PRIMARY KEY,
        name TEXT NOT NULL UNIQUE,
        created_at TEXT NOT NULL
    )
    """,
    """
    CREATE TABLE IF NOT EXISTS mobile_apps (
        id TEXT PRIMARY KEY,
        project_id TEXT NOT NULL,
        name TEXT NOT NULL,
        platform TEXT NOT NULL CHECK (platform IN ('android', 'ios')),
        created_at TEXT NOT NULL,
        UNIQUE(project_id, name, platform),
        FOREIGN KEY(project_id) REFERENCES projects(id) ON DELETE CASCADE
    )
    """,
    """
    CREATE TABLE IF NOT EXISTS app_versions (
        id TEXT PRIMARY KEY,
        app_id TEXT NOT NULL,
        version_name TEXT,
        build_identifier TEXT,
        file_name TEXT,
        file_extension TEXT,
        created_at TEXT NOT NULL,
        FOREIGN KEY(app_id) REFERENCES mobile_apps(id) ON DELETE CASCADE
    )
    """,
    """
    CREATE TABLE IF NOT EXISTS scans (
        id TEXT PRIMARY KEY,
        app_version_id TEXT NOT NULL,
        file_name TEXT NOT NULL,
        file_extension TEXT NOT NULL,
        status TEXT NOT NULL CHECK (status IN ('queued', 'running', 'completed', 'failed')),
        risk_level TEXT NOT NULL CHECK (risk_level IN ('low', 'medium', 'high', 'critical')),
        score INTEGER NOT NULL CHECK (score >= 0 AND score <= 100),
        error_code TEXT,
        error_message TEXT,
        started_at TEXT NOT NULL,
        completed_at TEXT,
        FOREIGN KEY(app_version_id) REFERENCES app_versions(id) ON DELETE CASCADE
    )
    """,
    """
    CREATE TABLE IF NOT EXISTS scan_results (
        scan_id TEXT PRIMARY KEY,
        report_json TEXT NOT NULL,
        summary_json TEXT NOT NULL,
        created_at TEXT NOT NULL,
        FOREIGN KEY(scan_id) REFERENCES scans(id) ON DELETE CASCADE
    )
    """,
    """
    CREATE TABLE IF NOT EXISTS findings (
        id TEXT PRIMARY KEY,
        scan_id TEXT NOT NULL,
        finding_key TEXT NOT NULL,
        title TEXT NOT NULL,
        severity TEXT NOT NULL CHECK (severity IN ('low', 'medium', 'high', 'critical')),
        category TEXT NOT NULL,
        description TEXT NOT NULL,
        recommendation TEXT NOT NULL,
        source TEXT NOT NULL,
        ordinal INTEGER NOT NULL,
        FOREIGN KEY(scan_id) REFERENCES scans(id) ON DELETE CASCADE
    )
    """,
    "CREATE INDEX IF NOT EXISTS idx_scans_completed_at ON scans(completed_at DESC)",
    "CREATE INDEX IF NOT EXISTS idx_scans_status ON scans(status)",
    "CREATE INDEX IF NOT EXISTS idx_findings_scan_id ON findings(scan_id)",
]

MIGRATIONS = [
    {
        "id": "001_app_version_build_metadata",
        "description": "Add app version build and package metadata columns",
        "columns": [
            ("app_versions", "build_identifier", "TEXT"),
            ("app_versions", "file_name", "TEXT"),
            ("app_versions", "file_extension", "TEXT"),
        ],
    },
    {
        "id": "002_scan_package_metadata",
        "description": "Add scan package metadata columns",
        "columns": [
            ("scans", "file_name", "TEXT"),
            ("scans", "file_extension", "TEXT"),
        ],
    },
    {
        "id": "003_scan_failure_metadata",
        "description": "Add scan failure recovery metadata columns",
        "columns": [
            ("scans", "error_code", "TEXT"),
            ("scans", "error_message", "TEXT"),
        ],
    },
]


def connect(database_url: str | None = None) -> sqlite3.Connection:
    database_path = _sqlite_path(database_url or settings.database_url)
    if database_path != ":memory:":
        Path(database_path).parent.mkdir(parents=True, exist_ok=True)

    connection = sqlite3.connect(database_path)
    connection.row_factory = sqlite3.Row
    connection.execute("PRAGMA foreign_keys = ON")
    return connection


def initialize_database(database_url: str | None = None) -> None:
    with closing(connect(database_url)) as connection:
        with connection:
            for statement in SCHEMA_STATEMENTS:
                connection.execute(statement)
            for migration in MIGRATIONS:
                _apply_migration(connection, migration)
            connection.execute(f"PRAGMA user_version = {SCHEMA_VERSION}")


def _sqlite_path(database_url: str) -> str:
    if database_url == "sqlite:///:memory:":
        return ":memory:"

    prefix = "sqlite:///"
    if not database_url.startswith(prefix):
        raise ValueError("Only sqlite:/// database URLs are supported")

    return database_url.removeprefix(prefix)


def _apply_migration(connection: sqlite3.Connection, migration: dict) -> None:
    migration_id = str(migration["id"])
    if _migration_applied(connection, migration_id):
        return

    for table_name, column_name, column_definition in migration["columns"]:
        if _column_exists(connection, table_name, column_name):
            continue
        connection.execute(f"ALTER TABLE {table_name} ADD COLUMN {column_name} {column_definition}")

    connection.execute(
        """
        INSERT OR REPLACE INTO schema_migrations (id, description, applied_at)
        VALUES (?, ?, ?)
        """,
        (
            migration_id,
            str(migration["description"]),
            datetime.now(timezone.utc).isoformat(),
        ),
    )


def _migration_applied(connection: sqlite3.Connection, migration_id: str) -> bool:
    row = connection.execute(
        "SELECT 1 FROM schema_migrations WHERE id = ?",
        (migration_id,),
    ).fetchone()
    return row is not None


def _column_exists(connection: sqlite3.Connection, table_name: str, column_name: str) -> bool:
    rows = connection.execute(f"PRAGMA table_info({table_name})").fetchall()
    return any(row["name"] == column_name for row in rows)
