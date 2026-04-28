"""Make backend/app importable when running pytest from repo root."""

import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from app.core.config import settings  # noqa: E402


@pytest.fixture(autouse=True)
def isolated_database(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(
        settings, "database_url", f"sqlite:///{tmp_path / 'appsec-test.sqlite3'}"
    )
