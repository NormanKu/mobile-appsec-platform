import subprocess
from pathlib import Path

from analyzers.android.external_tools import AndroidExternalToolResult, JadxAdapter


def test_jadx_adapter_reports_unavailable_when_binary_is_missing(monkeypatch) -> None:
    adapter = JadxAdapter()
    monkeypatch.setattr(adapter, "_resolve_executable", lambda: None)

    result = adapter.analyze_apk(file_name="sample.apk", file_bytes=b"placeholder")

    assert result == AndroidExternalToolResult(
        tool_name="jadx", available=False, executed=False
    )


def test_jadx_adapter_extracts_normalized_signals(monkeypatch) -> None:
    adapter = JadxAdapter()
    monkeypatch.setattr(adapter, "_resolve_executable", lambda: "/usr/local/bin/jadx")

    def fake_run(
        *, executable: str, input_path: Path, output_dir: Path
    ) -> subprocess.CompletedProcess[str]:
        source_dir = output_dir / "sources" / "com" / "example" / "internal"
        source_dir.mkdir(parents=True, exist_ok=True)
        (source_dir / "ApiClient.java").write_text(
            """
            package com.example.internal;

            public class ApiClient {
              private static final String BASE_URL = "https://staging.example.com/api";
            }
            """,
            encoding="utf-8",
        )
        (source_dir / "TokenVault.kt").write_text(
            """
            package com.example.internal.secret

            object TokenVault {
              const val API_KEY = "abcdef123456TOKEN"
            }
            """,
            encoding="utf-8",
        )
        return subprocess.CompletedProcess(
            args=[executable, str(input_path)], returncode=0, stdout="", stderr=""
        )

    monkeypatch.setattr(adapter, "_run_jadx", fake_run)

    result = adapter.analyze_apk(file_name="sample.apk", file_bytes=b"placeholder")
    kinds = {signal.kind for signal in result.signals}

    assert result.available is True
    assert result.executed is True
    assert result.source_files_scanned == 2
    assert {
        "readable_source",
        "hardcoded_url",
        "candidate_secret",
        "naming_pattern",
    } <= kinds
    assert any(
        "ApiClient" in signal.value
        for signal in result.signals
        if signal.kind == "readable_source"
    )
    assert any(
        "staging.example.com" in signal.value
        for signal in result.signals
        if signal.kind == "hardcoded_url"
    )
    assert any(
        "API_KEY=abcdef..." == signal.value
        for signal in result.signals
        if signal.kind == "candidate_secret"
    )
    assert any(
        "internal" in signal.value.lower()
        for signal in result.signals
        if signal.kind == "naming_pattern"
    )


def test_jadx_adapter_gracefully_handles_tool_execution_failure(monkeypatch) -> None:
    adapter = JadxAdapter(timeout_seconds=5)
    monkeypatch.setattr(adapter, "_resolve_executable", lambda: "/usr/local/bin/jadx")

    def fake_run(
        *, executable: str, input_path: Path, output_dir: Path
    ) -> subprocess.CompletedProcess[str]:
        raise subprocess.TimeoutExpired(cmd=[executable, str(input_path)], timeout=5)

    monkeypatch.setattr(adapter, "_run_jadx", fake_run)

    result = adapter.analyze_apk(file_name="sample.apk", file_bytes=b"placeholder")

    assert result.available is True
    assert result.executed is False
    assert result.signals == ()
    assert result.error is not None
