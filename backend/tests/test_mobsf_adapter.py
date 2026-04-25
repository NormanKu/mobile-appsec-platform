from __future__ import annotations

from analyzers.adapters import mobsf
from app.core.config import settings
from app.services import report_builder


def test_normalize_mobsf_findings_maps_common_report_shapes() -> None:
    report = {
        "code_analysis": {
            "high": [
                {
                    "rule": "Insecure TLS usage",
                    "metadata": {
                        "description": "TLS validation appears weakened",
                        "recommendation": "Use platform TLS validation defaults",
                    },
                    "file": "src/main/java/com/example/Network.kt",
                }
            ],
            "warning": [
                {
                    "title": "WebView debugging enabled",
                    "description": "Debug features are reachable in a WebView",
                }
            ],
        },
        "manifest_analysis": [
            {
                "severity": "critical",
                "name": "Exported provider without permission",
                "details": "A provider is exported and not permission protected",
                "recommendation": "Protect exported components with permissions",
            }
        ],
    }

    findings = mobsf.normalize_mobsf_findings(report, platform="android")

    assert len(findings) == 3
    assert {finding["severity"] for finding in findings} == {"high", "medium", "critical"}
    assert all(finding["title"].startswith("MobSF: ") for finding in findings)
    assert all(finding["source"].startswith("mobsf/") for finding in findings)
    assert any(
        finding["source"] == "mobsf/code-analysis:src/main/java/com/example/Network.kt"
        for finding in findings
    )
    assert all(finding["id"].startswith("MOBSF-ANDROID-") for finding in findings)


def test_optional_mobsf_analysis_is_disabled_by_default() -> None:
    assert (
        mobsf.run_optional_mobsf_analysis(
            enabled=False,
            base_url=None,
            api_key=None,
            timeout_seconds=30.0,
            re_scan=False,
            file_name="sample.apk",
            file_bytes=b"apk",
            platform="android",
        )
        == []
    )


def test_mobsf_adapter_falls_back_to_report_json_when_scan_has_no_findings() -> None:
    class FakeMobSFAdapter(mobsf.MobSFAdapter):
        def _upload(self, file_name: str, file_bytes: bytes):
            return {"hash": "abc123"}

        def _scan(self, scan_hash: str):
            return {"status": "scan completed"}

        def _report_json(self, scan_hash: str):
            return {
                "code_analysis": {
                    "high": [
                        {
                            "rule": "Weak crypto",
                            "description": "A weak primitive appears in code",
                        }
                    ]
                }
            }

    adapter = FakeMobSFAdapter(
        mobsf.MobSFConfig(base_url="http://localhost:8000", api_key="secret")
    )

    findings = adapter.analyze(
        file_name="sample.apk",
        file_bytes=b"apk",
        platform="android",
    )

    assert len(findings) == 1
    assert findings[0]["title"] == "MobSF: Weak crypto"
    assert findings[0]["severity"] == "high"


def test_optional_mobsf_analysis_skips_when_configuration_is_missing() -> None:
    assert (
        mobsf.run_optional_mobsf_analysis(
            enabled=True,
            base_url=None,
            api_key="secret",
            timeout_seconds=30.0,
            re_scan=False,
            file_name="sample.apk",
            file_bytes=b"apk",
            platform="android",
        )
        == []
    )
    assert (
        mobsf.run_optional_mobsf_analysis(
            enabled=True,
            base_url="http://localhost:8000",
            api_key=None,
            timeout_seconds=30.0,
            re_scan=False,
            file_name="sample.apk",
            file_bytes=b"apk",
            platform="android",
        )
        == []
    )


def test_optional_mobsf_analysis_fails_gracefully(monkeypatch) -> None:
    class BrokenMobSFAdapter:
        def __init__(self, config: mobsf.MobSFConfig):
            self.config = config

        def analyze(self, file_name: str, file_bytes: bytes, platform: str):
            raise mobsf.MobSFAdapterError("offline")

    monkeypatch.setattr(mobsf, "MobSFAdapter", BrokenMobSFAdapter)

    assert (
        mobsf.run_optional_mobsf_analysis(
            enabled=True,
            base_url="http://localhost:8000",
            api_key="secret",
            timeout_seconds=30.0,
            re_scan=False,
            file_name="sample.apk",
            file_bytes=b"apk",
            platform="android",
        )
        == []
    )


def test_report_builder_appends_mobsf_findings_when_enabled(monkeypatch) -> None:
    def fake_mobsf_analysis(**kwargs):
        assert kwargs["enabled"] is True
        assert kwargs["base_url"] == "http://localhost:8000"
        assert kwargs["api_key"] == "secret"
        return [
            {
                "id": "MOBSF-ANDROID-CODE-001",
                "title": "MobSF: Insecure TLS usage",
                "severity": "high",
                "category": "mobsf-code-analysis",
                "description": "TLS validation appears weakened",
                "recommendation": "Use platform TLS validation defaults",
                "source": "mobsf/code-analysis:Network.kt",
            }
        ]

    monkeypatch.setattr(settings, "mobsf_enabled", True)
    monkeypatch.setattr(settings, "mobsf_base_url", "http://localhost:8000")
    monkeypatch.setattr(settings, "mobsf_api_key", "secret")
    monkeypatch.setattr(report_builder, "run_optional_mobsf_analysis", fake_mobsf_analysis)

    report = report_builder.build_normalized_report(
        file_name="sample.apk",
        platform="android",
        file_bytes=b"not a zip",
        file_extension=".apk",
    )

    assert any(finding.id == "MOBSF-ANDROID-CODE-001" for finding in report.findings)
    assert report.summary.total_findings == len(report.findings)
    assert any(category.name == "mobsf-code-analysis" for category in report.categories)
