from __future__ import annotations

from dataclasses import dataclass
from hashlib import sha1
import json
import logging
import mimetypes
import re
from typing import Any
from urllib import error, request

logger = logging.getLogger(__name__)

SEVERITY_MAP = {
    "info": "low",
    "informational": "low",
    "secure": "low",
    "warning": "medium",
    "warn": "medium",
    "medium": "medium",
    "high": "high",
    "critical": "critical",
    "danger": "critical",
}


@dataclass(frozen=True)
class MobSFConfig:
    base_url: str
    api_key: str
    timeout_seconds: float = 30.0
    re_scan: bool = False


class MobSFAdapterError(Exception):
    """Raised when MobSF cannot return a usable response."""


class MobSFAdapter:
    def __init__(self, config: MobSFConfig):
        self.config = config

    def analyze(
        self,
        file_name: str,
        file_bytes: bytes,
        platform: str,
    ) -> list[dict[str, str]]:
        upload = self._upload(file_name=file_name, file_bytes=file_bytes)
        scan_hash = str(upload.get("hash") or upload.get("md5") or "")
        if not scan_hash:
            raise MobSFAdapterError("MobSF upload response did not include a scan hash")

        scan_report = self._scan(scan_hash=scan_hash)
        findings = normalize_mobsf_findings(scan_report, platform=platform)
        if findings:
            return findings

        report = self._report_json(scan_hash=scan_hash)
        return normalize_mobsf_findings(report, platform=platform)

    def _upload(self, file_name: str, file_bytes: bytes) -> dict[str, Any]:
        body, content_type = _multipart_body(file_name=file_name, file_bytes=file_bytes)
        return self._request_json(
            path="/api/v1/upload",
            body=body,
            content_type=content_type,
        )

    def _scan(self, scan_hash: str) -> dict[str, Any]:
        body = f"hash={scan_hash}&re_scan={1 if self.config.re_scan else 0}".encode()
        return self._request_json(
            path="/api/v1/scan",
            body=body,
            content_type="application/x-www-form-urlencoded",
        )

    def _report_json(self, scan_hash: str) -> dict[str, Any]:
        body = f"hash={scan_hash}".encode()
        return self._request_json(
            path="/api/v1/report_json",
            body=body,
            content_type="application/x-www-form-urlencoded",
        )

    def _request_json(
        self, path: str, body: bytes, content_type: str
    ) -> dict[str, Any]:
        url = f"{self.config.base_url.rstrip('/')}{path}"
        req = request.Request(
            url,
            data=body,
            headers={
                "Authorization": self.config.api_key,
                "X-Mobsf-Api-Key": self.config.api_key,
                "Content-Type": content_type,
                "Accept": "application/json",
            },
            method="POST",
        )
        try:
            with request.urlopen(req, timeout=self.config.timeout_seconds) as response:
                payload = response.read()
        except (TimeoutError, OSError, error.URLError, error.HTTPError) as exc:
            raise MobSFAdapterError(f"MobSF request failed for {path}: {exc}") from exc

        try:
            decoded = json.loads(payload.decode("utf-8"))
        except (json.JSONDecodeError, UnicodeDecodeError) as exc:
            raise MobSFAdapterError(
                f"MobSF returned non-JSON response for {path}"
            ) from exc

        if not isinstance(decoded, dict):
            raise MobSFAdapterError(
                f"MobSF returned unexpected response type for {path}"
            )
        if "error" in decoded:
            raise MobSFAdapterError(
                f"MobSF returned error for {path}: {decoded['error']}"
            )
        return decoded


def normalize_mobsf_findings(
    report: dict[str, Any], platform: str
) -> list[dict[str, str]]:
    findings: list[dict[str, str]] = []
    seen: set[str] = set()

    for section_name, section_value in report.items():
        for item, inherited_severity in _iter_finding_like_items(section_value):
            normalized = _normalize_finding_item(
                item=item,
                section_name=section_name,
                platform=platform,
                inherited_severity=inherited_severity,
            )
            if normalized is None:
                continue
            key = "|".join(
                [
                    normalized["title"],
                    normalized["severity"],
                    normalized["category"],
                    normalized["source"],
                ]
            )
            if key in seen:
                continue
            seen.add(key)
            findings.append(normalized)

    return findings


def run_optional_mobsf_analysis(
    enabled: bool,
    base_url: str | None,
    api_key: str | None,
    timeout_seconds: float,
    re_scan: bool,
    file_name: str,
    file_bytes: bytes,
    platform: str,
) -> list[dict[str, str]]:
    if not enabled:
        return []
    if not base_url or not api_key:
        logger.info(
            "MobSF analysis skipped because base URL or API key is not configured"
        )
        return []

    adapter = MobSFAdapter(
        MobSFConfig(
            base_url=base_url,
            api_key=api_key,
            timeout_seconds=timeout_seconds,
            re_scan=re_scan,
        )
    )
    try:
        return adapter.analyze(
            file_name=file_name, file_bytes=file_bytes, platform=platform
        )
    except MobSFAdapterError as exc:
        logger.warning("MobSF analysis unavailable: %s", exc)
        return []
    except Exception as exc:
        logger.warning("MobSF analysis failed unexpectedly: %s", exc)
        return []


def _iter_finding_like_items(
    value: Any,
    inherited_severity: str | None = None,
) -> list[tuple[dict[str, Any], str | None]]:
    items: list[tuple[dict[str, Any], str | None]] = []
    if isinstance(value, list):
        for child in value:
            items.extend(_iter_finding_like_items(child, inherited_severity))
        return items

    if not isinstance(value, dict):
        return items

    if _looks_like_finding(value, inherited_severity):
        items.append((value, inherited_severity))
        return items

    for key, child in value.items():
        child_severity = _normalize_severity(key) or inherited_severity
        items.extend(_iter_finding_like_items(child, child_severity))
    return items


def _looks_like_finding(value: dict[str, Any], inherited_severity: str | None) -> bool:
    keys = {_normalize_key(key) for key in value}
    has_severity = inherited_severity is not None or bool(
        keys & {"severity", "risk", "level", "cvss"}
    )
    has_title = bool(keys & {"title", "name", "rule", "issue", "finding"})
    has_details = bool(keys & {"description", "desc", "details", "message", "info"})
    return has_severity and (has_title or has_details)


def _normalize_finding_item(
    item: dict[str, Any],
    section_name: str,
    platform: str,
    inherited_severity: str | None,
) -> dict[str, str] | None:
    severity = _normalize_severity(
        _first_value(item, ["severity", "risk", "level", "cvss"])
    )
    severity = severity or inherited_severity
    if severity is None:
        return None

    title = _stringify(
        _first_value(item, ["title", "name", "rule", "issue", "finding"])
    )
    description = _stringify(
        _first_value(item, ["description", "desc", "details", "message", "info"])
    )
    if not title and description:
        title = description[:96]
    if not title:
        return None

    recommendation = _stringify(
        _first_value(item, ["recommendation", "remediation", "mitigation", "fix"])
    )
    path = _stringify(_first_value(item, ["file", "path", "component", "location"]))
    source = f"mobsf/{_normalize_key(section_name)}"
    if path:
        source = f"{source}:{path}"

    description = description or f"MobSF reported {title}"
    recommendation = (
        recommendation
        or "Review the MobSF finding and validate exploitability in release context"
    )
    category = f"mobsf-{_normalize_key(section_name)}"

    return {
        "id": _finding_id(
            platform=platform, section=section_name, title=title, source=source
        ),
        "title": f"MobSF: {title}",
        "severity": severity,
        "category": category,
        "description": description,
        "recommendation": recommendation,
        "source": source,
    }


def _normalize_severity(value: Any) -> str | None:
    if isinstance(value, (int, float)):
        if value >= 9:
            return "critical"
        if value >= 7:
            return "high"
        if value >= 4:
            return "medium"
        return "low"

    text = _normalize_key(_stringify(value))
    return SEVERITY_MAP.get(text)


def _first_value(item: dict[str, Any], keys: list[str]) -> Any:
    normalized_lookup = {_normalize_key(key): value for key, value in item.items()}
    for key in keys:
        value = normalized_lookup.get(_normalize_key(key))
        if value not in (None, "", [], {}):
            return value
    metadata = normalized_lookup.get("metadata")
    if isinstance(metadata, dict):
        return _first_value(metadata, keys)
    return None


def _multipart_body(file_name: str, file_bytes: bytes) -> tuple[bytes, str]:
    boundary = f"----mobile-appsec-{sha1(file_bytes[:1024]).hexdigest()}"
    content_type = mimetypes.guess_type(file_name)[0] or "application/octet-stream"
    body = b"".join(
        [
            f"--{boundary}\r\n".encode(),
            (
                'Content-Disposition: form-data; name="file"; '
                f'filename="{file_name}"\r\n'
            ).encode(),
            f"Content-Type: {content_type}\r\n\r\n".encode(),
            file_bytes,
            f"\r\n--{boundary}--\r\n".encode(),
        ]
    )
    return body, f"multipart/form-data; boundary={boundary}"


def _finding_id(platform: str, section: str, title: str, source: str) -> str:
    digest = (
        sha1(f"{section}|{title}|{source}".encode("utf-8")).hexdigest()[:10].upper()
    )
    return f"MOBSF-{platform.upper()}-{_normalize_key(section).upper()}-{digest}"


def _normalize_key(value: str) -> str:
    return re.sub(r"[^a-z0-9]+", "-", value.strip().lower()).strip("-")


def _stringify(value: Any) -> str:
    if value is None:
        return ""
    if isinstance(value, str):
        return value.strip()
    if isinstance(value, (int, float, bool)):
        return str(value)
    return json.dumps(value, sort_keys=True)
