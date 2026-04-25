# Backend (FastAPI)

Run locally:

```bash
python -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
uvicorn app.main:app --reload --port 8000
```

Endpoints:

- `GET /health`
- `GET /api/v1/projects`
- `POST /api/v1/projects`
- `GET /api/v1/projects/{project_id}/apps`
- `POST /api/v1/projects/{project_id}/apps`
- `GET /api/v1/apps/{app_id}/versions`
- `POST /api/v1/apps/{app_id}/versions`
- `POST /api/v1/upload` (multipart form field: `file`, supports `.apk`, `.aab`, `.ipa`)
- `GET /api/v1/scans` (recent scan history, optionally filtered by `app_id` or `app_version_id`)
- `GET /api/v1/scans/{scan_id}` (stored normalized report)
- `GET /api/v1/scans/{target_scan_id}/comparison?baseline_scan_id={baseline_scan_id}`
- `GET /api/v1/scans/{scan_id}/policy`

## Normalized Report Schema

`POST /api/v1/upload` returns a shared schema for both Android and iOS:

- `platform`
- `file_name`
- `risk_level`
- `score`
- `summary`
- `findings`
- `categories`
- `metadata`

See `backend/app/models/report.py` for typed models and example Android/iOS response objects.

External analyzer output is normalized into the same finding model. MobSF-derived findings are labeled with `source` values beginning with `mobsf/` and titles beginning with `MobSF:` so API consumers do not need to know MobSF's raw report shape.

## Architecture Notes

The backend is organized around a normalized report contract:

- `report_builder.py` composes built-in analyzer output and optional adapter output.
- `scan_history.py` persists completed and failed scan records.
- `scan_comparison.py` compares two completed scans for the same app.
- `policy_evaluator.py` turns a normalized report into a pass/warn/fail release signal.
- Optional adapters are isolated under `analyzers/adapters/` and must return normalized findings.

If core analysis fails before a normalized report exists, the upload endpoint stores a failed scan record with `error_code` and `error_message`, then returns a structured `SCAN_ANALYSIS_FAILED` error. Failed scans are intentionally not returned as successful reports.

## Persistent Scan History

Completed uploads are stored in SQLite using `APPSEC_DATABASE_URL` (default: `sqlite:///./appsec.sqlite3`).

The minimal schema stores projects, app records, app versions, scan jobs, scan results, and findings. App versions carry a version name and optional build identifier. The upload endpoint still returns the existing normalized report schema; scan retrieval returns the same schema from persisted history.

Migrations are tracked in `schema_migrations` and applied idempotently at startup. The current lightweight migration layer handles additive SQLite changes for app version metadata, scan package metadata, and failed-scan metadata. This keeps local development simple, but production deployments should still plan backup/restore and explicit migration review.

`POST /api/v1/upload` accepts optional scan context fields:

- `project_id` or `project_name`
- `app_id` or `app_name`
- `app_version_id` or `version_name` plus `build_identifier`

## Baseline Comparison

Scan comparisons require two scans from the same app. Results are grouped into new findings, resolved findings, unchanged findings, severity changes, and uncertain matches.

Exact matches use finding `id`, `category`, and `source`. Uncertain matches are possible when a rule id or source changes but title/category evidence still suggests a relationship. Treat uncertain matches as review hints, not proof.

Failed scans and scans without stored normalized reports cannot be compared; the API returns a structured error instead of pretending the missing result is empty.

## CI/CD Policy Gate

Stored scan results include a policy evaluation. The default policy:

- fails on confirmed critical findings
- fails when score is below `APPSEC_POLICY_MIN_SCORE` (default: `70`)
- warns on heuristic high-severity findings

For CI, request a non-2xx response when the policy fails:

```bash
curl -fsS \
  "http://localhost:8000/api/v1/scans/${SCAN_ID}/policy?min_score=80&fail_on_policy_failure=true"
```

This is a release decision aid, not a complete security guarantee.

Policy limitations:

- Policy decisions depend on available static scan output.
- Missing optional adapter results reduce coverage but do not automatically prove a release is safe.
- Heuristic findings can create false positives and false negatives.
- Confirmed means the current finding is not labeled heuristic; it is not a replacement for human validation.

## Optional MobSF Adapter

MobSF is optional and isolated behind `analyzers/adapters/mobsf.py`. When enabled, the report builder keeps the built-in analyzer output and appends normalized MobSF findings as an additional detection source.

Configuration:

```bash
APPSEC_MOBSF_ENABLED=true
APPSEC_MOBSF_BASE_URL=http://localhost:8000
APPSEC_MOBSF_API_KEY=<your-mobsf-api-key>
APPSEC_MOBSF_TIMEOUT_SECONDS=30
APPSEC_MOBSF_RE_SCAN=false
```

Local MobSF setup:

```bash
docker pull opensecurity/mobile-security-framework-mobsf:latest
docker run -it --rm -p 8000:8000 opensecurity/mobile-security-framework-mobsf:latest
```

The adapter calls MobSF's static API flow: upload the binary, request a scan, and fetch/report JSON when needed. If MobSF is disabled, not configured, unavailable, or returns an unsupported response, the backend logs the issue and returns the built-in analyzer report.

Limitations:

- MobSF JSON fields can vary by app type and MobSF version, so normalization is conservative.
- Severity mapping is best effort and should be validated against local release policy.
- MobSF calls currently run during the scan request; long-running analysis should move behind a queue later.
- Raw MobSF output is intentionally not exposed as the API or frontend contract.

## Optional Binary Analysis Entry Point

Advanced native/binary inspection is routed through `analyzers/adapters/binary_analysis.py`. The integration is optional and disabled by default:

```bash
APPSEC_BINARY_ANALYSIS_ENABLED=true
APPSEC_BINARY_ANALYSIS_MAX_ARTIFACTS=20
APPSEC_BINARY_ANALYSIS_MAX_ARTIFACT_BYTES=5242880
```

The built-in adapter is intentionally lightweight. It extracts metadata for Android native libraries, iOS app binaries, `.dylib` files, and framework binaries, then returns normalized findings with `binary-metadata/` or `binary-strings/` sources.

Future deep tooling should implement `BinaryAnalysisAdapter`:

- receive a bounded `BinaryArtifact`
- decide whether the adapter supports it
- return normalized report findings only
- keep raw tool output and tool-specific schemas inside the adapter

This is the intended path for Ghidra-like disassembly, symbol extraction, control-flow checks, or rule packs. Those tools should remain optional, replaceable, and preferably run behind background jobs because they can be slow and resource intensive.

Current tradeoffs:

- The built-in adapter only performs shallow format and marker checks.
- Artifact count and size limits protect request-time scanning but can miss large binaries.
- Binary findings are heuristic until backed by deeper tool-specific validation.
- The API contract stays stable because binary analysis never exposes raw adapter output.


## Upload Validation and Errors

- Supported extensions: `.apk`, `.aab`, `.ipa`
- Maximum upload size: configured via `max_upload_size_bytes` (default 25 MB)
- Invalid uploads return:

```json
{
  "error": {
    "code": "INVALID_FILE_TYPE",
    "message": "Only .apk, .aab, or .ipa files are supported",
    "details": {}
  }
}
```
