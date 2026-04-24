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
- `POST /api/v1/upload` (multipart form field: `file`, supports `.apk`, `.aab`, `.ipa`)
- `POST /api/v1/scans` (multipart form field: `file`, starts a lightweight async scan job)
- `GET /api/v1/scans/{job_id}` (poll scan job status and completed report)

## Lightweight Async Scan Jobs

`POST /api/v1/scans` returns `202 Accepted` with a local scan job identifier. Poll
`GET /api/v1/scans/{job_id}` until the job reaches `completed` or `failed`.
Completed jobs include the same normalized report schema returned by
`POST /api/v1/upload`.

The async workflow is intentionally process-local for the second phase MVP. It
uses an in-memory store and a small thread pool, so jobs are lost on backend
restart and are not shared across multiple backend processes.

Async jobs request partial reports from the report builder. If an optional tool
or analyzer step fails, the completed report can include `analysis_status`,
`warnings`, and `errors` so callers can distinguish a complete scan from a
partial or warning-only analysis. The legacy synchronous upload endpoint keeps
strict validation behavior for malformed archives.

## Optional JADX Enrichment for Android APKs

The Android analyzer can optionally call a local `jadx` binary to enrich heuristic findings from APK uploads. This enrichment is adapter-based and stays inside `analyzers/android`, so the shared backend report schema does not depend on raw `jadx` output.

When available, `jadx` can add heuristic findings for:

- readable source/code exposure indicators
- suspicious hardcoded URLs
- candidate secrets or tokens
- notable package/class naming patterns

If `jadx` is missing, misconfigured, or times out, upload analysis still succeeds and falls back to the baseline Android heuristics.

Local setup example:

```bash
brew install jadx
export APPSEC_ANDROID_JADX_PATH="$(command -v jadx)"
```

Optional tuning:

```bash
export APPSEC_ANDROID_JADX_TIMEOUT_SECONDS=45
export APPSEC_ANDROID_JADX_MAX_SOURCE_FILES=200
export APPSEC_ANDROID_JADX_MAX_SOURCE_FILE_SIZE=300000
```

## Normalized Report Schema

`POST /api/v1/upload` returns a shared schema for both Android and iOS:

- `platform`
- `file_name`
- `risk_level`
- `score`
- `analysis_status`
- `summary`
- `findings`
- `categories`
- `warnings`
- `errors`
- `metadata`

See `backend/app/models/report.py` for typed models and example Android/iOS response objects.


## Upload Validation and Errors

- Supported extensions: `.apk`, `.aab`, `.ipa`
- Maximum upload size: configured via `max_upload_size_bytes` (default 25 MB)
- Maximum safe extracted archive size: configured via `max_zip_extracted_bytes` (default 200 MB)
- Invalid uploads return JSON errors with `error.code`, `error.message`, and `error.details`
- Common error codes:
  - `INVALID_FILE_TYPE`: unsupported extension
  - `FILE_TOO_LARGE`: uploaded file exceeds `max_upload_size_bytes`
  - `INVALID_ARCHIVE`: ZIP is malformed or missing required package metadata
  - `ARCHIVE_LIMIT_EXCEEDED`: archive exceeds safe extraction limits
- Example error:

```json
{
  "error": {
    "code": "INVALID_FILE_TYPE",
    "message": "Only .apk, .aab, or .ipa files are supported",
    "details": {}
  }
}
```
