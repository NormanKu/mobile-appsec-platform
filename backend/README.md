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
