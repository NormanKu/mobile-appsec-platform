# Mobile AppSec Platform

## Project Overview
A mobile application security analysis platform that performs static analysis on Android (APK/AAB) and iOS (IPA) packages, producing normalized security reports.

## Architecture
- **Frontend**: Next.js 14 (React 18, TypeScript) — file upload UI + report display
- **Backend**: FastAPI (Python 3.10+) — API server with upload validation, rate limiting
- **Analyzers**: Standalone Python modules for Android/iOS static analysis
  - ZIP bomb protection via `safe_zip.py`
  - Secret/URL pattern scanning in archive strings
  - iOS Info.plist security checks (ATS, URL schemes)

## Directory Structure
```
├── frontend/          # Next.js app
│   ├── app/           # App router pages
│   └── __tests__/     # Vitest tests
├── backend/
│   ├── app/
│   │   ├── api/routes/ # FastAPI endpoints (health, upload)
│   │   ├── core/       # Config (pydantic-settings, env: APPSEC_*)
│   │   ├── errors/     # Custom exceptions + handlers
│   │   ├── models/     # Pydantic models (report, error)
│   │   └── services/   # Business logic (report_builder, upload_validator)
│   └── tests/          # pytest tests
├── analyzers/
│   ├── android/        # APK/AAB scanner
│   ├── ios/            # IPA scanner
│   └── safe_zip.py     # ZIP extraction safety
└── .github/workflows/  # CI pipeline
```

## Key Configuration
All backend settings use `APPSEC_` env prefix (via pydantic-settings):
- `APPSEC_MAX_UPLOAD_SIZE_BYTES` (default: 25MB)
- `APPSEC_MAX_ZIP_EXTRACTED_BYTES` (default: 200MB)
- `APPSEC_CORS_ALLOWED_ORIGINS` (comma-separated)
- `APPSEC_RATE_LIMIT_UPLOAD` (default: 10/minute)
- `APPSEC_RATE_LIMIT_DEFAULT` (default: 60/minute)

## Development Commands
```bash
# Backend
cd backend && pip install -r requirements.txt && pip install -e ..
uvicorn app.main:app --reload

# Frontend
cd frontend && npm install && npm run dev

# Tests
python -m pytest -v              # Backend + analyzers
cd frontend && npm test          # Frontend (vitest)

# Linting
ruff check . && ruff format .    # Python
cd frontend && npm run lint      # TypeScript
```

## Code Conventions
- Python: type hints required, async for I/O operations, specific exception handling (no bare `except Exception`)
- TypeScript: strict mode, functional components with hooks
- All security-critical functions must have docstrings
- Findings use structured format: id, title, severity, category, description, recommendation, source
