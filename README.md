# Mobile AppSec Platform (MVP Scaffold)

A modular MVP scaffold for a **mobile application security assessment platform** focused on static, pre-release analysis inputs for:

- Android APKs/AABs
- iOS IPAs

This repository currently provides:

- **Next.js + TypeScript frontend** for uploading a file and viewing a report
- **FastAPI backend** with an upload endpoint
- **Analyzer modules** for Android and iOS with placeholder logic
- **No auth, no database, no queue, no cloud deployment, and no dynamic analysis**

---

## Repository Structure

```text
mobile-appsec-platform/
├── frontend/                    # Next.js + TypeScript UI
│   ├── app/
│   │   ├── api/
│   │   │   └── health/route.ts
│   │   ├── globals.css
│   │   ├── layout.tsx
│   │   └── page.tsx             # Simple upload page
│   ├── public/
│   ├── next.config.ts
│   ├── package.json
│   ├── tsconfig.json
│   ├── next-env.d.ts
│   └── .eslintrc.json
├── backend/                     # FastAPI backend service
│   ├── app/
│   │   ├── api/
│   │   │   └── routes/
│   │   │       ├── health.py
│   │   │       └── upload.py    # Upload endpoint returning placeholder report
│   │   ├── core/
│   │   │   └── config.py
│   │   ├── models/
│   │   │   └── report.py
│   │   ├── services/
│   │   │   └── report_builder.py
│   │   └── main.py
│   ├── requirements.txt
│   └── README.md
└── analyzers/
    ├── android/
    │   ├── __init__.py
    │   ├── external_tools/
    │   │   ├── __init__.py
    │   │   ├── jadx.py
    │   │   └── models.py
    │   └── scanner.py
    └── ios/
        ├── __init__.py
        └── scanner.py
```

---

## Quick Start

### 1) Backend (FastAPI)

```bash
cd backend
python -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
uvicorn app.main:app --reload --port 8000
```

Backend runs at `http://localhost:8000`.

Health check:

```bash
curl http://localhost:8000/health
```

Upload endpoint:

```bash
curl -X POST "http://localhost:8000/api/v1/upload" \
  -F "file=@/path/to/app.apk"
# or /path/to/app.aab
```

---

### 2) Frontend (Next.js + TypeScript)

```bash
cd frontend
npm install
npm run dev
```

Frontend runs at `http://localhost:3000`.

By default, it posts upload requests to `http://localhost:8000/api/v1/upload`.

You can override backend URL:

```bash
NEXT_PUBLIC_API_BASE_URL=http://localhost:8000 npm run dev
```

---


## Normalized Report Schema

The backend now returns a shared normalized schema for both Android and iOS:

- `platform`
- `file_name`
- `risk_level`
- `score`
- `summary`
- `findings`
- `categories`
- `metadata`

Each finding includes `id`, `title`, `severity`, `category`, `description`, `recommendation`, and `source`.

Example response objects are defined in `backend/app/models/report.py` as:

- `ANDROID_EXAMPLE_REPORT`
- `IOS_EXAMPLE_REPORT`

---

## MVP Behavior

- User uploads `.apk`, `.aab`, or `.ipa` file from frontend.
- Backend validates extension, enforces upload size limits, and infers platform.
- Malformed archives, missing required package metadata, and unsafe ZIP payloads return JSON errors instead of a normalized report.
- Backend routes to platform analyzer module:
  - `analyzers/android/scanner.py`
  - `analyzers/ios/scanner.py`
- Analyzer returns a **placeholder security report JSON**.
- Android analyzer includes practical **heuristic** checks (e.g., debuggable/backup flags, URLs, candidate secrets) and may produce false positives.
- Android APK analysis can optionally enrich heuristic findings with local `jadx` output through `analyzers/android/external_tools/`.
- iOS analyzer includes practical **heuristic** checks (e.g., ATS exceptions, suspicious URLs, candidate secrets) and may produce false positives.
- Invalid uploads return consistent JSON errors with `error.code`, `error.message`, and `error.details`.

Common upload error codes:

- `INVALID_FILE_TYPE`: unsupported extension
- `FILE_TOO_LARGE`: uploaded file exceeds `max_upload_size_bytes`
- `INVALID_ARCHIVE`: ZIP is malformed or missing required package metadata such as Android manifest / iOS `Info.plist`
- `ARCHIVE_LIMIT_EXCEEDED`: compressed archive would exceed safe extraction limits

---

## Out of Scope (Current MVP Constraints)

- Authentication/authorization
- Database persistence
- Queue/async job workers
- Cloud deployment infrastructure
- Dynamic runtime analysis
- Large external reverse engineering platforms and dynamic instrumentation (e.g. MobSF orchestration, Frida)

---

## Optional JADX Setup

Android APK analysis can use locally installed `jadx` to enrich heuristic findings with:

- readable source/code exposure indicators
- suspicious hardcoded URLs
- candidate secrets or tokens
- notable package/class naming patterns

If `jadx` is not installed or cannot run, uploads still complete and the backend falls back to the baseline Android heuristics.

Example local setup on macOS:

```bash
brew install jadx
jadx --version
```

Optional environment variables:

```bash
export APPSEC_ANDROID_JADX_PATH="$(command -v jadx)"
export APPSEC_ANDROID_JADX_TIMEOUT_SECONDS=45
export APPSEC_ANDROID_JADX_MAX_SOURCE_FILES=200
export APPSEC_ANDROID_JADX_MAX_SOURCE_FILE_SIZE=300000
```

Then start the backend normally:

```bash
cd backend
uvicorn app.main:app --reload --port 8000
```

---

## Next Logical Steps

1. Add robust file validation, checksuming, and size limits.
2. Add persistent storage and report history.
3. Add background job processing for long-running analysis.
4. Integrate static analysis tooling in analyzer modules.
5. Add report severity scoring and policy gates.
6. Add auth + role-based access for enterprise use.
