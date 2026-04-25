# Mobile AppSec Platform (MVP Scaffold)

A modular MVP scaffold for a **mobile application security assessment platform** focused on static, pre-release analysis inputs for:

- Android APKs/AABs
- iOS IPAs

This repository currently provides:

- **Next.js + TypeScript frontend** for uploading a file and viewing a report
- **FastAPI backend** with an upload endpoint
- **Analyzer modules** for Android and iOS with placeholder logic
- **SQLite-backed scan history** for tracking recent upload reports
- **Optional MobSF adapter** for enriching findings while preserving the normalized report schema
- **Optional binary-analysis adapter entry point** for deeper native/binary inspection
- **No auth, no queue, no cloud deployment, and no dynamic analysis**

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

Recent scan history:

```bash
curl "http://localhost:8000/api/v1/projects"
curl "http://localhost:8000/api/v1/scans"
curl "http://localhost:8000/api/v1/scans/{scan_id}"
curl "http://localhost:8000/api/v1/scans/{target_scan_id}/comparison?baseline_scan_id={baseline_scan_id}"
curl "http://localhost:8000/api/v1/scans/{scan_id}/policy?fail_on_policy_failure=true"
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

Reports also include a simple policy evaluation with a `pass`, `warn`, or `fail` decision. The default policy fails on confirmed critical findings, fails below the configured score threshold, and warns on heuristic high-severity findings.

Optional external analyzer findings are normalized into this same schema. MobSF findings are labeled with `source` values beginning with `mobsf/` and titles beginning with `MobSF:` so downstream users can distinguish detection source without depending on raw MobSF JSON.

Example response objects are defined in `backend/app/models/report.py` as:

- `ANDROID_EXAMPLE_REPORT`
- `IOS_EXAMPLE_REPORT`

---

## Third-Phase Architecture

The third-phase backend keeps analyzer output behind adapters and service boundaries:

- `backend/app/services/report_builder.py` owns normalized report construction.
- `analyzers/android` and `analyzers/ios` provide built-in package heuristics.
- `analyzers/adapters/mobsf.py` and `analyzers/adapters/binary_analysis.py` are optional enrichment sources.
- `backend/app/services/scan_history.py` owns persistence and historical report compatibility repair.
- `backend/app/services/scan_comparison.py` owns version-to-version diffing.
- `backend/app/services/policy_evaluator.py` owns release gate decisions.

Optional tools never define the API contract. They return normalized findings or fail closed into an analyzer warning/log path. If core analysis fails before a normalized report is produced, the platform records a failed scan with error metadata rather than returning a misleading successful report.

---

## Persistent Scan History

Uploads still return the existing normalized report schema. The backend also stores each completed scan in a lightweight SQLite database configured by `APPSEC_DATABASE_URL` and defaulting to `sqlite:///./appsec.sqlite3`.

The persistence model is intentionally minimal:

- projects
- app records
- app versions with version/build identifiers
- scan jobs
- scan results
- findings

Schema changes are tracked in a `schema_migrations` table and mirrored to SQLite `PRAGMA user_version`. Current migrations add app version build metadata, scan package metadata, and failed-scan recovery metadata. The migration layer is intentionally simple and idempotent; it is not a replacement for a full production migration system.

Project/app/version endpoints:

- `GET /api/v1/projects`
- `POST /api/v1/projects`
- `GET /api/v1/projects/{project_id}/apps`
- `POST /api/v1/projects/{project_id}/apps`
- `GET /api/v1/apps/{app_id}/versions`
- `POST /api/v1/apps/{app_id}/versions`

Scan history endpoints:

- `GET /api/v1/scans` lists recent scans. It supports `app_id` and `app_version_id` filters.
- `GET /api/v1/scans/{scan_id}` returns the stored normalized report for a scan.
- `GET /api/v1/scans/{target_scan_id}/comparison?baseline_scan_id={baseline_scan_id}` compares two scans from the same app.
- `GET /api/v1/scans/{scan_id}/policy` returns the release gate decision for a scan.

Comparison output separates new, resolved, unchanged, severity-changed, and uncertain matches. Exact matching uses finding `id`, `category`, and `source`. Uncertain matches are labeled separately because analyzer findings are heuristic and may change when rules, source paths, or sampled package contents change.

Failed scans remain visible in recent history with `status=failed`, `error_code`, and `error_message`. They do not have a completed normalized report; retrieving them returns `SCAN_FAILED` so downstream tools do not mistake incomplete analysis for a clean scan.

---

## CI/CD Policy Gate

The policy endpoint is designed for simple release gates. It returns JSON by default and can return a non-2xx status when the policy decision is `fail`:

```bash
curl -fsS \
  "http://localhost:8000/api/v1/scans/${SCAN_ID}/policy?min_score=80&fail_on_policy_failure=true"
```

Example GitHub Actions step:

```yaml
- name: Enforce Mobile AppSec policy
  run: |
    curl -fsS \
      "${APPSEC_API_URL}/api/v1/scans/${SCAN_ID}/policy?min_score=80&fail_on_policy_failure=true"
```

This gate is an automation signal, not a complete security guarantee. Heuristic findings can be noisy, optional tool failures can reduce coverage, and policy decisions should be reviewed with release context.

---

## Optional MobSF Enrichment

MobSF can be used as an additional analysis source. It does not own the API contract or frontend model: the backend uploads the app to MobSF, reads the returned/static JSON report, and maps relevant entries into the shared finding schema.

Configuration:

```bash
APPSEC_MOBSF_ENABLED=true
APPSEC_MOBSF_BASE_URL=http://localhost:8000
APPSEC_MOBSF_API_KEY=<your-mobsf-api-key>
APPSEC_MOBSF_TIMEOUT_SECONDS=30
APPSEC_MOBSF_RE_SCAN=false
```

Local setup outline:

```bash
docker pull opensecurity/mobile-security-framework-mobsf:latest
docker run -it --rm -p 8000:8000 opensecurity/mobile-security-framework-mobsf:latest
```

Then start this backend with the `APPSEC_MOBSF_*` settings above. If MobSF is disabled, missing configuration, unreachable, or returns an unusable response, the scan still completes with the built-in analyzer findings and logs the MobSF issue.

The adapter currently uses MobSF's static-analysis REST flow (`/api/v1/upload`, `/api/v1/scan`, and `/api/v1/report_json`) and performs best-effort normalization of common JSON shapes. Treat MobSF-derived severity and matching as another heuristic signal unless your team validates the specific rule output.

---

## Optional Binary Analysis Entry Point

The backend includes a pluggable binary-analysis route for heavier future tooling without making those tools runtime requirements. Enable the lightweight metadata adapter with:

```bash
APPSEC_BINARY_ANALYSIS_ENABLED=true
APPSEC_BINARY_ANALYSIS_MAX_ARTIFACTS=20
APPSEC_BINARY_ANALYSIS_MAX_ARTIFACT_BYTES=5242880
```

When enabled, the current built-in adapter extracts lightweight metadata from:

- Android native libraries under `lib/<abi>/*.so`
- iOS app executables declared by `CFBundleExecutable`
- iOS `.dylib` and framework binaries

Outputs are normalized into the shared finding schema. Detection sources are labeled with prefixes such as `binary-metadata/` and `binary-strings/`.

Future tools should implement the `BinaryAnalysisAdapter` interface in `analyzers/adapters/binary_analysis.py`: accept a `BinaryArtifact`, return normalized findings, and keep tool-specific raw output private to the adapter. A Ghidra-like adapter can run offline disassembly, symbol extraction, call graph checks, or rule packs behind this interface without changing the API response shape.

This is an integration entry point, not a full reverse-engineering pipeline. Heavy tools should remain optional, isolated, bounded by artifact size/time limits, and ideally moved behind background jobs.

---

## MVP Behavior

- User uploads `.apk`, `.aab`, or `.ipa` file from frontend.
- User selects or creates a project, app, and version/build context.
- User can compare a target scan against a selected baseline scan for the same app.
- User can evaluate a scan against the simple release policy gate.
- Backend validates extension, enforces upload size limits, and infers platform.
- Backend routes to platform analyzer module:
  - `analyzers/android/scanner.py`
  - `analyzers/ios/scanner.py`
- Backend can optionally enrich findings through `analyzers/adapters/mobsf.py`.
- Backend can optionally inspect native/binary artifacts through `analyzers/adapters/binary_analysis.py`.
- Analyzer returns a **placeholder security report JSON**.
- Backend persists each completed report to scan history associated with the selected app version.
- Android analyzer includes practical **heuristic** checks (e.g., debuggable/backup flags, URLs, candidate secrets) and may produce false positives.
- iOS analyzer includes practical **heuristic** checks (e.g., ATS exceptions, suspicious URLs, candidate secrets) and may produce false positives.
- Invalid uploads return consistent JSON errors with `error.code`, `error.message`, and `error.details`.

---

## Out of Scope (Current MVP Constraints)

- Authentication/authorization
- Queue/async job workers
- Cloud deployment infrastructure
- Dynamic runtime analysis
- Deep external reverse engineering orchestration beyond optional static MobSF enrichment

---

## Next Logical Steps

1. Add robust file validation, checksuming, and size limits.
2. Add background job processing for long-running analysis.
3. Integrate static analysis tooling in analyzer modules.
4. Add report severity scoring and policy gates.
5. Add auth + role-based access for enterprise use.
