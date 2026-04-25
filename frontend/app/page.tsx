"use client";

import { FormEvent, ReactNode, useCallback, useEffect, useMemo, useState } from "react";

type Severity = "low" | "medium" | "high" | "critical";
type Platform = "android" | "ios";

type Project = {
  id: string;
  name: string;
  created_at: string;
};

type MobileApp = {
  id: string;
  project_id: string;
  name: string;
  platform: Platform;
  created_at: string;
};

type AppVersion = {
  id: string;
  app_id: string;
  version_name: string | null;
  build_identifier: string | null;
  created_at: string;
};

type RecentScan = {
  id: string;
  project_id: string;
  project_name: string;
  app_id: string;
  app_name: string;
  app_version_id: string;
  version_name: string | null;
  build_identifier: string | null;
  file_name: string;
  file_extension: ".apk" | ".aab" | ".ipa";
  platform: Platform;
  status: "queued" | "running" | "completed" | "failed";
  risk_level: Severity;
  score: number;
  finding_count: number;
  error_code?: string | null;
  error_message?: string | null;
  started_at: string;
  completed_at: string | null;
};

type Finding = {
  id: string;
  title: string;
  severity: Severity;
  category?: string;
  description?: string;
  recommendation?: string;
  source?: string;
};

type ReportResponse = {
  platform: Platform;
  file_name: string;
  risk_level: Severity;
  score: number;
  summary?: {
    total_findings: number;
    by_severity: { low: number; medium: number; high: number; critical: number };
  };
  findings?: Finding[];
  categories?: { name: string; count: number; max_severity: Severity }[];
  policy?: PolicyEvaluation | null;
  metadata: {
    generated_at: string;
    analyzer_version: string;
    analysis_mode: "static-placeholder";
    file_extension: ".apk" | ".aab" | ".ipa";
  };
};

type PolicyEvaluation = {
  decision: "pass" | "warn" | "fail";
  min_score: number;
  rules: {
    id: string;
    name: string;
    status: "pass" | "warn" | "fail";
    message: string;
    finding_ids: string[];
  }[];
  limitations: string[];
};

type ComparisonReport = {
  baseline_scan: ComparisonScanRef;
  target_scan: ComparisonScanRef;
  summary: {
    new: number;
    resolved: number;
    unchanged: number;
    severity_changed: number;
    uncertain: number;
  };
  new_findings: Finding[];
  resolved_findings: Finding[];
  unchanged_findings: Finding[];
  severity_changes: {
    match_key: string;
    baseline_severity: Severity;
    target_severity: Severity;
    baseline_finding: Finding;
    target_finding: Finding;
  }[];
  uncertain_matches: {
    confidence: "medium" | "low";
    reason: string;
    baseline_finding: Finding;
    target_finding: Finding;
  }[];
  match_strategy: string;
  limitations: string[];
};

type ComparisonScanRef = {
  scan_id: string;
  app_id: string;
  app_name: string;
  app_version_id: string;
  version_name: string | null;
  build_identifier: string | null;
  file_name: string;
};

type ApiErrorResponse = {
  error?: {
    code?: string;
    message?: string;
    details?: Record<string, unknown>;
  };
  detail?: string;
};

const SEVERITY_ORDER: Severity[] = ["critical", "high", "medium", "low"];
const EMPTY_SUMMARY = {
  total_findings: 0,
  by_severity: { low: 0, medium: 0, high: 0, critical: 0 },
};

async function requestJson<T>(apiBaseUrl: string, path: string, init?: RequestInit): Promise<T> {
  const response = await fetch(`${apiBaseUrl}${path}`, init);

  if (!response.ok) {
    let apiError: ApiErrorResponse | null = null;
    try {
      apiError = (await response.json()) as ApiErrorResponse;
    } catch {
      apiError = null;
    }

    const message = apiError?.error?.message ?? apiError?.detail ?? "Request failed.";
    throw new Error(message);
  }

  return (await response.json()) as T;
}

function versionLabel(version: { version_name: string | null; build_identifier: string | null }): string {
  const versionName = version.version_name ?? "Unspecified";
  return version.build_identifier ? `${versionName} (${version.build_identifier})` : versionName;
}

function inferPlatform(file: File | null): Platform {
  if (!file) {
    return "android";
  }

  return file.name.toLowerCase().endsWith(".ipa") ? "ios" : "android";
}

export default function HomePage() {
  const [projects, setProjects] = useState<Project[]>([]);
  const [apps, setApps] = useState<MobileApp[]>([]);
  const [versions, setVersions] = useState<AppVersion[]>([]);
  const [recentScans, setRecentScans] = useState<RecentScan[]>([]);

  const [selectedProjectId, setSelectedProjectId] = useState("");
  const [selectedAppId, setSelectedAppId] = useState("");
  const [selectedVersionId, setSelectedVersionId] = useState("");
  const [newProjectName, setNewProjectName] = useState("");
  const [newAppName, setNewAppName] = useState("");
  const [appPlatform, setAppPlatform] = useState<Platform>("android");
  const [versionName, setVersionName] = useState("");
  const [buildIdentifier, setBuildIdentifier] = useState("");
  const [baselineScanId, setBaselineScanId] = useState("");

  const [file, setFile] = useState<File | null>(null);
  const [loading, setLoading] = useState(false);
  const [contextLoading, setContextLoading] = useState(false);
  const [historyLoading, setHistoryLoading] = useState(false);
  const [scanLoading, setScanLoading] = useState(false);
  const [comparisonLoading, setComparisonLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [errorCode, setErrorCode] = useState<string | null>(null);
  const [report, setReport] = useState<ReportResponse | null>(null);
  const [comparison, setComparison] = useState<ComparisonReport | null>(null);
  const [activeScan, setActiveScan] = useState<RecentScan | null>(null);

  const apiBaseUrl = useMemo(
    () => process.env.NEXT_PUBLIC_API_BASE_URL ?? "http://localhost:8000",
    []
  );

  const selectedProject = useMemo(
    () => projects.find((project) => project.id === selectedProjectId) ?? null,
    [projects, selectedProjectId]
  );
  const selectedApp = useMemo(
    () => apps.find((app) => app.id === selectedAppId) ?? null,
    [apps, selectedAppId]
  );
  const selectedVersion = useMemo(
    () => versions.find((version) => version.id === selectedVersionId) ?? null,
    [versions, selectedVersionId]
  );

  const findingsBySeverity = useMemo(() => {
    if (!report) {
      return [] as { severity: Severity; findings: Finding[] }[];
    }

    const reportFindings = report.findings ?? [];
    return SEVERITY_ORDER.map((severity) => ({
      severity,
      findings: reportFindings.filter((finding) => finding.severity === severity),
    })).filter((group) => group.findings.length > 0);
  }, [report]);

  const reportSummary = useMemo(() => (report ? summaryForReport(report) : EMPTY_SUMMARY), [report]);

  const historyHeading = selectedApp
    ? `${selectedApp.name} scans`
    : "All application scans";
  const historySubheading = selectedVersion
    ? `Selected version: ${versionLabel(selectedVersion)}`
    : "Latest stored scans";

  const loadProjects = useCallback(async () => {
    const data = await requestJson<Project[]>(apiBaseUrl, "/api/v1/projects");
    setProjects(data);
    if (!selectedProjectId && data.length > 0) {
      setSelectedProjectId(data[0].id);
    }
  }, [apiBaseUrl, selectedProjectId]);

  const loadApps = useCallback(
    async (projectId: string) => {
      const data = await requestJson<MobileApp[]>(apiBaseUrl, `/api/v1/projects/${projectId}/apps`);
      setApps(data);
      setSelectedAppId((current) => (data.some((app) => app.id === current) ? current : ""));
    },
    [apiBaseUrl]
  );

  const loadVersions = useCallback(
    async (appId: string) => {
      const data = await requestJson<AppVersion[]>(apiBaseUrl, `/api/v1/apps/${appId}/versions`);
      setVersions(data);
      setSelectedVersionId((current) =>
        data.some((version) => version.id === current) ? current : ""
      );
    },
    [apiBaseUrl]
  );

  const loadRecentScans = useCallback(
    async (appId?: string, appVersionId?: string) => {
      const params = new URLSearchParams({ limit: "10" });
      if (appId) {
        params.set("app_id", appId);
      }
      if (appVersionId) {
        params.set("app_version_id", appVersionId);
      }

      setHistoryLoading(true);
      try {
        const data = await requestJson<RecentScan[]>(apiBaseUrl, `/api/v1/scans?${params.toString()}`);
        setRecentScans(data);
      } finally {
        setHistoryLoading(false);
      }
    },
    [apiBaseUrl]
  );

  useEffect(() => {
    loadProjects().catch((loadError) => setError(loadError instanceof Error ? loadError.message : "Unable to load projects."));
  }, [loadProjects]);

  useEffect(() => {
    if (!selectedProjectId) {
      setApps([]);
      setSelectedAppId("");
      return;
    }

    loadApps(selectedProjectId).catch((loadError) =>
      setError(loadError instanceof Error ? loadError.message : "Unable to load apps.")
    );
  }, [loadApps, selectedProjectId]);

  useEffect(() => {
    if (!selectedAppId) {
      setVersions([]);
      setSelectedVersionId("");
      return;
    }

    loadVersions(selectedAppId).catch((loadError) =>
      setError(loadError instanceof Error ? loadError.message : "Unable to load app versions.")
    );
  }, [loadVersions, selectedAppId]);

  useEffect(() => {
    loadRecentScans(selectedAppId || undefined).catch((loadError) =>
      setError(loadError instanceof Error ? loadError.message : "Unable to load scan history.")
    );
  }, [loadRecentScans, selectedAppId]);

  const createProject = async () => {
    setContextLoading(true);
    setError(null);
    try {
      const project = await requestJson<Project>(apiBaseUrl, "/api/v1/projects", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ name: newProjectName }),
      });
      setProjects((current) => [project, ...current.filter((item) => item.id !== project.id)]);
      setSelectedProjectId(project.id);
      setNewProjectName("");
    } catch (createError) {
      setError(createError instanceof Error ? createError.message : "Unable to create project.");
    } finally {
      setContextLoading(false);
    }
  };

  const createApp = async () => {
    if (!selectedProjectId) {
      setError("Select or create a project first.");
      return;
    }

    setContextLoading(true);
    setError(null);
    try {
      const mobileApp = await requestJson<MobileApp>(
        apiBaseUrl,
        `/api/v1/projects/${selectedProjectId}/apps`,
        {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ name: newAppName, platform: appPlatform }),
        }
      );
      setApps((current) => [mobileApp, ...current.filter((item) => item.id !== mobileApp.id)]);
      setSelectedAppId(mobileApp.id);
      setNewAppName("");
    } catch (createError) {
      setError(createError instanceof Error ? createError.message : "Unable to create app.");
    } finally {
      setContextLoading(false);
    }
  };

  const createVersion = async () => {
    if (!selectedAppId) {
      setError("Select or create an app first.");
      return;
    }

    setContextLoading(true);
    setError(null);
    try {
      const appVersion = await requestJson<AppVersion>(apiBaseUrl, `/api/v1/apps/${selectedAppId}/versions`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          version_name: versionName || null,
          build_identifier: buildIdentifier || null,
        }),
      });
      setVersions((current) => [appVersion, ...current.filter((item) => item.id !== appVersion.id)]);
      setSelectedVersionId(appVersion.id);
      setVersionName("");
      setBuildIdentifier("");
    } catch (createError) {
      setError(createError instanceof Error ? createError.message : "Unable to create version.");
    } finally {
      setContextLoading(false);
    }
  };

  const ensureProject = async (): Promise<string> => {
    if (selectedProjectId) {
      return selectedProjectId;
    }
    if (!newProjectName.trim()) {
      throw new Error("Select or create a project.");
    }

    const project = await requestJson<Project>(apiBaseUrl, "/api/v1/projects", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ name: newProjectName }),
    });
    setProjects((current) => [project, ...current.filter((item) => item.id !== project.id)]);
    setSelectedProjectId(project.id);
    setNewProjectName("");
    return project.id;
  };

  const ensureApp = async (projectId: string): Promise<string> => {
    if (selectedAppId) {
      return selectedAppId;
    }
    if (!newAppName.trim()) {
      throw new Error("Select or create an app.");
    }

    const mobileApp = await requestJson<MobileApp>(apiBaseUrl, `/api/v1/projects/${projectId}/apps`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ name: newAppName, platform: appPlatform }),
    });
    setApps((current) => [mobileApp, ...current.filter((item) => item.id !== mobileApp.id)]);
    setSelectedAppId(mobileApp.id);
    setNewAppName("");
    return mobileApp.id;
  };

  const ensureVersion = async (appId: string): Promise<string> => {
    if (selectedVersionId) {
      return selectedVersionId;
    }
    if (!versionName.trim() && !buildIdentifier.trim()) {
      throw new Error("Select or create a version/build identifier.");
    }

    const appVersion = await requestJson<AppVersion>(apiBaseUrl, `/api/v1/apps/${appId}/versions`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        version_name: versionName || null,
        build_identifier: buildIdentifier || null,
      }),
    });
    setVersions((current) => [appVersion, ...current.filter((item) => item.id !== appVersion.id)]);
    setSelectedVersionId(appVersion.id);
    setVersionName("");
    setBuildIdentifier("");
    return appVersion.id;
  };

  const onSubmit = async (event: FormEvent<HTMLFormElement>) => {
    event.preventDefault();

    if (!file) {
      setErrorCode("MISSING_FILE");
      setError("Select an APK, AAB, or IPA file first.");
      return;
    }

    setLoading(true);
    setError(null);
    setErrorCode(null);
    setReport(null);
    setComparison(null);
    setActiveScan(null);

    try {
      const projectId = await ensureProject();
      const appId = await ensureApp(projectId);
      const versionId = await ensureVersion(appId);

      const formData = new FormData();
      formData.append("file", file);
      formData.append("project_id", projectId);
      formData.append("app_id", appId);
      formData.append("app_version_id", versionId);

      const data = await requestJson<ReportResponse>(apiBaseUrl, "/api/v1/upload", {
        method: "POST",
        body: formData,
      });

      setReport(data);
      await loadRecentScans(appId);
    } catch (submitError) {
      const message =
        submitError instanceof Error
          ? submitError.message
          : "Unexpected upload error.";
      setErrorCode("UPLOAD_ERROR");
      setError(message);
    } finally {
      setLoading(false);
    }
  };

  const openScan = async (scanId: string) => {
    setError(null);
    setErrorCode(null);
    setScanLoading(true);
    setComparison(null);
    setReport(null);
    const scanForDetail = recentScans.find((scan) => scan.id === scanId) ?? null;
    setActiveScan(scanForDetail);
    try {
      const storedReport = await requestJson<ReportResponse>(apiBaseUrl, `/api/v1/scans/${scanId}`);
      setReport(storedReport);
    } catch (openError) {
      setError(openError instanceof Error ? openError.message : "Unable to open scan.");
    } finally {
      setScanLoading(false);
    }
  };

  const compareScan = async (targetScanId: string) => {
    if (!baselineScanId) {
      setError("Select a baseline scan first.");
      return;
    }
    if (baselineScanId === targetScanId) {
      setError("Choose a different target scan than the baseline.");
      return;
    }

    setError(null);
    setErrorCode(null);
    setComparisonLoading(true);
    setComparison(null);
    setReport(null);
    try {
      const data = await requestJson<ComparisonReport>(
        apiBaseUrl,
        `/api/v1/scans/${targetScanId}/comparison?baseline_scan_id=${baselineScanId}`
      );
      setComparison(data);
      setActiveScan(null);
    } catch (compareError) {
      setError(compareError instanceof Error ? compareError.message : "Unable to compare scans.");
    } finally {
      setComparisonLoading(false);
    }
  };

  return (
    <main className="container">
      <header className="page-header">
        <h1>Mobile AppSec Platform</h1>
        <p>Upload an Android APK/AAB or iOS IPA and attach the scan to an app version.</p>
      </header>

      <form onSubmit={onSubmit} className="scan-form">
        <section className="workspace-section">
          <h2>Workspace</h2>

          <div className="field-grid">
            <label>
              Project
              <select
                value={selectedProjectId}
                onChange={(event) => {
                  setSelectedProjectId(event.target.value);
                  setSelectedAppId("");
                  setSelectedVersionId("");
                }}
              >
                <option value="">Select project</option>
                {projects.map((project) => (
                  <option key={project.id} value={project.id}>
                    {project.name}
                  </option>
                ))}
              </select>
            </label>

            <label>
              New project
              <div className="inline-action">
                <input
                  type="text"
                  value={newProjectName}
                  placeholder="Internal project name"
                  onChange={(event) => setNewProjectName(event.target.value)}
                />
                <button type="button" onClick={createProject} disabled={contextLoading || !newProjectName.trim()}>
                  Create
                </button>
              </div>
            </label>

            <label>
              App
              <select
                value={selectedAppId}
                onChange={(event) => {
                  const nextAppId = event.target.value;
                  const nextApp = apps.find((app) => app.id === nextAppId);
                  setSelectedAppId(nextAppId);
                  setSelectedVersionId("");
                  if (nextApp) {
                    setAppPlatform(nextApp.platform);
                  }
                }}
                disabled={!selectedProject}
              >
                <option value="">Select app</option>
                {apps.map((mobileApp) => (
                  <option key={mobileApp.id} value={mobileApp.id}>
                    {mobileApp.name} - {mobileApp.platform}
                  </option>
                ))}
              </select>
            </label>

            <label>
              New app
              <div className="inline-action">
                <input
                  type="text"
                  value={newAppName}
                  placeholder="App record name"
                  onChange={(event) => setNewAppName(event.target.value)}
                />
                <select
                  aria-label="New app platform"
                  value={selectedApp?.platform ?? appPlatform}
                  onChange={(event) => setAppPlatform(event.target.value as Platform)}
                  disabled={Boolean(selectedApp)}
                >
                  <option value="android">Android</option>
                  <option value="ios">iOS</option>
                </select>
                <button
                  type="button"
                  onClick={createApp}
                  disabled={contextLoading || !selectedProjectId || !newAppName.trim()}
                >
                  Create
                </button>
              </div>
            </label>

            <label>
              Version
              <select
                value={selectedVersionId}
                onChange={(event) => setSelectedVersionId(event.target.value)}
                disabled={!selectedAppId}
              >
                <option value="">Select version/build</option>
                {versions.map((version) => (
                  <option key={version.id} value={version.id}>
                    {versionLabel(version)}
                  </option>
                ))}
              </select>
            </label>

            <label>
              New version/build
              <div className="inline-action">
                <input
                  type="text"
                  value={versionName}
                  placeholder="Version, e.g. 1.4.0"
                  onChange={(event) => setVersionName(event.target.value)}
                />
                <input
                  type="text"
                  value={buildIdentifier}
                  placeholder="Build, e.g. 1042"
                  onChange={(event) => setBuildIdentifier(event.target.value)}
                />
                <button
                  type="button"
                  onClick={createVersion}
                  disabled={contextLoading || !selectedAppId || (!versionName.trim() && !buildIdentifier.trim())}
                >
                  Create
                </button>
              </div>
            </label>
          </div>
        </section>

        <section className="upload-section">
          <h2>Scan Upload</h2>
          <input
            type="file"
            accept=".apk,.aab,.ipa"
            onChange={(event) => {
              const nextFile = event.target.files?.[0] ?? null;
              setFile(nextFile);
              setAppPlatform(inferPlatform(nextFile));
            }}
          />
          <button type="submit" disabled={loading}>
            {loading ? "Analyzing..." : "Upload for Analysis"}
          </button>
        </section>
      </form>

      {loading && <p className="status">Analysis in progress. Please wait...</p>}

      {error && (
        <div className="error" role="alert">
          {errorCode && <p>Error code: {errorCode}</p>}
          <p>{error}</p>
        </div>
      )}

      <section className="history-section">
        <div className="section-heading">
          <div>
            <h2>Recent Scans</h2>
            <p>{historyHeading} / {historySubheading}</p>
          </div>
          <button
            type="button"
            className="secondary-button"
            onClick={() => loadRecentScans(selectedAppId || undefined)}
            disabled={historyLoading}
          >
            {historyLoading ? "Refreshing..." : "Refresh"}
          </button>
        </div>

        <div className="history-toolbar">
          <label className="baseline-picker">
            Baseline scan
            <select
              value={baselineScanId}
              onChange={(event) => setBaselineScanId(event.target.value)}
              disabled={recentScans.length === 0 || historyLoading}
            >
              <option value="">Select baseline</option>
              {recentScans.map((scan) => (
                <option key={scan.id} value={scan.id}>
                  {versionLabel(scan)} - {scan.file_name} - {scan.risk_level.toUpperCase()}
                </option>
              ))}
            </select>
          </label>
          <p className="helper-text">
            Pick a baseline, then compare any other scan from the same app.
          </p>
        </div>

        {historyLoading ? (
          <p className="status">Loading scan history...</p>
        ) : recentScans.length === 0 ? (
          <p className="empty-state">No stored scans yet. Upload a package to start building history.</p>
        ) : (
          <div className="scan-list">
            {recentScans.map((scan) => (
              <article
                key={scan.id}
                className={`scan-row${activeScan?.id === scan.id ? " selected-scan-row" : ""}`}
              >
                <div className="scan-main">
                  <strong>{scan.app_name}</strong>
                  <span>{versionLabel(scan)}</span>
                  <p>{scan.file_name}</p>
                </div>
                <div className="scan-metrics">
                  <MetricPill label="Score" value={`${scan.score}/100`} />
                  <MetricPill label="Status" value={scan.status.toUpperCase()} />
                  <MetricPill label="Risk" value={scan.risk_level.toUpperCase()} tone={scan.risk_level} />
                  <MetricPill label="Findings" value={String(scan.finding_count)} />
                  <span className="scan-time">{formatDate(scan.completed_at ?? scan.started_at)}</span>
                </div>
                {scan.status === "failed" && (
                  <p className="scan-error">
                    {scan.error_code ?? "SCAN_FAILED"}: {scan.error_message ?? "No completed report was produced."}
                  </p>
                )}
                <div className="scan-actions">
                  <button
                    type="button"
                    onClick={() => openScan(scan.id)}
                    disabled={scanLoading || scan.status !== "completed"}
                  >
                    {scanLoading && activeScan?.id === scan.id ? "Opening..." : "Open"}
                  </button>
                  <button
                    type="button"
                    className="secondary-button"
                    onClick={() => compareScan(scan.id)}
                    disabled={
                      comparisonLoading ||
                      !baselineScanId ||
                      baselineScanId === scan.id ||
                      scan.status !== "completed"
                    }
                  >
                    Compare
                  </button>
                </div>
              </article>
            ))}
          </div>
        )}
      </section>

      {scanLoading && <p className="status">Loading scan detail...</p>}
      {comparisonLoading && <p className="status">Building comparison...</p>}

      {comparison && (
        <section className="comparison-section">
          <div className="section-heading">
            <div>
              <h2>Comparison</h2>
              <p>
                Baseline {versionLabel(comparison.baseline_scan)} compared with target{" "}
                {versionLabel(comparison.target_scan)}
              </p>
            </div>
            <button
              type="button"
              className="secondary-button"
              onClick={() => {
                setComparison(null);
                setBaselineScanId("");
              }}
            >
              Clear comparison
            </button>
          </div>

          <div className="comparison-summary">
            <SummaryTile label="New" value={comparison.summary.new} />
            <SummaryTile label="Resolved" value={comparison.summary.resolved} />
            <SummaryTile label="Severity changes" value={comparison.summary.severity_changed} />
            <SummaryTile label="Unchanged" value={comparison.summary.unchanged} />
            <SummaryTile label="Uncertain" value={comparison.summary.uncertain} />
          </div>

          <div className="comparison-note">
            <p>{comparison.match_strategy}</p>
            <ul>
              {comparison.limitations.map((limitation) => (
                <li key={limitation}>{limitation}</li>
              ))}
            </ul>
          </div>

          <ComparisonFindingGroup
            title="Severity Changes"
            emptyMessage="No findings changed severity."
          >
            {comparison.severity_changes.map((change) => (
              <article key={change.match_key} className="finding-card">
                <p>
                  <strong>{change.target_finding.id}</strong> - {change.target_finding.title}
                </p>
                <p>
                  {change.baseline_severity.toUpperCase()} to {change.target_severity.toUpperCase()} |{" "}
                  {change.target_finding.category}
                </p>
                <p>{change.target_finding.description}</p>
              </article>
            ))}
          </ComparisonFindingGroup>

          <ComparisonFindingGroup
            title="New Findings"
            emptyMessage="No new findings in the target scan."
          >
            {comparison.new_findings.map((finding) => (
              <FindingCard key={`${finding.id}-${finding.source}`} finding={finding} />
            ))}
          </ComparisonFindingGroup>

          <ComparisonFindingGroup
            title="Resolved Findings"
            emptyMessage="No baseline findings were resolved."
          >
            {comparison.resolved_findings.map((finding) => (
              <FindingCard key={`${finding.id}-${finding.source}`} finding={finding} />
            ))}
          </ComparisonFindingGroup>

          <ComparisonFindingGroup
            title="Unchanged Findings"
            emptyMessage="No findings matched unchanged across these scans."
          >
            {comparison.unchanged_findings.map((finding) => (
              <FindingCard key={`${finding.id}-${finding.source}`} finding={finding} compact />
            ))}
          </ComparisonFindingGroup>

          <ComparisonFindingGroup
            title="Uncertain Matches"
            emptyMessage="No uncertain matches were detected."
          >
            {comparison.uncertain_matches.map((match) => (
              <article
                key={`${match.baseline_finding.id}-${match.target_finding.id}-${match.reason}`}
                className="finding-card uncertain-card"
              >
                <p>
                  <strong>{match.confidence.toUpperCase()} confidence:</strong> {match.reason}
                </p>
                <p>
                  Baseline: {match.baseline_finding.id} - {match.baseline_finding.title}
                </p>
                <p>
                  Target: {match.target_finding.id} - {match.target_finding.title}
                </p>
              </article>
            ))}
          </ComparisonFindingGroup>
        </section>
      )}

      {!loading && !scanLoading && !comparisonLoading && !error && !report && !comparison && (
        <div className="empty-state">
          <p>No report selected. Upload a mobile app package or open a stored scan.</p>
        </div>
      )}

      {report && (
        <section className="report-section">
          <div className="section-heading">
            <div>
              <h2>Scan Detail</h2>
              <p>
                {activeScan
                  ? `${activeScan.project_name} / ${activeScan.app_name} / ${versionLabel(activeScan)}`
                  : "Latest uploaded scan"}
              </p>
            </div>
            {activeScan && <span className="scan-id">Scan ID: {activeScan.id}</span>}
          </div>

          <div className="detail-grid">
            <div className="score-panel">
              <span>Overall score</span>
              <strong>{report.score}</strong>
              <p>Risk level: {report.risk_level.toUpperCase()}</p>
            </div>
            <div className={`policy-status policy-${report.policy?.decision ?? "warn"}`}>
              <span>Policy result</span>
              <strong>{report.policy?.decision.toUpperCase() ?? "NOT EVALUATED"}</strong>
              <p>
                {report.policy
                  ? `Minimum score ${report.policy.min_score}`
                  : "No policy evaluation is attached to this report."}
              </p>
            </div>
            <div className="report-overview">
              <p>
                <strong>Platform:</strong> {report.platform}
              </p>
              <p>
                <strong>File name:</strong> {report.file_name}
              </p>
              <p>
                <strong>Generated:</strong> {formatDate(report.metadata.generated_at)}
              </p>
              <p>
                <strong>Analyzer:</strong> {report.metadata.analyzer_version}
              </p>
            </div>
          </div>

          {report.policy && (
            <section className={`policy-panel policy-${report.policy.decision}`}>
              <h3>Policy Gate</h3>
              <p>
                Decision: <strong>{report.policy.decision.toUpperCase()}</strong> | Minimum score: {report.policy.min_score}
              </p>
              <div className="policy-rules">
                {report.policy.rules.map((rule) => (
                  <article key={rule.id} className="policy-rule">
                    <strong>{rule.status.toUpperCase()}</strong>
                    <p>{rule.name}</p>
                    <p>{rule.message}</p>
                    {rule.finding_ids.length > 0 && <p>Findings: {rule.finding_ids.join(", ")}</p>}
                  </article>
                ))}
              </div>
              <p className="policy-note">
                Policy gates are release signals based on static scan output, not complete security guarantees.
              </p>
            </section>
          )}

          <h3>Findings Summary</h3>
          <div className="findings-summary">
            <SummaryTile label="Total" value={reportSummary.total_findings} />
            <SummaryTile label="Critical" value={reportSummary.by_severity.critical} />
            <SummaryTile label="High" value={reportSummary.by_severity.high} />
            <SummaryTile label="Medium" value={reportSummary.by_severity.medium} />
            <SummaryTile label="Low" value={reportSummary.by_severity.low} />
          </div>

          <h3>Findings by severity</h3>
          {findingsBySeverity.length === 0 ? (
            <p className="empty-state">No findings were reported for this scan.</p>
          ) : (
            findingsBySeverity.map((group) => (
              <div key={group.severity} className="severity-group">
                <h4>{group.severity.toUpperCase()}</h4>
                {group.findings.map((finding) => (
                  <FindingCard key={`${finding.id}-${finding.source}`} finding={finding} />
                ))}
              </div>
            ))
          )}
        </section>
      )}
    </main>
  );
}

function formatDate(value: string | null): string {
  if (!value) {
    return "Pending";
  }

  return new Intl.DateTimeFormat("en", {
    dateStyle: "medium",
    timeStyle: "short",
  }).format(new Date(value));
}

function summaryForReport(report: ReportResponse) {
  const summary = report.summary ?? EMPTY_SUMMARY;
  const bySeverity = {
    low: summary.by_severity?.low ?? 0,
    medium: summary.by_severity?.medium ?? 0,
    high: summary.by_severity?.high ?? 0,
    critical: summary.by_severity?.critical ?? 0,
  };

  if (report.summary) {
    return {
      total_findings:
        summary.total_findings ??
        bySeverity.low + bySeverity.medium + bySeverity.high + bySeverity.critical,
      by_severity: bySeverity,
    };
  }

  for (const finding of report.findings ?? []) {
    bySeverity[finding.severity] += 1;
  }

  return {
    total_findings: bySeverity.low + bySeverity.medium + bySeverity.high + bySeverity.critical,
    by_severity: bySeverity,
  };
}

function SummaryTile({ label, value }: { label: string; value: number }) {
  return (
    <div className="summary-tile">
      <strong>{value}</strong>
      <span>{label}</span>
    </div>
  );
}

function MetricPill({
  label,
  value,
  tone,
}: {
  label: string;
  value: string;
  tone?: Severity;
}) {
  return (
    <span className={`metric-pill${tone ? ` severity-${tone}` : ""}`}>
      <span>{label}</span>
      <strong>{value}</strong>
    </span>
  );
}

function FindingCard({ finding, compact = false }: { finding: Finding; compact?: boolean }) {
  const category = finding.category ?? "uncategorized";
  const source = finding.source ?? "historical/unknown-source";
  const description = finding.description ?? "No description was stored for this historical finding.";
  const recommendation = finding.recommendation ?? "Review the finding with the original scan context.";

  return (
    <article className={`finding-card${compact ? " compact-finding-card" : ""}`}>
      <div className="finding-title-row">
        <p>
          <strong>{finding.id}</strong> - {finding.title}
        </p>
        <span className={`severity-badge severity-${finding.severity}`}>{finding.severity}</span>
      </div>
      <p>
        Category: {category} | Source: {source}
      </p>
      {!compact && (
        <>
          <p>{description}</p>
          <p>
            <strong>Recommendation:</strong> {recommendation}
          </p>
        </>
      )}
    </article>
  );
}

function ComparisonFindingGroup({
  title,
  children,
  emptyMessage,
}: {
  title: string;
  children: ReactNode;
  emptyMessage: string;
}) {
  const hasChildren = Array.isArray(children) ? children.length > 0 : Boolean(children);

  return (
    <div className="comparison-group">
      <h3>{title}</h3>
      {hasChildren ? children : <p className="inline-empty-state">{emptyMessage}</p>}
    </div>
  );
}
