"use client";

import { FormEvent, ReactNode, useEffect, useMemo, useState } from "react";
import { buildHtmlExport, buildJsonExport, downloadExport } from "./report-export";
import {
  AnalysisStatus,
  ConfidenceLevel,
  FindingResponse,
  Platform,
  ReportDiagnostic,
  ReportResponse,
  ScanJobResponse,
  ScanJobStatus,
  Severity,
} from "./report-types";

type ApiErrorResponse = {
  error: {
    code: string;
    message: string;
    details?: Record<string, unknown>;
  };
};

const SEVERITY_ORDER: Severity[] = ["critical", "high", "medium", "low"];
const CONFIDENCE_ORDER: ConfidenceLevel[] = ["confirmed", "heuristic", "informational"];
const CONFIDENCE_PREFIX = /^(Confirmed|Heuristic|Informational):\s*/i;
const SCAN_POLL_INTERVAL_MS = 750;

function getConfidenceLevel(finding: FindingResponse): ConfidenceLevel {
  if (finding.confidence_level) {
    return finding.confidence_level;
  }

  const match = finding.title.match(CONFIDENCE_PREFIX)?.[1]?.toLowerCase();
  if (match === "confirmed" || match === "heuristic" || match === "informational") {
    return match;
  }

  return "heuristic";
}

function cleanFindingTitle(title: string): string {
  return title.replace(CONFIDENCE_PREFIX, "");
}

function formatConfidenceLabel(confidence: ConfidenceLevel): string {
  return confidence.charAt(0).toUpperCase() + confidence.slice(1);
}

function formatLabel(value: string): string {
  return value
    .split(/[-_]/)
    .filter(Boolean)
    .map((part) => part.charAt(0).toUpperCase() + part.slice(1))
    .join(" ");
}

function compareFindingsByPriority(left: FindingResponse, right: FindingResponse): number {
  const severityDiff =
    SEVERITY_ORDER.indexOf(left.severity) - SEVERITY_ORDER.indexOf(right.severity);
  if (severityDiff !== 0) {
    return severityDiff;
  }

  const confidenceDiff =
    CONFIDENCE_ORDER.indexOf(getConfidenceLevel(left)) -
    CONFIDENCE_ORDER.indexOf(getConfidenceLevel(right));
  if (confidenceDiff !== 0) {
    return confidenceDiff;
  }

  return cleanFindingTitle(left.title).localeCompare(cleanFindingTitle(right.title));
}

function getScoreTone(score: number): "strong" | "moderate" | "elevated" | "severe" {
  if (score >= 85) {
    return "strong";
  }
  if (score >= 70) {
    return "moderate";
  }
  if (score >= 50) {
    return "elevated";
  }
  return "severe";
}

function getScoreLabel(score: number): string {
  if (score >= 85) {
    return "Lower apparent exposure";
  }
  if (score >= 70) {
    return "Moderate review priority";
  }
  if (score >= 50) {
    return "Elevated review priority";
  }
  return "High review priority";
}

function getScanStatusLabel(scanJob: ScanJobResponse): string {
  if (scanJob.status === "queued") {
    return "Upload started. Scan is queued.";
  }
  if (scanJob.status === "running") {
    return "Scan in progress. This page will update automatically.";
  }
  if (scanJob.status === "completed" && scanJob.report?.analysis_status === "partial") {
    return "Partial analysis completed. Review report errors before relying on results.";
  }
  if (scanJob.status === "completed" && scanJob.report?.analysis_status === "warning") {
    return "Scan completed with warnings. Review analysis diagnostics.";
  }
  if (scanJob.status === "completed") {
    return "Scan completed. Report is ready.";
  }
  return "Scan failed.";
}

function getScanStatusTone(scanJob: ScanJobResponse): ScanJobStatus | AnalysisStatus {
  if (
    scanJob.status === "completed" &&
    scanJob.report?.analysis_status &&
    scanJob.report.analysis_status !== "complete"
  ) {
    return scanJob.report.analysis_status;
  }
  return scanJob.status;
}

function getScanStatusDetail(scanJob: ScanJobResponse): string {
  const updatedAt = new Date(scanJob.updated_at).toLocaleString();
  return `Job ${scanJob.job_id} | ${formatLabel(scanJob.platform)} | Updated ${updatedAt}`;
}

function getAnalysisStatusLabel(status: AnalysisStatus | undefined): string {
  if (status === "partial") {
    return "Partial analysis";
  }
  if (status === "warning") {
    return "Completed with warnings";
  }
  return "Complete";
}

function SummaryCard(props: { title: string; value: string; detail?: string; accent?: string }) {
  return (
    <article className={`summary-card ${props.accent ?? ""}`.trim()}>
      <p className="summary-card-label">{props.title}</p>
      <p className="summary-card-value">{props.value}</p>
      {props.detail && <p className="summary-card-detail">{props.detail}</p>}
    </article>
  );
}

function FindingCard(props: { finding: FindingResponse; compact?: boolean }) {
  const confidence = getConfidenceLevel(props.finding);
  const evidence = props.finding.evidence ?? [];

  return (
    <article className={`finding-card ${props.compact ? "finding-card-compact" : ""}`.trim()}>
      <div className="finding-header">
        <p>
          <strong>{props.finding.id}</strong> — {cleanFindingTitle(props.finding.title)}
        </p>
        <span
          className={`confidence-badge confidence-${confidence}`}
          aria-label={`Confidence ${confidence}`}
        >
          {formatConfidenceLabel(confidence)}
        </span>
      </div>
      <p>
        Category: {props.finding.category} | Severity: {formatLabel(props.finding.severity)} |
        Source: {props.finding.source}
      </p>
      {props.finding.source_location && (
        <p>
          <strong>Location:</strong> {props.finding.source_location}
        </p>
      )}
      {props.finding.detection_method && (
        <p>
          <strong>Detection:</strong> {props.finding.detection_method}
        </p>
      )}
      <p>{props.finding.description}</p>
      {!props.compact && evidence.length > 0 && (
        <div>
          <strong>Evidence:</strong>
          <ul className="evidence-list">
            {evidence.map((entry) => (
              <li key={`${props.finding.id}-${entry}`}>{entry}</li>
            ))}
          </ul>
        </div>
      )}
      <p>
        <strong>Recommendation:</strong> {props.finding.recommendation}
      </p>
    </article>
  );
}

function DiagnosticCard(props: { diagnostic: ReportDiagnostic }) {
  const details = props.diagnostic.details ?? {};
  const detailEntries = Object.entries(details)
    .filter(([, value]) => value !== null && value !== undefined && value !== "")
    .slice(0, 6);

  return (
    <article className={`diagnostic-card diagnostic-${props.diagnostic.level}`}>
      <div className="diagnostic-header">
        <p>
          <strong>{props.diagnostic.code}</strong> — {props.diagnostic.message}
        </p>
        <span className={`diagnostic-badge diagnostic-badge-${props.diagnostic.level}`}>
          {formatLabel(props.diagnostic.level)}
        </span>
      </div>
      <p>
        Stage: {props.diagnostic.stage} | Source: {props.diagnostic.source}
        {props.diagnostic.tool ? ` | Tool: ${props.diagnostic.tool}` : ""}
      </p>
      {props.diagnostic.recommendation && (
        <p>
          <strong>Recommendation:</strong> {props.diagnostic.recommendation}
        </p>
      )}
      {detailEntries.length > 0 && (
        <ul className="diagnostic-details">
          {detailEntries.map(([key, value]) => (
            <li key={`${props.diagnostic.code}-${key}`}>
              {formatLabel(key)}: {String(value)}
            </li>
          ))}
        </ul>
      )}
    </article>
  );
}

function GroupSection(props: {
  title: string;
  groups: { label: string; count: number; content: ReactNode }[];
}) {
  return (
    <section className="grouped-section">
      <h3>{props.title}</h3>
      {props.groups.map((group) => (
        <div key={group.label} className="group-block">
          <div className="group-heading">
            <h4>{group.label}</h4>
            <span className="group-count">{group.count}</span>
          </div>
          {group.content}
        </div>
      ))}
    </section>
  );
}

export default function HomePage() {
  const [file, setFile] = useState<File | null>(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [errorCode, setErrorCode] = useState<string | null>(null);
  const [errorDetails, setErrorDetails] = useState<Record<string, unknown> | null>(null);
  const [report, setReport] = useState<ReportResponse | null>(null);
  const [scanJob, setScanJob] = useState<ScanJobResponse | null>(null);

  const apiBaseUrl = useMemo(
    () => process.env.NEXT_PUBLIC_API_BASE_URL ?? "http://localhost:8000",
    []
  );

  const findingsBySeverity = useMemo(() => {
    if (!report) {
      return [] as { label: string; count: number; content: ReactNode }[];
    }

    return SEVERITY_ORDER.map((severity) => {
      const findings = report.findings.filter((finding) => finding.severity === severity);
      return {
        label: formatLabel(severity),
        count: findings.length,
        content: (
          <>
            {findings.map((finding) => (
              <FindingCard key={finding.id} finding={finding} />
            ))}
          </>
        ),
      };
    }).filter((group) => group.count > 0);
  }, [report]);

  const findingsByCategory = useMemo(() => {
    if (!report) {
      return [] as { label: string; count: number; content: ReactNode }[];
    }

    const grouped = new Map<string, FindingResponse[]>();
    for (const finding of report.findings) {
      const existing = grouped.get(finding.category) ?? [];
      existing.push(finding);
      grouped.set(finding.category, existing);
    }

    return [...grouped.entries()]
      .map(([category, findings]) => ({
        label: formatLabel(category),
        count: findings.length,
        content: (
          <>
            {findings
              .slice()
              .sort(compareFindingsByPriority)
              .map((finding) => (
                <FindingCard key={finding.id} finding={finding} />
              ))}
          </>
        ),
      }))
      .sort((left, right) => right.count - left.count || left.label.localeCompare(right.label));
  }, [report]);

  const topRisks = useMemo(() => {
    if (!report) {
      return [] as FindingResponse[];
    }

    const risks = report.top_risks?.length
      ? report.top_risks
      : report.findings.slice().sort(compareFindingsByPriority).slice(0, 3);
    return risks.slice(0, 3);
  }, [report]);

  const platformSummary = useMemo(() => {
    if (!report) {
      return [] as { label: string; value: number }[];
    }

    return Object.entries(report.summary.by_platform ?? {})
      .filter((entry): entry is [Platform, number] => typeof entry[1] === "number")
      .map(([platform, count]) => ({ label: formatLabel(platform), value: count }))
      .filter((entry) => entry.value > 0);
  }, [report]);

  const reportWarnings = report?.warnings ?? [];
  const reportErrors = report?.errors ?? [];

  useEffect(() => {
    if (!scanJob || scanJob.status === "completed" || scanJob.status === "failed") {
      return;
    }

    let cancelled = false;
    const timeoutId = window.setTimeout(async () => {
      try {
        const response = await fetch(`${apiBaseUrl}/api/v1/scans/${scanJob.job_id}`);
        if (!response.ok) {
          throw new Error("Scan status could not be refreshed.");
        }

        const data = (await response.json()) as ScanJobResponse;
        if (cancelled) {
          return;
        }

        setScanJob(data);
        if (data.status === "completed") {
          if (data.report) {
            setReport(data.report);
            setLoading(false);
            return;
          }

          setErrorCode("SCAN_RESULT_MISSING");
          setError("Scan completed but did not return a report.");
          setErrorDetails({ job_id: data.job_id });
          setLoading(false);
        }

        if (data.status === "failed") {
          setErrorCode(data.error?.code ?? "SCAN_FAILED");
          setError(data.error?.message ?? "Static analysis failed.");
          setErrorDetails({ ...(data.error?.details ?? {}), job_id: data.job_id });
          setLoading(false);
        }
      } catch (statusError) {
        if (cancelled) {
          return;
        }

        const message =
          statusError instanceof Error
            ? statusError.message
            : "Scan status could not be refreshed.";
        setErrorCode("SCAN_STATUS_ERROR");
        setError(message);
        setErrorDetails({ job_id: scanJob.job_id });
        setLoading(false);
      }
    }, SCAN_POLL_INTERVAL_MS);

    return () => {
      cancelled = true;
      window.clearTimeout(timeoutId);
    };
  }, [apiBaseUrl, scanJob]);

  const onSubmit = async (event: FormEvent<HTMLFormElement>) => {
    event.preventDefault();

    if (!file) {
      setErrorCode("MISSING_FILE");
      setError("Select an APK, AAB, or IPA file first.");
      setErrorDetails(null);
      return;
    }

    const MAX_FILE_SIZE = 25 * 1024 * 1024; // 25 MB — matches backend APPSEC_MAX_UPLOAD_SIZE_BYTES
    if (file.size > MAX_FILE_SIZE) {
      setErrorCode("FILE_TOO_LARGE");
      setError(
        `File size (${(file.size / 1024 / 1024).toFixed(1)} MB) exceeds the ${
          MAX_FILE_SIZE / 1024 / 1024
        } MB limit.`
      );
      setErrorDetails(null);
      return;
    }

    setLoading(true);
    setError(null);
    setErrorCode(null);
    setErrorDetails(null);
    setReport(null);
    setScanJob(null);

    const formData = new FormData();
    formData.append("file", file);
    let keepLoadingForScan = false;

    try {
      const response = await fetch(`${apiBaseUrl}/api/v1/scans`, {
        method: "POST",
        body: formData,
      });

      if (!response.ok) {
        let apiError: ApiErrorResponse | null = null;
        try {
          apiError = (await response.json()) as ApiErrorResponse;
        } catch {
          apiError = null;
        }

        if (apiError?.error) {
          setErrorCode(apiError.error.code);
          setError(apiError.error.message);
          setErrorDetails(apiError.error.details ?? null);
          return;
        }

        throw new Error("Upload failed.");
      }

      const data = (await response.json()) as ScanJobResponse;
      setScanJob(data);
      if (data.status === "completed") {
        if (data.report) {
          setReport(data.report);
          setLoading(false);
          return;
        }

        setErrorCode("SCAN_RESULT_MISSING");
        setError("Scan completed but did not return a report.");
        setErrorDetails({ job_id: data.job_id });
        setLoading(false);
      }

      if (data.status === "failed") {
        setErrorCode(data.error?.code ?? "SCAN_FAILED");
        setError(data.error?.message ?? "Static analysis failed.");
        setErrorDetails({ ...(data.error?.details ?? {}), job_id: data.job_id });
        setLoading(false);
      }

      keepLoadingForScan = data.status === "queued" || data.status === "running";
    } catch (submitError) {
      const message =
        submitError instanceof Error ? submitError.message : "Unexpected upload error.";
      setErrorCode("UPLOAD_ERROR");
      setError(message);
      setErrorDetails(null);
    } finally {
      if (!keepLoadingForScan) {
        setLoading(false);
      }
    }
  };

  return (
    <main className="container">
      <h1>Mobile AppSec Platform</h1>
      <p>Upload an Android APK/AAB or iOS IPA to view a normalized security report.</p>

      <form onSubmit={onSubmit}>
        <input
          type="file"
          accept=".apk,.aab,.ipa"
          onChange={(event) => setFile(event.target.files?.[0] ?? null)}
        />
        <button type="submit" disabled={loading}>
          {loading ? "Scan Running..." : "Upload for Analysis"}
        </button>
      </form>

      {loading && !scanJob && (
        <p className="status">Upload started. Creating scan job...</p>
      )}

      {scanJob && !error && (
        <div className={`status scan-status scan-status-${getScanStatusTone(scanJob)}`}>
          <p>{getScanStatusLabel(scanJob)}</p>
          <p>{getScanStatusDetail(scanJob)}</p>
          {scanJob.message && <p>{scanJob.message}</p>}
        </div>
      )}

      {error && (
        <div className="error" role="alert">
          {errorCode && <p>Error code: {errorCode}</p>}
          <p>{error}</p>
          {errorCode === "ANALYSIS_FAILED" && (
            <p>
              The upload was received, but static analysis did not complete safely. Review the
              failure stage below before retrying.
            </p>
          )}
          {errorCode === "SCAN_FAILED" && (
            <p>The upload was accepted, but the scan job did not complete successfully.</p>
          )}
          {typeof errorDetails?.stage === "string" && <p>Failure stage: {errorDetails.stage}</p>}
          {typeof errorDetails?.tool === "string" && <p>Tool: {errorDetails.tool}</p>}
          {typeof errorDetails?.job_id === "string" && <p>Job ID: {errorDetails.job_id}</p>}
          {errorCode === "ANALYSIS_FAILED" && typeof errorDetails?.reason === "string" && (
            <p>Failure summary: {errorDetails.reason}</p>
          )}
        </div>
      )}

      {!loading && !error && !report && (
        <div className="empty-state">
          <p>No report yet. Upload a mobile app package to start analysis.</p>
        </div>
      )}

      {report && (
        <section className="report-section">
          <div className="report-header">
            <h2>Report</h2>
            <div className="report-actions">
              <button
                type="button"
                className="secondary-button"
                onClick={() => downloadExport(buildJsonExport(report))}
              >
                Export JSON
              </button>
              <button
                type="button"
                className="secondary-button"
                onClick={() => downloadExport(buildHtmlExport(report))}
              >
                Export HTML
              </button>
            </div>
          </div>

          <div className="score-hero">
            <div className={`score-card score-card-${getScoreTone(report.score)}`}>
              <p className="score-card-label">Overall Score</p>
              <p className="score-card-value">{report.score}/100</p>
              <p className="score-card-detail">{getScoreLabel(report.score)}</p>
            </div>

            <div className="summary-grid">
              <SummaryCard
                title="Top Risk"
                value={topRisks[0] ? cleanFindingTitle(topRisks[0].title) : "No findings"}
                detail={
                  topRisks[0]
                    ? `${formatLabel(topRisks[0].severity)} · ${formatLabel(
                        getConfidenceLevel(topRisks[0])
                      )}`
                    : "No prioritized risks to surface"
                }
              />
              <SummaryCard
                title="Platform"
                value={formatLabel(report.platform)}
                detail={`${report.file_name} · ${report.metadata.file_extension}`}
              />
              <SummaryCard
                title="Findings"
                value={String(report.summary.total_findings)}
                detail={`Risk level ${formatLabel(report.risk_level)}`}
              />
              <SummaryCard
                title="Categories"
                value={String(report.categories.length)}
                detail={`Analyzer ${report.metadata.analyzer_version}`}
              />
              <SummaryCard
                title="Analysis Status"
                value={getAnalysisStatusLabel(report.analysis_status)}
                detail={`${reportErrors.length} error(s) · ${reportWarnings.length} warning(s)`}
              />
            </div>
          </div>

          <p className="score-caveat">
            Score is a directional indicator weighted by finding severity and confidence. It helps
            prioritize review but does not represent complete application security coverage.
          </p>

          {(reportErrors.length > 0 || reportWarnings.length > 0) && (
            <section className="grouped-section diagnostics-section">
              <h3>Analysis Diagnostics</h3>
              {reportErrors.length > 0 && (
                <div className="diagnostic-group">
                  <div className="group-heading">
                    <h4>Errors</h4>
                    <span className="group-count">{reportErrors.length}</span>
                  </div>
                  {reportErrors.map((diagnostic) => (
                    <DiagnosticCard key={diagnostic.code} diagnostic={diagnostic} />
                  ))}
                </div>
              )}
              {reportWarnings.length > 0 && (
                <div className="diagnostic-group">
                  <div className="group-heading">
                    <h4>Warnings</h4>
                    <span className="group-count">{reportWarnings.length}</span>
                  </div>
                  {reportWarnings.map((diagnostic) => (
                    <DiagnosticCard key={diagnostic.code} diagnostic={diagnostic} />
                  ))}
                </div>
              )}
            </section>
          )}

          <section className="grouped-section">
            <h3>Summary Cards</h3>
            <div className="pill-grid">
              {SEVERITY_ORDER.map((severity) => (
                <div key={severity} className="summary-pill">
                  <span>{formatLabel(severity)}</span>
                  <strong>{report.summary.by_severity[severity]}</strong>
                </div>
              ))}
            </div>

            <div className="pill-grid">
              {report.categories.map((category) => (
                <div key={category.name} className="summary-pill">
                  <span>{formatLabel(category.name)}</span>
                  <strong>{category.count}</strong>
                  <small>{formatLabel(category.max_severity)}</small>
                </div>
              ))}
            </div>

            {platformSummary.length > 0 && (
              <div className="pill-grid">
                {platformSummary.map((platform) => (
                  <div key={platform.label} className="summary-pill">
                    <span>{platform.label}</span>
                    <strong>{platform.value}</strong>
                  </div>
                ))}
              </div>
            )}
          </section>

          <section className="grouped-section">
            <h3>Top Risks</h3>
            {topRisks.length > 0 ? (
              <div className="top-risks-grid">
                {topRisks.map((finding) => (
                  <FindingCard key={`top-risk-${finding.id}`} finding={finding} compact />
                ))}
              </div>
            ) : (
              <p className="empty-subsection">No findings were prioritized as top risks.</p>
            )}
          </section>

          <GroupSection title="Findings by Severity" groups={findingsBySeverity} />
          <GroupSection title="Findings by Category" groups={findingsByCategory} />
        </section>
      )}
    </main>
  );
}
