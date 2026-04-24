"use client";

import { FormEvent, useMemo, useState } from "react";

type Severity = "low" | "medium" | "high" | "critical";
type ConfidenceLevel = "confirmed" | "heuristic" | "informational";

type ReportResponse = {
  platform: "android" | "ios";
  file_name: string;
  risk_level: Severity;
  score: number;
  summary: {
    total_findings: number;
    by_severity: { low: number; medium: number; high: number; critical: number };
  };
  findings: {
    id: string;
    title: string;
    severity: Severity;
    category: string;
    description: string;
    recommendation: string;
    source: string;
    confidence_level?: ConfidenceLevel;
    evidence?: string[];
    detection_method?: string | null;
    source_location?: string | null;
  }[];
  categories: { name: string; count: number; max_severity: Severity }[];
  metadata: {
    generated_at: string;
    analyzer_version: string;
    analysis_mode: "static-placeholder";
    file_extension: ".apk" | ".aab" | ".ipa";
  };
};

type ApiErrorResponse = {
  error: {
    code: string;
    message: string;
    details?: Record<string, unknown>;
  };
};

const SEVERITY_ORDER: Severity[] = ["critical", "high", "medium", "low"];
const CONFIDENCE_PREFIX = /^(Confirmed|Heuristic|Informational):\s*/i;

function getConfidenceLevel(finding: ReportResponse["findings"][number]): ConfidenceLevel {
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

export default function HomePage() {
  const [file, setFile] = useState<File | null>(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [errorCode, setErrorCode] = useState<string | null>(null);
  const [errorDetails, setErrorDetails] = useState<Record<string, unknown> | null>(null);
  const [report, setReport] = useState<ReportResponse | null>(null);

  const apiBaseUrl = useMemo(
    () => process.env.NEXT_PUBLIC_API_BASE_URL ?? "http://localhost:8000",
    []
  );

  const findingsBySeverity = useMemo(() => {
    if (!report) {
      return [] as { severity: Severity; findings: ReportResponse["findings"] }[];
    }

    return SEVERITY_ORDER.map((severity) => ({
      severity,
      findings: report.findings.filter((finding) => finding.severity === severity),
    })).filter((group) => group.findings.length > 0);
  }, [report]);

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
      setError(`File size (${(file.size / 1024 / 1024).toFixed(1)} MB) exceeds the ${MAX_FILE_SIZE / 1024 / 1024} MB limit.`);
      setErrorDetails(null);
      return;
    }

    setLoading(true);
    setError(null);
    setErrorCode(null);
    setErrorDetails(null);
    setReport(null);

    const formData = new FormData();
    formData.append("file", file);

    try {
      const response = await fetch(`${apiBaseUrl}/api/v1/upload`, {
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

      const data = (await response.json()) as ReportResponse;
      setReport(data);
    } catch (submitError) {
      const message =
        submitError instanceof Error
          ? submitError.message
          : "Unexpected upload error.";
      setErrorCode("UPLOAD_ERROR");
      setError(message);
      setErrorDetails(null);
    } finally {
      setLoading(false);
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
          {loading ? "Analyzing..." : "Upload for Analysis"}
        </button>
      </form>

      {loading && <p className="status">Analysis in progress. Please wait...</p>}

      {error && (
        <div className="error" role="alert">
          {errorCode && <p>Error code: {errorCode}</p>}
          <p>{error}</p>
          {errorCode === "ANALYSIS_FAILED" && (
            <p>
              The upload was received, but static analysis did not complete safely. Review the failure stage below before retrying.
            </p>
          )}
          {typeof errorDetails?.stage === "string" && (
            <p>Failure stage: {errorDetails.stage}</p>
          )}
          {typeof errorDetails?.tool === "string" && (
            <p>Tool: {errorDetails.tool}</p>
          )}
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
          <h2>Report</h2>

          <div className="report-overview">
            <p>
              <strong>Platform:</strong> {report.platform}
            </p>
            <p>
              <strong>File name:</strong> {report.file_name}
            </p>
            <p>
              <strong>Score:</strong> {report.score}/100
            </p>
            <p>
              <strong>Risk level:</strong> {report.risk_level.toUpperCase()}
            </p>
          </div>

          <h3>Summary</h3>
          <p>
            Total findings: {report.summary.total_findings} | Critical: {report.summary.by_severity.critical} | High: {report.summary.by_severity.high} | Medium: {report.summary.by_severity.medium} | Low: {report.summary.by_severity.low}
          </p>

          <h3>Findings by severity</h3>
          {findingsBySeverity.map((group) => (
            <div key={group.severity} className="severity-group">
              <h4>{group.severity.toUpperCase()}</h4>
              {group.findings.map((finding) => {
                const confidence = getConfidenceLevel(finding);
                const evidence = finding.evidence ?? [];

                return (
                  <article key={finding.id} className="finding-card">
                    <div className="finding-header">
                      <p>
                        <strong>{finding.id}</strong> — {cleanFindingTitle(finding.title)}
                      </p>
                      <span
                        className={`confidence-badge confidence-${confidence}`}
                        aria-label={`Confidence ${confidence}`}
                      >
                        {formatConfidenceLabel(confidence)}
                      </span>
                    </div>
                    <p>
                      Category: {finding.category} | Source: {finding.source}
                    </p>
                    {finding.source_location && (
                      <p>
                        <strong>Location:</strong> {finding.source_location}
                      </p>
                    )}
                    {finding.detection_method && (
                      <p>
                        <strong>Detection:</strong> {finding.detection_method}
                      </p>
                    )}
                    <p>{finding.description}</p>
                    {evidence.length > 0 && (
                      <div>
                        <strong>Evidence:</strong>
                        <ul className="evidence-list">
                          {evidence.map((entry) => (
                            <li key={`${finding.id}-${entry}`}>{entry}</li>
                          ))}
                        </ul>
                      </div>
                    )}
                    <p>
                      <strong>Recommendation:</strong> {finding.recommendation}
                    </p>
                  </article>
                );
              })}
            </div>
          ))}
        </section>
      )}
    </main>
  );
}
