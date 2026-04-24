import {
  ConfidenceLevel,
  FindingResponse,
  ReportDiagnostic,
  ReportResponse,
  Severity,
} from "./report-types";

const SEVERITY_ORDER: Severity[] = ["critical", "high", "medium", "low"];
const CONFIDENCE_ORDER: ConfidenceLevel[] = ["confirmed", "heuristic", "informational"];
const CONFIDENCE_PREFIX = /^(Confirmed|Heuristic|Informational):\s*/i;
const EXPORT_NOTE =
  "Export generated from normalized scan results. Score is a prioritization aid, not a complete measure of application security.";

export type ReportExportPayload = {
  content: string;
  fileName: string;
  mimeType: string;
};

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

function getTopRisks(report: ReportResponse): FindingResponse[] {
  const risks = report.top_risks?.length
    ? report.top_risks
    : report.findings.slice().sort(compareFindingsByPriority).slice(0, 3);
  return risks.slice(0, 3);
}

function escapeHtml(value: string): string {
  return value
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll('"', "&quot;")
    .replaceAll("'", "&#39;");
}

function sanitizeFileName(value: string): string {
  return value
    .toLowerCase()
    .replace(/[^a-z0-9._-]+/g, "-")
    .replace(/-+/g, "-")
    .replace(/^-|-$/g, "");
}

function buildExportBaseName(report: ReportResponse): string {
  const baseName = report.file_name.replace(/\.[^.]+$/, "") || `${report.platform}-scan`;
  const timestamp = report.metadata.generated_at.replace(/[:]/g, "-");
  return sanitizeFileName(`${baseName}-${report.platform}-report-${timestamp}`);
}

function buildKeyValueRows(entries: { label: string; value: string }[]): string {
  return entries
    .map(
      (entry) =>
        `<div class="meta-card"><span class="label">${escapeHtml(entry.label)}</span><strong>${escapeHtml(
          entry.value
        )}</strong></div>`
    )
    .join("");
}

function buildSummaryList(entries: { label: string; value: string }[]): string {
  if (entries.length === 0) {
    return '<p class="empty">No summary data available.</p>';
  }

  return `<ul class="summary-list">${entries
    .map(
      (entry) =>
        `<li><span>${escapeHtml(entry.label)}</span><strong>${escapeHtml(entry.value)}</strong></li>`
    )
    .join("")}</ul>`;
}

function buildFindingCard(finding: FindingResponse): string {
  const evidence = finding.evidence ?? [];
  const confidence = getConfidenceLevel(finding);

  return `
    <article class="finding-card">
      <div class="finding-header">
        <h4>${escapeHtml(cleanFindingTitle(finding.title))}</h4>
        <span class="confidence confidence-${escapeHtml(confidence)}">${escapeHtml(
          formatLabel(confidence)
        )}</span>
      </div>
      <p class="finding-meta">
        <strong>${escapeHtml(finding.id)}</strong> · ${escapeHtml(formatLabel(finding.severity))} ·
        ${escapeHtml(formatLabel(finding.category))} · ${escapeHtml(finding.source)}
      </p>
      <p>${escapeHtml(finding.description)}</p>
      ${
        finding.source_location
          ? `<p><strong>Location:</strong> ${escapeHtml(finding.source_location)}</p>`
          : ""
      }
      ${
        finding.detection_method
          ? `<p><strong>Detection:</strong> ${escapeHtml(finding.detection_method)}</p>`
          : ""
      }
      ${
        evidence.length > 0
          ? `<div><strong>Evidence:</strong><ul>${evidence
              .map((entry) => `<li>${escapeHtml(entry)}</li>`)
              .join("")}</ul></div>`
          : ""
      }
      <p><strong>Recommendation:</strong> ${escapeHtml(finding.recommendation)}</p>
    </article>
  `;
}

function buildDiagnosticCard(diagnostic: ReportDiagnostic): string {
  const details = Object.entries(diagnostic.details ?? {})
    .filter(([, value]) => value !== null && value !== undefined && value !== "")
    .slice(0, 6);

  return `
    <article class="diagnostic-card diagnostic-${escapeHtml(diagnostic.level)}">
      <div class="finding-header">
        <h4>${escapeHtml(diagnostic.code)}</h4>
        <span class="diagnostic-badge">${escapeHtml(formatLabel(diagnostic.level))}</span>
      </div>
      <p>${escapeHtml(diagnostic.message)}</p>
      <p class="finding-meta">
        ${escapeHtml(diagnostic.stage)} · ${escapeHtml(diagnostic.source)}
        ${diagnostic.tool ? ` · ${escapeHtml(diagnostic.tool)}` : ""}
      </p>
      ${
        diagnostic.recommendation
          ? `<p><strong>Recommendation:</strong> ${escapeHtml(diagnostic.recommendation)}</p>`
          : ""
      }
      ${
        details.length > 0
          ? `<ul>${details
              .map(([key, value]) => `<li>${escapeHtml(formatLabel(key))}: ${escapeHtml(String(value))}</li>`)
              .join("")}</ul>`
          : ""
      }
    </article>
  `;
}

function buildDiagnosticsSection(report: ReportResponse): string {
  const errors = report.errors ?? [];
  const warnings = report.warnings ?? [];
  if (errors.length === 0 && warnings.length === 0) {
    return "";
  }

  return `
    <section>
      <h2>Analysis Diagnostics</h2>
      ${
        errors.length > 0
          ? `<div><h3>Errors</h3>${errors.map((diagnostic) => buildDiagnosticCard(diagnostic)).join("")}</div>`
          : ""
      }
      ${
        warnings.length > 0
          ? `<div><h3>Warnings</h3>${warnings.map((diagnostic) => buildDiagnosticCard(diagnostic)).join("")}</div>`
          : ""
      }
    </section>
  `;
}

function buildFindingsBySeverity(report: ReportResponse): string {
  const groups = SEVERITY_ORDER.map((severity) => {
    const findings = report.findings.filter((finding) => finding.severity === severity);
    if (findings.length === 0) {
      return "";
    }

    return `
      <section class="finding-group">
        <div class="section-heading">
          <h3>${escapeHtml(formatLabel(severity))}</h3>
          <span>${findings.length}</span>
        </div>
        ${findings
          .slice()
          .sort(compareFindingsByPriority)
          .map((finding) => buildFindingCard(finding))
          .join("")}
      </section>
    `;
  }).filter(Boolean);

  if (groups.length === 0) {
    return '<p class="empty">No findings detected in this report.</p>';
  }

  return groups.join("");
}

export function buildJsonExport(report: ReportResponse): ReportExportPayload {
  return {
    content: `${JSON.stringify(report, null, 2)}\n`,
    fileName: `${buildExportBaseName(report)}.json`,
    mimeType: "application/json",
  };
}

export function buildHtmlExport(report: ReportResponse): ReportExportPayload {
  const topRisks = getTopRisks(report);
  const warnings = report.warnings ?? [];
  const errors = report.errors ?? [];
  const severitySummary = SEVERITY_ORDER.map((severity) => ({
    label: formatLabel(severity),
    value: String(report.summary.by_severity[severity]),
  }));
  const categorySummary = report.categories.map((category) => ({
    label: formatLabel(category.name),
    value: `${category.count} · ${formatLabel(category.max_severity)}`,
  }));
  const platformSummary = Object.entries(report.summary.by_platform ?? {})
    .filter((entry): entry is [string, number] => typeof entry[1] === "number" && entry[1] > 0)
    .map(([platform, count]) => ({
      label: formatLabel(platform),
      value: String(count),
    }));

  return {
    fileName: `${buildExportBaseName(report)}.html`,
    mimeType: "text/html",
    content: `<!doctype html>
<html lang="en">
  <head>
    <meta charset="utf-8" />
    <meta name="viewport" content="width=device-width, initial-scale=1" />
    <title>Mobile AppSec Report Export</title>
    <style>
      :root {
        color-scheme: light;
        font-family: Inter, Arial, sans-serif;
      }
      body {
        margin: 0;
        background: #f8fafc;
        color: #0f172a;
      }
      main {
        max-width: 960px;
        margin: 0 auto;
        padding: 32px 20px 48px;
      }
      h1, h2, h3, h4, p {
        margin-top: 0;
      }
      .hero {
        margin-bottom: 24px;
        padding: 24px;
        border-radius: 18px;
        background: linear-gradient(145deg, #1d4ed8, #1e3a8a);
        color: #ffffff;
      }
      .hero p:last-child {
        margin-bottom: 0;
      }
      .meta-grid {
        display: grid;
        grid-template-columns: repeat(auto-fit, minmax(180px, 1fr));
        gap: 12px;
        margin: 24px 0;
      }
      .meta-card, .finding-card, .panel {
        border: 1px solid #dbeafe;
        border-radius: 14px;
        background: #ffffff;
      }
      .meta-card {
        padding: 14px 16px;
      }
      .meta-card .label {
        display: block;
        margin-bottom: 6px;
        font-size: 12px;
        font-weight: 700;
        letter-spacing: 0.04em;
        text-transform: uppercase;
        color: #475569;
      }
      .panels {
        display: grid;
        grid-template-columns: repeat(auto-fit, minmax(220px, 1fr));
        gap: 16px;
        margin-bottom: 24px;
      }
      .panel {
        padding: 18px;
      }
      .summary-list, .finding-card ul {
        margin: 0;
        padding-left: 18px;
      }
      .summary-list li, .finding-card li {
        margin-bottom: 8px;
      }
      .top-risk-grid {
        display: grid;
        grid-template-columns: repeat(auto-fit, minmax(260px, 1fr));
        gap: 16px;
        margin-bottom: 24px;
      }
      .finding-group {
        margin-bottom: 24px;
      }
      .finding-card {
        margin-bottom: 14px;
        padding: 18px;
      }
      .finding-header, .section-heading {
        display: flex;
        justify-content: space-between;
        gap: 12px;
        align-items: flex-start;
      }
      .finding-header h4 {
        margin-bottom: 8px;
      }
      .finding-meta, .empty, .note {
        color: #475569;
      }
      .confidence {
        display: inline-flex;
        border-radius: 999px;
        padding: 4px 10px;
        font-size: 12px;
        font-weight: 700;
        white-space: nowrap;
      }
      .confidence-confirmed {
        background: #dcfce7;
        color: #166534;
      }
      .confidence-heuristic {
        background: #fef3c7;
        color: #92400e;
      }
      .confidence-informational {
        background: #dbeafe;
        color: #1d4ed8;
      }
      .diagnostic-card {
        margin-bottom: 14px;
        padding: 18px;
        border: 1px solid #e2e8f0;
        border-radius: 14px;
        background: #ffffff;
      }
      .diagnostic-error {
        border-color: #fecaca;
        background: #fff7f7;
      }
      .diagnostic-warning {
        border-color: #fde68a;
        background: #fffbeb;
      }
      .diagnostic-badge {
        display: inline-flex;
        border-radius: 999px;
        padding: 4px 10px;
        background: #f1f5f9;
        color: #334155;
        font-size: 12px;
        font-weight: 700;
      }
      @media (max-width: 640px) {
        main {
          padding: 20px 14px 32px;
        }
        .finding-header, .section-heading {
          flex-direction: column;
        }
      }
    </style>
  </head>
  <body>
    <main>
      <section class="hero">
        <h1>Mobile AppSec Report Export</h1>
        <p><strong>File:</strong> ${escapeHtml(report.file_name)}</p>
        <p><strong>Platform:</strong> ${escapeHtml(formatLabel(report.platform))}</p>
        <p><strong>Scan Timestamp:</strong> ${escapeHtml(report.metadata.generated_at)}</p>
        <p><strong>Analysis Status:</strong> ${escapeHtml(formatLabel(report.analysis_status ?? "complete"))}</p>
        <p><strong>Overall Score:</strong> ${escapeHtml(String(report.score))}/100 (${escapeHtml(
          formatLabel(report.risk_level)
        )} risk level)</p>
      </section>

      <section>
        <h2>Overview</h2>
        <div class="meta-grid">
          ${buildKeyValueRows([
            { label: "Platform", value: formatLabel(report.platform) },
            { label: "File Name", value: report.file_name },
            { label: "File Extension", value: report.metadata.file_extension },
            { label: "Analyzer Version", value: report.metadata.analyzer_version },
            { label: "Analysis Mode", value: report.metadata.analysis_mode },
            { label: "Total Findings", value: String(report.summary.total_findings) },
            { label: "Analysis Status", value: formatLabel(report.analysis_status ?? "complete") },
            { label: "Warnings", value: String(warnings.length) },
            { label: "Errors", value: String(errors.length) },
          ])}
        </div>
        <p class="note">${escapeHtml(EXPORT_NOTE)}</p>
      </section>

      <section>
        <h2>Grouped Summary</h2>
        <div class="panels">
          <article class="panel">
            <h3>By Severity</h3>
            ${buildSummaryList(severitySummary)}
          </article>
          <article class="panel">
            <h3>By Category</h3>
            ${buildSummaryList(categorySummary)}
          </article>
          <article class="panel">
            <h3>By Platform</h3>
            ${buildSummaryList(platformSummary)}
          </article>
        </div>
      </section>

      ${buildDiagnosticsSection(report)}

      <section>
        <h2>Top Risks</h2>
        ${
          topRisks.length > 0
            ? `<div class="top-risk-grid">${topRisks.map((finding) => buildFindingCard(finding)).join("")}</div>`
            : '<p class="empty">No prioritized risks were identified in this report.</p>'
        }
      </section>

      <section>
        <h2>Findings by Severity</h2>
        ${buildFindingsBySeverity(report)}
      </section>
    </main>
  </body>
</html>
`,
  };
}

export function downloadExport(payload: ReportExportPayload): void {
  const blob = new Blob([payload.content], {
    type: `${payload.mimeType};charset=utf-8`,
  });
  const objectUrl = URL.createObjectURL(blob);
  const link = document.createElement("a");
  link.href = objectUrl;
  link.download = payload.fileName;
  link.rel = "noopener";
  document.body.append(link);
  link.click();
  link.remove();
  URL.revokeObjectURL(objectUrl);
}
