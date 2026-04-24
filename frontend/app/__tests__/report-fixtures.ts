import { ReportResponse, ScanJobResponse } from "../report-types";

export const mockReport: ReportResponse = {
  platform: "android",
  file_name: "test.apk",
  risk_level: "high",
  score: 72,
  analysis_status: "complete",
  summary: {
    total_findings: 3,
    by_severity: { low: 1, medium: 1, high: 1, critical: 0 },
    by_platform: { android: 3, ios: 0 },
  },
  findings: [
    {
      id: "ANDROID-001",
      title: "Heuristic: Test finding",
      severity: "high",
      category: "security",
      description: "A test finding",
      recommendation: "Fix it",
      source: "test",
      confidence_level: "heuristic",
      evidence: ["hardcoded_url=https://staging.example.com"],
      detection_method: "archive-string-scan",
      source_location: "assets/config.txt",
    },
    {
      id: "ANDROID-002",
      title: "Confirmed: Cleartext traffic allowed",
      severity: "medium",
      category: "network",
      description: "Manifest allows cleartext traffic",
      recommendation: "Disable cleartext traffic",
      source: "AndroidManifest.xml",
      confidence_level: "confirmed",
      evidence: ['android:usesCleartextTraffic="true"'],
      detection_method: "manifest-inspection",
      source_location: "AndroidManifest.xml",
    },
    {
      id: "ANDROID-003",
      title: "Informational: Metadata extracted",
      severity: "low",
      category: "metadata",
      description: "Extracted package metadata",
      recommendation: "Review metadata",
      source: "archive/metadata",
      confidence_level: "informational",
      evidence: ["package_name=com.example.app"],
      detection_method: "archive-metadata-inspection",
      source_location: null,
    },
  ],
  categories: [
    { name: "security", count: 1, max_severity: "high" },
    { name: "network", count: 1, max_severity: "medium" },
    { name: "metadata", count: 1, max_severity: "low" },
  ],
  top_risks: [
    {
      id: "ANDROID-001",
      title: "Heuristic: Test finding",
      severity: "high",
      category: "security",
      description: "A test finding",
      recommendation: "Fix it",
      source: "test",
      confidence_level: "heuristic",
      evidence: ["hardcoded_url=https://staging.example.com"],
      detection_method: "archive-string-scan",
      source_location: "assets/config.txt",
    },
    {
      id: "ANDROID-002",
      title: "Confirmed: Cleartext traffic allowed",
      severity: "medium",
      category: "network",
      description: "Manifest allows cleartext traffic",
      recommendation: "Disable cleartext traffic",
      source: "AndroidManifest.xml",
      confidence_level: "confirmed",
      evidence: ['android:usesCleartextTraffic="true"'],
      detection_method: "manifest-inspection",
      source_location: "AndroidManifest.xml",
    },
  ],
  warnings: [],
  errors: [],
  metadata: {
    generated_at: "2025-01-01T00:00:00Z",
    analyzer_version: "0.1.0",
    analysis_mode: "static-placeholder",
    file_extension: ".apk",
  },
};

export const mockWarningReport: ReportResponse = {
  ...mockReport,
  analysis_status: "warning",
  warnings: [
    {
      level: "warning",
      code: "ANDROID-JADX-SKIPPED",
      message: "JADX was not available, so Android code-level enrichment was skipped",
      stage: "jadx-source-analysis",
      source: "jadx",
      tool: "jadx",
      recommendation: "Install and configure JADX to enable Android code-level heuristics",
      details: { available: false, executed: false },
    },
  ],
  errors: [],
};

export const mockPartialReport: ReportResponse = {
  ...mockReport,
  file_name: "broken.apk",
  score: 40,
  analysis_status: "partial",
  warnings: [],
  errors: [
    {
      level: "error",
      code: "INVALID_ARCHIVE",
      message: "Android manifest not found",
      stage: "manifest-inspection",
      source: "archive/manifest",
      recommendation: "Validate build output and ensure manifest is packaged",
      details: {
        file_name: "broken.apk",
        finding_id: "ANDROID-MANIFEST-404",
        reason: "Archive does not contain a supported Android manifest path",
      },
    },
  ],
};

export const mockQueuedScanJob: ScanJobResponse = {
  job_id: "scan-123",
  status: "queued",
  platform: "android",
  file_name: "test.apk",
  created_at: "2025-01-01T00:00:00Z",
  updated_at: "2025-01-01T00:00:00Z",
  message: "Scan queued",
  report: null,
  error: null,
};

export const mockRunningScanJob: ScanJobResponse = {
  ...mockQueuedScanJob,
  status: "running",
  updated_at: "2025-01-01T00:00:01Z",
  message: "Scan in progress",
};

export const mockCompletedScanJob: ScanJobResponse = {
  ...mockQueuedScanJob,
  status: "completed",
  updated_at: "2025-01-01T00:00:02Z",
  message: "Scan completed",
  report: mockReport,
};

export const mockWarningScanJob: ScanJobResponse = {
  ...mockQueuedScanJob,
  status: "completed",
  updated_at: "2025-01-01T00:00:02Z",
  message: "Scan completed with warnings",
  report: mockWarningReport,
};

export const mockPartialScanJob: ScanJobResponse = {
  ...mockQueuedScanJob,
  status: "completed",
  file_name: "broken.apk",
  updated_at: "2025-01-01T00:00:02Z",
  message: "Partial analysis completed with errors",
  report: mockPartialReport,
};

export const mockFailedScanJob: ScanJobResponse = {
  ...mockQueuedScanJob,
  status: "failed",
  updated_at: "2025-01-01T00:00:02Z",
  message: "Uploaded archive is invalid or missing required package metadata",
  error: {
    code: "INVALID_ARCHIVE",
    message: "Uploaded archive is invalid or missing required package metadata",
    status_code: 400,
    details: {
      file_name: "test.apk",
      stage: "android-analyzer",
      reason: "Missing AndroidManifest.xml",
    },
  },
};
