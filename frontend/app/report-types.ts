export type Severity = "low" | "medium" | "high" | "critical";
export type ConfidenceLevel = "confirmed" | "heuristic" | "informational";
export type Platform = "android" | "ios";
export type ScanJobStatus = "queued" | "running" | "completed" | "failed";
export type AnalysisStatus = "complete" | "warning" | "partial";
export type DiagnosticLevel = "warning" | "error";

export type FindingResponse = {
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
};

export type ReportResponse = {
  platform: Platform;
  file_name: string;
  risk_level: Severity;
  score: number;
  analysis_status?: AnalysisStatus;
  summary: {
    total_findings: number;
    by_severity: { low: number; medium: number; high: number; critical: number };
    by_platform?: Partial<Record<Platform, number>>;
  };
  findings: FindingResponse[];
  categories: { name: string; count: number; max_severity: Severity }[];
  top_risks?: FindingResponse[];
  warnings?: ReportDiagnostic[];
  errors?: ReportDiagnostic[];
  metadata: {
    generated_at: string;
    analyzer_version: string;
    analysis_mode: "static-placeholder";
    file_extension: ".apk" | ".aab" | ".ipa";
  };
};

export type ReportDiagnostic = {
  level: DiagnosticLevel;
  code: string;
  message: string;
  stage: string;
  source: string;
  tool?: string | null;
  recommendation?: string | null;
  details?: Record<string, unknown>;
};

export type ScanJobResponse = {
  job_id: string;
  status: ScanJobStatus;
  platform: Platform;
  file_name: string;
  created_at: string;
  updated_at: string;
  message?: string | null;
  report?: ReportResponse | null;
  error?: {
    code: string;
    message: string;
    status_code: number;
    details?: Record<string, unknown>;
  } | null;
};
