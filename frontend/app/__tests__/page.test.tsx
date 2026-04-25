import { describe, it, expect, vi, beforeEach } from "vitest";
import { render, screen, fireEvent, waitFor } from "@testing-library/react";
import HomePage from "../page";

const mockFetch = vi.fn();
global.fetch = mockFetch;

const mockProject = { id: "project-1", name: "Payments", created_at: "2026-01-01T00:00:00Z" };
const mockApp = {
  id: "app-1",
  project_id: mockProject.id,
  name: "Wallet",
  platform: "android",
  created_at: "2026-01-01T00:00:00Z",
};
const mockVersion = {
  id: "version-1",
  app_id: mockApp.id,
  version_name: "1.2.3",
  build_identifier: "42",
  created_at: "2026-01-01T00:00:00Z",
};
const mockBaselineScan = {
  id: "scan-1",
  project_id: mockProject.id,
  project_name: mockProject.name,
  app_id: mockApp.id,
  app_name: mockApp.name,
  app_version_id: mockVersion.id,
  version_name: "1.2.3",
  build_identifier: "42",
  file_name: "test.apk",
  file_extension: ".apk",
  platform: "android",
  status: "completed",
  risk_level: "medium",
  score: 72,
  finding_count: 1,
  started_at: "2026-01-01T00:00:00Z",
  completed_at: "2026-01-01T00:00:00Z",
};
const mockTargetScan = {
  ...mockBaselineScan,
  id: "scan-2",
  version_name: "1.3.0",
  build_identifier: "43",
  file_name: "test-next.apk",
};

const mockReport = {
  platform: "android",
  file_name: "test.apk",
  risk_level: "medium",
  score: 72,
  summary: {
    total_findings: 1,
    by_severity: { low: 0, medium: 0, high: 1, critical: 0 },
  },
  findings: [
    {
      id: "ANDROID-001",
      title: "Test finding",
      severity: "high",
      category: "security",
      description: "A test finding",
      recommendation: "Fix it",
      source: "test",
    },
  ],
  categories: [{ name: "security", count: 1, max_severity: "high" }],
  policy: {
    decision: "warn",
    min_score: 70,
    rules: [
      {
        id: "warn-high-heuristic",
        name: "Warn on heuristic high-severity findings",
        status: "warn",
        message: "1 heuristic high-severity finding(s) require review",
        finding_ids: ["ANDROID-001"],
      },
    ],
    limitations: ["Policy decisions are not complete security guarantees."],
  },
  metadata: {
    generated_at: "2026-01-01T00:00:00Z",
    analyzer_version: "0.1.0",
    analysis_mode: "static-placeholder",
    file_extension: ".apk",
  },
};
const mockComparison = {
  baseline_scan: {
    scan_id: mockBaselineScan.id,
    app_id: mockApp.id,
    app_name: mockApp.name,
    app_version_id: mockVersion.id,
    version_name: "1.2.3",
    build_identifier: "42",
    file_name: "test.apk",
  },
  target_scan: {
    scan_id: mockTargetScan.id,
    app_id: mockApp.id,
    app_name: mockApp.name,
    app_version_id: "version-2",
    version_name: "1.3.0",
    build_identifier: "43",
    file_name: "test-next.apk",
  },
  summary: { new: 1, resolved: 0, unchanged: 1, severity_changed: 1, uncertain: 0 },
  new_findings: mockReport.findings,
  resolved_findings: [],
  unchanged_findings: mockReport.findings,
  severity_changes: [
    {
      match_key: "ANDROID-001|security|test",
      baseline_severity: "medium",
      target_severity: "high",
      baseline_finding: { ...mockReport.findings[0], severity: "medium" },
      target_finding: mockReport.findings[0],
    },
  ],
  uncertain_matches: [],
  match_strategy: "Exact matches use finding id + category + source.",
  limitations: ["Heuristic analyzer output can change."],
};

function jsonResponse(body: unknown, ok = true) {
  return Promise.resolve({
    ok,
    json: () => Promise.resolve(body),
  });
}

function mockDefaultApi(
  uploadResponse = jsonResponse(mockReport),
  scansResponse: unknown[] = [],
  comparisonResponse: unknown = mockComparison,
  scanReportResponse: unknown = mockReport
) {
  mockFetch.mockImplementation((input: RequestInfo | URL, init?: RequestInit) => {
    const url = String(input);
    const method = init?.method ?? "GET";

    if (url.endsWith("/api/v1/projects") && method === "POST") {
      return jsonResponse(mockProject);
    }
    if (url.endsWith(`/api/v1/projects/${mockProject.id}/apps`) && method === "POST") {
      return jsonResponse(mockApp);
    }
    if (url.endsWith(`/api/v1/apps/${mockApp.id}/versions`) && method === "POST") {
      return jsonResponse(mockVersion);
    }
    if (url.endsWith("/api/v1/projects")) {
      return jsonResponse([]);
    }
    if (url.includes("/api/v1/scans?")) {
      return jsonResponse(scansResponse);
    }
    if (url.includes(`/api/v1/scans/${mockTargetScan.id}/comparison`)) {
      return jsonResponse(comparisonResponse);
    }
    if (url.endsWith(`/api/v1/scans/${mockBaselineScan.id}`)) {
      return jsonResponse(scanReportResponse);
    }
    if (url.endsWith(`/api/v1/scans/${mockTargetScan.id}`)) {
      return jsonResponse(scanReportResponse);
    }
    if (url.endsWith("/api/v1/upload")) {
      return uploadResponse;
    }

    return jsonResponse([]);
  });
}

describe("HomePage", () => {
  beforeEach(() => {
    mockFetch.mockReset();
    mockDefaultApi();
  });

  it("renders the organized upload form", () => {
    render(<HomePage />);
    expect(screen.getByText("Mobile AppSec Platform")).toBeDefined();
    expect(screen.getByText("Workspace")).toBeDefined();
    expect(screen.getByText("Scan Upload")).toBeDefined();
    expect(screen.getByText("Upload for Analysis")).toBeDefined();
  });

  it("shows empty state when no report is selected", async () => {
    render(<HomePage />);
    await waitFor(() => {
      expect(screen.getByText(/No report selected/)).toBeDefined();
    });
  });

  it("shows error when submitting without a file", async () => {
    render(<HomePage />);
    const submitButton = screen.getByText("Upload for Analysis");
    fireEvent.click(submitButton);
    expect(screen.getByText(/Select an APK, AAB, or IPA file first/)).toBeDefined();
  });

  it("creates context and displays report after successful upload", async () => {
    render(<HomePage />);

    fireEvent.change(screen.getByPlaceholderText("Internal project name"), {
      target: { value: "Payments" },
    });
    fireEvent.change(screen.getByPlaceholderText("App record name"), {
      target: { value: "Wallet" },
    });
    fireEvent.change(screen.getByPlaceholderText("Version, e.g. 1.4.0"), {
      target: { value: "1.2.3" },
    });
    fireEvent.change(screen.getByPlaceholderText("Build, e.g. 1042"), {
      target: { value: "42" },
    });

    const input = document.querySelector('input[type="file"]') as HTMLInputElement;
    const file = new File(["test"], "test.apk", { type: "application/octet-stream" });
    fireEvent.change(input, { target: { files: [file] } });

    fireEvent.click(screen.getByText("Upload for Analysis"));

    await waitFor(() => {
      expect(screen.getByText("Scan Detail")).toBeDefined();
    });

    expect(screen.getByText(/test.apk/)).toBeDefined();
    expect(screen.getByText("Overall score")).toBeDefined();
    expect(screen.getByText("Policy Gate")).toBeDefined();
    expect(screen.getByText(/Decision:/)).toBeDefined();
  });

  it("handles API error response", async () => {
    mockDefaultApi(
      jsonResponse(
        {
          error: { code: "INVALID_FILE_TYPE", message: "Only .apk, .aab, or .ipa files are supported" },
        },
        false
      )
    );

    render(<HomePage />);

    fireEvent.change(screen.getByPlaceholderText("Internal project name"), {
      target: { value: "Payments" },
    });
    fireEvent.change(screen.getByPlaceholderText("App record name"), {
      target: { value: "Wallet" },
    });
    fireEvent.change(screen.getByPlaceholderText("Version, e.g. 1.4.0"), {
      target: { value: "1.2.3" },
    });

    const input = document.querySelector('input[type="file"]') as HTMLInputElement;
    const file = new File(["test"], "test.apk", { type: "application/octet-stream" });
    fireEvent.change(input, { target: { files: [file] } });

    fireEvent.click(screen.getByText("Upload for Analysis"));

    await waitFor(() => {
      expect(screen.getByText(/Only .apk, .aab, or .ipa files are supported/)).toBeDefined();
    });
  });

  it("renders comparison results for a selected baseline", async () => {
    mockDefaultApi(jsonResponse(mockReport), [mockBaselineScan, mockTargetScan]);

    render(<HomePage />);

    await waitFor(() => {
      expect(screen.getByText(/test-next.apk/)).toBeDefined();
    });

    fireEvent.change(screen.getByLabelText("Baseline scan"), {
      target: { value: mockBaselineScan.id },
    });
    fireEvent.click(screen.getAllByText("Compare")[1]);

    await waitFor(() => {
      expect(screen.getByText("Comparison")).toBeDefined();
    });

    expect(screen.getByText("Severity Changes")).toBeDefined();
    expect(screen.getByText("New Findings")).toBeDefined();
    expect(screen.getByText("Unchanged Findings")).toBeDefined();
  });

  it("opens a stored scan detail from recent scans", async () => {
    mockDefaultApi(jsonResponse(mockReport), [mockBaselineScan]);

    render(<HomePage />);

    await waitFor(() => {
      expect(screen.getByText(/test.apk/)).toBeDefined();
    });

    fireEvent.click(screen.getByText("Open"));

    await waitFor(() => {
      expect(screen.getByText("Scan Detail")).toBeDefined();
    });

    expect(screen.getByText(/Payments \/ Wallet \/ 1.2.3/)).toBeDefined();
    expect(screen.getByText(/Scan ID: scan-1/)).toBeDefined();
  });

  it("renders historical scan detail when optional policy and source are missing", async () => {
    const historicalReport = {
      ...mockReport,
      policy: null,
      summary: undefined,
      findings: [{ ...mockReport.findings[0], source: undefined }],
    };
    mockDefaultApi(jsonResponse(mockReport), [mockBaselineScan], mockComparison, historicalReport);

    render(<HomePage />);

    await waitFor(() => {
      expect(screen.getByText(/test.apk/)).toBeDefined();
    });

    fireEvent.click(screen.getByText("Open"));

    await waitFor(() => {
      expect(screen.getByText("Scan Detail")).toBeDefined();
    });

    expect(screen.getByText("NOT EVALUATED")).toBeDefined();
    expect(screen.getByText(/historical\/unknown-source/)).toBeDefined();
    expect(screen.getByText("Findings Summary")).toBeDefined();
  });

  it("renders failed scans without allowing open or compare actions", async () => {
    const failedScan = {
      ...mockBaselineScan,
      status: "failed",
      score: 0,
      finding_count: 0,
      error_code: "SCAN_ANALYSIS_FAILED",
      error_message: "analyzer crashed",
    };
    mockDefaultApi(jsonResponse(mockReport), [failedScan]);

    render(<HomePage />);

    await waitFor(() => {
      expect(screen.getByText(/SCAN_ANALYSIS_FAILED/)).toBeDefined();
    });

    expect(screen.getByText(/analyzer crashed/)).toBeDefined();
    expect((screen.getByText("Open") as HTMLButtonElement).disabled).toBe(true);
  });
});
