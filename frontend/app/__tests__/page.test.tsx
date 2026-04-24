import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { fireEvent, render, screen, waitFor } from "@testing-library/react";

import HomePage from "../page";
import {
  mockCompletedScanJob,
  mockFailedScanJob,
  mockPartialScanJob,
  mockQueuedScanJob,
  mockRunningScanJob,
  mockWarningScanJob,
} from "./report-fixtures";

const mockFetch = vi.fn();
global.fetch = mockFetch;

function getFileInput(): HTMLInputElement {
  return document.querySelector('input[type="file"]') as HTMLInputElement;
}

describe("HomePage", () => {
  let createObjectUrlSpy: ReturnType<typeof vi.fn>;
  let revokeObjectUrlSpy: ReturnType<typeof vi.fn>;
  let clickSpy: ReturnType<typeof vi.fn>;

  beforeEach(() => {
    vi.useRealTimers();
    mockFetch.mockReset();
    createObjectUrlSpy = vi.fn(() => "blob:mock-export");
    revokeObjectUrlSpy = vi.fn();
    clickSpy = vi.fn();

    URL.createObjectURL = createObjectUrlSpy as typeof URL.createObjectURL;
    URL.revokeObjectURL = revokeObjectUrlSpy as typeof URL.revokeObjectURL;
    HTMLAnchorElement.prototype.click = clickSpy as () => void;
  });

  afterEach(() => {
    vi.useRealTimers();
  });

  it("renders the upload form", () => {
    render(<HomePage />);
    expect(screen.getByText("Mobile AppSec Platform")).toBeDefined();
    expect(screen.getByText("Upload for Analysis")).toBeDefined();
    expect(screen.getByText(/Upload an Android/)).toBeDefined();
  });

  it("shows empty state when no report", () => {
    render(<HomePage />);
    expect(screen.getByText(/No report yet/)).toBeDefined();
  });

  it("shows error when submitting without a file", async () => {
    render(<HomePage />);
    fireEvent.click(screen.getByText("Upload for Analysis"));
    expect(screen.getByText(/Select an APK, AAB, or IPA file first/)).toBeDefined();
  });

  it("shows loading state during upload", async () => {
    let resolveFetch: (value: {
      ok: boolean;
      json: () => Promise<typeof mockCompletedScanJob>;
    }) => void = () => undefined;

    mockFetch.mockImplementation(
      () =>
        new Promise((resolve) => {
          resolveFetch = resolve as typeof resolveFetch;
        })
    );

    render(<HomePage />);

    fireEvent.change(getFileInput(), {
      target: { files: [new File(["test"], "test.apk", { type: "application/octet-stream" })] },
    });
    fireEvent.click(screen.getByText("Upload for Analysis"));

    await waitFor(() => {
      expect(screen.getByText("Scan Running...")).toBeDefined();
    });
    expect(screen.getByText("Upload started. Creating scan job...")).toBeDefined();

    resolveFetch({
      ok: true,
      json: () => Promise.resolve(mockCompletedScanJob),
    });

    await waitFor(() => {
      expect(screen.getByText("Report")).toBeDefined();
    });
  });

  it("displays score cards, top risks, and grouped findings after successful upload", async () => {
    mockFetch.mockResolvedValueOnce({
      ok: true,
      json: () => Promise.resolve(mockCompletedScanJob),
    });

    render(<HomePage />);

    fireEvent.change(getFileInput(), {
      target: { files: [new File(["test"], "test.apk", { type: "application/octet-stream" })] },
    });
    fireEvent.click(screen.getByText("Upload for Analysis"));

    await waitFor(() => {
      expect(screen.getByText("Report")).toBeDefined();
    });

    expect(screen.getByText(/Overall Score/)).toBeDefined();
    expect(screen.getByText(/Scan completed. Report is ready./)).toBeDefined();
    expect(screen.getByText(/72\/100/)).toBeDefined();
    expect(screen.getByText(/Moderate review priority/)).toBeDefined();
    expect(screen.getByText(/Top Risks/)).toBeDefined();
    expect(screen.getByText(/Findings by Severity/)).toBeDefined();
    expect(screen.getByText(/Findings by Category/)).toBeDefined();
    expect(screen.getByText(/Score is a directional indicator/i)).toBeDefined();
    expect(screen.getAllByText(/archive-string-scan/).length).toBeGreaterThan(0);
    expect(screen.getAllByText(/assets\/config.txt/).length).toBeGreaterThan(0);
    expect(
      screen.getAllByText(/hardcoded_url=https:\/\/staging.example.com/).length
    ).toBeGreaterThan(0);
    expect(screen.getAllByText("Security").length).toBeGreaterThan(0);
    expect(screen.getAllByText("Network").length).toBeGreaterThan(0);
    expect(screen.getAllByText("Metadata").length).toBeGreaterThan(0);
    expect(screen.getAllByLabelText("Confidence heuristic").length).toBeGreaterThan(0);
  });

  it("offers JSON and HTML export actions after a successful upload", async () => {
    mockFetch.mockResolvedValueOnce({
      ok: true,
      json: () => Promise.resolve(mockCompletedScanJob),
    });

    render(<HomePage />);

    fireEvent.change(getFileInput(), {
      target: { files: [new File(["test"], "test.apk", { type: "application/octet-stream" })] },
    });
    fireEvent.click(screen.getByText("Upload for Analysis"));

    await waitFor(() => {
      expect(screen.getByText("Export JSON")).toBeDefined();
    });

    fireEvent.click(screen.getByText("Export JSON"));
    fireEvent.click(screen.getByText("Export HTML"));

    expect(createObjectUrlSpy).toHaveBeenCalledTimes(2);
    expect(revokeObjectUrlSpy).toHaveBeenCalledTimes(2);
    expect(clickSpy).toHaveBeenCalledTimes(2);
  });

  it("distinguishes partial analysis from scan failure", async () => {
    mockFetch.mockResolvedValueOnce({
      ok: true,
      json: () => Promise.resolve(mockPartialScanJob),
    });

    render(<HomePage />);

    fireEvent.change(getFileInput(), {
      target: { files: [new File(["test"], "broken.apk", { type: "application/octet-stream" })] },
    });
    fireEvent.click(screen.getByText("Upload for Analysis"));

    await waitFor(() => {
      expect(screen.getByText("Report")).toBeDefined();
    });

    expect(screen.getAllByText(/Partial analysis completed/).length).toBeGreaterThan(0);
    expect(screen.getByText("Partial analysis")).toBeDefined();
    expect(screen.getByText("Analysis Diagnostics")).toBeDefined();
    expect(screen.getByText(/INVALID_ARCHIVE/)).toBeDefined();
    expect(screen.queryByRole("alert")).toBeNull();
  });

  it("surfaces warning-only completed results", async () => {
    mockFetch.mockResolvedValueOnce({
      ok: true,
      json: () => Promise.resolve(mockWarningScanJob),
    });

    render(<HomePage />);

    fireEvent.change(getFileInput(), {
      target: { files: [new File(["test"], "test.apk", { type: "application/octet-stream" })] },
    });
    fireEvent.click(screen.getByText("Upload for Analysis"));

    await waitFor(() => {
      expect(screen.getByText("Report")).toBeDefined();
    });

    expect(screen.getAllByText(/Scan completed with warnings/).length).toBeGreaterThan(0);
    expect(screen.getByText("Completed with warnings")).toBeDefined();
    expect(screen.getByText(/ANDROID-JADX-SKIPPED/)).toBeDefined();
    expect(screen.queryByRole("alert")).toBeNull();
  });

  it("polls scan status until the report is completed", async () => {
    mockFetch
      .mockResolvedValueOnce({
        ok: true,
        json: () => Promise.resolve(mockQueuedScanJob),
      })
      .mockResolvedValueOnce({
        ok: true,
        json: () => Promise.resolve(mockRunningScanJob),
      })
      .mockResolvedValueOnce({
        ok: true,
        json: () => Promise.resolve(mockCompletedScanJob),
      });

    render(<HomePage />);

    fireEvent.change(getFileInput(), {
      target: { files: [new File(["test"], "test.apk", { type: "application/octet-stream" })] },
    });
    fireEvent.click(screen.getByText("Upload for Analysis"));

    await waitFor(() => {
      expect(screen.getByText(/Upload started. Scan is queued./)).toBeDefined();
    });

    await waitFor(() => {
      expect(screen.getByText(/Scan in progress./)).toBeDefined();
    }, { timeout: 2000 });

    await waitFor(() => {
      expect(screen.getByText("Report")).toBeDefined();
    }, { timeout: 2500 });
    expect(screen.getByText(/Scan completed. Report is ready./)).toBeDefined();
  });

  it("shows failed scan status from the job result", async () => {
    mockFetch.mockResolvedValueOnce({
      ok: true,
      json: () => Promise.resolve(mockFailedScanJob),
    });

    render(<HomePage />);

    fireEvent.change(getFileInput(), {
      target: { files: [new File(["test"], "test.apk", { type: "application/octet-stream" })] },
    });
    fireEvent.click(screen.getByText("Upload for Analysis"));

    await waitFor(() => {
      expect(screen.getByText(/INVALID_ARCHIVE/)).toBeDefined();
    });

    expect(screen.getByText(/Uploaded archive is invalid/)).toBeDefined();
    expect(screen.getByText(/Failure stage: android-analyzer/)).toBeDefined();
    expect(screen.getByText(/Job ID: scan-123/)).toBeDefined();
  });

  it("handles API error response", async () => {
    mockFetch.mockResolvedValueOnce({
      ok: false,
      json: () =>
        Promise.resolve({
          error: {
            code: "INVALID_FILE_TYPE",
            message: "Only .apk, .aab, or .ipa files are supported",
          },
        }),
    });

    render(<HomePage />);

    fireEvent.change(getFileInput(), {
      target: { files: [new File(["test"], "test.apk", { type: "application/octet-stream" })] },
    });
    fireEvent.click(screen.getByText("Upload for Analysis"));

    await waitFor(() => {
      expect(screen.getByText(/INVALID_FILE_TYPE/)).toBeDefined();
    });
  });

  it("shows analyzer failure details clearly", async () => {
    mockFetch.mockResolvedValueOnce({
      ok: false,
      json: () =>
        Promise.resolve({
          error: {
            code: "ANALYSIS_FAILED",
            message: "Static analysis could not be completed safely",
            details: {
              stage: "android-analyzer",
              tool: "jadx",
              reason: "Analyzer raised an unexpected error",
            },
          },
        }),
    });

    render(<HomePage />);

    fireEvent.change(getFileInput(), {
      target: { files: [new File(["test"], "test.apk", { type: "application/octet-stream" })] },
    });
    fireEvent.click(screen.getByText("Upload for Analysis"));

    await waitFor(() => {
      expect(screen.getByText(/ANALYSIS_FAILED/)).toBeDefined();
    });

    expect(screen.getByText(/static analysis did not complete safely/i)).toBeDefined();
    expect(screen.getByText(/Failure stage: android-analyzer/)).toBeDefined();
    expect(screen.getByText(/Tool: jadx/)).toBeDefined();
    expect(screen.getByText(/Failure summary: Analyzer raised an unexpected error/)).toBeDefined();
  });
});
