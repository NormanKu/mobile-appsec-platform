import { describe, it, expect, vi, beforeEach } from "vitest";
import { render, screen, fireEvent, waitFor } from "@testing-library/react";
import HomePage from "../page";

// Mock fetch globally
const mockFetch = vi.fn();
global.fetch = mockFetch;

const mockReport = {
  platform: "android",
  file_name: "test.apk",
  risk_level: "medium",
  score: 72,
  summary: {
    total_findings: 3,
    by_severity: { low: 1, medium: 1, high: 1, critical: 0 },
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
  metadata: {
    generated_at: "2025-01-01T00:00:00Z",
    analyzer_version: "0.1.0",
    analysis_mode: "static-placeholder",
    file_extension: ".apk",
  },
};

function getFileInput(): HTMLInputElement {
  return document.querySelector('input[type="file"]') as HTMLInputElement;
}

describe("HomePage", () => {
  beforeEach(() => {
    mockFetch.mockReset();
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
    const submitButton = screen.getByText("Upload for Analysis");
    fireEvent.click(submitButton);
    expect(screen.getByText(/Select an APK, AAB, or IPA file first/)).toBeDefined();
  });

  it("shows loading state during upload", async () => {
    let resolveFetch: (value: {
      ok: boolean;
      json: () => Promise<typeof mockReport>;
    }) => void = () => undefined;

    mockFetch.mockImplementation(
      () =>
        new Promise((resolve) => {
          resolveFetch = resolve as typeof resolveFetch;
        })
    );

    render(<HomePage />);

    const file = new File(["test"], "test.apk", { type: "application/octet-stream" });
    fireEvent.change(getFileInput(), { target: { files: [file] } });
    fireEvent.click(screen.getByText("Upload for Analysis"));

    await waitFor(() => {
      expect(screen.getByText("Analyzing...")).toBeDefined();
    });
    expect(screen.getByText("Analysis in progress. Please wait...")).toBeDefined();

    resolveFetch({
      ok: true,
      json: () => Promise.resolve(mockReport),
    });

    await waitFor(() => {
      expect(screen.getByText("Report")).toBeDefined();
    });
  });

  it("displays report after successful upload", async () => {
    mockFetch.mockResolvedValueOnce({
      ok: true,
      json: () => Promise.resolve(mockReport),
    });

    render(<HomePage />);

    const file = new File(["test"], "test.apk", { type: "application/octet-stream" });
    fireEvent.change(getFileInput(), { target: { files: [file] } });

    const submitButton = screen.getByText("Upload for Analysis");
    fireEvent.click(submitButton);

    await waitFor(() => {
      expect(screen.getByText("Report")).toBeDefined();
    });

    expect(screen.getByText(/test.apk/)).toBeDefined();
    expect(screen.getByText(/72\/100/)).toBeDefined();
  });

  it("handles API error response", async () => {
    mockFetch.mockResolvedValueOnce({
      ok: false,
      json: () =>
        Promise.resolve({
          error: { code: "INVALID_FILE_TYPE", message: "Only .apk, .aab, or .ipa files are supported" },
        }),
    });

    render(<HomePage />);

    const file = new File(["test"], "test.apk", { type: "application/octet-stream" });
    fireEvent.change(getFileInput(), { target: { files: [file] } });

    const submitButton = screen.getByText("Upload for Analysis");
    fireEvent.click(submitButton);

    await waitFor(() => {
      expect(screen.getByText(/INVALID_FILE_TYPE/)).toBeDefined();
    });
  });
});
