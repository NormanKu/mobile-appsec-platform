import { describe, expect, it } from "vitest";

import { buildHtmlExport, buildJsonExport } from "../report-export";
import { mockReport } from "./report-fixtures";

describe("report export helpers", () => {
  it("builds a full JSON export from the normalized report schema", () => {
    const exportPayload = buildJsonExport(mockReport);

    expect(exportPayload.mimeType).toBe("application/json");
    expect(exportPayload.fileName).toBe("test-android-report-2025-01-01t00-00-00z.json");
    expect(JSON.parse(exportPayload.content)).toEqual(mockReport);
  });

  it("builds a human-readable HTML export with report metadata and grouped summary data", () => {
    const exportPayload = buildHtmlExport(mockReport);

    expect(exportPayload.mimeType).toBe("text/html");
    expect(exportPayload.fileName).toBe("test-android-report-2025-01-01t00-00-00z.html");
    expect(exportPayload.content).toContain("Mobile AppSec Report Export");
    expect(exportPayload.content).toContain("Scan Timestamp:</strong> 2025-01-01T00:00:00Z");
    expect(exportPayload.content).toContain("Analysis Status:</strong> Complete");
    expect(exportPayload.content).toContain("Overall Score:</strong> 72/100");
    expect(exportPayload.content).toContain("<h3>By Severity</h3>");
    expect(exportPayload.content).toContain("<h3>By Category</h3>");
    expect(exportPayload.content).toContain("<h3>By Platform</h3>");
    expect(exportPayload.content).toContain("Top Risks");
    expect(exportPayload.content).toContain("hardcoded_url=https://staging.example.com");
  });
});
