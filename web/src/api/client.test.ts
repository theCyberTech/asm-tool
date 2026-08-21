import { afterEach, describe, expect, it, vi } from "vitest";
import { ApiError, fetchDomains, fetchOverview, startRun } from "./client";

afterEach(() => {
  vi.unstubAllGlobals();
});

describe("api client", () => {
  it("fetches overview JSON", async () => {
    const payload = {
      status: "ok",
      stats: { domains: 1, subdomains: 0, ports: 0, certificates: 0, urls: 0, apis: 0, cloud_buckets: 0, takeovers: 0 },
      findings: { total: 0, critical: 0, high: 0, medium: 0, low: 0, info: 0 },
      domains: [{ id: 1, domain: "example.com", added_at: "2026-01-01T00:00:00Z", subdomain_count: 0, port_count: 0, critical_count: 0, high_count: 0 }],
      change_events: [],
    };
    vi.stubGlobal(
      "fetch",
      vi.fn().mockResolvedValue({
        ok: true,
        json: async () => payload,
      }),
    );

    const result = await fetchOverview();
    expect(result.domains[0]?.domain).toBe("example.com");
    expect(fetch).toHaveBeenCalledWith("/api/overview", {
      headers: { Accept: "application/json" },
    });
  });

  it("sends domain filters as query params", async () => {
    vi.stubGlobal(
      "fetch",
      vi.fn().mockResolvedValue({
        ok: true,
        json: async () => ({ status: "ok", domains: [], count: 0 }),
      }),
    );

    await fetchDomains({ q: "ex", from: "2026-01-01" });
    expect(fetch).toHaveBeenCalledWith("/api/domains?q=ex&from=2026-01-01", {
      headers: { Accept: "application/json" },
    });
  });

  it("raises ApiError on failure", async () => {
    vi.stubGlobal(
      "fetch",
      vi.fn().mockResolvedValue({
        ok: false,
        status: 400,
        statusText: "Bad Request",
        text: async () => JSON.stringify({ status: "error", message: "invalid from date" }),
      }),
    );

    await expect(fetchDomains({ from: "nope" })).rejects.toMatchObject({
      name: "ApiError",
      status: 400,
      message: "invalid from date",
    } satisfies Partial<ApiError>);
  });

  it("posts JSON to start a run", async () => {
    vi.stubGlobal(
      "fetch",
      vi.fn().mockResolvedValue({
        ok: true,
        json: async () => ({
          status: "ok",
          run: { id: 1, action: "status", label: "Status", status: "running" },
        }),
      }),
    );

    const run = await startRun({ action: "status" }, "secret");
    expect(run.action).toBe("status");
    expect(fetch).toHaveBeenCalledWith("/api/runs/start", {
      method: "POST",
      headers: {
        Accept: "application/json",
        "Content-Type": "application/json",
        "X-ASM-Token": "secret",
      },
      body: JSON.stringify({ action: "status" }),
    });
  });
});
