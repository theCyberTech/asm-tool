import { describe, expect, it } from "vitest";
import { createApp } from "../app.ts";
import type { AppConfig } from "../config.ts";
import { openDatabase } from "../db/database.ts";
import { Store } from "../db/store.ts";

function testConfig(): AppConfig {
  return {
    host: "127.0.0.1",
    port: 8080,
    databasePath: ":memory:",
    webDistDir: "/tmp/asm-web-missing",
    token: "",
    ports: [80, 443],
  };
}

describe("api", () => {
  it("serves overview and domain detail from stored results", async () => {
    const store = new Store(openDatabase(":memory:"));
    store.ensureDomain("crewai.com");
    store.saveSubdomains("crewai.com", ["app.crewai.com"]);
    store.savePorts("app.crewai.com", [{ port: 443, service: "https" }]);
    const app = createApp(store, testConfig());

    const overview = await app.request("/api/overview");
    expect(overview.status).toBe(200);
    const body = (await overview.json()) as { stats: { domains: number; subdomains: number }; domains: Array<{ domain: string }> };
    expect(body.stats.domains).toBe(1);
    expect(body.stats.subdomains).toBe(1);
    expect(body.domains[0]?.domain).toBe("crewai.com");

    const detail = await app.request("/api/domains/crewai.com");
    const detailBody = (await detail.json()) as { status: string; subdomains: unknown[] };
    expect(detailBody.status).toBe("ok");
    expect(detailBody.subdomains).toHaveLength(1);
  });

  it("rejects out-of-scope scan starts", async () => {
    const store = new Store(openDatabase(":memory:"));
    const app = createApp(store, testConfig());
    const response = await app.request("/api/runs/start", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ action: "scan", target: "google.com" }),
    });
    expect(response.status).toBe(400);
    const body = (await response.json()) as { message: string };
    expect(body.message).toMatch(/restricted to crewai.com/);
  });

  it("runs an in-process discover job against mocked sources", async () => {
    const store = new Store(openDatabase(":memory:"));
    const fetchImpl: typeof fetch = async (input) => {
      const url = String(input);
      if (url.includes("certspotter")) {
        return new Response(JSON.stringify([{ dns_names: ["app.crewai.com"] }]), { status: 200 });
      }
      if (url.includes("hackertarget")) {
        return new Response("crewai.com,1.1.1.1\n", { status: 200 });
      }
      if (url.includes("crt.sh")) {
        return new Response("[]", { status: 200 });
      }
      return new Response("", { status: 404 });
    };
    const app = createApp(store, testConfig(), fetchImpl);
    const started = await app.request("/api/runs/start", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ action: "discover", target: "crewai.com" }),
    });
    expect(started.status).toBe(200);
    const payload = (await started.json()) as { run: { id: number; status: string } };
    expect(payload.run.status).toBe("running");

    const finished = await waitForRun(app, payload.run.id);
    expect(finished.status).toBe("succeeded");
    expect(store.listSubdomains("crewai.com").map((row) => row.subdomain)).toContain("app.crewai.com");
  });
});

async function waitForRun(app: ReturnType<typeof createApp>, id: number) {
  for (let attempt = 0; attempt < 40; attempt += 1) {
    const ops = await app.request("/api/operations");
    const opsBody = (await ops.json()) as { runs: Array<{ id: number; status: string; action: string }> };
    const run = opsBody.runs.find((item) => item.id === id);
    if (run && run.status !== "running") {
      return run;
    }
    await new Promise((resolve) => setTimeout(resolve, 25));
  }
  throw new Error("timed out waiting for run");
}
