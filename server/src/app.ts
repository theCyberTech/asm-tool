import { readFileSync } from "node:fs";
import path from "node:path";
import { Hono } from "hono";
import type { AppConfig } from "./config.ts";
import type { Store } from "./db/store.ts";
import { ACTIONS, JobRunner, type StartRunInput } from "./jobs/runner.ts";
import { normalizeTarget } from "./target.ts";

const ASSET_TITLES: Record<string, string> = {
  subdomains: "Subdomains",
  ports: "Open Ports",
  certificates: "Certificates",
  urls: "URLs",
  apis: "API Endpoints",
  emails: "Email Addresses",
  cloud: "Cloud Storage",
  findings: "Findings",
  takeovers: "Takeovers",
  technologies: "Technologies",
  dns: "DNS Records",
  vulnerabilities: "Findings",
};

type Env = {
  Variables: {
    store: Store;
    runner: JobRunner;
    config: AppConfig;
  };
};

function domainAssets(store: Store, domain: string, kind: string): unknown[] {
  switch (kind) {
    case "subdomains":
      return store.listSubdomains(domain);
    case "ports":
      return store.listPorts(domain);
    case "certificates":
      return store.listCertificates(domain);
    case "technologies":
      return store.listTechnologies(domain);
    case "dns":
      return store.listDns(domain);
    case "vulnerabilities":
    case "findings":
      return store.listFindings(domain);
    case "urls":
      return store.listUrls(domain);
    case "apis":
      return store.listApis(domain);
    case "emails":
      return store.listEmails(domain);
    case "cloud":
      return store.listCloud(domain);
    case "takeovers":
      return store.listTakeovers(domain);
    default:
      return [];
  }
}

function globalAssets(store: Store, kind: string): unknown[] {
  switch (kind) {
    case "subdomains":
      return store.listSubdomains();
    case "ports":
      return store.listPorts();
    case "certificates":
      return store.listCertificates();
    case "urls":
      return store.listUrls();
    case "apis":
      return store.listApis();
    case "emails":
      return store.listEmails();
    case "cloud":
      return store.listCloud();
    case "findings":
      return store.listFindings();
    case "takeovers":
      return store.listTakeovers();
    default:
      return [];
  }
}

function serializeRun(run: ReturnType<Store["listRuns"]>[number]) {
  return {
    ...run,
    duration: run.finished_at
      ? `${Math.max(0, new Date(run.finished_at).getTime() - new Date(run.started_at).getTime())}ms`
      : undefined,
  };
}

function sameOrigin(c: { req: { header: (name: string) => string | undefined; url: string } }): boolean {
  const origin = c.req.header("origin");
  if (!origin) {
    return true;
  }
  try {
    return new URL(origin).host === new URL(c.req.url).host;
  } catch {
    return false;
  }
}

export function createApp(store: Store, config: AppConfig, fetchImpl: typeof fetch = fetch): Hono<Env> {
  const app = new Hono<Env>();
  const runner = new JobRunner(store, config.ports, fetchImpl);

  app.use("*", async (c, next) => {
    c.set("store", store);
    c.set("runner", runner);
    c.set("config", config);
    await next();
  });

  app.get("/health", (c) => c.json({ status: "ok" }));
  app.get("/api/health", (c) => c.json({ status: "ok" }));

  app.get("/api/stats", (c) => {
    const stats = store.getStats();
    const findings = store.getFindingCounts();
    return c.json({
      status: "ok",
      ...stats,
      findings_total: findings.total,
      critical: findings.critical,
      high: findings.high,
      medium: findings.medium,
      low: findings.low,
      info: findings.info,
    });
  });

  app.get("/api/overview", (c) => {
    return c.json({
      status: "ok",
      stats: store.getStats(),
      findings: store.getFindingCounts(),
      domains: store.getDomainsWithStats(),
      change_events: store.getChangeEvents(undefined, 15).map((event) => ({
        domain: event.domain,
        change_type: event.change_type,
        severity: event.severity,
        description: event.description,
        old_value: event.old_value,
        new_value: event.new_value,
        timestamp: event.timestamp,
      })),
    });
  });

  app.get("/api/domains", (c) => {
    const q = (c.req.query("q") ?? "").trim().toLowerCase();
    let domains = store.getDomainsWithStats();
    if (q) {
      domains = domains.filter((item) => item.domain.toLowerCase().includes(q));
    }
    return c.json({ status: "ok", domains, count: domains.length });
  });

  app.get("/api/domains/:name", (c) => {
    let domain: string;
    try {
      domain = normalizeTarget(c.req.param("name"));
    } catch {
      return c.json({ status: "error", message: "invalid domain" }, 404);
    }
    const row = store.getDomain(domain);
    if (!row) {
      return c.json({ status: "error", message: "domain not found" }, 404);
    }
    return c.json({
      status: "ok",
      domain: row.domain,
      added_at: row.added_at,
      last_scanned: row.last_scanned,
      stats: store.domainDetailStats(domain),
      subdomains: store.listSubdomains(domain),
      ports: store.listPorts(domain),
      certificates: store.listCertificates(domain),
      technologies: store.listTechnologies(domain),
      dns_records: store.listDns(domain),
      findings: store.listFindings(domain),
      urls: store.listUrls(domain),
      apis: store.listApis(domain),
      emails: store.listEmails(domain),
      cloud_storage: store.listCloud(domain),
      takeovers: store.listTakeovers(domain),
      change_events: store.getChangeEvents(domain, 20),
    });
  });

  app.get("/api/domains/:name/assets/:kind", (c) => {
    let domain: string;
    try {
      domain = normalizeTarget(c.req.param("name"));
    } catch {
      return c.json({ status: "error", message: "invalid domain" }, 404);
    }
    const kind = c.req.param("kind");
    const title = ASSET_TITLES[kind];
    if (!title || !store.getDomain(domain)) {
      return c.json({ status: "error", message: "not found" }, 404);
    }
    const items = domainAssets(store, domain, kind);
    return c.json({ status: "ok", kind, title, count: items.length, items });
  });

  app.get("/api/assets/:kind", (c) => {
    const kind = c.req.param("kind");
    const title = ASSET_TITLES[kind];
    if (!title || kind === "technologies" || kind === "dns" || kind === "vulnerabilities") {
      if (kind !== "findings") {
        return c.json({ status: "error", message: "unknown asset kind" }, 404);
      }
    }
    const items = globalAssets(store, kind);
    return c.json({ status: "ok", kind, title: title ?? "Findings", count: items.length, items });
  });

  app.get("/api/operations", (c) => {
    if (config.token && c.req.header("x-asm-token") !== config.token) {
      // Still return the shell so the UI can prompt for a token; hide run history.
      return c.json({
        status: "ok",
        enabled: true,
        actions: ACTIONS,
        runs: [],
        running_count: 0,
        binary_path: "typescript-backend",
        config_path: "",
        database_path: config.databasePath,
        log_path: "",
      });
    }
    const runs = store.listRuns().map(serializeRun);
    return c.json({
      status: "ok",
      enabled: true,
      actions: ACTIONS,
      runs,
      running_count: store.runningCount(),
      binary_path: "typescript-backend",
      config_path: "",
      database_path: config.databasePath,
      log_path: "",
    });
  });

  app.get("/api/runs", (c) => {
    if (config.token && c.req.header("x-asm-token") !== config.token) {
      return c.json({ status: "error", message: "unauthorized" }, 401);
    }
    return c.json({ status: "ok", runs: store.listRuns().map(serializeRun) });
  });

  app.post("/api/runs/start", async (c) => {
    if (config.token && c.req.header("x-asm-token") !== config.token) {
      return c.json({ status: "error", message: "unauthorized" }, 401);
    }
    if (config.token && !sameOrigin(c) && c.req.header("x-asm-token") !== config.token) {
      return c.json({ status: "error", message: "csrf check failed" }, 403);
    }
    let body: StartRunInput;
    try {
      body = (await c.req.json()) as StartRunInput;
    } catch {
      return c.json({ status: "error", message: "invalid json" }, 400);
    }
    try {
      const run = runner.start(body);
      return c.json({ status: "ok", run: serializeRun(run) });
    } catch (err) {
      return c.json({ status: "error", message: err instanceof Error ? err.message : String(err) }, 400);
    }
  });

  app.get("/*", (c) => {
    const dist = config.webDistDir;
    const urlPath = new URL(c.req.url).pathname;
    const filePath = path.join(dist, urlPath === "/" ? "index.html" : urlPath);
    try {
      const data = readFileSync(filePath);
      const ext = path.extname(filePath);
      const types: Record<string, string> = {
        ".html": "text/html; charset=utf-8",
        ".js": "text/javascript; charset=utf-8",
        ".css": "text/css; charset=utf-8",
        ".svg": "image/svg+xml",
        ".json": "application/json",
      };
        return c.newResponse(data, 200, { "Content-Type": types[ext] ?? "application/octet-stream" });
      } catch {
        try {
          const index = readFileSync(path.join(dist, "index.html"));
          return c.newResponse(index, 200, { "Content-Type": "text/html; charset=utf-8" });
      } catch {
        return c.json({ status: "error", message: "frontend build missing; run npm run build -w web" }, 503);
      }
    }
  });

  return app;
}
