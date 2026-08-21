import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { DatabaseSync } from "node:sqlite";
import { describe, expect, it } from "vitest";
import { openDatabase } from "./database.ts";
import { Store } from "./store.ts";

describe("store", () => {
  it("persists domains, subdomains, and overview stats", () => {
    const store = new Store(openDatabase(":memory:"));
    store.ensureDomain("crewai.com");
    store.saveSubdomains("crewai.com", ["app.crewai.com", "crewai.com"]);
    store.savePorts("app.crewai.com", [{ port: 443, service: "https" }]);
    store.saveFinding({
      templateId: "missing-hsts",
      name: "Missing HSTS",
      severity: "medium",
      description: "no hsts",
      host: "crewai.com",
    });
    store.markScanned("crewai.com");

    const stats = store.getStats();
    expect(stats.domains).toBe(1);
    expect(stats.subdomains).toBe(2);
    expect(stats.ports).toBe(1);

    const domains = store.getDomainsWithStats();
    expect(domains[0]?.domain).toBe("crewai.com");
    expect(domains[0]?.subdomain_count).toBe(2);
    expect(domains[0]?.port_count).toBe(1);
    expect(store.listSubdomains("crewai.com")).toHaveLength(2);
  });

  it("opens an existing database that still has an emails table and drops it", () => {
    const dir = mkdtempSync(join(tmpdir(), "asm-emails-"));
    const path = join(dir, "asm.db");
    try {
      const previous = new DatabaseSync(path);
      previous.exec(`
        CREATE TABLE emails (
          id INTEGER PRIMARY KEY AUTOINCREMENT,
          domain TEXT NOT NULL,
          email TEXT NOT NULL UNIQUE,
          source TEXT,
          discovered_at TEXT NOT NULL
        );
        INSERT INTO emails (domain, email, source, discovered_at)
        VALUES ('crewai.com', 'a@crewai.com', 'html', '2026-01-01T00:00:00Z');
      `);
      previous.close();

      const db = openDatabase(path);
      try {
        const leftover = db.prepare("SELECT name FROM sqlite_master WHERE type = 'table' AND name = 'emails'").get();
        expect(leftover).toBeUndefined();
        const store = new Store(db);
        expect(store.getStats().domains).toBe(0);
      } finally {
        db.close();
      }
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });
});
