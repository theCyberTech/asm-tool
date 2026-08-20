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
});
