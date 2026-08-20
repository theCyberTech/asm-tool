import { describe, expect, it } from "vitest";
import { isAllowedScanTarget, normalizeScanTarget, normalizeSubdomain, normalizeTarget } from "./target.ts";

describe("target", () => {
  it("normalizes DNS names", () => {
    expect(normalizeTarget(" CrewAI.COM. ")).toBe("crewai.com");
  });

  it("allows crewai.com and subdomains for scans", () => {
    expect(normalizeScanTarget("APP.crewai.com")).toBe("app.crewai.com");
    expect(isAllowedScanTarget("crewai.com")).toBe(true);
  });

  it("rejects other scan targets", () => {
    expect(() => normalizeScanTarget("google.com")).toThrow(/restricted to crewai.com/);
    expect(isAllowedScanTarget("notcrewai.com")).toBe(false);
  });

  it("enforces subdomain label boundaries", () => {
    expect(normalizeSubdomain("api.crewai.com", "crewai.com")).toBe("api.crewai.com");
    expect(normalizeSubdomain("crewai.com.attacker.com", "crewai.com")).toBeNull();
  });
});
