import { describe, expect, it } from "vitest";
import { findingsFromHeaders } from "./findings.ts";
import { enumerateSubdomains } from "./subdomains.ts";

describe("scanners", () => {
  it("flags missing security headers", () => {
    const findings = findingsFromHeaders("crewai.com", { server: "nginx" });
    expect(findings.some((item) => item.templateId === "missing-hsts")).toBe(true);
  });

  it("enumerates subdomains from injected sources", async () => {
    const fetchImpl: typeof fetch = async (input) => {
      const url = String(input);
      if (url.includes("certspotter")) {
        return new Response(JSON.stringify([{ dns_names: ["app.crewai.com", "crewai.com"] }]), { status: 200 });
      }
      if (url.includes("hackertarget")) {
        return new Response("docs.crewai.com,1.2.3.4\n", { status: 200 });
      }
      if (url.includes("crt.sh")) {
        return new Response(JSON.stringify([{ name_value: "www.crewai.com" }]), { status: 200 });
      }
      return new Response("nope", { status: 404 });
    };
    const result = await enumerateSubdomains("crewai.com", fetchImpl);
    expect(result.subdomains).toEqual(["app.crewai.com", "crewai.com", "docs.crewai.com", "www.crewai.com"]);
    expect(result.errors).toEqual([]);
  });
});
