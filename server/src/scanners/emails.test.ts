import { describe, expect, it } from "vitest";
import { emailsFromTxt, enumerateEmails, extractEmails, extractFromHtml, soaRnameToEmail } from "./emails.ts";

describe("email discovery", () => {
  it("keeps in-scope addresses and drops file-extension false positives", () => {
    expect(extractEmails("Contact us@crewai.com and other@gmail.com and ops@app.crewai.com", "crewai.com")).toEqual([
      "us@crewai.com",
      "ops@app.crewai.com",
    ]);
    expect(extractEmails("background-image: url(icon@2x.png)", "crewai.com")).toEqual([]);
  });

  it("still parses mailto and json-ld on pages fingerprinting already fetched", () => {
    const html = `
      <a href="mailto:security@crewai.com">mail</a>
      <script type="application/ld+json">{"email":"press@crewai.com"}</script>
      support@crewai.com
    `;
    expect(extractFromHtml(html, "crewai.com")).toEqual([
      { address: "press@crewai.com", source: "json-ld" },
      { address: "security@crewai.com", source: "mailto" },
      { address: "support@crewai.com", source: "html" },
    ]);
  });

  it("converts public DNS records into emails", () => {
    expect(soaRnameToEmail("hostmaster.crewai.com.", "crewai.com")).toBe("hostmaster@crewai.com");
    expect(emailsFromTxt([["v=DMARC1; rua=mailto:dmarc@crewai.com"]], "crewai.com")).toEqual(["dmarc@crewai.com"]);
  });

  it("enumerates OSINT sources and does not crawl first-party contact pages", async () => {
    const requested: string[] = [];
    const fetchImpl: typeof fetch = async (input) => {
      const url = String(input);
      requested.push(url);
      if (url.includes("hunter.io")) {
        return new Response(JSON.stringify({ data: { emails: [{ value: "jane@crewai.com" }, { value: "other@gmail.com" }] } }), { status: 200 });
      }
      if (url.includes("api.github.com/search/commits")) {
        return new Response(JSON.stringify({ items: [{ commit: { author: { email: "dev@crewai.com" } } }] }), { status: 200 });
      }
      if (url.includes("api.github.com")) {
        return new Response(JSON.stringify({ items: [] }), { status: 200 });
      }
      if (url.includes("keyserver.ubuntu.com") || url.includes("pgp.mit.edu")) {
        return new Response("uid Jane Doe <pgp@crewai.com>", { status: 200 });
      }
      if (url.includes("bing.com")) {
        return new Response("index of sales@crewai.com", { status: 200 });
      }
      if (url.includes("duckduckgo.com")) {
        return new Response("careers listing jobs@crewai.com", { status: 200 });
      }
      if (url.includes("skymem.info")) {
        return new Response("skymem result media@crewai.com", { status: 200 });
      }
      if (url.includes("urlscan.io")) {
        return new Response(JSON.stringify({ results: [{ page: { url: "https://crewai.com" } }], emails: ["osint@crewai.com"] }), { status: 200 });
      }
      if (url.includes("rdap.org")) {
        return new Response(JSON.stringify({ entities: [{ vcardArray: ["vcard", [["email", {}, "text", "admin@crewai.com"]]] }] }), { status: 200 });
      }
      return new Response("unexpected " + url, { status: 500 });
    };

    const result = await enumerateEmails("crewai.com", {
      fetchImpl,
      hunterApiKey: "test-key",
      resolveSoa: async () => ({
        nsname: "ns.crewai.com",
        hostmaster: "hostmaster.crewai.com",
        serial: 1,
        refresh: 1,
        retry: 1,
        expire: 1,
        minttl: 1,
      }),
      resolveTxt: async (name) => {
        if (String(name).startsWith("_dmarc.")) {
          return [["v=DMARC1; rua=mailto:dmarc@crewai.com"]];
        }
        return [];
      },
    });

    expect(requested.some((url) => url.includes("crewai.com/contact") || url.includes("/.well-known/security.txt"))).toBe(false);
    expect(result.emails.map((item) => `${item.source}:${item.address}`).sort()).toEqual(
      [
        "bing:sales@crewai.com",
        "dns:dmarc@crewai.com",
        "dns:hostmaster@crewai.com",
        "duckduckgo:jobs@crewai.com",
        "github:dev@crewai.com",
        "hunter:jane@crewai.com",
        "pgp:pgp@crewai.com",
        "rdap:admin@crewai.com",
        "skymem:media@crewai.com",
        "urlscan:osint@crewai.com",
      ].sort(),
    );
    expect(result.emails.some((item) => item.address.endsWith("@gmail.com") || item.source === "guessed")).toBe(false);
  });
});
