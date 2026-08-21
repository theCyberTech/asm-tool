import { describe, expect, it } from "vitest";
import {
  emailsFromTxt,
  enumerateEmails,
  extractEmails,
  extractFromHtml,
  parseSecurityTxt,
  soaRnameToEmail,
} from "./emails.ts";

describe("email discovery", () => {
  it("keeps in-scope addresses and drops file-extension false positives", () => {
    expect(extractEmails("Contact us@crewai.com and other@gmail.com and ops@app.crewai.com", "crewai.com")).toEqual([
      "us@crewai.com",
      "ops@app.crewai.com",
    ]);
    expect(extractEmails("background-image: url(icon@2x.png)", "crewai.com")).toEqual([]);
  });

  it("prefers mailto and json-ld over raw html matches", () => {
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

  it("decodes Cloudflare cfemail obfuscation", () => {
    // security@crewai.com encoded with key 0x0a
    const encoded = encodeCfEmail("security@crewai.com", 0x0a);
    const html = `<a href="/cdn-cgi/l/email-protection" data-cfemail="${encoded}">email</a>`;
    expect(extractFromHtml(html, "crewai.com")).toEqual([{ address: "security@crewai.com", source: "mailto" }]);
  });

  it("parses security.txt contact mailtos", () => {
    expect(
      parseSecurityTxt(
        ["# comment", "Contact: mailto:security@crewai.com", "Contact: https://crewai.com/security", "Encryption: https://crewai.com/pgp"].join("\n"),
        "crewai.com",
      ),
    ).toEqual(["security@crewai.com"]);
  });

  it("converts SOA rname and DMARC rua into emails", () => {
    expect(soaRnameToEmail("hostmaster.crewai.com.", "crewai.com")).toBe("hostmaster@crewai.com");
    expect(emailsFromTxt([["v=DMARC1; rua=mailto:dmarc@crewai.com"]], "crewai.com")).toEqual(["dmarc@crewai.com"]);
  });

  it("enumerates first-party pages, DNS, and hunter without guessing mailboxes", async () => {
    const fetchImpl: typeof fetch = async (input) => {
      const url = String(input);
      if (url.includes("hunter.io")) {
        return new Response(JSON.stringify({ data: { emails: [{ value: "jane@crewai.com" }, { value: "other@gmail.com" }] } }), { status: 200 });
      }
      if (url.includes("api.github.com")) {
        return new Response(JSON.stringify({ items: [{ commit: { author: { email: "dev@crewai.com" } } }] }), { status: 200 });
      }
      if (url.endsWith("/.well-known/security.txt")) {
        return new Response("Contact: mailto:security@crewai.com\n", { status: 200 });
      }
      if (url.endsWith("/contact")) {
        return new Response('<a href="mailto:hello@crewai.com">Hello</a>', { status: 200 });
      }
      return new Response("", { status: 404 });
    };

    const result = await enumerateEmails("crewai.com", {
      fetchImpl,
      hunterApiKey: "test-key",
      extraUrls: ["https://docs.crewai.com/privacy", "https://google.com/contact"],
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

    expect(result.emails).toEqual([
      { address: "dev@crewai.com", source: "github" },
      { address: "dmarc@crewai.com", source: "dmarc" },
      { address: "hello@crewai.com", source: "mailto" },
      { address: "hostmaster@crewai.com", source: "dns-soa" },
      { address: "jane@crewai.com", source: "hunter" },
      { address: "security@crewai.com", source: "security.txt" },
    ]);
    expect(result.emails.some((item) => item.source === "guessed" || item.address.startsWith("info@"))).toBe(false);
  });
});

function encodeCfEmail(email: string, key: number): string {
  const bytes = [key, ...[...email].map((char) => char.charCodeAt(0) ^ key)];
  return bytes.map((byte) => byte.toString(16).padStart(2, "0")).join("");
}
