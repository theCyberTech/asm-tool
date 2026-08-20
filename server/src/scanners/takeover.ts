import { promises as dns } from "node:dns";
import { fetchText } from "../lib/http.ts";

const FINGERPRINTS = [
  { service: "GitHub Pages", cname: "github.io", body: "There isn't a GitHub Pages site here" },
  { service: "Heroku", cname: "herokuapp.com", body: "no-such-app" },
  { service: "AWS S3", cname: "s3.amazonaws.com", body: "NoSuchBucket" },
  { service: "Shopify", cname: "myshopify.com", body: "Sorry, this shop is currently unavailable" },
  { service: "Pantheon", cname: "pantheonsite.io", body: "404 error unknown site" },
];

export type TakeoverRecord = {
  subdomain: string;
  cname: string;
  service: string;
  takeoverType: string;
  confidence: "HIGH" | "MEDIUM" | "LOW";
  evidence: string;
};

export async function checkTakeover(host: string, fetchImpl: typeof fetch = fetch): Promise<TakeoverRecord | null> {
  let cnames: string[] = [];
  try {
    cnames = await dns.resolveCname(host);
  } catch {
    return null;
  }
  const cname = cnames[0] ?? "";
  const fp = FINGERPRINTS.find((item) => cname.includes(item.cname));
  if (!fp) {
    return null;
  }
  try {
    const { body, status } = await fetchText(`https://${host}`, {}, fetchImpl);
    if (body.includes(fp.body) || status === 404) {
      return {
        subdomain: host,
        cname,
        service: fp.service,
        takeoverType: "cname",
        confidence: "HIGH",
        evidence: `CNAME ${cname} matched ${fp.service} fingerprint`,
      };
    }
  } catch {
    return {
      subdomain: host,
      cname,
      service: fp.service,
      takeoverType: "cname",
      confidence: "MEDIUM",
      evidence: `CNAME ${cname} points at ${fp.service}; HTTP check failed`,
    };
  }
  return null;
}
