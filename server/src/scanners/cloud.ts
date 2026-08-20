import { fetchText } from "../lib/http.ts";

export type CloudRecord = {
  provider: "s3" | "azure" | "gcs";
  bucketName: string;
  url: string;
  accessLevel: "listing_enabled" | "public_read" | "authenticated_only" | "not_found";
  severity: "critical" | "high" | "medium" | "low";
  evidence: string;
};

function namesFor(domain: string): string[] {
  const apex = domain.split(".").slice(-2).join("");
  const label = domain.split(".")[0] ?? domain;
  return [...new Set([label, apex, `${label}-prod`, `${label}-dev`, `${label}-assets`, `${label}-static`])];
}

export async function probeCloudBuckets(domain: string, fetchImpl: typeof fetch = fetch): Promise<CloudRecord[]> {
  const found: CloudRecord[] = [];
  for (const name of namesFor(domain)) {
    const url = `https://${name}.s3.amazonaws.com`;
    try {
      const { status, body } = await fetchText(url, {}, fetchImpl);
      if (status === 404) {
        continue;
      }
      const listing = /<ListBucketResult|<Contents>/i.test(body);
      found.push({
        provider: "s3",
        bucketName: name,
        url,
        accessLevel: listing ? "listing_enabled" : status < 400 ? "public_read" : "authenticated_only",
        severity: listing ? "critical" : status < 400 ? "high" : "low",
        evidence: `HTTP ${status}`,
      });
    } catch {
      // ignore unreachable names
    }
  }
  return found;
}
