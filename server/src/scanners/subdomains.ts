import { fetchJSON, fetchText } from "../lib/http.ts";
import { normalizeSubdomain } from "../target.ts";

export type SubdomainSource = {
  name: string;
  enumerate: (domain: string, fetchImpl: typeof fetch) => Promise<string[]>;
};

async function fromCertSpotter(domain: string, fetchImpl: typeof fetch): Promise<string[]> {
  const data = await fetchJSON<Array<{ dns_names?: string[] }>>(
    `https://api.certspotter.com/v1/issuances?domain=${encodeURIComponent(domain)}&include_subdomains=true&expand=dns_names`,
    fetchImpl,
  );
  return data.flatMap((item) => item.dns_names ?? []);
}

async function fromHackerTarget(domain: string, fetchImpl: typeof fetch): Promise<string[]> {
  const { status, body } = await fetchText(
    `https://api.hackertarget.com/hostsearch/?q=${encodeURIComponent(domain)}`,
    {},
    fetchImpl,
  );
  if (status >= 400 || body.toLowerCase().includes("error")) {
    throw new Error(`hackertarget status ${status}`);
  }
  return body
    .split(/\r?\n/)
    .map((line) => line.split(",")[0]?.trim() ?? "")
    .filter(Boolean);
}

async function fromCrtSh(domain: string, fetchImpl: typeof fetch): Promise<string[]> {
  const data = await fetchJSON<Array<{ name_value?: string }>>(
    `https://crt.sh/?q=${encodeURIComponent(`%.${domain}`)}&output=json`,
    fetchImpl,
  );
  return data.flatMap((row) => (row.name_value ?? "").split("\n"));
}

export const defaultSubdomainSources: SubdomainSource[] = [
  { name: "certspotter", enumerate: fromCertSpotter },
  { name: "hackertarget", enumerate: fromHackerTarget },
  { name: "crtsh", enumerate: fromCrtSh },
];

export async function enumerateSubdomains(
  domain: string,
  fetchImpl: typeof fetch = fetch,
  sources = defaultSubdomainSources,
): Promise<{ subdomains: string[]; sources: Record<string, number>; errors: string[] }> {
  const seen = new Set<string>();
  const sourceCounts: Record<string, number> = {};
  const errors: string[] = [];

  const results = await Promise.allSettled(sources.map((source) => source.enumerate(domain, fetchImpl)));
  results.forEach((result, index) => {
    const source = sources[index];
    if (!source) {
      return;
    }
    if (result.status === "rejected") {
      errors.push(`${source.name}: ${result.reason instanceof Error ? result.reason.message : String(result.reason)}`);
      sourceCounts[source.name] = 0;
      return;
    }
    let count = 0;
    for (const raw of result.value) {
      const host = normalizeSubdomain(raw, domain);
      if (host && !seen.has(host)) {
        seen.add(host);
        count += 1;
      }
    }
    sourceCounts[source.name] = count;
  });

  return { subdomains: [...seen].sort(), sources: sourceCounts, errors };
}
