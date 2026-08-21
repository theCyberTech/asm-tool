import { fetchText } from "../lib/http.ts";

const INTERESTING = /(\.git|backup|config|\.env|admin|api|swagger|graphql|wp-login|phpinfo)/i;

export type UrlRecord = {
  url: string;
  source: string;
  category: string;
  interesting: boolean;
};

export type UrlEnumResult = {
  urls: UrlRecord[];
  error?: string;
};

function categorize(url: string): string {
  if (/\/api\/|graphql|swagger|openapi/i.test(url)) return "api";
  if (/\.js(\?|$)/i.test(url)) return "js";
  if (/\.(json|ya?ml|xml|conf|env)(\?|$)/i.test(url)) return "config";
  if (/admin|login|dashboard/i.test(url)) return "admin";
  return "other";
}

export async function enumerateUrls(domain: string, fetchImpl: typeof fetch = fetch, limit = 200): Promise<UrlEnumResult> {
  const endpoint = `https://web.archive.org/cdx/search/cdx?url=${encodeURIComponent(`*.${domain}/*`)}&output=json&fl=original&collapse=urlkey&limit=${limit}`;
  const { status, body } = await fetchText(endpoint, { headers: { Accept: "application/json" } }, fetchImpl);
  if (status >= 400) {
    return { urls: [], error: `wayback CDX ${status}` };
  }
  let data: unknown;
  try {
    data = JSON.parse(body) as unknown;
  } catch {
    return { urls: [], error: "wayback CDX returned invalid JSON" };
  }
  const rows = Array.isArray(data) ? data.slice(1) : [];
  const seen = new Set<string>();
  const urls: UrlRecord[] = [];
  for (const row of rows) {
    const url = Array.isArray(row) ? String(row[0] ?? "") : "";
    if (!url || seen.has(url)) {
      continue;
    }
    seen.add(url);
    urls.push({
      url,
      source: "wayback",
      category: categorize(url),
      interesting: INTERESTING.test(url),
    });
  }
  return { urls };
}
