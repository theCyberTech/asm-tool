import { promises as dns } from "node:dns";
import { fetchJSON, fetchText, withTimeout } from "../lib/http.ts";
import { isSubdomainOf, normalizeTarget } from "../target.ts";

export type FoundEmail = {
  address: string;
  source: string;
};

const EMAIL_RE = /[a-zA-Z0-9](?:[a-zA-Z0-9._%+-]{0,62}[a-zA-Z0-9])?@[a-zA-Z0-9](?:[a-zA-Z0-9.-]{0,251}[a-zA-Z0-9])?\.[a-zA-Z]{2,24}/g;
const MAILTO_RE = /mailto:([^\s"'<>?]+)/gi;
const JSON_LD_EMAIL_RE = /"email"\s*:\s*"([^"]+)"/gi;
const CONTACT_PAGE_RE = /contact|privacy|legal|security|about|impressum|team|support|careers/i;
const FILE_TLDS = new Set([
  "png",
  "jpg",
  "jpeg",
  "gif",
  "webp",
  "svg",
  "css",
  "js",
  "mjs",
  "cjs",
  "map",
  "json",
  "xml",
  "html",
  "htm",
  "pdf",
  "ico",
  "woff",
  "woff2",
  "ttf",
  "mp4",
  "zip",
  "gz",
  "tgz",
]);
const FIRST_PARTY_PATHS = [
  "/.well-known/security.txt",
  "/security.txt",
  "/contact",
  "/contact-us",
  "/about",
  "/about-us",
  "/privacy",
  "/privacy-policy",
  "/legal",
  "/impressum",
  "/team",
  "/support",
];

export function isInScopeEmail(email: string, domain: string): boolean {
  const normalized = normalizeEmail(email);
  if (!normalized) {
    return false;
  }
  const host = normalized.split("@")[1] ?? "";
  try {
    return isSubdomainOf(host, domain);
  } catch {
    return false;
  }
}

export function normalizeEmail(raw: string): string | null {
  const email = (decodeURIComponentSafe(raw).replace(/&amp;/g, "&").trim().toLowerCase().replace(/^mailto:/i, "").split("?")[0] ?? "").replace(
    /[>,;]+$/g,
    "",
  );
  if (!email.includes("@")) {
    return null;
  }
  const [local, host] = email.split("@");
  if (!local || !host) {
    return null;
  }
  if (local.startsWith(".") || local.endsWith(".") || local.includes("..")) {
    return null;
  }
  if (local.length > 64 || host.length > 253) {
    return null;
  }
  const tld = host.split(".").pop() ?? "";
  if (FILE_TLDS.has(tld)) {
    return null;
  }
  if (!/^[a-z0-9](?:[a-z0-9._%+-]{0,62}[a-z0-9])?$/.test(local)) {
    return null;
  }
  try {
    normalizeTarget(host);
  } catch {
    return null;
  }
  return `${local}@${host}`;
}

export function extractEmails(text: string, domain: string): string[] {
  return unique(Array.from(text.matchAll(EMAIL_RE), (match) => match[0]).filter((email) => isInScopeEmail(email, domain)).map((email) => normalizeEmail(email)!));
}

export function extractFromHtml(html: string, domain: string): FoundEmail[] {
  const found: FoundEmail[] = [];
  const decoded = decodeHtmlEntities(html);

  for (const match of decoded.matchAll(MAILTO_RE)) {
    const email = normalizeEmail(match[1] ?? "");
    if (email && isInScopeEmail(email, domain)) {
      found.push({ address: email, source: "mailto" });
    }
  }

  for (const match of decoded.matchAll(/data-cfemail="([0-9a-f]+)"/gi)) {
    const email = normalizeEmail(decodeCfEmail(match[1] ?? ""));
    if (email && isInScopeEmail(email, domain)) {
      found.push({ address: email, source: "mailto" });
    }
  }

  for (const match of decoded.matchAll(JSON_LD_EMAIL_RE)) {
    const email = normalizeEmail(match[1] ?? "");
    if (email && isInScopeEmail(email, domain)) {
      found.push({ address: email, source: "json-ld" });
    }
  }

  for (const email of extractEmails(decoded, domain)) {
    found.push({ address: email, source: "html" });
  }
  return dedupeFound(found);
}

export function parseSecurityTxt(text: string, domain: string): string[] {
  const emails: string[] = [];
  for (const line of text.split(/\r?\n/)) {
    const trimmed = line.trim();
    if (!trimmed || trimmed.startsWith("#")) {
      continue;
    }
    const match = trimmed.match(/^contact:\s*(.+)$/i);
    if (!match?.[1]) {
      continue;
    }
    const value = match[1].trim();
    if (/^mailto:/i.test(value) || value.includes("@")) {
      const email = normalizeEmail(value);
      if (email && isInScopeEmail(email, domain)) {
        emails.push(email);
      }
    }
  }
  return unique(emails);
}

export function soaRnameToEmail(rname: string, domain: string): string | null {
  const raw = rname.trim().replace(/\.$/, "").replace(/\\\./g, "\u0000");
  const dot = raw.indexOf(".");
  if (dot <= 0) {
    return null;
  }
  const local = raw.slice(0, dot).replaceAll("\u0000", ".");
  const host = raw.slice(dot + 1).replaceAll("\u0000", ".");
  const email = normalizeEmail(`${local}@${host}`);
  if (!email || !isInScopeEmail(email, domain)) {
    return null;
  }
  return email;
}

export function emailsFromTxt(records: string[][], domain: string): string[] {
  const blob = records.flat().join(" ");
  const found: string[] = [];
  for (const match of blob.matchAll(/mailto:([^\s"';]+)/gi)) {
    const email = normalizeEmail(match[1] ?? "");
    if (email && isInScopeEmail(email, domain)) {
      found.push(email);
    }
  }
  return unique(found);
}

export type EmailEnumDeps = {
  fetchImpl?: typeof fetch;
  extraUrls?: string[];
  hunterApiKey?: string;
  resolveSoa?: typeof dns.resolveSoa;
  resolveTxt?: typeof dns.resolveTxt;
};

export async function enumerateEmails(
  domain: string,
  deps: EmailEnumDeps = {},
): Promise<{ emails: FoundEmail[]; errors: string[] }> {
  const fetchImpl = deps.fetchImpl ?? fetch;
  const found: FoundEmail[] = [];
  const errors: string[] = [];
  const hunterApiKey = deps.hunterApiKey ?? process.env.ASM_HUNTER_API_KEY ?? process.env.HUNTER_API_KEY ?? "";

  const [dnsEmails, dnsErrors] = await collectDnsEmails(domain, deps);
  found.push(...dnsEmails);
  errors.push(...dnsErrors);

  const pages = firstPartyPages(domain, deps.extraUrls ?? []);
  await pool(pages, 5, async (url) => {
    try {
      const { status, body } = await withTimeout(fetchText(url, {}, fetchImpl), 10_000, url);
      if (status >= 400) {
        return;
      }
      if (/security\.txt(?:$|\?)/i.test(url)) {
        for (const email of parseSecurityTxt(body, domain)) {
          found.push({ address: email, source: "security.txt" });
        }
        return;
      }
      found.push(...extractFromHtml(body, domain));
    } catch (err) {
      errors.push(`${url}: ${err instanceof Error ? err.message : String(err)}`);
    }
  });

  if (hunterApiKey.trim()) {
    try {
      const hunter = await collectHunterEmails(domain, hunterApiKey.trim(), fetchImpl);
      found.push(...hunter);
    } catch (err) {
      errors.push(`hunter: ${err instanceof Error ? err.message : String(err)}`);
    }
  }

  try {
    found.push(...(await collectGithubEmails(domain, fetchImpl)));
  } catch (err) {
    errors.push(`github: ${err instanceof Error ? err.message : String(err)}`);
  }

  return { emails: dedupeFound(found), errors };
}

function firstPartyPages(domain: string, extraUrls: string[]): string[] {
  const hosts = unique([domain, `www.${domain}`]);
  const pages = hosts.flatMap((host) => FIRST_PARTY_PATHS.map((path) => `https://${host}${path}`));
  const extra = extraUrls
    .map((url) => url.trim())
    .filter((url) => /^https?:\/\//i.test(url))
    .filter((url) => CONTACT_PAGE_RE.test(url))
    .filter((url) => {
      try {
        return isSubdomainOf(new URL(url).hostname, domain);
      } catch {
        return false;
      }
    })
    .slice(0, 20);
  return unique([...pages, ...extra]);
}

async function collectDnsEmails(domain: string, deps: EmailEnumDeps): Promise<[FoundEmail[], string[]]> {
  const found: FoundEmail[] = [];
  const errors: string[] = [];
  const resolveSoa = deps.resolveSoa ?? dns.resolveSoa;
  const resolveTxt = deps.resolveTxt ?? dns.resolveTxt;
  try {
    const soa = await resolveSoa(domain);
    const email = soaRnameToEmail(soa.hostmaster, domain);
    if (email) {
      found.push({ address: email, source: "dns-soa" });
    }
  } catch (err) {
    errors.push(`dns-soa: ${err instanceof Error ? err.message : String(err)}`);
  }
  for (const name of unique([domain, `_dmarc.${domain}`])) {
    try {
      const txt = await resolveTxt(name);
      for (const email of emailsFromTxt(txt, domain)) {
        found.push({ address: email, source: name.startsWith("_dmarc.") ? "dmarc" : "dns-txt" });
      }
    } catch (err) {
      errors.push(`dns-txt ${name}: ${err instanceof Error ? err.message : String(err)}`);
    }
  }
  return [found, errors];
}

async function collectHunterEmails(domain: string, apiKey: string, fetchImpl: typeof fetch): Promise<FoundEmail[]> {
  const data = await fetchJSON<{ data?: { emails?: Array<{ value?: string }> } }>(
    `https://api.hunter.io/v2/domain-search?domain=${encodeURIComponent(domain)}&api_key=${encodeURIComponent(apiKey)}`,
    fetchImpl,
  );
  return unique((data.data?.emails ?? []).map((row) => row.value ?? ""))
    .filter((email) => isInScopeEmail(email, domain))
    .map((email) => ({ address: normalizeEmail(email)!, source: "hunter" }));
}

async function collectGithubEmails(domain: string, fetchImpl: typeof fetch): Promise<FoundEmail[]> {
  const url = `https://api.github.com/search/commits?q=${encodeURIComponent(`author-email:@${domain}`)}&per_page=30`;
  const { status, body } = await withTimeout(
    fetchText(
      url,
      {
        headers: {
          Accept: "application/vnd.github+json",
          "X-GitHub-Api-Version": "2022-11-28",
        },
      },
      fetchImpl,
    ),
    10_000,
    "github",
  );
  if (status === 401 || status === 403 || status === 429) {
    throw new Error(`GitHub search unavailable (${status})`);
  }
  if (status >= 400) {
    throw new Error(`status ${status}`);
  }
  const payload = JSON.parse(body) as { items?: Array<{ commit?: { author?: { email?: string }; committer?: { email?: string } } }> };
  const emails: string[] = [];
  for (const item of payload.items ?? []) {
    emails.push(item.commit?.author?.email ?? "", item.commit?.committer?.email ?? "");
  }
  return unique(emails)
    .filter((email) => isInScopeEmail(email, domain))
    .map((email) => ({ address: normalizeEmail(email)!, source: "github" }));
}

function decodeCfEmail(hex: string): string {
  const bytes = hex.match(/.{2}/g)?.map((part) => Number.parseInt(part, 16)) ?? [];
  if (bytes.length < 2) {
    return "";
  }
  const key = bytes[0] ?? 0;
  return String.fromCharCode(...bytes.slice(1).map((byte) => byte ^ key));
}

function decodeHtmlEntities(value: string): string {
  return value
    .replace(/&#x([0-9a-f]+);/gi, (_, hex: string) => String.fromCharCode(Number.parseInt(hex, 16)))
    .replace(/&#(\d+);/g, (_, dec: string) => String.fromCharCode(Number(dec)))
    .replace(/&amp;/g, "&")
    .replace(/&#64;/g, "@");
}

function decodeURIComponentSafe(value: string): string {
  try {
    return decodeURIComponent(value);
  } catch {
    return value;
  }
}

function unique(values: string[]): string[] {
  return [...new Set(values.filter(Boolean))];
}

function dedupeFound(found: FoundEmail[]): FoundEmail[] {
  const rank: Record<string, number> = {
    "security.txt": 0,
    mailto: 1,
    "json-ld": 2,
    hunter: 3,
    github: 4,
    dmarc: 5,
    "dns-soa": 6,
    "dns-txt": 7,
    html: 8,
  };
  const best = new Map<string, FoundEmail>();
  for (const item of found) {
    const current = best.get(item.address);
    if (!current || (rank[item.source] ?? 99) < (rank[current.source] ?? 99)) {
      best.set(item.address, item);
    }
  }
  return [...best.values()].sort((a, b) => a.address.localeCompare(b.address));
}

async function pool<T>(items: T[], size: number, worker: (item: T) => Promise<void>): Promise<void> {
  let index = 0;
  await Promise.all(
    Array.from({ length: Math.min(size, Math.max(items.length, 1)) }, async () => {
      while (index < items.length) {
        const current = items[index];
        index += 1;
        if (current !== undefined) {
          await worker(current);
        }
      }
    }),
  );
}
