import { promises as dns } from "node:dns";
import { fetchJSON, fetchText, withTimeout } from "../lib/http.ts";
import { isSubdomainOf, normalizeTarget } from "../target.ts";

export type FoundEmail = {
  address: string;
  source: string;
};

export type EmailEnumDeps = {
  fetchImpl?: typeof fetch;
  hunterApiKey?: string;
  githubToken?: string;
  resolveSoa?: typeof dns.resolveSoa;
  resolveTxt?: typeof dns.resolveTxt;
};

type SourceCtx = {
  domain: string;
  fetchImpl: typeof fetch;
  hunterApiKey: string;
  githubToken: string;
};

type EmailSource = {
  name: string;
  run: (ctx: SourceCtx) => Promise<string[]>;
};

const EMAIL_RE = /[a-zA-Z0-9](?:[a-zA-Z0-9._%+-]{0,62}[a-zA-Z0-9])?@[a-zA-Z0-9](?:[a-zA-Z0-9.-]{0,251}[a-zA-Z0-9])?\.[a-zA-Z]{2,24}/g;
const MAILTO_RE = /mailto:([^\s"'<>?]+)/gi;
const JSON_LD_EMAIL_RE = /"email"\s*:\s*"([^"]+)"/gi;
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
const SEARCH_UA =
  "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36";

const OSINT_SOURCES: EmailSource[] = [
  { name: "hunter", run: fromHunter },
  { name: "github", run: fromGithub },
  { name: "npm", run: fromNpm },
  { name: "pypi", run: fromPypi },
  { name: "pgp", run: fromPgp },
  { name: "bing", run: fromBing },
  { name: "duckduckgo", run: fromDuckDuckGo },
  { name: "urlscan", run: fromUrlscan },
  { name: "rdap", run: fromRdap },
  { name: "dns", run: fromPublicDns },
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
  if (!/[a-z]/i.test(local)) {
    return null;
  }
  if (!/^[a-z0-9](?:[a-z0-9._%+-]{0,62}[a-z0-9])?$/i.test(local)) {
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
  return unique(
    Array.from(text.matchAll(EMAIL_RE), (match) => match[0])
      .filter((email) => isInScopeEmail(email, domain))
      .map((email) => normalizeEmail(email)!),
  );
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

export async function enumerateEmails(
  domain: string,
  deps: EmailEnumDeps = {},
): Promise<{ emails: FoundEmail[]; errors: string[] }> {
  const ctx: SourceCtx = {
    domain,
    fetchImpl: deps.fetchImpl ?? fetch,
    hunterApiKey: deps.hunterApiKey ?? process.env.ASM_HUNTER_API_KEY ?? process.env.HUNTER_API_KEY ?? "",
    githubToken: deps.githubToken ?? process.env.ASM_GITHUB_TOKEN ?? process.env.GITHUB_TOKEN ?? "",
  };
  const dnsDeps = { resolveSoa: deps.resolveSoa, resolveTxt: deps.resolveTxt };
  const found: FoundEmail[] = [];
  const errors: string[] = [];

  const results = await Promise.all(
    OSINT_SOURCES.map(async (source) => {
      try {
        const emails =
          source.name === "dns"
            ? await fromPublicDns(ctx, dnsDeps)
            : await withTimeout(source.run(ctx), 15_000, source.name);
        return { source: source.name, emails, error: "" };
      } catch (err) {
        return {
          source: source.name,
          emails: [] as string[],
          error: `${source.name}: ${err instanceof Error ? err.message : String(err)}`,
        };
      }
    }),
  );

  for (const result of results) {
    if (result.error) {
      errors.push(result.error);
    }
    for (const email of result.emails) {
      found.push({ address: email, source: result.source });
    }
  }
  return { emails: dedupeFound(found), errors };
}

async function fromHunter(ctx: SourceCtx): Promise<string[]> {
  if (!ctx.hunterApiKey.trim()) {
    return [];
  }
  const data = await fetchJSON<{ data?: { emails?: Array<{ value?: string }> } }>(
    `https://api.hunter.io/v2/domain-search?domain=${encodeURIComponent(ctx.domain)}&api_key=${encodeURIComponent(ctx.hunterApiKey.trim())}`,
    ctx.fetchImpl,
  );
  return scoped(ctx.domain, (data.data?.emails ?? []).map((row) => row.value ?? ""));
}

async function fromGithub(ctx: SourceCtx): Promise<string[]> {
  const headers: Record<string, string> = {
    Accept: "application/vnd.github+json",
    "X-GitHub-Api-Version": "2022-11-28",
  };
  if (ctx.githubToken.trim()) {
    headers.Authorization = `Bearer ${ctx.githubToken.trim()}`;
  }
  const emails: string[] = [];
  const label = ctx.domain.split(".")[0] ?? ctx.domain;
  const candidates = unique([label, `${label}inc`, `${label}-ai`]);

  for (const candidate of candidates) {
    const repos = await githubRepos(ctx, candidate, headers);
    for (const repo of repos.slice(0, 12)) {
      const { status, body } = await fetchText(
        `https://api.github.com/repos/${repo}/commits?per_page=50`,
        { headers },
        ctx.fetchImpl,
      );
      if (status >= 400) {
        continue;
      }
      emails.push(...extractEmails(body, ctx.domain));
      try {
        const commits = JSON.parse(body) as Array<{ commit?: { author?: { email?: string }; committer?: { email?: string } } }>;
        if (Array.isArray(commits)) {
          for (const commit of commits) {
            emails.push(commit.commit?.author?.email ?? "", commit.commit?.committer?.email ?? "");
          }
        }
      } catch {
        // body was not commit JSON
      }
    }
  }

  if (ctx.githubToken.trim()) {
    const { status, body } = await fetchText(
      `https://api.github.com/search/commits?q=${encodeURIComponent(`author-email:@${ctx.domain}`)}&per_page=30`,
      { headers: { ...headers, Accept: "application/vnd.github.text-match+json" } },
      ctx.fetchImpl,
    );
    if (status < 400) {
      emails.push(...extractEmails(body, ctx.domain));
    }
  }
  return scoped(ctx.domain, emails);
}

async function githubRepos(ctx: SourceCtx, candidate: string, headers: Record<string, string>): Promise<string[]> {
  for (const path of [`orgs/${candidate}/repos?per_page=30&type=public`, `users/${candidate}/repos?per_page=30&type=public`]) {
    const { status, body } = await fetchText(`https://api.github.com/${path}`, { headers }, ctx.fetchImpl);
    if (status === 404) {
      continue;
    }
    if (status >= 400) {
      continue;
    }
    try {
      const repos = JSON.parse(body) as Array<{ full_name?: string }>;
      return (Array.isArray(repos) ? repos : []).map((repo) => repo.full_name ?? "").filter(Boolean);
    } catch {
      continue;
    }
  }
  return [];
}

async function fromNpm(ctx: SourceCtx): Promise<string[]> {
  const label = ctx.domain.split(".")[0] ?? ctx.domain;
  const emails: string[] = [];
  for (const pkg of unique([label, ctx.domain])) {
    const { status, body } = await fetchText(`https://registry.npmjs.org/${encodeURIComponent(pkg)}`, {}, ctx.fetchImpl);
    if (status >= 400) {
      continue;
    }
    emails.push(...extractEmails(body, ctx.domain));
  }
  const search = await fetchText(
    `https://registry.npmjs.org/-/v1/search?text=${encodeURIComponent(label)}&size=10`,
    {},
    ctx.fetchImpl,
  );
  if (search.status < 400) {
    emails.push(...extractEmails(search.body, ctx.domain));
  }
  return scoped(ctx.domain, emails);
}

async function fromPypi(ctx: SourceCtx): Promise<string[]> {
  const label = ctx.domain.split(".")[0] ?? ctx.domain;
  const { status, body } = await fetchText(`https://pypi.org/pypi/${encodeURIComponent(label)}/json`, {}, ctx.fetchImpl);
  if (status >= 400) {
    return [];
  }
  return extractEmails(body, ctx.domain);
}

async function fromPgp(ctx: SourceCtx): Promise<string[]> {
  const urls = [
    `https://keyserver.ubuntu.com/pks/lookup?search=${encodeURIComponent(ctx.domain)}&op=index&options=mr`,
    `https://pgp.mit.edu/pks/lookup?search=${encodeURIComponent(`@${ctx.domain}`)}&op=index`,
  ];
  const emails: string[] = [];
  for (const url of urls) {
    emails.push(...(await extractFromUrl(ctx, url, { "User-Agent": SEARCH_UA })));
  }
  return unique(emails);
}

async function fromBing(ctx: SourceCtx): Promise<string[]> {
  return extractFromUrl(
    ctx,
    `https://www.bing.com/search?q=${encodeURIComponent(`"@${ctx.domain}"`)}`,
    { "User-Agent": SEARCH_UA, Accept: "text/html" },
  );
}

async function fromDuckDuckGo(ctx: SourceCtx): Promise<string[]> {
  return extractFromUrl(
    ctx,
    `https://html.duckduckgo.com/html/?q=${encodeURIComponent(`"@${ctx.domain}"`)}`,
    { "User-Agent": SEARCH_UA, Accept: "text/html" },
  );
}

async function fromUrlscan(ctx: SourceCtx): Promise<string[]> {
  const { status, body } = await fetchText(
    `https://urlscan.io/api/v1/search/?q=${encodeURIComponent(`page.domain:${ctx.domain}`)}&size=50`,
    { headers: { Accept: "application/json" }, timeoutMs: 15_000 },
    ctx.fetchImpl,
  );
  if (status >= 400) {
    return [];
  }
  return extractEmails(body, ctx.domain);
}

async function fromRdap(ctx: SourceCtx): Promise<string[]> {
  const endpoints = [
    `https://rdap.verisign.com/com/v1/domain/${encodeURIComponent(ctx.domain)}`,
    `https://rdap.org/domain/${encodeURIComponent(ctx.domain)}`,
  ];
  for (const endpoint of endpoints) {
    try {
      const { status, body } = await fetchText(
        endpoint,
        { headers: { Accept: "application/rdap+json, application/json" }, timeoutMs: 20_000 },
        ctx.fetchImpl,
      );
      if (status >= 400) {
        continue;
      }
      return extractEmails(body, ctx.domain);
    } catch {
      // try next RDAP service
    }
  }
  return [];
}

async function fromPublicDns(ctx: SourceCtx, deps: Pick<EmailEnumDeps, "resolveSoa" | "resolveTxt"> = {}): Promise<string[]> {
  const emails: string[] = [];
  const resolveSoa = deps.resolveSoa ?? dns.resolveSoa;
  const resolveTxt = deps.resolveTxt ?? dns.resolveTxt;
  try {
    const soa = await resolveSoa(ctx.domain);
    const email = soaRnameToEmail(soa.hostmaster, ctx.domain);
    if (email) {
      emails.push(email);
    }
  } catch {
    // SOA is optional; other OSINT sources still run
  }
  for (const name of [ctx.domain, `_dmarc.${ctx.domain}`]) {
    try {
      const txt = await resolveTxt(name);
      emails.push(...emailsFromTxt(txt, ctx.domain));
    } catch {
      // TXT is optional
    }
  }
  return scoped(ctx.domain, emails);
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

async function extractFromUrl(ctx: SourceCtx, url: string, headers: Record<string, string>): Promise<string[]> {
  const { status, body } = await fetchText(url, { headers }, ctx.fetchImpl);
  if (status === 404 || status === 403 || status === 429) {
    return [];
  }
  if (status >= 400) {
    throw new Error(`status ${status}`);
  }
  return extractEmails(decodeHtmlEntities(body), ctx.domain);
}

function scoped(domain: string, emails: string[]): string[] {
  return unique(
    emails
      .map((email) => normalizeEmail(email))
      .filter((email): email is string => email !== null)
      .filter((email) => isInScopeEmail(email, domain)),
  );
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
    hunter: 0,
    github: 1,
    npm: 2,
    pypi: 3,
    pgp: 4,
    rdap: 5,
    dns: 6,
    bing: 7,
    duckduckgo: 8,
    urlscan: 9,
    mailto: 10,
    "json-ld": 11,
    html: 12,
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
