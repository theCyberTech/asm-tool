export const ALLOWED_ROOT_DOMAIN = "crewai.com";

const DOMAIN_RE = /^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?(\.[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?)*$/;

export function normalizeTarget(raw: string): string {
  const domain = raw.trim().toLowerCase().replace(/\.$/, "");
  if (!domain) {
    throw new Error("target domain is required");
  }
  if (domain.length > 253) {
    throw new Error("target domain is too long");
  }
  if (!DOMAIN_RE.test(domain)) {
    throw new Error(`invalid target domain "${raw}"`);
  }
  return domain;
}

export function isSubdomainOf(host: string, domain: string): boolean {
  const normalizedHost = normalizeTarget(host);
  const normalizedDomain = normalizeTarget(domain);
  return normalizedHost === normalizedDomain || normalizedHost.endsWith(`.${normalizedDomain}`);
}

export function normalizeScanTarget(raw: string): string {
  const domain = normalizeTarget(raw);
  if (!isSubdomainOf(domain, ALLOWED_ROOT_DOMAIN)) {
    throw new Error(
      `scanning is restricted to ${ALLOWED_ROOT_DOMAIN} and its subdomains (got "${domain}")`,
    );
  }
  return domain;
}

export function isAllowedScanTarget(raw: string): boolean {
  try {
    normalizeScanTarget(raw);
    return true;
  } catch {
    return false;
  }
}

export function normalizeSubdomain(raw: string, domain: string): string | null {
  const host = raw.trim().toLowerCase().replace(/^\*\./, "").replace(/\.$/, "");
  if (!host) {
    return null;
  }
  try {
    const normalizedHost = normalizeTarget(host);
    const normalizedDomain = normalizeTarget(domain);
    if (!isSubdomainOf(normalizedHost, normalizedDomain)) {
      return null;
    }
    return normalizedHost;
  } catch {
    return null;
  }
}

export function hostMatchesDomain(host: string, domain: string): boolean {
  try {
    return isSubdomainOf(host, domain);
  } catch {
    return false;
  }
}
