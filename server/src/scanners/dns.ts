import { promises as dns } from "node:dns";

export type DnsSnapshot = {
  domain: string;
  records: string;
};

async function lookup(kind: string, fn: () => Promise<unknown>): Promise<Record<string, unknown>> {
  try {
    return { [kind]: await fn() };
  } catch (err) {
    return { [kind]: { error: err instanceof Error ? err.message : String(err) } };
  }
}

export async function queryDns(domain: string): Promise<DnsSnapshot> {
  const parts = await Promise.all([
    lookup("A", () => dns.resolve4(domain)),
    lookup("AAAA", () => dns.resolve6(domain)),
    lookup("CNAME", () => dns.resolveCname(domain)),
    lookup("MX", () => dns.resolveMx(domain)),
    lookup("NS", () => dns.resolveNs(domain)),
    lookup("TXT", () => dns.resolveTxt(domain)),
    lookup("SOA", () => dns.resolveSoa(domain)),
    lookup("CAA", () => dns.resolveCaa(domain)),
  ]);
  const records = Object.assign({}, ...parts) as Record<string, unknown>;
  return { domain, records: JSON.stringify(records, null, 2) };
}
