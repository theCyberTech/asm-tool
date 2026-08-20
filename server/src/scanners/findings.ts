export type SecurityFinding = {
  templateId: string;
  name: string;
  severity: "critical" | "high" | "medium" | "low" | "info";
  description: string;
  host: string;
  matchedAt: string;
  tags: string;
};

export function findingsFromHeaders(host: string, headers: Record<string, string>): SecurityFinding[] {
  const lower: Record<string, string> = {};
  for (const [key, value] of Object.entries(headers)) {
    lower[key.toLowerCase()] = value;
  }
  const out: SecurityFinding[] = [];
  if (!lower["strict-transport-security"]) {
    out.push({
      templateId: "missing-hsts",
      name: "Missing Strict-Transport-Security header",
      severity: "medium",
      description: "The host does not send HSTS, so browsers will not force HTTPS.",
      host,
      matchedAt: "/",
      tags: "headers,misconfig",
    });
  }
  if (!lower["content-security-policy"]) {
    out.push({
      templateId: "missing-csp",
      name: "Missing Content-Security-Policy header",
      severity: "low",
      description: "No CSP header was found on the HTTP response.",
      host,
      matchedAt: "/",
      tags: "headers,misconfig",
    });
  }
  if (!lower["x-frame-options"] && !lower["content-security-policy"]) {
    out.push({
      templateId: "missing-xfo",
      name: "Missing X-Frame-Options header",
      severity: "info",
      description: "Clickjacking protections were not advertised via X-Frame-Options.",
      host,
      matchedAt: "/",
      tags: "headers,misconfig",
    });
  }
  return out;
}
