import type { DomainAssetKind } from "../api/types";
import type { Column } from "../components/DataTable";
import { formatDate, severityClass } from "../lib/format";

function text(value: unknown): string {
  if (value === null || value === undefined) {
    return "";
  }
  return String(value);
}

function col(key: string, header: string, extra?: Partial<Column<Record<string, unknown>>>): Column<Record<string, unknown>> {
  return {
    key,
    header,
    value: (row) => text(row[key]),
    ...extra,
  };
}

export function domainAssetColumns(kind: DomainAssetKind): Array<Column<Record<string, unknown>>> {
  switch (kind) {
    case "subdomains":
      return [
        col("subdomain", "Subdomain", { render: (row) => <span className="text-mono">{text(row.subdomain)}</span> }),
        col("discovered_at", "Discovered", { value: (row) => formatDate(text(row.discovered_at)) }),
        col("last_seen", "Last Seen", { value: (row) => formatDate(text(row.last_seen)) }),
      ];
    case "ports":
      return [
        col("host", "Host", { render: (row) => <span className="text-mono">{text(row.host)}</span> }),
        col("port", "Port", { value: (row) => Number(row.port ?? 0), render: (row) => <span className="badge badge-blue">{text(row.port)}</span> }),
        col("protocol", "Protocol"),
        col("service", "Service"),
        col("banner", "Banner"),
        col("discovered_at", "Discovered", { value: (row) => formatDate(text(row.discovered_at)) }),
      ];
    case "certificates":
      return [
        col("host", "Host", { render: (row) => <span className="text-mono">{text(row.host)}</span> }),
        col("subject", "Subject"),
        col("issuer", "Issuer"),
        col("days_until_expiry", "Days Left", { value: (row) => Number(row.days_until_expiry ?? 0) }),
        col("not_after", "Expires", { value: (row) => formatDate(text(row.not_after)) }),
      ];
    case "technologies":
      return [
        col("host", "Host"),
        col("title", "Title"),
        col("server", "Server"),
        col("technologies", "Technologies"),
        col("status_code", "Status", { value: (row) => Number(row.status_code ?? 0) }),
      ];
    case "dns":
      return [
        col("domain", "Domain"),
        col("records", "Records"),
        col("checked_at", "Checked", { value: (row) => formatDate(text(row.checked_at)) }),
      ];
    case "vulnerabilities":
    case "findings":
      return [
        col("severity", "Severity", {
          render: (row) => <span className={severityClass(text(row.severity))}>{text(row.severity)}</span>,
        }),
        col("name", "Name"),
        col("host", "Host"),
        col("matched_at", "Matched"),
        col("discovered_at", "Discovered", { value: (row) => formatDate(text(row.discovered_at)) }),
      ];
    case "urls":
      return [
        col("url", "URL", { render: (row) => <span className="text-mono">{text(row.url)}</span> }),
        col("source", "Source"),
        col("interesting", "Interesting", { value: (row) => (row.interesting ? "yes" : "no") }),
        col("discovered_at", "Discovered", { value: (row) => formatDate(text(row.discovered_at)) }),
      ];
    case "apis":
      return [
        col("url", "URL"),
        col("type", "Type"),
        col("title", "Title"),
        col("version", "Version"),
      ];
    case "emails":
      return [
        col("address", "Address"),
        col("source", "Source"),
        col("discovered_at", "Discovered", { value: (row) => formatDate(text(row.discovered_at)) }),
      ];
    case "cloud":
      return [
        col("provider", "Provider"),
        col("bucket_name", "Bucket"),
        col("severity", "Severity", {
          render: (row) => <span className={severityClass(text(row.severity))}>{text(row.severity)}</span>,
        }),
        col("status", "Status"),
      ];
    case "takeovers":
      return [
        col("subdomain", "Subdomain"),
        col("service", "Service"),
        col("confidence", "Confidence"),
        col("cname", "CNAME"),
      ];
    default: {
      const exhaustive: never = kind;
      return [col("value", String(exhaustive))];
    }
  }
}
