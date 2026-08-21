import type { AssetRowByKind, DomainAssetKind, Finding } from "../api/types";
import type { Column } from "../components/DataTable";
import { formatDate, severityClass } from "../lib/format";

function col<T>(
  key: keyof T & string,
  header: string,
  extra?: Partial<Column<T>>,
): Column<T> {
  return {
    key,
    header,
    value: (row) => {
      const value = row[key];
      if (typeof value === "number") {
        return value;
      }
      if (typeof value === "boolean") {
        return value ? "yes" : "no";
      }
      if (value === null || value === undefined) {
        return "";
      }
      return String(value);
    },
    ...extra,
  };
}

const findingColumns: Array<Column<Finding>> = [
  col("severity", "Severity", {
    render: (row) => <span className={severityClass(row.severity)}>{row.severity}</span>,
  }),
  col("name", "Name"),
  col("host", "Host"),
  col("matched_at", "Matched"),
  col("discovered_at", "Discovered", { value: (row) => formatDate(row.discovered_at) }),
];

export const assetColumns = {
  subdomains: [
    col("subdomain", "Subdomain", { render: (row) => <span className="text-mono">{row.subdomain}</span> }),
    col("discovered_at", "Discovered", { value: (row) => formatDate(row.discovered_at) }),
    col("last_seen", "Last Seen", { value: (row) => formatDate(row.last_seen) }),
  ],
  ports: [
    col("host", "Host", { render: (row) => <span className="text-mono">{row.host}</span> }),
    col("port", "Port", { render: (row) => <span className="badge badge-blue">{row.port}</span> }),
    col("protocol", "Protocol"),
    col("service", "Service"),
    col("banner", "Banner"),
    col("discovered_at", "Discovered", { value: (row) => formatDate(row.discovered_at) }),
  ],
  certificates: [
    col("host", "Host", { render: (row) => <span className="text-mono">{row.host}</span> }),
    col("subject", "Subject"),
    col("issuer", "Issuer"),
    col("days_until_expiry", "Days Left"),
    col("not_after", "Expires", { value: (row) => formatDate(row.not_after) }),
  ],
  technologies: [
    col("host", "Host"),
    col("title", "Title"),
    col("server", "Server"),
    col("technologies", "Technologies"),
    col("status_code", "Status"),
  ],
  dns: [
    col("domain", "Domain"),
    col("records", "Records"),
    col("checked_at", "Checked", { value: (row) => formatDate(row.checked_at) }),
  ],
  vulnerabilities: findingColumns,
  findings: findingColumns,
  urls: [
    col("url", "URL", { render: (row) => <span className="text-mono">{row.url}</span> }),
    col("source", "Source"),
    col("interesting", "Interesting"),
    col("discovered_at", "Discovered", { value: (row) => formatDate(row.discovered_at) }),
  ],
  apis: [
    col("url", "URL"),
    col("type", "Type"),
    col("title", "Title"),
    col("version", "Version"),
  ],
  emails: [
    col("address", "Address"),
    col("source", "Source"),
    col("discovered_at", "Discovered", { value: (row) => formatDate(row.discovered_at) }),
  ],
  cloud: [
    col("provider", "Provider"),
    col("bucket_name", "Bucket"),
    col("severity", "Severity", {
      render: (row) => <span className={severityClass(row.severity)}>{row.severity}</span>,
    }),
    col("status", "Status"),
  ],
  takeovers: [
    col("subdomain", "Subdomain"),
    col("service", "Service"),
    col("confidence", "Confidence"),
    col("cname", "CNAME"),
  ],
} satisfies { [K in DomainAssetKind]: Array<Column<AssetRowByKind[K]>> };

export function domainAssetColumns<K extends DomainAssetKind>(kind: K): Array<Column<AssetRowByKind[K]>> {
  return assetColumns[kind] as Array<Column<AssetRowByKind[K]>>;
}
