import { useCallback } from "react";
import { Link } from "react-router-dom";
import { fetchOverview } from "../api/client";
import { Layout } from "../components/Layout";
import { ErrorAlert, LoadingState, WarningAlert } from "../components/Status";
import { useApi } from "../hooks/useApi";
import { formatDate, severityClass } from "../lib/format";

const STAT_LINKS = [
  { key: "domains", label: "Domains", href: "/domains" },
  { key: "subdomains", label: "Subdomains", href: "/subdomains" },
  { key: "ports", label: "Open Ports", href: "/ports" },
  { key: "certificates", label: "Certificates", href: "/certificates" },
  { key: "urls", label: "URLs", href: "/urls" },
  { key: "apis", label: "APIs", href: "/apis" },
  { key: "emails", label: "Emails", href: "/emails" },
  { key: "cloud_buckets", label: "Cloud Buckets", href: "/cloud" },
] as const;

export function DashboardPage() {
  const loader = useCallback(() => fetchOverview(), []);
  const { data, error, loading, reload } = useApi(loader);

  return (
    <Layout activePage="dashboard" stats={data?.stats} findings={data?.findings}>
      <div className="page-header">
        <div>
          <h1 className="page-title">Attack Surface Overview</h1>
          <p className="page-description">Real-time view of your attack surface</p>
        </div>
        <button type="button" className="btn btn-secondary" onClick={() => void reload()}>
          Refresh
        </button>
      </div>

      {error ? <ErrorAlert message={error} /> : null}
      {data?.warning ? <WarningAlert message={data.warning} /> : null}
      {loading && !data ? <LoadingState label="Loading dashboard" /> : null}

      {data ? (
        <>
          <div className="stats-grid">
            {STAT_LINKS.map((card) => (
              <Link key={card.key} className="stat-card stat-card-link" to={card.href} aria-label={`View ${card.label.toLowerCase()}`}>
                <div className="stat-label">{card.label}</div>
                <div className="stat-value">{data.stats[card.key]}</div>
              </Link>
            ))}
          </div>

          <div className="card">
            <div className="card-header">
              <h2 className="card-title">Domains</h2>
              <Link to="/domains" className="btn btn-sm btn-secondary">
                View All
              </Link>
            </div>
            <div className="card-body">
              {data.domains.length === 0 ? (
                <div className="empty-state">
                  <h3>No domains yet</h3>
                  <p>Run a scan to start monitoring a domain</p>
                </div>
              ) : (
                <div className="table-container">
                  <table>
                    <thead>
                      <tr>
                        <th>Domain</th>
                        <th>Last Scan</th>
                        <th>Subdomains</th>
                        <th>Ports</th>
                        <th>Critical</th>
                        <th>High</th>
                      </tr>
                    </thead>
                    <tbody>
                      {data.domains.map((domain) => (
                        <tr key={domain.id} className="domain-row">
                          <td>
                            <Link className="domain-link" to={`/domains/${domain.domain}`}>
                              {domain.domain}
                            </Link>
                          </td>
                          <td className="text-muted">{formatDate(domain.last_scanned)}</td>
                          <td>{domain.subdomain_count}</td>
                          <td>{domain.port_count}</td>
                          <td>{domain.critical_count}</td>
                          <td>{domain.high_count}</td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              )}
            </div>
          </div>

          <div className="card">
            <div className="card-header">
              <h2 className="card-title">Security Findings</h2>
              <Link to="/findings" className="btn btn-sm btn-secondary">
                View All
              </Link>
            </div>
            <div className="card-body">
              {data.findings.total === 0 ? (
                <div className="empty-state">
                  <h3>No findings</h3>
                  <p>Run a Nuclei scan to populate vulnerabilities</p>
                </div>
              ) : (
                <div className="flex gap-md flex-wrap">
                  {data.findings.critical > 0 ? <span className={severityClass("critical")}>{data.findings.critical} Critical</span> : null}
                  {data.findings.high > 0 ? <span className={severityClass("high")}>{data.findings.high} High</span> : null}
                  {data.findings.medium > 0 ? <span className={severityClass("medium")}>{data.findings.medium} Medium</span> : null}
                  {data.findings.low > 0 ? <span className={severityClass("low")}>{data.findings.low} Low</span> : null}
                  {data.findings.info > 0 ? <span className={severityClass("info")}>{data.findings.info} Info</span> : null}
                </div>
              )}
            </div>
          </div>

          <div className="card">
            <div className="card-header">
              <h2 className="card-title">Recent Changes</h2>
            </div>
            <div className="card-body">
              {data.change_events.length === 0 ? (
                <div className="empty-state">
                  <h3>No recent changes</h3>
                  <p>DNS and inventory changes will appear here</p>
                </div>
              ) : (
                <div className="table-container">
                  <table>
                    <thead>
                      <tr>
                        <th>Domain</th>
                        <th>Type</th>
                        <th>Severity</th>
                        <th>Description</th>
                        <th>When</th>
                      </tr>
                    </thead>
                    <tbody>
                      {data.change_events.map((event, index) => (
                        <tr key={`${event.domain}-${event.timestamp}-${index}`}>
                          <td className="text-mono">{event.domain}</td>
                          <td>{event.change_type}</td>
                          <td>
                            <span className={severityClass(event.severity)}>{event.severity}</span>
                          </td>
                          <td>{event.description}</td>
                          <td className="text-muted">{formatDate(event.timestamp)}</td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              )}
            </div>
          </div>
        </>
      ) : null}
    </Layout>
  );
}
