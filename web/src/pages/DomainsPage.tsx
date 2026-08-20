import { useCallback, useMemo, useState } from "react";
import { Link } from "react-router-dom";
import { fetchDomains, fetchOverview } from "../api/client";
import { Layout } from "../components/Layout";
import { ErrorAlert, LoadingState } from "../components/Status";
import { useApi } from "../hooks/useApi";
import { formatDate } from "../lib/format";

export function DomainsPage() {
  const [query, setQuery] = useState("");
  const [from, setFrom] = useState("");
  const [to, setTo] = useState("");
  const overviewLoader = useCallback(() => fetchOverview(), []);
  const { data: overview } = useApi(overviewLoader);

  const filters = useMemo(() => ({ q: query, from, to }), [from, query, to]);
  const domainLoader = useCallback(() => fetchDomains(filters), [filters]);
  const { data, error, loading } = useApi(domainLoader);

  return (
    <Layout activePage="domains" stats={overview?.stats} findings={overview?.findings}>
      <div className="page-header">
        <div>
          <h1 className="page-title">Domains</h1>
          <p className="page-description">Monitored domains and latest scan summaries</p>
        </div>
      </div>

      <div className="search-filter-bar">
        <div className="search-input-container">
          <svg xmlns="http://www.w3.org/2000/svg" width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
            <circle cx="11" cy="11" r="8" />
            <line x1="21" y1="21" x2="16.65" y2="16.65" />
          </svg>
          <input
            className="form-input"
            style={{ paddingLeft: "2rem" }}
            value={query}
            onChange={(event) => setQuery(event.target.value)}
            placeholder="Search domains"
            aria-label="Search domains"
          />
        </div>
        <input className="form-input" type="date" value={from} onChange={(event) => setFrom(event.target.value)} aria-label="From date" />
        <input className="form-input" type="date" value={to} onChange={(event) => setTo(event.target.value)} aria-label="To date" />
      </div>

      {error ? <ErrorAlert message={error} /> : null}
      {loading && !data ? <LoadingState label="Loading domains" /> : null}

      <div className="card">
        <div className="card-header">
          <h2 className="card-title">All Domains</h2>
          <span className="badge badge-blue">{data?.count ?? 0}</span>
        </div>
        <div className="card-body">
          {!data || data.domains.length === 0 ? (
            <div className="empty-state">
              <h3>No domains found</h3>
              <p>Adjust filters or run a scan to add domains</p>
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
    </Layout>
  );
}
