import { useCallback, useMemo, useState } from "react";
import { Link, useParams } from "react-router-dom";
import { fetchDomain, fetchDomainAssets, fetchOverview } from "../api/client";
import type { DomainAssetKind } from "../api/types";
import { DataTable, type Column } from "../components/DataTable";
import { Layout } from "../components/Layout";
import { Modal } from "../components/Modal";
import { ErrorAlert, LoadingState, WarningAlert } from "../components/Status";
import { useApi } from "../hooks/useApi";
import { formatDate, formatDateTime, severityClass } from "../lib/format";
import { domainAssetColumns } from "./assetColumns";

const MODULES: Array<{ kind: DomainAssetKind; label: string; countKey: keyof import("../api/types").DomainDetailStats }> = [
  { kind: "subdomains", label: "Subdomains", countKey: "subdomain_count" },
  { kind: "ports", label: "Open Ports", countKey: "port_count" },
  { kind: "certificates", label: "Certificates", countKey: "certificate_count" },
  { kind: "technologies", label: "Technologies", countKey: "technology_count" },
  { kind: "dns", label: "DNS Records", countKey: "dns_record_count" },
  { kind: "vulnerabilities", label: "Vulnerabilities", countKey: "vuln_count" },
  { kind: "urls", label: "URLs", countKey: "url_count" },
  { kind: "apis", label: "APIs", countKey: "api_count" },
  { kind: "emails", label: "Emails", countKey: "email_count" },
  { kind: "cloud", label: "Cloud Storage", countKey: "cloud_count" },
  { kind: "takeovers", label: "Takeovers", countKey: "takeover_count" },
];

export function DomainDetailPage() {
  const { name = "" } = useParams();
  const overviewLoader = useCallback(() => fetchOverview(), []);
  const { data: overview } = useApi(overviewLoader);
  const loader = useCallback(() => fetchDomain(name), [name]);
  const { data, error, loading, reload } = useApi(loader);
  const [modalKind, setModalKind] = useState<DomainAssetKind | null>(null);

  return (
    <Layout activePage="domains" stats={overview?.stats} findings={overview?.findings}>
      <div className="breadcrumb">
        <Link to="/">Dashboard</Link>
        <span>/</span>
        <Link to="/domains">Domains</Link>
        <span>/</span>
        <span>{name}</span>
      </div>

      <div className="page-header">
        <div>
          <h1 className="page-title">{name}</h1>
          <p className="page-description">
            Added {formatDate(data?.added_at)} · Last scanned {formatDate(data?.last_scanned)}
          </p>
        </div>
        <button type="button" className="btn btn-secondary" onClick={() => void reload()}>
          Refresh
        </button>
      </div>

      {error ? <ErrorAlert message={error} /> : null}
      {data?.warning ? <WarningAlert message={data.warning} /> : null}
      {loading && !data ? <LoadingState label="Loading domain" /> : null}

      {data ? (
        <>
          <div className="module-grid">
            {MODULES.map((module) => (
              <button
                key={module.kind}
                type="button"
                className="stat-card stat-card-clickable"
                onClick={() => setModalKind(module.kind)}
              >
                <div className="stat-label">{module.label}</div>
                <div className="stat-value">{data.stats[module.countKey]}</div>
              </button>
            ))}
          </div>

          <div className="card">
            <div className="card-header">
              <h2 className="card-title">Change Events</h2>
            </div>
            <div className="card-body">
              {data.change_events.length === 0 ? (
                <div className="empty-state">
                  <h3>No changes recorded</h3>
                  <p>Future inventory diffs for this domain will show up here</p>
                </div>
              ) : (
                <div className="table-container">
                  <table>
                    <thead>
                      <tr>
                        <th>Type</th>
                        <th>Severity</th>
                        <th>Description</th>
                        <th>When</th>
                      </tr>
                    </thead>
                    <tbody>
                      {data.change_events.map((event, index) => (
                        <tr key={`${event.timestamp}-${index}`}>
                          <td>{event.change_type}</td>
                          <td>
                            <span className={severityClass(event.severity)}>{event.severity}</span>
                          </td>
                          <td>{event.description}</td>
                          <td className="text-muted">{formatDateTime(event.timestamp)}</td>
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

      <AssetModal domain={name} kind={modalKind} onClose={() => setModalKind(null)} />
    </Layout>
  );
}

function AssetModal({
  domain,
  kind,
  onClose,
}: {
  domain: string;
  kind: DomainAssetKind | null;
  onClose: () => void;
}) {
  const loader = useCallback(async () => {
    if (!kind) {
      return { status: "ok", kind: "", title: "", count: 0, items: [] };
    }
    return fetchDomainAssets<Record<string, unknown>>(domain, kind);
  }, [domain, kind]);
  const { data, error, loading } = useApi(loader);
  const columns = useMemo(() => (kind ? domainAssetColumns(kind) : []), [kind]);
  const module = MODULES.find((item) => item.kind === kind);

  return (
    <Modal title={module?.label ?? "Assets"} open={kind !== null} onClose={onClose}>
      {error ? <ErrorAlert message={error} /> : null}
      {loading ? <LoadingState label="Loading assets" /> : null}
      {!loading && data ? (
        <DataTable
          rows={data.items}
          columns={columns as Array<Column<Record<string, unknown>>>}
          emptyTitle="No records"
          emptyDescription="This module has no findings yet"
        />
      ) : null}
    </Modal>
  );
}
