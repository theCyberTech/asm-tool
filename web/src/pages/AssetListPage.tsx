import { useCallback } from "react";
import { useParams } from "react-router-dom";
import { fetchAssets, fetchOverview } from "../api/client";
import type { AssetKind } from "../api/types";
import { DataTable, type Column } from "../components/DataTable";
import { Layout } from "../components/Layout";
import { ErrorAlert, LoadingState } from "../components/Status";
import { useApi } from "../hooks/useApi";
import { domainAssetColumns } from "./assetColumns";

const TITLES: Record<AssetKind, string> = {
  subdomains: "Subdomains",
  ports: "Open Ports",
  certificates: "Certificates",
  urls: "URLs",
  apis: "API Endpoints",
  emails: "Email Addresses",
  cloud: "Cloud Storage",
  findings: "Findings",
  takeovers: "Takeovers",
};

export function AssetListPage() {
  const { kind = "subdomains" } = useParams();
  const assetKind = (kind in TITLES ? kind : "subdomains") as AssetKind;
  const overviewLoader = useCallback(() => fetchOverview(), []);
  const { data: overview } = useApi(overviewLoader);
  const loader = useCallback(() => fetchAssets<Record<string, unknown>>(assetKind), [assetKind]);
  const { data, error, loading } = useApi(loader);
  const title = data?.title || TITLES[assetKind];

  return (
    <Layout activePage={assetKind} stats={overview?.stats} findings={overview?.findings}>
      <div className="page-header">
        <div>
          <h1 className="page-title">{title}</h1>
        </div>
      </div>
      {error ? <ErrorAlert message={error} /> : null}
      {loading && !data ? <LoadingState label={`Loading ${title}`} /> : null}
      <div className="card">
        <div className="card-header">
          <h2 className="card-title">All {title}</h2>
          <span className="badge badge-blue">{data?.count ?? 0}</span>
        </div>
        <div className="card-body">
          {data ? (
            <DataTable
              rows={data.items}
              columns={domainAssetColumns(assetKind) as Array<Column<Record<string, unknown>>>}
              emptyTitle={`No ${title.toLowerCase()} found`}
              emptyDescription="Run a scan to populate this inventory"
            />
          ) : null}
        </div>
      </div>
    </Layout>
  );
}
