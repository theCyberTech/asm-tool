import { FormEvent, useCallback, useEffect, useMemo, useState } from "react";
import { fetchOperations, startRun } from "../api/client";
import type { OperationAction } from "../api/types";
import { Layout } from "../components/Layout";
import { ErrorAlert, LoadingState } from "../components/Status";
import { useApi } from "../hooks/useApi";
import { formatDateTime, severityClass } from "../lib/format";

export function OperationsPage() {
  const [token, setToken] = useState("");
  const loader = useCallback(() => fetchOperations(token || undefined), [token]);
  const { data, error, loading, reload } = useApi(loader);

  const selectedDefault = data?.actions[0]?.id ?? "status";
  const [actionId, setActionId] = useState(selectedDefault);
  const [target, setTarget] = useState("");
  const [allKnown, setAllKnown] = useState(false);
  const [ports, setPorts] = useState("");
  const [outputFormat, setOutputFormat] = useState("");
  const [nuclei, setNuclei] = useState(false);
  const [verbose, setVerbose] = useState(false);
  const [formError, setFormError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  const action = useMemo(
    () => data?.actions.find((item) => item.id === actionId) ?? data?.actions[0],
    [actionId, data?.actions],
  );

  useEffect(() => {
    if (!data?.running_count) {
      return;
    }
    const timer = window.setInterval(() => {
      void reload();
    }, 2000);
    return () => window.clearInterval(timer);
  }, [data?.running_count, reload]);

  async function onSubmit(event: FormEvent) {
    event.preventDefault();
    if (!action) {
      return;
    }
    setBusy(true);
    setFormError(null);
    try {
      await startRun(
        {
          action: action.id,
          target,
          all_known: allKnown,
          ports,
          output_format: outputFormat,
          nuclei,
          verbose,
        },
        token || undefined,
      );
      await reload();
    } catch (err) {
      setFormError(err instanceof Error ? err.message : "Failed to start run");
    } finally {
      setBusy(false);
    }
  }

  return (
    <Layout
      activePage="operations"
      runningCount={data?.running_count}
    >
      <div className="page-header">
        <div>
          <h1 className="page-title">Operations</h1>
          <p className="page-description">Run and monitor ASM scans from this host</p>
        </div>
        <button type="button" className="btn btn-secondary" onClick={() => void reload()}>
          Refresh
        </button>
      </div>

      {error ? <ErrorAlert message={error} /> : null}
      {formError ? <ErrorAlert message={formError} /> : null}
      {loading && !data ? <LoadingState label="Loading operations" /> : null}

      {data ? (
        <div className="ops-grid">
          <div className="card">
            <div className="card-header">
              <h2 className="card-title">Start a run</h2>
            </div>
            <div className="card-body">
              <form onSubmit={(event) => void onSubmit(event)}>
                <div className="form-group">
                  <label className="form-label" htmlFor="ops-token">
                    Token
                  </label>
                  <input
                    id="ops-token"
                    className="form-input"
                    type="password"
                    value={token}
                    onChange={(event) => setToken(event.target.value)}
                    placeholder="Optional X-ASM-Token"
                  />
                </div>
                <div className="form-group">
                  <label className="form-label" htmlFor="ops-action">
                    Action
                  </label>
                  <select
                    id="ops-action"
                    className="form-input"
                    value={action?.id ?? ""}
                    onChange={(event) => setActionId(event.target.value)}
                  >
                    {data.actions.map((item) => (
                      <option key={item.id} value={item.id}>
                        {item.label}
                      </option>
                    ))}
                  </select>
                </div>
                <ActionFields
                  action={action}
                  target={target}
                  setTarget={setTarget}
                  allKnown={allKnown}
                  setAllKnown={setAllKnown}
                  ports={ports}
                  setPorts={setPorts}
                  outputFormat={outputFormat}
                  setOutputFormat={setOutputFormat}
                  nuclei={nuclei}
                  setNuclei={setNuclei}
                  verbose={verbose}
                  setVerbose={setVerbose}
                />
                <button type="submit" className="btn btn-primary" disabled={busy}>
                  {busy ? "Starting…" : "Start run"}
                </button>
              </form>
              <p className="text-muted mt-md">Binary: {data.binary_path || "unknown"}</p>
            </div>
          </div>

          <div className="card">
            <div className="card-header">
              <h2 className="card-title">Recent runs</h2>
              {data.running_count > 0 ? <span className="badge badge-blue">{data.running_count} running</span> : null}
            </div>
            <div className="card-body">
              {data.runs.length === 0 ? (
                <div className="empty-state">
                  <h3>No runs yet</h3>
                  <p>Start a scan to see command output here</p>
                </div>
              ) : (
                data.runs.map((run) => (
                  <div key={run.id} className="card" style={{ padding: "1rem" }}>
                    <div className="flex items-center justify-between gap-sm">
                      <strong>{run.label}</strong>
                      <span className={severityClass(run.status === "failed" ? "critical" : run.status === "succeeded" ? "low" : "info")}>
                        {run.status}
                      </span>
                    </div>
                    <p className="text-muted text-mono">{run.command}</p>
                    <p className="text-muted">
                      {formatDateTime(run.started_at)}
                      {run.duration ? ` · ${run.duration}` : ""}
                      {run.target ? ` · ${run.target}` : ""}
                    </p>
                    {run.stdout ? <pre className="run-output">{run.stdout}</pre> : null}
                    {run.stderr ? <pre className="run-output">{run.stderr}</pre> : null}
                    {run.error ? <p className="alert alert-danger">{run.error}</p> : null}
                  </div>
                ))
              )}
            </div>
          </div>
        </div>
      ) : null}
    </Layout>
  );
}

function ActionFields({
  action,
  target,
  setTarget,
  allKnown,
  setAllKnown,
  ports,
  setPorts,
  outputFormat,
  setOutputFormat,
  nuclei,
  setNuclei,
  verbose,
  setVerbose,
}: {
  action?: OperationAction;
  target: string;
  setTarget: (value: string) => void;
  allKnown: boolean;
  setAllKnown: (value: boolean) => void;
  ports: string;
  setPorts: (value: string) => void;
  outputFormat: string;
  setOutputFormat: (value: string) => void;
  nuclei: boolean;
  setNuclei: (value: boolean) => void;
  verbose: boolean;
  setVerbose: (value: boolean) => void;
}) {
  if (!action) {
    return null;
  }
  return (
    <>
      {action.requires_target ? (
        <div className="form-group">
          <label className="form-label" htmlFor="ops-target">
            Target
          </label>
          <input
            id="ops-target"
            className="form-input"
            value={target}
            onChange={(event) => setTarget(event.target.value)}
            disabled={allKnown}
            placeholder="example.com"
          />
        </div>
      ) : null}
      {action.supports_all_known ? (
        <label className="checkbox-row">
          <input type="checkbox" checked={allKnown} onChange={(event) => setAllKnown(event.target.checked)} />
          All known domains
        </label>
      ) : null}
      {action.supports_ports ? (
        <div className="form-group">
          <label className="form-label" htmlFor="ops-ports">
            Ports
          </label>
          <input id="ops-ports" className="form-input" value={ports} onChange={(event) => setPorts(event.target.value)} placeholder="80,443,8080" />
        </div>
      ) : null}
      {action.supports_output_format ? (
        <div className="form-group">
          <label className="form-label" htmlFor="ops-format">
            Output format
          </label>
          <select id="ops-format" className="form-input" value={outputFormat} onChange={(event) => setOutputFormat(event.target.value)}>
            <option value="">None</option>
            <option value="json">JSON</option>
            <option value="markdown">Markdown</option>
            <option value="html">HTML</option>
          </select>
        </div>
      ) : null}
      {action.supports_nuclei ? (
        <label className="checkbox-row">
          <input type="checkbox" checked={nuclei} onChange={(event) => setNuclei(event.target.checked)} />
          Include Nuclei
        </label>
      ) : null}
      <label className="checkbox-row">
        <input type="checkbox" checked={verbose} onChange={(event) => setVerbose(event.target.checked)} />
        Verbose
      </label>
    </>
  );
}
