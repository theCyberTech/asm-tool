import { nowIso } from "../db/database.ts";
import type { RunRow, Store } from "../db/store.ts";
import { parsePorts } from "../config.ts";
import { runModule } from "../scanners/full.ts";
import { ALLOWED_ROOT_DOMAIN, isAllowedScanTarget, normalizeScanTarget } from "../target.ts";

export type OperationAction = {
  id: string;
  label: string;
  requires_target: boolean;
  supports_all_known: boolean;
  supports_ports: boolean;
  supports_output_format: boolean;
  supports_nuclei: boolean;
};

export const ACTIONS: OperationAction[] = [
  { id: "scan", label: "Full scan", requires_target: true, supports_all_known: false, supports_ports: false, supports_output_format: true, supports_nuclei: true },
  { id: "discover", label: "Discover subdomains", requires_target: true, supports_all_known: true, supports_ports: false, supports_output_format: false, supports_nuclei: false },
  { id: "dns", label: "DNS check", requires_target: true, supports_all_known: true, supports_ports: false, supports_output_format: false, supports_nuclei: false },
  { id: "urls", label: "URL enumeration", requires_target: true, supports_all_known: true, supports_ports: false, supports_output_format: false, supports_nuclei: false },
  { id: "certificates", label: "Certificate check", requires_target: true, supports_all_known: true, supports_ports: false, supports_output_format: false, supports_nuclei: false },
  { id: "takeover", label: "Takeover check", requires_target: true, supports_all_known: true, supports_ports: false, supports_output_format: false, supports_nuclei: false },
  { id: "fingerprint", label: "Fingerprint", requires_target: true, supports_all_known: true, supports_ports: false, supports_output_format: false, supports_nuclei: false },
  { id: "apis", label: "API discovery", requires_target: true, supports_all_known: true, supports_ports: false, supports_output_format: false, supports_nuclei: false },
  { id: "emails", label: "Email enumeration", requires_target: true, supports_all_known: true, supports_ports: false, supports_output_format: false, supports_nuclei: false },
  { id: "cloudstorage", label: "Cloud storage", requires_target: true, supports_all_known: true, supports_ports: false, supports_output_format: false, supports_nuclei: false },
  { id: "portscan", label: "Port scan", requires_target: true, supports_all_known: true, supports_ports: true, supports_output_format: false, supports_nuclei: false },
  { id: "nuclei", label: "Nuclei scan", requires_target: true, supports_all_known: true, supports_ports: false, supports_output_format: false, supports_nuclei: false },
  { id: "report", label: "Generate report", requires_target: true, supports_all_known: false, supports_ports: false, supports_output_format: true, supports_nuclei: false },
];

export type StartRunInput = {
  action: string;
  target?: string;
  all_known?: boolean;
  ports?: string;
  output_format?: string;
  nuclei?: boolean;
  verbose?: boolean;
};

export class JobRunner {
  constructor(
    private readonly store: Store,
    private readonly defaultPorts: number[],
    private readonly fetchImpl: typeof fetch = fetch,
  ) {}

  start(input: StartRunInput): RunRow {
    const def = ACTIONS.find((item) => item.id === input.action);
    if (!def) {
      throw new Error(`unsupported action "${input.action}"`);
    }
    if (input.all_known && !def.supports_all_known) {
      throw new Error(`${def.label} does not support all-known mode`);
    }
    if (def.requires_target && !input.all_known && !String(input.target ?? "").trim()) {
      throw new Error(`${def.label} requires a target domain`);
    }

    const targets = this.resolveTargets(def, input);
    const ports = input.ports?.trim() ? parsePorts(input.ports) : this.defaultPorts;
    if (def.supports_ports && input.ports?.trim() && ports.length === 0) {
      throw new Error("ports must be a comma-separated list or range");
    }

    const command = `scan:${def.id} ${input.all_known ? "--all-known" : targets.join(" ")}`;
    const run = this.store.insertRun({
      action: def.id,
      label: def.label,
      command,
      target: input.all_known ? "all-known" : (targets[0] ?? ""),
      status: "running",
      exit_code: -1,
      started_at: nowIso(),
      stdout: "",
      stderr: "",
    });

    void this.execute(run.id, def.id, targets, ports);
    return run;
  }

  private resolveTargets(def: OperationAction, input: StartRunInput): string[] {
    if (!def.requires_target) {
      return [ALLOWED_ROOT_DOMAIN];
    }
    if (input.all_known) {
      const known = this.store.listDomainNames().filter((domain) => isAllowedScanTarget(domain));
      if (known.length > 0) {
        return known;
      }
      return [ALLOWED_ROOT_DOMAIN];
    }
    return [normalizeScanTarget(String(input.target))];
  }

  private async execute(id: number, action: string, targets: string[], ports: number[]): Promise<void> {
    const logs: string[] = [];
    const warnings: string[] = [];
    const log = {
      info: (message: string) => logs.push(message),
      warn: (message: string) => warnings.push(message),
    };
    try {
      for (const target of targets) {
        log.info(`running ${action} on ${target}`);
        await runModule(this.store, action, target, log, { fetchImpl: this.fetchImpl, ports });
      }
      this.store.updateRun(id, {
        status: "succeeded",
        exit_code: 0,
        finished_at: nowIso(),
        stdout: logs.join("\n"),
        stderr: warnings.join("\n"),
      });
    } catch (err) {
      this.store.updateRun(id, {
        status: "failed",
        exit_code: 1,
        finished_at: nowIso(),
        stdout: logs.join("\n"),
        stderr: warnings.join("\n"),
        error: err instanceof Error ? err.message : String(err),
      });
    }
  }
}
