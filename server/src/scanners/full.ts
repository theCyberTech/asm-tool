import type { Store } from "../db/store.ts";
import { discoverApis } from "./apis.ts";
import { checkCertificate } from "./certificates.ts";
import { probeCloudBuckets } from "./cloud.ts";
import { queryDns } from "./dns.ts";
import { findingsFromHeaders } from "./findings.ts";
import { scanPorts } from "./ports.ts";
import { enumerateSubdomains } from "./subdomains.ts";
import { checkTakeover } from "./takeover.ts";
import { fingerprintHost } from "./technologies.ts";
import { enumerateUrls } from "./urls.ts";

export type ScanLogger = {
  info: (message: string) => void;
  warn: (message: string) => void;
};

export type ScanDeps = {
  fetchImpl?: typeof fetch;
  ports?: number[];
};

const DEFAULT_PORTS = [21, 22, 23, 25, 53, 80, 110, 143, 443, 445, 3306, 3389, 5432, 8080, 8443];
const HOST_SCAN_LIMIT = 25;

function scanHosts(store: Store, domain: string): string[] {
  const hosts = store.hostsForDomain(domain);
  if (hosts.length <= HOST_SCAN_LIMIT) {
    return hosts;
  }
  const rest = hosts.filter((host) => host !== domain).slice(0, HOST_SCAN_LIMIT - 1);
  return [domain, ...rest];
}

async function runIsolated(
  store: Store,
  moduleId: string,
  domain: string,
  log: ScanLogger,
  deps: ScanDeps,
): Promise<void> {
  try {
    await runModule(store, moduleId, domain, log, deps);
  } catch (err) {
    log.warn(`${moduleId} failed: ${err instanceof Error ? err.message : String(err)}`);
  }
}

export async function runModule(
  store: Store,
  moduleId: string,
  domain: string,
  log: ScanLogger,
  deps: ScanDeps = {},
): Promise<void> {
  const fetchImpl = deps.fetchImpl ?? fetch;
  store.ensureDomain(domain);
  if (moduleId !== "scan" && moduleId !== "status") {
    log.info(`${moduleId}: starting for ${domain}`);
  }

  switch (moduleId) {
    case "status":
      log.info("database ok");
      return;
    case "discover": {
      const result = await enumerateSubdomains(domain, fetchImpl);
      store.saveSubdomains(domain, result.subdomains);
      for (const err of result.errors) {
        log.warn(err);
      }
      log.info(`found ${result.subdomains.length} subdomains`);
      return;
    }
    case "dns": {
      const snapshot = await queryDns(domain);
      store.saveDns(domain, snapshot.records);
      log.info(`stored DNS snapshot for ${domain}`);
      return;
    }
    case "urls": {
      const result = await enumerateUrls(domain, fetchImpl);
      if (result.error) {
        log.warn(result.error);
      }
      for (const url of result.urls) {
        store.saveUrl(domain, url.url, url.source, url.category, url.interesting);
      }
      log.info(`stored ${result.urls.length} URLs`);
      return;
    }
    case "certificates": {
      const hosts = scanHosts(store, domain);
      let saved = 0;
      for (const host of hosts) {
        try {
          const cert = await checkCertificate(host);
          store.saveCertificate(cert);
          saved += 1;
          if (cert.daysUntilExpiry <= 30) {
            store.saveFinding({
              templateId: "cert-expiring",
              name: "Certificate expiring soon",
              severity: cert.daysUntilExpiry <= 0 ? "high" : "medium",
              description: `${host} certificate expires in ${cert.daysUntilExpiry} days`,
              host,
              matchedAt: "443",
              tags: "tls,certificate",
            });
          }
        } catch (err) {
          log.warn(`${host}: ${err instanceof Error ? err.message : String(err)}`);
        }
      }
      log.info(`checked ${saved} certificates`);
      return;
    }
    case "portscan": {
      const hosts = scanHosts(store, domain);
      const ports = deps.ports?.length ? deps.ports : DEFAULT_PORTS;
      let open = 0;
      for (const host of hosts) {
        const found = await scanPorts(host, ports);
        store.savePorts(host, found);
        open += found.length;
        log.info(`${host}: ${found.length} open ports`);
      }
      log.info(`stored ${open} open ports`);
      return;
    }
    case "fingerprint": {
      const hosts = scanHosts(store, domain);
      for (const host of hosts) {
        try {
          const tech = await fingerprintHost(host, fetchImpl);
          store.saveTechnology(host, tech.statusCode, tech.title, tech.server, tech.technologies);
          for (const finding of findingsFromHeaders(host, tech.headers)) {
            store.saveFinding(finding);
          }
          log.info(`${host}: ${tech.statusCode} ${tech.technologies || "no tech"}`);
        } catch (err) {
          log.warn(`${host}: ${err instanceof Error ? err.message : String(err)}`);
        }
      }
      log.info("fingerprint complete");
      return;
    }
    case "apis": {
      const hosts = scanHosts(store, domain);
      let count = 0;
      for (const host of hosts) {
        const apis = await discoverApis(host, fetchImpl);
        for (const api of apis) {
          store.saveApi(api.url, api.type, api.title, api.version);
          count += 1;
        }
      }
      log.info(`found ${count} API endpoints`);
      return;
    }
    case "cloudstorage": {
      const buckets = await probeCloudBuckets(domain, fetchImpl);
      for (const bucket of buckets) {
        store.saveCloud({ ...bucket, domain });
      }
      log.info(`probed cloud buckets, found ${buckets.length}`);
      return;
    }
    case "takeover": {
      const hosts = scanHosts(store, domain);
      let count = 0;
      for (const host of hosts) {
        const finding = await checkTakeover(host, fetchImpl);
        if (finding) {
          store.saveTakeover(finding);
          store.saveFinding({
            templateId: `takeover-${finding.service}`,
            name: `Possible ${finding.service} takeover`,
            severity: finding.confidence === "HIGH" ? "high" : "medium",
            description: finding.evidence,
            host,
            matchedAt: finding.cname,
            tags: "takeover",
          });
          count += 1;
        }
      }
      log.info(`takeover hits: ${count}`);
      return;
    }
    case "nuclei":
      log.warn("Nuclei is optional and not bundled; header-based findings are collected during fingerprinting");
      return;
    case "scan": {
      log.info("full scan: discover, then dns/urls, ports, and host checks");
      await runIsolated(store, "discover", domain, log, deps);
      await Promise.all([
        runIsolated(store, "dns", domain, log, deps),
        runIsolated(store, "urls", domain, log, deps),
      ]);
      await runIsolated(store, "portscan", domain, log, deps);
      await Promise.all([
        runIsolated(store, "certificates", domain, log, deps),
        runIsolated(store, "fingerprint", domain, log, deps),
        runIsolated(store, "apis", domain, log, deps),
        runIsolated(store, "cloudstorage", domain, log, deps),
        runIsolated(store, "takeover", domain, log, deps),
      ]);
      store.markScanned(domain);
      log.info(`full scan complete for ${domain}`);
      return;
    }
    case "report": {
      const stats = store.domainDetailStats(domain);
      log.info(JSON.stringify({ domain, stats }, null, 2));
      return;
    }
    default:
      throw new Error(`unsupported action "${moduleId}"`);
  }
}
