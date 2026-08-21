import { randomUUID } from "node:crypto";
import type { DatabaseSync } from "node:sqlite";
import { asRecord, nowIso } from "./database.ts";

export type DomainRow = {
  id: number;
  domain: string;
  added_at: string;
  last_scanned?: string;
  subdomain_count: number;
  port_count: number;
  critical_count: number;
  high_count: number;
};

export type Stats = {
  domains: number;
  subdomains: number;
  ports: number;
  certificates: number;
  urls: number;
  apis: number;
  cloud_buckets: number;
  takeovers: number;
};

export type FindingCounts = {
  total: number;
  critical: number;
  high: number;
  medium: number;
  low: number;
  info: number;
};

export type RunRow = {
  id: number;
  action: string;
  label: string;
  command: string;
  target: string;
  status: string;
  exit_code: number;
  started_at: string;
  finished_at?: string;
  stdout: string;
  stderr: string;
  error?: string;
  truncated: boolean;
};

function count(db: DatabaseSync, sql: string, params: Array<string | number> = []): number {
  const row = db.prepare(sql).get(...params) as { n?: number } | undefined;
  return Number(row?.n ?? 0);
}

function likeHost(domain: string): string {
  return `%.${domain}`;
}

export class Store {
  constructor(private readonly db: DatabaseSync) {}

  ensureDomain(domain: string): number {
    const existing = this.db.prepare("SELECT id FROM domains WHERE domain = ?").get(domain) as { id?: number } | undefined;
    if (existing?.id) {
      return Number(existing.id);
    }
    const result = this.db.prepare("INSERT INTO domains (domain, added_at, active) VALUES (?, ?, 1)").run(domain, nowIso());
    return Number(result.lastInsertRowid);
  }

  markScanned(domain: string): void {
    const id = this.ensureDomain(domain);
    this.db.prepare("UPDATE domains SET last_scanned = ? WHERE id = ?").run(nowIso(), id);
  }

  getDomain(domain: string): { id: number; domain: string; added_at: string; last_scanned?: string } | undefined {
    const row = this.db.prepare("SELECT id, domain, added_at, last_scanned FROM domains WHERE domain = ? AND active = 1").get(domain);
    if (!row) {
      return undefined;
    }
    const rec = asRecord(row);
    return {
      id: Number(rec.id),
      domain: String(rec.domain),
      added_at: String(rec.added_at),
      last_scanned: rec.last_scanned ? String(rec.last_scanned) : undefined,
    };
  }

  listDomainNames(): string[] {
    return this.db
      .prepare("SELECT domain FROM domains WHERE active = 1 ORDER BY domain")
      .all()
      .map((row) => String(asRecord(row).domain));
  }

  getStats(): Stats {
    return {
      domains: count(this.db, "SELECT COUNT(*) AS n FROM domains WHERE active = 1"),
      subdomains: count(this.db, "SELECT COUNT(*) AS n FROM subdomains WHERE active = 1"),
      ports: count(this.db, "SELECT COUNT(*) AS n FROM ports WHERE state = 'open'"),
      certificates: count(this.db, "SELECT COUNT(*) AS n FROM certificates"),
      urls: count(this.db, "SELECT COUNT(*) AS n FROM urls"),
      apis: count(this.db, "SELECT COUNT(*) AS n FROM apis"),
      cloud_buckets: count(this.db, "SELECT COUNT(*) AS n FROM cloud_storage WHERE status = 'open'"),
      takeovers: count(this.db, "SELECT COUNT(*) AS n FROM takeovers WHERE status = 'open'"),
    };
  }

  getFindingCounts(): FindingCounts {
    const rows = this.db.prepare("SELECT severity, COUNT(*) AS n FROM findings WHERE status = 'open' GROUP BY severity").all();
    const counts: FindingCounts = { total: 0, critical: 0, high: 0, medium: 0, low: 0, info: 0 };
    for (const row of rows) {
      const rec = asRecord(row);
      const severity = String(rec.severity);
      const n = Number(rec.n);
      counts.total += n;
      if (severity === "critical") counts.critical = n;
      if (severity === "high") counts.high = n;
      if (severity === "medium") counts.medium = n;
      if (severity === "low") counts.low = n;
      if (severity === "info") counts.info = n;
    }
    return counts;
  }

  getDomainsWithStats(): DomainRow[] {
    const rows = this.db
      .prepare(
        `SELECT
            d.id, d.domain, d.added_at, d.last_scanned,
            COALESCE(sub.subdomain_count, 0) AS subdomain_count,
            COALESCE(p.port_count, 0) AS port_count,
            COALESCE(f.critical_count, 0) AS critical_count,
            COALESCE(f.high_count, 0) AS high_count
         FROM domains d
         LEFT JOIN (
            SELECT domain_id, COUNT(*) AS subdomain_count FROM subdomains WHERE active = 1 GROUP BY domain_id
         ) sub ON sub.domain_id = d.id
         LEFT JOIN (
            SELECT d2.id AS domain_id, COUNT(*) AS port_count
            FROM domains d2
            JOIN ports pt ON (pt.host = d2.domain OR pt.host LIKE '%.' || d2.domain) AND pt.state = 'open'
            GROUP BY d2.id
         ) p ON p.domain_id = d.id
         LEFT JOIN (
            SELECT d3.id AS domain_id,
              SUM(CASE WHEN f.severity = 'critical' THEN 1 ELSE 0 END) AS critical_count,
              SUM(CASE WHEN f.severity = 'high' THEN 1 ELSE 0 END) AS high_count
            FROM domains d3
            JOIN findings f ON (f.host = d3.domain OR f.host LIKE '%.' || d3.domain) AND f.status = 'open'
            GROUP BY d3.id
         ) f ON f.domain_id = d.id
         WHERE d.active = 1
         ORDER BY d.domain`,
      )
      .all();
    return rows.map((row) => {
      const rec = asRecord(row);
      return {
        id: Number(rec.id),
        domain: String(rec.domain),
        added_at: String(rec.added_at),
        last_scanned: rec.last_scanned ? String(rec.last_scanned) : undefined,
        subdomain_count: Number(rec.subdomain_count),
        port_count: Number(rec.port_count),
        critical_count: Number(rec.critical_count),
        high_count: Number(rec.high_count),
      };
    });
  }

  getChangeEvents(domain?: string, limit = 20): Array<Record<string, unknown>> {
    const sql = domain
      ? "SELECT domain, change_type, severity, description, old_value, new_value, timestamp FROM change_events WHERE domain = ? ORDER BY timestamp DESC LIMIT ?"
      : "SELECT domain, change_type, severity, description, old_value, new_value, timestamp FROM change_events ORDER BY timestamp DESC LIMIT ?";
    const rows = domain ? this.db.prepare(sql).all(domain, limit) : this.db.prepare(sql).all(limit);
    return rows.map((row) => asRecord(row));
  }

  recordChange(domain: string, changeType: string, severity: string, description: string, oldValue = "", newValue = ""): void {
    this.db
      .prepare(
        "INSERT INTO change_events (event_id, domain, change_type, severity, description, old_value, new_value, timestamp) VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
      )
      .run(randomUUID(), domain, changeType, severity, description, oldValue, newValue, nowIso());
  }

  saveSubdomains(domain: string, hosts: string[]): number {
    const domainId = this.ensureDomain(domain);
    let added = 0;
    const insert = this.db.prepare(
      "INSERT INTO subdomains (domain_id, subdomain, discovered_at, last_seen, active) VALUES (?, ?, ?, ?, 1) ON CONFLICT(domain_id, subdomain) DO UPDATE SET last_seen = excluded.last_seen, active = 1",
    );
    const exists = this.db.prepare("SELECT 1 FROM subdomains WHERE domain_id = ? AND subdomain = ?");
    const ts = nowIso();
    for (const host of hosts) {
      const had = exists.get(domainId, host);
      insert.run(domainId, host, ts, ts);
      if (!had) {
        added += 1;
        this.recordChange(domain, "subdomain_added", "info", `New subdomain ${host}`, "", host);
      }
    }
    return added;
  }

  listSubdomains(domain?: string): Array<Record<string, unknown>> {
    if (domain) {
      return this.db
        .prepare(
          `SELECT s.subdomain, s.discovered_at, s.last_seen
           FROM subdomains s JOIN domains d ON d.id = s.domain_id
           WHERE d.domain = ? AND s.active = 1 ORDER BY s.subdomain`,
        )
        .all(domain)
        .map((row) => asRecord(row));
    }
    return this.db
      .prepare("SELECT subdomain, discovered_at, last_seen FROM subdomains WHERE active = 1 ORDER BY subdomain")
      .all()
      .map((row) => asRecord(row));
  }

  hostsForDomain(domain: string): string[] {
    const hosts = new Set<string>([domain]);
    for (const row of this.listSubdomains(domain)) {
      hosts.add(String(row.subdomain));
    }
    return [...hosts];
  }

  savePorts(host: string, ports: Array<{ port: number; protocol?: string; service?: string; banner?: string; state?: string }>): void {
    const ts = nowIso();
    const stmt = this.db.prepare(
      `INSERT INTO ports (host, port, protocol, service, version, product, state, banner, discovered_at, last_seen)
       VALUES (?, ?, ?, ?, '', '', ?, ?, ?, ?)
       ON CONFLICT(host, port, protocol) DO UPDATE SET
         service = excluded.service, state = excluded.state, banner = excluded.banner, last_seen = excluded.last_seen`,
    );
    for (const port of ports) {
      stmt.run(host, port.port, port.protocol ?? "tcp", port.service ?? "", port.state ?? "open", port.banner ?? "", ts, ts);
    }
  }

  listPorts(domain?: string): Array<Record<string, unknown>> {
    if (domain) {
      return this.db
        .prepare("SELECT host, port, protocol, service, version, product, state, banner, discovered_at FROM ports WHERE host = ? OR host LIKE ? ORDER BY host, port")
        .all(domain, likeHost(domain))
        .map((row) => asRecord(row));
    }
    return this.db
      .prepare("SELECT host, port, protocol, service, version, product, state, banner, discovered_at FROM ports ORDER BY host, port")
      .all()
      .map((row) => asRecord(row));
  }

  saveCertificate(cert: {
    host: string;
    port: number;
    subject: string;
    issuer: string;
    notAfter: string;
    daysUntilExpiry: number;
    san: string;
  }): void {
    this.db
      .prepare(
        `INSERT INTO certificates (host, port, subject, issuer, not_after, days_until_expiry, san, checked_at)
         VALUES (?, ?, ?, ?, ?, ?, ?, ?)
         ON CONFLICT(host, port) DO UPDATE SET
           subject = excluded.subject, issuer = excluded.issuer, not_after = excluded.not_after,
           days_until_expiry = excluded.days_until_expiry, san = excluded.san, checked_at = excluded.checked_at`,
      )
      .run(cert.host, cert.port, cert.subject, cert.issuer, cert.notAfter, cert.daysUntilExpiry, cert.san, nowIso());
  }

  listCertificates(domain?: string): Array<Record<string, unknown>> {
    if (domain) {
      return this.db
        .prepare("SELECT host, port, subject, issuer, not_after, days_until_expiry, san FROM certificates WHERE host = ? OR host LIKE ? ORDER BY host")
        .all(domain, likeHost(domain))
        .map((row) => asRecord(row));
    }
    return this.db
      .prepare("SELECT host, port, subject, issuer, not_after, days_until_expiry, san FROM certificates ORDER BY host")
      .all()
      .map((row) => asRecord(row));
  }

  saveTechnology(host: string, statusCode: number, title: string, server: string, technologies: string): void {
    this.db
      .prepare(
        `INSERT INTO technologies (host, status_code, title, server, technologies, headers, content_length, redirect_url, checked_at)
         VALUES (?, ?, ?, ?, ?, '', 0, '', ?)
         ON CONFLICT(host) DO UPDATE SET
           status_code = excluded.status_code, title = excluded.title, server = excluded.server,
           technologies = excluded.technologies, checked_at = excluded.checked_at`,
      )
      .run(host, statusCode, title, server, technologies, nowIso());
  }

  listTechnologies(domain: string): Array<Record<string, unknown>> {
    return this.db
      .prepare("SELECT host, status_code, title, server, technologies, checked_at FROM technologies WHERE host = ? OR host LIKE ? ORDER BY host")
      .all(domain, likeHost(domain))
      .map((row) => asRecord(row));
  }

  saveDns(domain: string, records: string): void {
    this.db
      .prepare(
        `INSERT INTO dns_records (domain, records, checked_at) VALUES (?, ?, ?)
         ON CONFLICT(domain) DO UPDATE SET records = excluded.records, checked_at = excluded.checked_at`,
      )
      .run(domain, records, nowIso());
  }

  listDns(domain?: string): Array<Record<string, unknown>> {
    if (domain) {
      return this.db
        .prepare("SELECT domain, records, checked_at FROM dns_records WHERE domain = ? OR domain LIKE ? ORDER BY domain")
        .all(domain, likeHost(domain))
        .map((row) => asRecord(row));
    }
    return this.db.prepare("SELECT domain, records, checked_at FROM dns_records ORDER BY domain").all().map((row) => asRecord(row));
  }

  saveFinding(finding: {
    templateId: string;
    name: string;
    severity: "critical" | "high" | "medium" | "low" | "info";
    description: string;
    host: string;
    matchedAt?: string;
    tags?: string;
  }): void {
    this.db
      .prepare(
        `INSERT INTO findings (template_id, name, severity, description, host, matched_at, tags, status, discovered_at)
         VALUES (?, ?, ?, ?, ?, ?, ?, 'open', ?)
         ON CONFLICT(template_id, host) DO UPDATE SET
           name = excluded.name, severity = excluded.severity, description = excluded.description,
           matched_at = excluded.matched_at, tags = excluded.tags, status = 'open'`,
      )
      .run(
        finding.templateId,
        finding.name,
        finding.severity,
        finding.description,
        finding.host,
        finding.matchedAt ?? "",
        finding.tags ?? "",
        nowIso(),
      );
  }

  listFindings(domain?: string): Array<Record<string, unknown>> {
    const order = `ORDER BY CASE severity WHEN 'critical' THEN 1 WHEN 'high' THEN 2 WHEN 'medium' THEN 3 WHEN 'low' THEN 4 ELSE 5 END, name`;
    if (domain) {
      return this.db
        .prepare(
          `SELECT id, name, severity, description, host, matched_at, tags, discovered_at FROM findings
           WHERE status = 'open' AND (host = ? OR host LIKE ?) ${order}`,
        )
        .all(domain, likeHost(domain))
        .map((row) => asRecord(row));
    }
    return this.db
      .prepare(`SELECT id, name, severity, description, host, matched_at, tags, discovered_at FROM findings WHERE status = 'open' ${order}`)
      .all()
      .map((row) => asRecord(row));
  }

  saveUrl(domain: string, url: string, source: string, category: string, interesting: boolean): void {
    this.db
      .prepare(
        `INSERT INTO urls (domain, url, interesting, category, source, discovered_at)
         VALUES (?, ?, ?, ?, ?, ?)
         ON CONFLICT(url) DO UPDATE SET source = excluded.source, category = excluded.category, interesting = excluded.interesting`,
      )
      .run(domain, url, interesting ? 1 : 0, category, source, nowIso());
  }

  listUrls(domain?: string): Array<Record<string, unknown>> {
    const map = (row: unknown) => {
      const rec = asRecord(row);
      return { ...rec, interesting: Boolean(rec.interesting) };
    };
    if (domain) {
      return this.db
        .prepare("SELECT url, domain, category, interesting, source, discovered_at FROM urls WHERE domain = ? OR domain LIKE ? ORDER BY url")
        .all(domain, likeHost(domain))
        .map(map);
    }
    return this.db.prepare("SELECT url, domain, category, interesting, source, discovered_at FROM urls ORDER BY url").all().map(map);
  }

  saveApi(url: string, type: string, title: string, version: string): void {
    this.db
      .prepare(
        `INSERT INTO apis (url, api_type, title, version, discovered_at)
         VALUES (?, ?, ?, ?, ?)
         ON CONFLICT(url) DO UPDATE SET api_type = excluded.api_type, title = excluded.title, version = excluded.version`,
      )
      .run(url, type, title, version, nowIso());
  }

  listApis(domain?: string): Array<Record<string, unknown>> {
    const map = (row: unknown) => {
      const rec = asRecord(row);
      return { url: rec.url, type: rec.api_type, title: rec.title, version: rec.version, discovered_at: rec.discovered_at };
    };
    if (domain) {
      return this.db.prepare("SELECT url, api_type, title, version, discovered_at FROM apis WHERE url LIKE ? ORDER BY url").all(`%${domain}%`).map(map);
    }
    return this.db.prepare("SELECT url, api_type, title, version, discovered_at FROM apis ORDER BY url").all().map(map);
  }

  saveCloud(record: {
    provider: "s3" | "azure" | "gcs";
    bucketName: string;
    url: string;
    domain: string;
    accessLevel: "listing_enabled" | "public_read" | "authenticated_only" | "not_found";
    severity: "critical" | "high" | "medium" | "low";
    evidence: string;
  }): void {
    this.db
      .prepare(
        `INSERT INTO cloud_storage (url, provider, bucket_name, domain, source, access_level, severity, evidence, status, discovered_at)
         VALUES (?, ?, ?, ?, 'probe', ?, ?, ?, 'open', ?)
         ON CONFLICT(url) DO UPDATE SET access_level = excluded.access_level, severity = excluded.severity, evidence = excluded.evidence, status = 'open'`,
      )
      .run(record.url, record.provider, record.bucketName, record.domain, record.accessLevel, record.severity, record.evidence, nowIso());
  }

  listCloud(domain?: string): Array<Record<string, unknown>> {
    const map = (row: unknown) => {
      const rec = asRecord(row);
      return {
        provider: rec.provider,
        bucket_name: rec.bucket_name,
        url: rec.url,
        access_level: rec.access_level,
        severity: rec.severity,
        evidence: rec.evidence,
        status: rec.status,
      };
    };
    if (domain) {
      return this.db
        .prepare("SELECT provider, bucket_name, url, access_level, severity, evidence, status FROM cloud_storage WHERE domain = ? AND status = 'open'")
        .all(domain)
        .map(map);
    }
    return this.db
      .prepare("SELECT provider, bucket_name, url, access_level, severity, evidence, status FROM cloud_storage WHERE status = 'open'")
      .all()
      .map(map);
  }

  saveTakeover(record: {
    subdomain: string;
    cname: string;
    service: string;
    takeoverType: string;
    confidence: "HIGH" | "MEDIUM" | "LOW";
    evidence: string;
  }): void {
    this.db
      .prepare(
        `INSERT INTO takeovers (subdomain, cname, service, takeover_type, confidence, evidence, status, discovered_at)
         VALUES (?, ?, ?, ?, ?, ?, 'open', ?)
         ON CONFLICT(subdomain, service) DO UPDATE SET cname = excluded.cname, evidence = excluded.evidence, confidence = excluded.confidence, status = 'open'`,
      )
      .run(record.subdomain, record.cname, record.service, record.takeoverType, record.confidence, record.evidence, nowIso());
  }

  listTakeovers(domain?: string): Array<Record<string, unknown>> {
    const map = (row: unknown) => {
      const rec = asRecord(row);
      return {
        subdomain: rec.subdomain,
        cname: rec.cname,
        service: rec.service,
        takeover_type: rec.takeover_type,
        confidence: rec.confidence,
        evidence: rec.evidence,
        discovered_at: rec.discovered_at,
      };
    };
    if (domain) {
      return this.db
        .prepare(
          `SELECT subdomain, cname, service, takeover_type, confidence, evidence, discovered_at
           FROM takeovers WHERE status = 'open' AND (subdomain = ? OR subdomain LIKE ?) ORDER BY subdomain`,
        )
        .all(domain, likeHost(domain))
        .map(map);
    }
    return this.db
      .prepare("SELECT subdomain, cname, service, takeover_type, confidence, evidence, discovered_at FROM takeovers WHERE status = 'open' ORDER BY subdomain")
      .all()
      .map(map);
  }

  domainDetailStats(domain: string): Record<string, number> {
    const like = likeHost(domain);
    return {
      subdomain_count: count(
        this.db,
        "SELECT COUNT(*) AS n FROM subdomains s JOIN domains d ON d.id = s.domain_id WHERE d.domain = ? AND s.active = 1",
        [domain],
      ),
      port_count: count(this.db, "SELECT COUNT(*) AS n FROM ports WHERE (host = ? OR host LIKE ?) AND state = 'open'", [domain, like]),
      certificate_count: count(this.db, "SELECT COUNT(*) AS n FROM certificates WHERE host = ? OR host LIKE ?", [domain, like]),
      technology_count: count(this.db, "SELECT COUNT(*) AS n FROM technologies WHERE host = ? OR host LIKE ?", [domain, like]),
      dns_record_count: count(this.db, "SELECT COUNT(*) AS n FROM dns_records WHERE domain = ? OR domain LIKE ?", [domain, like]),
      vuln_count: count(this.db, "SELECT COUNT(*) AS n FROM findings WHERE status = 'open' AND (host = ? OR host LIKE ?)", [domain, like]),
      url_count: count(this.db, "SELECT COUNT(*) AS n FROM urls WHERE domain = ? OR domain LIKE ?", [domain, like]),
      api_count: count(this.db, "SELECT COUNT(*) AS n FROM apis WHERE url LIKE ?", [`%${domain}%`]),
      cloud_count: count(this.db, "SELECT COUNT(*) AS n FROM cloud_storage WHERE domain = ?", [domain]),
      takeover_count: count(this.db, "SELECT COUNT(*) AS n FROM takeovers WHERE status = 'open' AND (subdomain = ? OR subdomain LIKE ?)", [domain, like]),
    };
  }

  insertRun(run: Omit<RunRow, "id" | "truncated"> & { truncated?: boolean }): RunRow {
    const result = this.db
      .prepare(
        `INSERT INTO runs (action, label, command, target, status, exit_code, started_at, finished_at, stdout, stderr, error, truncated)
         VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
      )
      .run(
        run.action,
        run.label,
        run.command,
        run.target,
        run.status,
        run.exit_code,
        run.started_at,
        run.finished_at ?? null,
        run.stdout,
        run.stderr,
        run.error ?? null,
        run.truncated ? 1 : 0,
      );
    return this.getRun(Number(result.lastInsertRowid))!;
  }

  updateRun(id: number, patch: Partial<Omit<RunRow, "id">>): RunRow {
    const current = this.getRun(id);
    if (!current) {
      throw new Error(`run ${id} not found`);
    }
    const next = { ...current, ...patch };
    this.db
      .prepare(
        `UPDATE runs SET action=?, label=?, command=?, target=?, status=?, exit_code=?, started_at=?, finished_at=?, stdout=?, stderr=?, error=?, truncated=? WHERE id=?`,
      )
      .run(
        next.action,
        next.label,
        next.command,
        next.target,
        next.status,
        next.exit_code,
        next.started_at,
        next.finished_at ?? null,
        next.stdout,
        next.stderr,
        next.error ?? null,
        next.truncated ? 1 : 0,
        id,
      );
    return this.getRun(id)!;
  }

  getRun(id: number): RunRow | undefined {
    const row = this.db.prepare("SELECT * FROM runs WHERE id = ?").get(id);
    if (!row) {
      return undefined;
    }
    return mapRun(row);
  }

  listRuns(limit = 50): RunRow[] {
    return this.db.prepare("SELECT * FROM runs ORDER BY id DESC LIMIT ?").all(limit).map(mapRun);
  }

  runningCount(): number {
    return count(this.db, "SELECT COUNT(*) AS n FROM runs WHERE status = 'running'");
  }
}

function mapRun(row: unknown): RunRow {
  const rec = asRecord(row);
  return {
    id: Number(rec.id),
    action: String(rec.action),
    label: String(rec.label),
    command: String(rec.command),
    target: String(rec.target ?? ""),
    status: String(rec.status),
    exit_code: Number(rec.exit_code),
    started_at: String(rec.started_at),
    finished_at: rec.finished_at ? String(rec.finished_at) : undefined,
    stdout: String(rec.stdout ?? ""),
    stderr: String(rec.stderr ?? ""),
    error: rec.error ? String(rec.error) : undefined,
    truncated: Boolean(rec.truncated),
  };
}
