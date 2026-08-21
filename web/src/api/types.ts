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

export type DomainSummary = {
  id: number;
  domain: string;
  added_at: string;
  last_scanned?: string;
  subdomain_count: number;
  port_count: number;
  critical_count: number;
  high_count: number;
};

export type ChangeEvent = {
  domain: string;
  change_type: string;
  severity: string;
  description: string;
  old_value: string;
  new_value: string;
  timestamp: string;
};

export type OverviewResponse = {
  status: string;
  stats: Stats;
  findings: FindingCounts;
  domains: DomainSummary[];
  change_events: ChangeEvent[];
  warning?: string;
};

export type DomainListResponse = {
  status: string;
  domains: DomainSummary[];
  count: number;
};

export type DomainDetailStats = {
  subdomain_count: number;
  port_count: number;
  certificate_count: number;
  technology_count: number;
  dns_record_count: number;
  vuln_count: number;
  url_count: number;
  api_count: number;
  cloud_count: number;
  takeover_count: number;
};

export type Subdomain = {
  subdomain: string;
  discovered_at: string;
  last_seen: string;
};

export type Port = {
  host: string;
  port: number;
  protocol: string;
  service: string;
  version: string;
  product: string;
  state: string;
  banner: string;
  discovered_at: string;
};

export type Certificate = {
  host: string;
  port: number;
  subject: string;
  issuer: string;
  not_after: string;
  days_until_expiry: number;
  san: string;
};

export type Technology = {
  host: string;
  status_code: number;
  title: string;
  server: string;
  technologies: string;
  checked_at: string;
};

export type DNSRecord = {
  domain: string;
  records: string;
  checked_at: string;
};

export type Finding = {
  id: number;
  name: string;
  severity: string;
  description: string;
  host: string;
  matched_at: string;
  tags: string;
  discovered_at: string;
};

export type DiscoveredURL = {
  url: string;
  domain: string;
  category?: string;
  interesting: boolean;
  source: string;
  discovered_at: string;
};

export type APIEndpoint = {
  url: string;
  type?: string;
  title?: string;
  version?: string;
  discovered_at: string;
};

export type CloudStorage = {
  provider: string;
  bucket_name: string;
  url: string;
  access_level: string;
  severity: string;
  evidence: string;
  status: string;
};

export type Takeover = {
  subdomain: string;
  cname: string;
  service: string;
  takeover_type: string;
  confidence: string;
  evidence: string;
  discovered_at: string;
};

export type DomainDetail = {
  status: string;
  domain: string;
  added_at: string;
  last_scanned?: string;
  stats: DomainDetailStats;
  subdomains: Subdomain[];
  ports: Port[];
  certificates: Certificate[];
  technologies: Technology[];
  dns_records: DNSRecord[];
  findings: Finding[];
  urls: DiscoveredURL[];
  apis: APIEndpoint[];
  cloud_storage: CloudStorage[];
  takeovers: Takeover[];
  change_events: ChangeEvent[];
  warning?: string;
};

export type AssetListResponse<T> = {
  status: string;
  kind: string;
  title: string;
  count: number;
  items: T[];
};

export type OperationAction = {
  id: string;
  label: string;
  requires_target: boolean;
  supports_all_known: boolean;
  supports_ports: boolean;
  supports_output_format: boolean;
  supports_nuclei: boolean;
};

export type RunRecord = {
  id: number;
  action: string;
  label: string;
  command: string;
  target: string;
  status: string;
  exit_code: number;
  started_at: string;
  finished_at?: string;
  duration?: string;
  stdout: string;
  stderr: string;
  error?: string;
  truncated: boolean;
};

export type OperationsResponse = {
  status: string;
  enabled: boolean;
  actions: OperationAction[];
  runs: RunRecord[];
  running_count: number;
  binary_path: string;
  config_path: string;
  database_path: string;
  log_path: string;
};

export type StartRunRequest = {
  action: string;
  target?: string;
  all_known?: boolean;
  ports?: string;
  output_format?: string;
  nuclei?: boolean;
  verbose?: boolean;
};

export type ErrorResponse = {
  status: string;
  message: string;
};

export type AssetKind =
  | "subdomains"
  | "ports"
  | "certificates"
  | "urls"
  | "apis"
  | "cloud"
  | "findings"
  | "takeovers";

export type DomainAssetKind =
  | AssetKind
  | "technologies"
  | "dns"
  | "vulnerabilities";
