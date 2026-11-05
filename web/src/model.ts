export interface Session {
  token: string;
  expiresAt: string;
}

export interface ObservationPoint {
  id: string;
  nodeType: string;
  platform: string;
  architecture: string;
  interfaces: string[];
  capabilities: string[];
  privileges: string[];
  isolation: string;
  compatibility: string[];
}

export interface Selector {
  kind: string;
  value: string;
}

export interface PortRange {
  start: number;
  end: number;
}

export interface Grant {
  id: string;
  name: string;
  subjectType: string;
  selectors: Selector[];
  transports: string[];
  ports: PortRange[];
  operations: string[];
  points: string[];
  validFrom: string;
  validUntil: string | null;
  maxTargets: number;
  maxAddresses: number;
  maxConnections: number;
  maxRequests: number;
  maxConcurrency: number;
  maxRatePerSecond: number;
  maxRuntimeSeconds: number;
  maxEvidenceBytes: number;
  status: string;
  revocationReason: string;
  createdAt: string;
}

export interface Revision {
  id: string;
  action: string;
  actorId: string;
  at: string;
  content: unknown;
}

export interface Schedule {
  id: string;
  name: string;
  trigger: string;
  status: string;
  intervalSeconds: number;
  nextRunAt: string;
  grantId: string;
  target: string;
  lastResult: string;
}

export interface ScanRun {
  id: string;
  name: string;
  grantId: string;
  trigger: string;
  status: string;
  total: number;
  done: number;
  failed: number;
  skipped: number;
  summary: string;
  createdAt: string;
  startedAt: string | null;
  finishedAt: string | null;
}

export interface Observation {
  id: string;
  type: string;
  subject: string;
  status: string;
  observedAt: string;
  value: unknown;
}

export interface Finding {
  id: string;
  key: string;
  type: string;
  vulnerabilityId: string;
  title: string;
  severity: string;
  status: string;
  assetId: string;
  endpointId: string;
  firstSeen: string;
  lastSeen: string;
  dispositionType: string;
}

export interface Disposition {
  id: string;
  type: string;
  reason: string;
  createdAt: string;
  validUntil: string | null;
}

export interface Asset {
  id: string;
  type: string;
  family: string;
  name: string;
  version: string;
  hash: string;
  status: string;
  lastSeen: string;
}

export interface Endpoint {
  id: string;
  address: string;
  transport: string;
  port: number;
  state: string;
  assetId: string;
  lastSeen: string;
}

export interface Target {
  id: string;
  type: string;
  raw: string;
  normalized: string;
  transport: string;
  createdAt: string;
}

export interface Hypothesis {
  id: string;
  endpointId: string;
  service: string;
  product: string;
  version: string;
  normalized: string;
  status: string;
  confidence: string;
  evaluatedAt: string;
}

export interface Pack {
  id: string;
  version: string;
  status: string;
  rules?: number;
  accepted?: number;
  skipped?: number;
  license: boolean;
}

export interface Template {
  id: string;
  key: string;
  name: string;
  severity: string;
  cve: string;
  status: string;
  enabled: boolean;
  bound: number;
}

export interface Snapshot {
  id: string;
  digest: string;
  sources: string[];
  statements: number;
  publishedAt: string;
}

type Row = Record<string, unknown>;

function text(row: Row, key: string): string {
  const value = row[key];
  return typeof value === "string" ? value : "";
}

function num(row: Row, key: string): number {
  const value = row[key];
  return typeof value === "number" ? value : 0;
}

function list(value: unknown): string[] {
  return Array.isArray(value) ? value.filter((item): item is string => typeof item === "string") : [];
}

function labeled(value: unknown): string[] {
  if (!value || typeof value !== "object" || Array.isArray(value)) {
    return [];
  }
  return Object.entries(value as Record<string, unknown>)
    .map(([key, item]) => `${key}: ${typeof item === "string" || typeof item === "number" ? String(item) : ""}`)
    .filter((item) => !item.endsWith(": "))
    .sort();
}

function interfaceLines(value: unknown): string[] {
  if (!Array.isArray(value)) {
    return [];
  }
  return value.flatMap((item) => {
    if (!item || typeof item !== "object") {
      return [];
    }
    const row = item as Row;
    const name = text(row, "name");
    if (!name) {
      return [];
    }
    const flags = [row.up === true ? "up" : "down", row.loopback === true ? "loopback" : ""].filter(Boolean).join(", ");
    const addresses = list(row.addresses).join(", ");
    return [`${name} (${flags})${addresses ? " " + addresses : ""}`];
  });
}

function optionalTime(value: unknown): string | null {
  return typeof value === "string" ? value : null;
}

export function loadSession(): Session | null {
  const raw = sessionStorage.getItem("vesper.session");
  if (!raw) {
    return null;
  }
  try {
    const parsed = JSON.parse(raw) as Session;
    if (!parsed.token || !parsed.expiresAt) {
      return null;
    }
    return parsed;
  } catch {
    return null;
  }
}

export function saveSession(session: Session | null) {
  if (session) {
    sessionStorage.setItem("vesper.session", JSON.stringify(session));
  } else {
    sessionStorage.removeItem("vesper.session");
  }
}

export function pointFrom(row: Row): ObservationPoint {
  const caps = row.capabilities;
  const priv = row.privileges;
  return {
    id: text(row, "id"),
    nodeType: text(row, "node_type"),
    platform: text(row, "platform"),
    architecture: text(row, "architecture"),
    interfaces: interfaceLines(row.network_interfaces),
    capabilities: labeled(caps),
    privileges: labeled(priv),
    isolation: labeled(row.network_isolation).join("；"),
    compatibility: labeled(row.probe_compatibility),
  };
}

export function grantFrom(row: Row): Grant {
  const selectors = Array.isArray(row.Selectors)
    ? row.Selectors.map((item) => {
        const selector = item as Row;
        return { kind: text(selector, "kind"), value: text(selector, "value") };
      })
    : [];
  const ports = Array.isArray(row.Ports)
    ? row.Ports.map((item) => {
        const port = item as Row;
        return { start: num(port, "start"), end: num(port, "end") };
      })
    : [];
  return {
    id: text(row, "ID"),
    name: text(row, "Name"),
    subjectType: text(row, "SubjectType"),
    selectors,
    transports: list(row.AllowedTransports),
    ports,
    operations: list(row.AllowedOperations),
    points: list(row.ObservationPointIDs),
    validFrom: text(row, "ValidFrom"),
    validUntil: optionalTime(row.ValidUntil),
    maxTargets: num(row, "MaxTargets"),
    maxAddresses: num(row, "MaxAddresses"),
    maxConnections: num(row, "MaxConnections"),
    maxRequests: num(row, "MaxRequests"),
    maxConcurrency: num(row, "MaxConcurrency"),
    maxRatePerSecond: num(row, "MaxRatePerSecond"),
    maxRuntimeSeconds: Math.round(num(row, "MaxRuntime") / 1e9),
    maxEvidenceBytes: num(row, "MaxEvidenceBytes"),
    status: text(row, "Status"),
    revocationReason: text(row, "RevocationReason"),
    createdAt: text(row, "CreatedAt"),
  };
}

export function revisionFrom(row: Row): Revision {
  return {
    id: text(row, "ID"),
    action: text(row, "Action"),
    actorId: text(row, "ActorID"),
    at: text(row, "At"),
    content: row.Content ?? null,
  };
}

export function scheduleFrom(row: Row): Schedule {
  return {
    id: text(row, "id"),
    name: text(row, "name"),
    trigger: text(row, "trigger_type"),
    status: text(row, "status"),
    intervalSeconds: num(row, "interval_seconds"),
    nextRunAt: text(row, "next_run_at"),
    grantId: text(row, "grant_id"),
    target: text(row, "target"),
    lastResult: text(row, "last_result"),
  };
}

export function scanFrom(row: Row): ScanRun {
  return {
    id: text(row, "ID"),
    name: text(row, "Name"),
    grantId: text(row, "ScopeGrantID"),
    trigger: text(row, "TriggerType"),
    status: text(row, "Status"),
    total: num(row, "ProgressTotal"),
    done: num(row, "ProgressDone"),
    failed: num(row, "ProgressFailed"),
    skipped: num(row, "ProgressSkipped"),
    summary: text(row, "FailureSummary"),
    createdAt: text(row, "CreatedAt"),
    startedAt: optionalTime(row.StartedAt),
    finishedAt: optionalTime(row.FinishedAt),
  };
}

export function observationFrom(row: Row): Observation {
  return {
    id: text(row, "ID"),
    type: text(row, "Type"),
    subject: text(row, "SubjectKey"),
    status: text(row, "ResultStatus"),
    observedAt: text(row, "ObservedAt"),
    value: row.Value ?? null,
  };
}

export function findingFrom(row: Row): Finding {
  return {
    id: text(row, "ID"),
    key: text(row, "FindingKey"),
    type: text(row, "FindingType"),
    vulnerabilityId: text(row, "VulnerabilityID"),
    title: text(row, "Title"),
    severity: text(row, "Severity"),
    status: text(row, "Status"),
    assetId: text(row, "AssetID"),
    endpointId: text(row, "EndpointID"),
    firstSeen: text(row, "FirstSeenAt"),
    lastSeen: text(row, "LastSeenAt"),
    dispositionType: text(row, "ActiveDispositionType"),
  };
}

export function dispositionFrom(row: Row): Disposition {
  return {
    id: text(row, "ID"),
    type: text(row, "Type"),
    reason: text(row, "Reason"),
    createdAt: text(row, "CreatedAt"),
    validUntil: optionalTime(row.ValidUntil),
  };
}

export function assetFrom(row: Row): Asset {
  return {
    id: text(row, "ID"),
    type: text(row, "AssetType"),
    family: text(row, "PlatformFamily"),
    name: text(row, "PlatformName"),
    version: text(row, "PlatformVersion"),
    hash: text(row, "MachineIDHash"),
    status: text(row, "IdentityStatus"),
    lastSeen: text(row, "LastObservedAt"),
  };
}

export function endpointFrom(row: Row): Endpoint {
  return {
    id: text(row, "ID"),
    address: text(row, "Address"),
    transport: text(row, "Transport"),
    port: num(row, "Port"),
    state: text(row, "CurrentState"),
    assetId: text(row, "AssetID"),
    lastSeen: text(row, "LastObservedAt"),
  };
}

export function targetFrom(row: Row): Target {
  return {
    id: text(row, "ID"),
    type: text(row, "TargetType"),
    raw: text(row, "RawValue"),
    normalized: text(row, "NormalizedValue"),
    transport: text(row, "Transport"),
    createdAt: text(row, "CreatedAt"),
  };
}

export function hypothesisFrom(row: Row): Hypothesis {
  return {
    id: text(row, "ID"),
    endpointId: text(row, "EndpointID"),
    service: text(row, "ServiceType"),
    product: text(row, "RawProductName"),
    version: text(row, "RawVersion"),
    normalized: text(row, "NormalizedVersion"),
    status: text(row, "IdentityStatus"),
    confidence: text(row, "Confidence"),
    evaluatedAt: text(row, "EvaluatedAt"),
  };
}

export function packFrom(row: Row): Pack {
  return {
    id: text(row, "id"),
    version: text(row, "version"),
    status: text(row, "status"),
    rules: Array.isArray(row.rules) ? row.rules.length : typeof row.rules === "number" ? row.rules : undefined,
    accepted: typeof row.accepted === "number" ? row.accepted : undefined,
    skipped: typeof row.skipped === "number" ? row.skipped : undefined,
    license: row.license_recorded === true,
  };
}

export function templateFrom(row: Row): Template {
  return {
    id: text(row, "id"),
    key: text(row, "key"),
    name: text(row, "name"),
    severity: text(row, "severity"),
    cve: text(row, "cve_id"),
    status: text(row, "status"),
    enabled: row.enabled === true,
    bound: num(row, "request_bound"),
  };
}

export function snapshotFrom(row: Row): Snapshot {
  return {
    id: text(row, "id"),
    digest: text(row, "content_digest"),
    sources: list(row.sources),
    statements: num(row, "statement_count"),
    publishedAt: text(row, "published_at"),
  };
}

export function rows(payload: unknown, key: string): Row[] {
  if (!payload || typeof payload !== "object") {
    return [];
  }
  const value = (payload as Row)[key];
  return Array.isArray(value) ? value.filter((item): item is Row => !!item && typeof item === "object") : [];
}

export function zeroID(value: string): boolean {
  return value === "" || value === "00000000-0000-0000-0000-000000000000";
}

export function when(value: string | null): string {
  if (!value) {
    return "";
  }
  const date = new Date(value);
  if (Number.isNaN(date.getTime())) {
    return value;
  }
  return date.toLocaleString();
}
