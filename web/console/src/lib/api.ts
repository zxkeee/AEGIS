// Thin admin-API client. Auth is cookie-based (HttpOnly session set by the
// gateway); mutations carry the CSRF token from the readable aegis_csrf cookie
// (double-submit). All requests are same-origin with credentials.

export class ApiError extends Error {
  status: number;
  constructor(status: number, message: string) {
    super(message);
    this.status = status;
  }
}

function csrfToken(): string {
  const m = document.cookie.match(/(?:^|;\s*)aegis_csrf=([^;]+)/);
  return m ? decodeURIComponent(m[1]) : "";
}

async function request<T>(method: string, path: string, body?: unknown): Promise<T> {
  const headers: Record<string, string> = {};
  const opts: RequestInit = { method, credentials: "same-origin", headers };
  if (body !== undefined) {
    headers["Content-Type"] = "application/json";
    opts.body = JSON.stringify(body);
  }
  if (method !== "GET" && method !== "HEAD") {
    headers["X-CSRF-Token"] = csrfToken();
  }
  const res = await fetch(path, opts);
  if (res.status === 401 || res.status === 403) {
    // Session gone / not authorized — signal the app to show the login screen.
    if (path !== "/api/login") window.dispatchEvent(new CustomEvent("aegis:unauthorized"));
  }
  const text = await res.text();
  const data = text ? safeJSON(text) : null;
  if (!res.ok) {
    const msg = (data && (data.error || data.message)) || res.statusText;
    throw new ApiError(res.status, msg);
  }
  return data as T;
}

function safeJSON(t: string): any {
  try {
    return JSON.parse(t);
  } catch {
    return null;
  }
}

export const api = {
  get: <T>(p: string) => request<T>("GET", p),
  post: <T>(p: string, b?: unknown) => request<T>("POST", p, b),
  del: <T>(p: string, b?: unknown) => request<T>("DELETE", p, b),

  // ── Auth ──
  loginSecret: (secret: string) => request<LoginResp>("POST", "/api/login", { secret }),
  loginPassword: (email: string, password: string, tenant?: string) =>
    request<LoginResp>("POST", "/api/login", { email, password, tenant }),
  logout: () => request<unknown>("POST", "/api/logout"),
  session: () => request<SessionResp>("GET", "/api/session"),
  license: () => request<LicenseResp>("GET", "/api/license"),

  // ── Tenants & users (Settings page) ──
  listTenants: () => request<{ tenants: Tenant[]; count: number }>("GET", "/api/tenants"),
  createTenant: (id: string, name: string) => request<Tenant>("POST", "/api/tenants", { id, name }),
  deleteTenant: (id: string) => request<{ id: string; deleted: boolean }>("DELETE", `/api/tenants/${encodeURIComponent(id)}`),
  listUsers: (tenant?: string) => request<{ users: IamUser[]; count: number }>("GET", tenant ? `/api/users?tenant=${encodeURIComponent(tenant)}` : "/api/users"),
  createUser: (body: { email: string; password: string; role: string; tenant?: string; super_admin?: boolean }) =>
    request<IamUser>("POST", "/api/users", body),
  deleteUser: (id: string) => request<{ id: string; deleted: boolean }>("DELETE", `/api/users/${encodeURIComponent(id)}`),
  audit: (params: { action?: string; limit?: number; all?: boolean } = {}) => {
    const q = new URLSearchParams();
    if (params.action) q.set("action", params.action);
    if (params.limit) q.set("limit", String(params.limit));
    if (params.all) q.set("all", "true");
    const qs = q.toString();
    return request<{ entries: AuditEntry[]; count: number }>("GET", `/api/audit${qs ? `?${qs}` : ""}`);
  },
};

// ── Response types ──
export interface LoginResp {
  auth: boolean;
  csrf: string;
  tenant?: string;
  role?: string;
  super_admin?: boolean;
}

export interface SessionResp {
  tenant: string;
  role: string;
  super_admin: boolean;
}

export interface LicenseResp {
  valid: boolean;
  grace: boolean;
  licensee?: string;
  tier?: string;
  expires_at?: string;
  days_left?: number;
  grace_until?: string;
  reason?: string;
}

/** Client-side session shape held in App state, threaded down to pages. */
export type Session = { tenant?: string; role?: string; superAdmin?: boolean };

export interface Tenant {
  id: string;
  name: string;
  created_at: string;
}

export interface IamUser {
  id: string;
  tenant_id: string;
  email: string;
  role: string;
  super_admin: boolean;
  created_at: string;
}

export interface AuditEntry {
  time: string;
  tenant_id: string;
  actor_id?: string;
  actor_email?: string;
  role?: string;
  super_admin?: boolean;
  action: string;
  method?: string;
  path?: string;
  status?: number;
  ip?: string;
  detail?: string;
}

// The answer to "has the forensic log been tampered with", as GET
// /api/forensic/seals returns it.
//
// `intact` is the whole answer and requires both halves: every sealed period
// still recomputes AND no seal is missing. A chain can be internally perfect and
// three periods short, which is the cheap attack the chain head exists to catch.
export interface SealChainCheck {
  complete: boolean;
  head_present: boolean;
  head_seq: number;
  seals_found: number;
  highest_seq: number;
  head_key_id?: string;
  detail?: string;
}

export interface SealCheck {
  seal: {
    tenant_id: string;
    seq: number;
    period_start: string;
    period_end: string;
    entry_count: number;
    merkle_root: string;
    prev_root: string;
    sealed_at: string;
  };
  actual_count: number;
  actual_root: string;
  intact: boolean;
  detail?: string;
}

export interface SealReport {
  generated_at: string;
  tenant: string;
  intact: boolean;
  chain: SealChainCheck;
  seals: SealCheck[];
  summary: { periods: number; intact: number; altered: number };
  // What this document does NOT establish, carried with the result rather than
  // left in the API docs. Rendered, not hidden behind a link: a green
  // verification result is exactly the thing a reader over-interprets.
  limits: string[];
}

export type Metrics = Record<string, number>;

export interface PostureSummary {
  total: number;
  protected: number;
  partial: number;
  unprotected: number;
  shadow: number;
  coverage_pct: number;
  top_risky?: Endpoint[];
}

export interface Endpoint {
  id: string;
  method: string;
  path_template: string;
  posture: string;
  risk_score: number;
  request_count: number;
  error_count: number;
  auth_present_count: number;
  anon_count: number;
  pii_count: number;
  avg_latency_ms: number;
  last_seen: string;
}

export interface Consumer {
  id: string;
  kind: string;
  label: string;
  request_count: number;
  error_count: number;
  endpoints_touched: number;
  last_seen: string;
}

export interface Finding {
  method: string;
  path_template: string;
  risk_score: number;
  // Field names match discovery.Finding (Go) exactly — code/owasp/severity/title/why.
  finding: { code: string; owasp: string; severity: string; title: string; why: string };
}

export interface BlockEntry {
  tenant?: string;
  timestamp: string;
  ip: string;
  path: string;
  method: string;
  reason: string;
  code: number;
  // extra carries per-event detail (severity, why, owner, …) for abuse
  // detections like BOLA/BFLA. Present on security-relevant events.
  extra?: Record<string, unknown>;
}

export interface GraphNode {
  id: string;
  type: "consumer" | "endpoint";
  label: string;
  requests: number;
  kind?: string;
  method?: string;
  posture?: string;
  risk?: number;
  pii?: boolean;
  flagged?: boolean; // appears in recent BOLA/BFLA abuse events
  abuse_count?: number;
}
export interface GraphEdge {
  source: string;
  target: string;
  requests: number;
}
export interface Graph {
  nodes: GraphNode[];
  edges: GraphEdge[];
}

export interface ComplianceControl {
  framework: string;
  control: string;
  title: string;
  severity: string;
  count: number;
  issues: string[];
}
export interface UncoveredControl {
  control: string;
  title: string;
  reason: string;
}
export interface ComplianceFramework {
  framework: string;
  controls: ComplianceControl[];
  /** Controls of this framework AEGIS structurally cannot evidence, with the reason. */
  not_evidenced?: UncoveredControl[];
}
export interface ComplianceReport {
  frameworks: ComplianceFramework[];
  summary: { critical: number; warning: number; controls_affected: number };
}

export interface Effectiveness {
  blocks_by_control: Record<string, number>;
  total_blocks: number;
  passed_waf: number;
  coverage_pct?: number;
}
