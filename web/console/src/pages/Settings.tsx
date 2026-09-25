import { motion } from "framer-motion";
import { Buildings, Scroll, SealQuestion, Trash, UserPlus, UsersThree } from "@phosphor-icons/react";
import { useState } from "react";
import { ErrorNote, PageHeader, Row, Table, Td, Th } from "@/components/PageBits";
import { Badge, Button, Card, EmptyState, Input, Spinner } from "@/components/ui";
import { api, type AuditEntry, type IamUser, type Session, type Tenant } from "@/lib/api";
import { useData } from "@/lib/hooks";
import { useToast } from "@/lib/toast";
import { timeAgo } from "@/lib/utils";

export function Settings({ session }: { session: Session }) {
  return (
    <div className="space-y-8">
      <PageHeader
        title="System Settings & Governance"
        desc="Multi-tenant organization partitioning, role-based access delegation, and cryptographically verified audit records."
        badge={
          <Badge tone="accent" className="font-mono text-xs">
            TENANT: {session.tenant ?? "default"}
          </Badge>
        }
      />
      <TenantsSection session={session} />
      <UsersSection session={session} />
      <AuditSection session={session} />
    </div>
  );
}

// ── Tenants ──────────────────────────────────────────────────────────────────
function TenantsSection({ session }: { session: Session }) {
  const toast = useToast();
  const tenants = useData<{ tenants: Tenant[]; count: number }>(() => api.listTenants(), []);
  const [id, setId] = useState("");
  const [name, setName] = useState("");
  const [busy, setBusy] = useState<string | null>(null);

  async function create() {
    if (!id.trim()) return;
    setBusy("create");
    try {
      await api.createTenant(id.trim(), name.trim() || id.trim());
      toast("ok", `Tenant "${id.trim()}" created`);
      setId("");
      setName("");
      tenants.refresh();
    } catch (e) {
      toast("err", e instanceof Error ? e.message : "Failed to create tenant");
    } finally {
      setBusy(null);
    }
  }

  async function remove(tid: string) {
    setBusy(tid);
    try {
      await api.deleteTenant(tid);
      toast("ok", `Tenant "${tid}" deleted`);
      tenants.refresh();
    } catch (e) {
      toast("err", e instanceof Error ? e.message : "Failed to delete tenant");
    } finally {
      setBusy(null);
    }
  }

  return (
    <section>
      <div className="mb-3 flex items-center justify-between">
        <h3 className="flex items-center gap-2 text-sm font-semibold text-fg">
          <Buildings size={16} className="text-accent" />
          <span>Tenants & Workspaces</span>
        </h3>
        <span className="font-mono text-xs text-muted">
          {tenants.data?.count ?? 0} active tenant{tenants.data?.count === 1 ? "" : "s"}
        </span>
      </div>

      <Card className="p-5 sm:p-6">
        {session.superAdmin && (
          <div className="mb-5 flex flex-wrap gap-2.5 border-b border-border/50 pb-4">
            <Input
              value={id}
              onChange={(e) => setId(e.target.value)}
              placeholder="tenant-id (e.g. acme-corp)"
              className="max-w-[12rem] font-mono text-xs"
            />
            <Input
              value={name}
              onChange={(e) => setName(e.target.value)}
              placeholder="Display name (optional)"
              className="max-w-xs text-xs"
            />
            <Button onClick={create} disabled={busy === "create"} className="shrink-0">
              {busy === "create" ? <Spinner /> : <Buildings size={15} />}
              <span>Create Tenant</span>
            </Button>
          </div>
        )}

        {tenants.error ? (
          <ErrorNote error={tenants.error} />
        ) : !tenants.data?.tenants.length ? (
          <EmptyState title="No tenants registered" />
        ) : (
          <div className="space-y-2">
            {tenants.data.tenants.map((t) => (
              <motion.div
                key={t.id}
                layout
                initial={{ opacity: 0 }}
                animate={{ opacity: 1 }}
                className="flex items-center justify-between gap-3 rounded-lg border border-border/70 bg-bg/70 px-3.5 py-2.5 transition-colors hover:bg-elevated/40"
              >
                <div className="flex items-center gap-2.5 font-mono text-xs">
                  <span className="font-semibold text-fg">{t.id}</span>
                  {t.name && t.name !== t.id && <span className="font-sans text-xs text-muted">({t.name})</span>}
                  {t.id === session.tenant && (
                    <Badge tone="ok" dot className="text-[10px]">
                      ACTIVE CONTEXT
                    </Badge>
                  )}
                </div>

                {session.superAdmin && t.id !== "default" && (
                  <Button
                    variant="ghost"
                    size="icon"
                    onClick={() => remove(t.id)}
                    disabled={busy === t.id}
                    aria-label={`Delete ${t.id}`}
                    className="text-muted hover:text-danger"
                  >
                    {busy === t.id ? <Spinner /> : <Trash size={15} />}
                  </Button>
                )}
              </motion.div>
            ))}
          </div>
        )}
        {!session.superAdmin && (
          <p className="mt-3 text-xs text-muted/70">
            Scope limited to tenant: <code className="text-fg">{session.tenant}</code>. Super-admin privilege required for multi-tenant administration.
          </p>
        )}
      </Card>
    </section>
  );
}

// ── Users ────────────────────────────────────────────────────────────────────
function UsersSection({ session }: { session: Session }) {
  const toast = useToast();
  const users = useData<{ users: IamUser[]; count: number }>(() => api.listUsers(), []);
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [role, setRole] = useState("admin");
  const [superAdmin, setSuperAdmin] = useState(false);
  const [busy, setBusy] = useState<string | null>(null);

  async function create() {
    if (!email.trim() || password.length < 12) {
      toast("err", "Email and a 12+ character password are required");
      return;
    }
    setBusy("create");
    try {
      await api.createUser({ email: email.trim(), password, role, super_admin: session.superAdmin ? superAdmin : undefined });
      toast("ok", `User ${email.trim()} created`);
      setEmail("");
      setPassword("");
      users.refresh();
    } catch (e) {
      toast("err", e instanceof Error ? e.message : "Failed to create user");
    } finally {
      setBusy(null);
    }
  }

  async function remove(u: IamUser) {
    setBusy(u.id);
    try {
      await api.deleteUser(u.id);
      toast("ok", `${u.email} removed`);
      users.refresh();
    } catch (e) {
      toast("err", e instanceof Error ? e.message : "Failed to delete user");
    } finally {
      setBusy(null);
    }
  }

  return (
    <section>
      <div className="mb-3 flex items-center justify-between">
        <h3 className="flex items-center gap-2 text-sm font-semibold text-fg">
          <UsersThree size={16} className="text-accent" />
          <span>Console Operators (IAM)</span>
        </h3>
        <span className="font-mono text-xs text-muted">
          {users.data?.count ?? 0} operator{users.data?.count === 1 ? "" : "s"}
        </span>
      </div>

      <Card className="p-5 sm:p-6">
        <div className="mb-5 flex flex-wrap items-center gap-2.5 border-b border-border/50 pb-4">
          <Input
            value={email}
            onChange={(e) => setEmail(e.target.value)}
            placeholder="operator@company.com"
            className="max-w-[14rem] text-xs"
          />
          <Input
            value={password}
            onChange={(e) => setPassword(e.target.value)}
            placeholder="Password (min 12 chars)"
            type="password"
            className="max-w-[12rem] text-xs"
          />
          <select
            value={role}
            onChange={(e) => setRole(e.target.value)}
            className="h-9 rounded-lg border border-border/80 bg-bg px-3 text-xs text-fg focus-visible:outline-none focus-visible:ring-1 focus-visible:ring-accent"
          >
            <option value="admin">Administrator</option>
            <option value="viewer">Security Auditor (Read-only)</option>
          </select>
          {session.superAdmin && (
            <label className="flex h-9 items-center gap-2 rounded-lg border border-border/80 px-3 text-xs text-muted cursor-pointer hover:bg-elevated/40">
              <input type="checkbox" checked={superAdmin} onChange={(e) => setSuperAdmin(e.target.checked)} className="accent-accent" />
              <span>Super-admin</span>
            </label>
          )}
          <Button onClick={create} disabled={busy === "create"} className="shrink-0">
            {busy === "create" ? <Spinner /> : <UserPlus size={15} />}
            <span>Add Operator</span>
          </Button>
        </div>

        {users.error ? (
          <ErrorNote error={users.error} />
        ) : !users.data?.users.length ? (
          <EmptyState title="No operators configured yet" hint="Create credentials so teammates have individual audit trails." />
        ) : (
          <Table
            head={
              <>
                <Th>Operator Identity</Th>
                <Th>RBAC Role</Th>
                <Th className="hidden md:table-cell">Tenant Scope</Th>
                <Th className="hidden text-right sm:table-cell">Enrolled</Th>
                <Th className="text-right">Action</Th>
              </>
            }
          >
            {users.data.users.map((u, i) => (
              <Row key={u.id} i={i}>
                <Td className="text-xs">
                  <div className="flex items-center gap-2">
                    <span className="font-semibold text-fg">{u.email}</span>
                  </div>
                </Td>
                <Td>
                  <div className="flex items-center gap-1.5 font-mono text-xs">
                    <Badge tone={u.role === "admin" ? "accent" : "neutral"} className="uppercase text-[10px]">
                      {u.role}
                    </Badge>
                    {u.super_admin && <Badge tone="warn" className="uppercase text-[10px]">SUPER</Badge>}
                  </div>
                </Td>
                <Td className="hidden font-mono text-xs text-muted md:table-cell">{u.tenant_id}</Td>
                <Td className="hidden text-right font-mono text-xs text-muted sm:table-cell">{timeAgo(u.created_at)}</Td>
                <Td className="text-right">
                  <Button
                    variant="ghost"
                    size="icon"
                    onClick={() => remove(u)}
                    disabled={busy === u.id}
                    aria-label={`Remove ${u.email}`}
                    className="text-muted hover:text-danger"
                  >
                    {busy === u.id ? <Spinner /> : <Trash size={15} />}
                  </Button>
                </Td>
              </Row>
            ))}
          </Table>
        )}
      </Card>
    </section>
  );
}

// ── Audit log ────────────────────────────────────────────────────────────────
function AuditSection({ session }: { session: Session }) {
  const [all, setAll] = useState(false);
  const audit = useData<{ entries: AuditEntry[]; count: number }>(() => api.audit({ limit: 100, all }), [all]);
  const disabled = audit.error?.includes("audit log is disabled");

  return (
    <section>
      <div className="mb-3 flex items-center justify-between">
        <h3 className="flex items-center gap-2 text-sm font-semibold text-fg">
          <Scroll size={16} className="text-accent" />
          <span>Administrative Action Log</span>
        </h3>
        {session.superAdmin && (
          <label className="flex items-center gap-2 font-mono text-xs text-muted cursor-pointer hover:text-fg">
            <input type="checkbox" checked={all} onChange={(e) => setAll(e.target.checked)} className="accent-accent" />
            <span>Show all cluster tenants</span>
          </label>
        )}
      </div>

      {audit.error && !disabled ? (
        <ErrorNote error={audit.error} />
      ) : disabled || !audit.data?.entries.length ? (
        <Card className="p-5">
          <EmptyState
            icon={<SealQuestion size={36} />}
            title={disabled ? "Audit logging is dormant" : "No administrative events yet"}
            hint={disabled ? "Configure forensic_dsn in aegis.yaml to enable cryptographically sealed audit logging." : "Logins, policy changes, and token revocations will record here."}
          />
        </Card>
      ) : (
        <Table
          head={
            <>
              <Th>Operation</Th>
              <Th>Operator</Th>
              <Th className="hidden md:table-cell">Tenant</Th>
              <Th className="hidden text-right sm:table-cell">Status</Th>
              <Th className="text-right">Timestamp</Th>
            </>
          }
        >
          {(audit.data?.entries ?? []).map((e, i) => (
            <Row key={i} i={i}>
              <Td>
                <Badge
                  tone={e.action.includes("fail") ? "danger" : e.action === "login" ? "accent" : "neutral"}
                  className="font-mono uppercase text-[10px]"
                >
                  {e.action.replace(/_/g, " ")}
                </Badge>
              </Td>
              <Td className="font-mono text-xs">{e.actor_email || e.actor_id || "bootstrap secret"}</Td>
              <Td className="hidden font-mono text-xs text-muted md:table-cell">{e.tenant_id}</Td>
              <Td className="hidden text-right font-mono text-xs tnum sm:table-cell">
                {e.status ? (
                  <span className={e.status >= 400 ? "text-danger font-semibold" : "text-ok"}>{e.status}</span>
                ) : (
                  <span className="text-muted/60">—</span>
                )}
              </Td>
              <Td className="text-right font-mono text-xs text-muted">{timeAgo(e.time)}</Td>
            </Row>
          ))}
        </Table>
      )}
    </section>
  );
}
