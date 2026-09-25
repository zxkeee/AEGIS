import { motion } from "framer-motion";
import { Prohibit, Key, ShieldSlash, Trash, Clock, MagnifyingGlass } from "@phosphor-icons/react";
import { useMemo, useState } from "react";
import { ErrorNote, PageHeader } from "@/components/PageBits";
import { Badge, Button, Card, CopyButton, EmptyState, Input, Spinner } from "@/components/ui";
import { api } from "@/lib/api";
import { useData } from "@/lib/hooks";
import { useToast } from "@/lib/toast";

interface BlockedIP {
  ip: string;
  source: "manual" | "auto" | "manual+auto";
  ttl_seconds?: number;
}

function fmtTTL(secs?: number): string {
  if (!secs || secs <= 0) return "";
  const m = Math.ceil(secs / 60);
  return m < 60 ? `${m}m` : `${Math.ceil(m / 60)}h`;
}

export function Access() {
  const toast = useToast();
  const ips = useData<{ ips: BlockedIP[]; count: number }>(() => api.get("/api/blocked-ips"), []);
  const [newIP, setNewIP] = useState("");
  const [jti, setJti] = useState("");
  const [searchIP, setSearchIP] = useState("");
  const [busy, setBusy] = useState<string | null>(null);

  async function block() {
    if (!newIP.trim()) return;
    setBusy("block");
    try {
      await api.post("/api/blocked-ips", { ip: newIP.trim(), reason: "manual" });
      toast("ok", `Blocked ${newIP.trim()}`);
      setNewIP("");
      ips.refresh();
    } catch (e) {
      toast("err", e instanceof Error ? e.message : "Failed to block IP");
    } finally {
      setBusy(null);
    }
  }

  async function unblock(ip: string, source?: "manual" | "auto") {
    setBusy(ip + (source ?? ""));
    try {
      const qs = source ? `?source=${source}` : "";
      await api.del(`/api/blocked-ips/${encodeURIComponent(ip)}${qs}`);
      toast("ok", source ? `Lifted ${source} block on ${ip}` : `Unblocked ${ip}`);
      ips.refresh();
    } catch (e) {
      toast("err", e instanceof Error ? e.message : "Failed to unblock");
    } finally {
      setBusy(null);
    }
  }

  async function revoke() {
    if (!jti.trim()) return;
    setBusy("revoke");
    try {
      await api.post("/api/jwt/revoke", { jti: jti.trim() });
      toast("ok", "Token revoked and blacklisted");
      setJti("");
    } catch (e) {
      toast("err", e instanceof Error ? e.message : "Failed to revoke token");
    } finally {
      setBusy(null);
    }
  }

  const filteredIPs = useMemo(() => {
    const list = ips.data?.ips ?? [];
    if (!searchIP.trim()) return list;
    return list.filter((i) => i.ip.includes(searchIP.trim()));
  }, [ips.data, searchIP]);

  return (
    <div className="space-y-6">
      <PageHeader
        title="Access Control & Shield Policies"
        desc="Instant perimeter containment: tenant-scoped IP blocklisting, automated threat bans, and cryptographic token revocation."
        badge={
          <Badge tone="accent" className="font-mono text-xs">
            {ips.data?.count ?? 0} ACTIVE BANS
          </Badge>
        }
      />

      <div className="grid gap-6 lg:grid-cols-2">
        {/* IP Blocklist Card */}
        <Card className="flex flex-col p-5 sm:p-6">
          <div className="flex items-center justify-between border-b border-border/50 pb-3">
            <h3 className="flex items-center gap-2 text-sm font-semibold text-fg">
              <ShieldSlash size={17} className="text-danger" />
              <span>IP Containment List</span>
            </h3>
            <span className="font-mono text-xs text-muted">
              {filteredIPs.length} IP{filteredIPs.length === 1 ? "" : "s"}
            </span>
          </div>

          <div className="mt-4 flex gap-2">
            <Input
              value={newIP}
              onChange={(e) => setNewIP(e.target.value)}
              onKeyDown={(e) => e.key === "Enter" && block()}
              placeholder="e.g. 198.51.100.42"
              className="font-mono text-xs"
            />
            <Button onClick={block} disabled={busy === "block"} className="shrink-0">
              {busy === "block" ? <Spinner /> : <Prohibit size={15} />}
              <span>Block IP</span>
            </Button>
          </div>

          {ips.data && ips.data.ips.length > 5 && (
            <div className="relative mt-3">
              <MagnifyingGlass size={13} className="absolute left-2.5 top-1/2 -translate-y-1/2 text-muted/60" />
              <Input
                value={searchIP}
                onChange={(e) => setSearchIP(e.target.value)}
                placeholder="Filter blocked IPs..."
                className="h-8 pl-8 font-mono text-xs"
              />
            </div>
          )}

          <div className="mt-4 flex-1 space-y-2 max-h-[460px] overflow-y-auto pr-1">
            {ips.error ? (
              <ErrorNote error={ips.error} />
            ) : filteredIPs.length ? (
              filteredIPs.map((row) => (
                <motion.div
                  key={row.ip}
                  layout
                  initial={{ opacity: 0 }}
                  animate={{ opacity: 1 }}
                  exit={{ opacity: 0 }}
                  className="flex items-center justify-between gap-3 rounded-lg border border-border/70 bg-bg/70 px-3.5 py-2.5 transition-colors hover:bg-elevated/40"
                >
                  <div className="flex min-w-0 items-center gap-2.5">
                    <span className="font-mono text-xs font-semibold text-fg">{row.ip}</span>
                    <CopyButton text={row.ip} />

                    <span
                      className={`inline-flex items-center gap-1 rounded border px-2 py-0.5 font-mono text-[10px] uppercase tracking-wider ${
                        row.source === "manual"
                          ? "border-danger/30 bg-danger/10 text-danger"
                          : row.source === "auto"
                          ? "border-warn/30 bg-warn/10 text-warn"
                          : "border-purple-500/30 bg-purple-500/10 text-purple-400"
                      }`}
                    >
                      {row.source === "auto" && <Clock size={11} />}
                      <span>{row.source}</span>
                      {row.source !== "manual" && row.ttl_seconds ? ` · ${fmtTTL(row.ttl_seconds)}` : ""}
                    </span>
                  </div>

                  {row.source === "manual+auto" ? (
                    <div className="flex shrink-0 gap-1">
                      <Button
                        variant="ghost"
                        size="xs"
                        onClick={() => unblock(row.ip, "auto")}
                        disabled={busy === row.ip + "auto"}
                        title="Lift only auto-ban, preserve permanent manual block"
                        className="text-muted hover:text-fg font-mono text-[11px]"
                      >
                        {busy === row.ip + "auto" ? <Spinner /> : "Lift auto"}
                      </Button>
                      <Button
                        variant="ghost"
                        size="icon"
                        onClick={() => unblock(row.ip, "manual")}
                        disabled={busy === row.ip + "manual"}
                        title="Lift manual block"
                        className="text-muted hover:text-danger"
                      >
                        {busy === row.ip + "manual" ? <Spinner /> : <Trash size={14} />}
                      </Button>
                    </div>
                  ) : (
                    <Button
                      variant="ghost"
                      size="icon"
                      onClick={() => unblock(row.ip)}
                      disabled={busy === row.ip}
                      aria-label={`Unblock ${row.ip}`}
                      className="text-muted hover:text-danger"
                    >
                      {busy === row.ip ? <Spinner /> : <Trash size={14} />}
                    </Button>
                  )}
                </motion.div>
              ))
            ) : (
              <EmptyState title="No IPs currently restricted" hint="Manual and behavioral bans will appear here." />
            )}
          </div>
        </Card>

        {/* JWT Revocation Card */}
        <Card className="flex flex-col p-5 sm:p-6 h-fit">
          <div className="border-b border-border/50 pb-3">
            <h3 className="flex items-center gap-2 text-sm font-semibold text-fg">
              <Key size={17} className="text-warn" />
              <span>Token Revocation (JWT Blacklist)</span>
            </h3>
            <p className="mt-1 text-xs text-muted">
              Broadcast token revocation across all cluster gateway instances using the unique token identifier.
            </p>
          </div>

          <div className="mt-4 space-y-3">
            <label className="block">
              <span className="mb-1.5 block font-mono text-xs font-medium text-muted/80">JWT ID (jti claim)</span>
              <div className="flex gap-2">
                <Input
                  value={jti}
                  onChange={(e) => setJti(e.target.value)}
                  onKeyDown={(e) => e.key === "Enter" && revoke()}
                  placeholder="e.g. b2f1c849-6a34-4b5c-9d10-8e1234567890"
                  className="font-mono text-xs"
                />
                <Button variant="danger" onClick={revoke} disabled={busy === "revoke"} className="shrink-0">
                  {busy === "revoke" ? <Spinner /> : "Revoke"}
                </Button>
              </div>
            </label>

            <div className="rounded-lg border border-border/60 bg-bg/50 p-3.5 text-xs text-muted leading-relaxed font-mono">
              <div className="flex items-center gap-1.5 font-semibold text-fg mb-1">
                <span>POLICY NOTE:</span>
              </div>
              Revoking a token adds its unique <code className="text-accent">jti</code> hash to the distributed Redis revocation store. Any incoming request carrying this token will be instantly rejected with <code className="text-danger">401 Unauthorized</code> until its natural TTL expires.
            </div>
          </div>
        </Card>
      </div>
    </div>
  );
}
