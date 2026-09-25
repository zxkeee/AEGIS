import { motion } from "framer-motion";
import { Key, EnvelopeSimple, ShieldCheck } from "@phosphor-icons/react";
import { useEffect, useState } from "react";
import { Button, Card, Input, Spinner } from "@/components/ui";
import { api } from "@/lib/api";

interface Env {
  admin_auth: boolean;
  sso: boolean;
}

export function Login({ onAuthed }: { onAuthed: (s: { tenant?: string; role?: string; superAdmin?: boolean }) => void }) {
  const [env, setEnv] = useState<Env | null>(null);
  const [mode, setMode] = useState<"secret" | "password">("secret");
  const [secret, setSecret] = useState("");
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [tenant, setTenant] = useState("");
  const [busy, setBusy] = useState(false);
  const [err, setErr] = useState<string | null>(null);

  useEffect(() => {
    api
      .get<Env>("/api/console/env")
      .then(setEnv)
      .catch(() => setEnv({ admin_auth: true, sso: false }));
    if (new URLSearchParams(location.search).has("sso_error")) {
      setErr("SSO sign-in failed. Please try again.");
    }
  }, []);

  async function submit(e: React.FormEvent) {
    e.preventDefault();
    setBusy(true);
    setErr(null);
    try {
      const resp =
        mode === "secret"
          ? await api.loginSecret(secret.trim())
          : await api.loginPassword(email.trim().toLowerCase(), password, tenant.trim() || undefined);
      onAuthed({ tenant: resp.tenant, role: resp.role, superAdmin: resp.super_admin });
    } catch (e2) {
      setErr(e2 instanceof Error ? e2.message : "Invalid credentials");
    } finally {
      setBusy(false);
    }
  }

  return (
    <div className="relative flex min-h-dvh items-center justify-center overflow-hidden px-4">
      {/* Ambient background glow */}
      <div className="pointer-events-none absolute inset-0">
        <div className="absolute left-1/2 top-1/3 h-[40rem] w-[40rem] -translate-x-1/2 rounded-full bg-accent/10 blur-[120px]" />
      </div>

      <motion.div
        initial={{ opacity: 0, y: 16, scale: 0.98 }}
        animate={{ opacity: 1, y: 0, scale: 1 }}
        transition={{ type: "spring", stiffness: 260, damping: 24 }}
        className="relative w-full max-w-sm"
      >
        <Card className="p-8 shadow-card border-border/80">
          <div className="mb-6 flex items-center gap-3">
            <div className="flex h-11 w-11 items-center justify-center rounded-xl bg-accent/15 text-accent border border-accent/30 shadow-[0_0_16px_hsl(var(--accent)/0.3)]">
              <ShieldCheck size={24} weight="bold" />
            </div>
            <div>
              <div className="flex items-center gap-2">
                <h1 className="font-mono text-base font-extrabold tracking-wider text-fg">AEGIS</h1>
                <span className="rounded bg-elevated/90 px-1.5 py-0.5 font-mono text-[9px] font-bold text-accent uppercase tracking-widest border border-border/60">
                  SEC-GW
                </span>
              </div>
              <p className="text-xs text-muted/80">Security Perimeter Command Console</p>
            </div>
          </div>

          <form onSubmit={submit} className="space-y-3">
            {mode === "secret" ? (
              <label className="block">
                <span className="mb-1.5 block text-xs font-medium text-muted">Admin secret</span>
                <div className="relative">
                  <Key size={15} className="absolute left-3 top-1/2 -translate-y-1/2 text-muted/60" />
                  <Input
                    type="password"
                    autoFocus
                    value={secret}
                    onChange={(e) => setSecret(e.target.value)}
                    placeholder="••••••••••••••••"
                    className="pl-9"
                  />
                </div>
              </label>
            ) : (
              <div className="space-y-3">
                <label className="block">
                  <span className="mb-1.5 block text-xs font-medium text-muted">Email</span>
                  <div className="relative">
                    <EnvelopeSimple size={15} className="absolute left-3 top-1/2 -translate-y-1/2 text-muted/60" />
                    <Input
                      type="email"
                      autoComplete="username"
                      value={email}
                      onChange={(e) => setEmail(e.target.value)}
                      placeholder="you@company.com"
                      className="pl-9"
                    />
                  </div>
                </label>
                <Input
                  type="password"
                  autoComplete="current-password"
                  value={password}
                  onChange={(e) => setPassword(e.target.value)}
                  placeholder="Password"
                />
                <Input value={tenant} onChange={(e) => setTenant(e.target.value)} placeholder="Tenant (optional)" />
              </div>
            )}

            {err && (
              <motion.p
                initial={{ opacity: 0, height: 0 }}
                animate={{ opacity: 1, height: "auto" }}
                className="text-xs font-medium text-danger"
              >
                {err}
              </motion.p>
            )}

            <Button type="submit" disabled={busy} className="w-full">
              {busy ? <Spinner /> : "Authenticate"}
            </Button>
          </form>

          {env?.sso && (
            <a href="/api/auth/oidc/login" className="mt-2 block">
              <Button variant="outline" className="w-full">
                Sign in with SSO
              </Button>
            </a>
          )}

          <button
            onClick={() => {
              setErr(null);
              setMode((m) => (m === "secret" ? "password" : "secret"));
            }}
            className="mt-4 w-full text-center text-xs text-muted transition-colors hover:text-fg"
          >
            {mode === "secret" ? "Use email & password" : "Use admin secret"}
          </button>
        </Card>
      </motion.div>
    </div>
  );
}
