import { motion } from "framer-motion";
import { Ghost, ShieldCheck, ShieldWarning, Warning } from "@phosphor-icons/react";
import { PageHeader, StatCard, stagger } from "@/components/PageBits";
import { Badge, Card, EmptyState, Skeleton } from "@/components/ui";
import { api, type PostureSummary } from "@/lib/api";
import { useData } from "@/lib/hooks";
import { fmt } from "@/lib/utils";

export function Posture() {
  const { data, loading, error } = useData<PostureSummary>(() => api.get("/api/posture/summary"), []);
  const total = data?.total ?? 0;

  return (
    <div className="space-y-6">
      <PageHeader
        title="API Perimeter Posture"
        desc="Quantified security coverage across all discovered endpoints — evaluating policy attachment, schema validation, and authentication guarantees."
        badge={
          <Badge tone="accent" className="font-mono text-xs">
            {fmt(total)} ENDPOINTS
          </Badge>
        }
      />

      {error ? (
        <EmptyState title="Posture unavailable" hint={error} />
      ) : (
        <div className="space-y-6">
          <div className="grid gap-6 lg:grid-cols-[300px_1fr]">
            <CoverageRing pct={data?.coverage_pct ?? 0} loading={loading} />
            <motion.div variants={stagger} initial="hidden" animate="show" className="grid grid-cols-2 gap-4">
              <StatCard
                label="Shield Protected"
                value={data?.protected ?? 0}
                icon={<ShieldCheck size={16} />}
                tone="ok"
                loading={loading}
                hint={total > 0 ? `${Math.round(((data?.protected ?? 0) / total) * 100)}% of perimeter` : "Full policy shield"}
              />
              <StatCard
                label="Partial Shield"
                value={data?.partial ?? 0}
                icon={<ShieldWarning size={16} />}
                tone="warn"
                loading={loading}
                hint="Missing rate limit or schema filter"
              />
              <StatCard
                label="Unprotected"
                value={data?.unprotected ?? 0}
                icon={<Warning size={16} />}
                tone="danger"
                loading={loading}
                hint="Zero mitigation policies attached"
              />
              <StatCard
                label="Shadow Endpoints"
                value={data?.shadow ?? 0}
                icon={<Ghost size={16} />}
                tone="danger"
                loading={loading}
                hint="Undocumented routes in production"
              />
            </motion.div>
          </div>

          {/* Breakdown progress bar */}
          {data && total > 0 && (
            <Card className="p-5 sm:p-6">
              <div className="flex items-center justify-between border-b border-border/50 pb-3">
                <h3 className="text-sm font-semibold text-fg">Perimeter Distribution Spectrum</h3>
                <span className="font-mono text-xs text-muted">{fmt(total)} total routes</span>
              </div>

              <div className="mt-4">
                <div className="flex h-3 w-full overflow-hidden rounded-full bg-elevated/80 border border-border/50">
                  <div
                    style={{ width: `${(data.protected / total) * 100}%` }}
                    className="bg-emerald-500 transition-all duration-500"
                    title={`Protected: ${data.protected}`}
                  />
                  <div
                    style={{ width: `${(data.partial / total) * 100}%` }}
                    className="bg-amber-500 transition-all duration-500"
                    title={`Partial: ${data.partial}`}
                  />
                  <div
                    style={{ width: `${(data.unprotected / total) * 100}%` }}
                    className="bg-slate-500 transition-all duration-500"
                    title={`Unprotected: ${data.unprotected}`}
                  />
                  <div
                    style={{ width: `${(data.shadow / total) * 100}%` }}
                    className="bg-rose-500 transition-all duration-500"
                    title={`Shadow: ${data.shadow}`}
                  />
                </div>

                <div className="mt-4 grid grid-cols-2 gap-4 font-mono text-xs sm:grid-cols-4">
                  <div className="flex items-center gap-2">
                    <span className="h-2 w-2 rounded-full bg-emerald-500 shrink-0" />
                    <span className="text-muted">Protected:</span>
                    <span className="font-semibold text-fg">{data.protected}</span>
                  </div>
                  <div className="flex items-center gap-2">
                    <span className="h-2 w-2 rounded-full bg-amber-500 shrink-0" />
                    <span className="text-muted">Partial:</span>
                    <span className="font-semibold text-fg">{data.partial}</span>
                  </div>
                  <div className="flex items-center gap-2">
                    <span className="h-2 w-2 rounded-full bg-slate-500 shrink-0" />
                    <span className="text-muted">Unprotected:</span>
                    <span className="font-semibold text-fg">{data.unprotected}</span>
                  </div>
                  <div className="flex items-center gap-2">
                    <span className="h-2 w-2 rounded-full bg-rose-500 shrink-0" />
                    <span className="text-muted">Shadow:</span>
                    <span className="font-semibold text-fg">{data.shadow}</span>
                  </div>
                </div>
              </div>
            </Card>
          )}
        </div>
      )}
    </div>
  );
}

function CoverageRing({ pct, loading }: { pct: number; loading: boolean }) {
  const r = 54;
  const c = 2 * Math.PI * r;
  const tone = pct >= 70 ? "hsl(var(--ok))" : pct >= 40 ? "hsl(var(--warn))" : "hsl(var(--danger))";

  return (
    <Card className="flex flex-col items-center justify-center p-6 text-center">
      {loading ? (
        <Skeleton className="h-36 w-36 rounded-full" />
      ) : (
        <div className="relative h-40 w-40 flex items-center justify-center">
          <svg className="h-full w-full -rotate-90" viewBox="0 0 136 136">
            <circle cx="68" cy="68" r={r} fill="none" stroke="hsl(var(--elevated))" strokeWidth="12" />
            <motion.circle
              cx="68"
              cy="68"
              r={r}
              fill="none"
              stroke={tone}
              strokeWidth="12"
              strokeLinecap="round"
              strokeDasharray={c}
              initial={{ strokeDashoffset: c }}
              animate={{ strokeDashoffset: c - (c * pct) / 100 }}
              transition={{ duration: 0.9, ease: "easeOut" }}
            />
          </svg>
          <div className="absolute inset-0 flex flex-col items-center justify-center">
            <span className="font-mono text-3xl font-bold tnum text-fg">{Math.round(pct)}%</span>
            <span className="font-mono text-[9px] uppercase tracking-wider text-muted">SHIELD COVERAGE</span>
          </div>
        </div>
      )}
      <p className="mt-3 text-xs text-muted max-w-[200px] leading-relaxed">
        Proportion of catalog routes covered by active WAF and rate policies.
      </p>
    </Card>
  );
}
