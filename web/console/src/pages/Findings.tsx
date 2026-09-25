import { motion } from "framer-motion";
import { useMemo, useState } from "react";
import {
  DownloadSimple,
  MagnifyingGlass,
  Pulse,
  ShieldCheck,
  ShieldWarning,
  Warning,
  WarningCircle,
  X,
} from "@phosphor-icons/react";
import { MethodBadge, SeverityBadge } from "@/components/badges";
import { ErrorNote, PageHeader, StatCard } from "@/components/PageBits";
import { Badge, Card, CopyButton, EmptyState, Input, Skeleton } from "@/components/ui";
import { api, type Finding } from "@/lib/api";
import { useData } from "@/lib/hooks";
import { fmt } from "@/lib/utils";

interface FindingsResp {
  findings: Finding[];
  count: number;
  by_severity: { critical: number; warning: number; info: number };
}

export function Findings() {
  const { data, loading, error } = useData<FindingsResp>(() => api.get("/api/findings"), []);
  const [filter, setFilter] = useState<"all" | "critical" | "warning">("all");
  const [q, setQ] = useState("");

  const avgRisk = useMemo(() => {
    if (!data?.findings.length) return undefined;
    return Math.round(data.findings.reduce((sum, f) => sum + f.risk_score, 0) / data.findings.length);
  }, [data]);

  const filtered = useMemo(() => {
    let list = data?.findings ?? [];
    if (filter !== "all") {
      list = list.filter((f) => f.finding.severity === filter);
    }
    if (q.trim()) {
      const s = q.toLowerCase();
      list = list.filter(
        (f) =>
          f.path_template.toLowerCase().includes(s) ||
          f.method.toLowerCase().includes(s) ||
          f.finding.title.toLowerCase().includes(s) ||
          (f.finding.owasp && f.finding.owasp.toLowerCase().includes(s)),
      );
    }
    return list;
  }, [data, filter, q]);

  return (
    <div className="space-y-6">
      <PageHeader
        title="Vulnerability Findings"
        desc="Actionable security exposures derived from traffic profiling, mapped against the OWASP API Security Top 10."
        badge={
          <Badge tone={data?.by_severity.critical ? "danger" : "ok"} dot className="font-mono text-xs">
            {data?.by_severity.critical ?? 0} CRITICAL
          </Badge>
        }
        action={
          data?.findings.length ? (
            <a
              href="/api/findings?format=csv"
              className="flex items-center gap-1.5 rounded-lg border border-border/80 bg-surface/60 px-3 py-1.5 font-mono text-xs text-muted hover:border-border hover:bg-elevated hover:text-fg transition-all"
              download="aegis-findings.csv"
            >
              <DownloadSimple size={14} />
              <span>Export CSV</span>
            </a>
          ) : null
        }
      />

      {error ? (
        <ErrorNote error={error} />
      ) : (
        <div className="grid grid-cols-2 gap-4 lg:grid-cols-4">
          <StatCard
            label="Critical Severity"
            value={data ? fmt(data.by_severity.critical) : undefined}
            icon={<WarningCircle size={16} />}
            tone="danger"
            loading={loading}
            hint="immediate remediation required"
          />
          <StatCard
            label="Warning Severity"
            value={data ? fmt(data.by_severity.warning) : undefined}
            icon={<Warning size={16} />}
            tone="warn"
            loading={loading}
            hint="configuration & auth gaps"
          />
          <StatCard
            label="Total Findings"
            value={data ? fmt(data.count) : undefined}
            icon={<ShieldWarning size={16} />}
            tone="accent"
            loading={loading}
            hint="catalog exposures detected"
          />
          <StatCard
            label="Avg Risk Score"
            value={fmt(avgRisk)}
            icon={<Pulse size={16} />}
            loading={loading}
            hint={avgRisk == null ? undefined : "out of 100 max score"}
          />
        </div>
      )}

      {/* Filter and Search Bar */}
      <div className="flex flex-wrap items-center justify-between gap-3">
        <div className="relative min-w-[16rem] flex-1 max-w-md">
          <MagnifyingGlass size={15} className="absolute left-3 top-1/2 -translate-y-1/2 text-muted/60" />
          <Input
            value={q}
            onChange={(e) => setQ(e.target.value)}
            placeholder="Filter findings by path, OWASP rule, or vulnerability..."
            className="pl-9 pr-8 font-mono text-xs"
          />
          {q && (
            <button
              onClick={() => setQ("")}
              className="absolute right-2.5 top-1/2 -translate-y-1/2 text-muted hover:text-fg"
            >
              <X size={14} />
            </button>
          )}
        </div>

        <div className="flex gap-1 rounded-lg border border-border/70 bg-surface/80 p-1">
          <button
            onClick={() => setFilter("all")}
            className={`rounded-md px-3 py-1 text-xs font-medium transition-all ${
              filter === "all" ? "bg-accent text-accent-fg shadow-sm" : "text-muted hover:text-fg hover:bg-elevated/70"
            }`}
          >
            All ({data?.count ?? 0})
          </button>
          <button
            onClick={() => setFilter("critical")}
            className={`flex items-center gap-1.5 rounded-md px-3 py-1 text-xs font-medium transition-all ${
              filter === "critical"
                ? "bg-danger text-white shadow-sm"
                : "text-muted hover:text-danger hover:bg-danger/10"
            }`}
          >
            <span className="h-1.5 w-1.5 rounded-full bg-danger animate-pulse" />
            <span>Critical ({data?.by_severity.critical ?? 0})</span>
          </button>
          <button
            onClick={() => setFilter("warning")}
            className={`rounded-md px-3 py-1 text-xs font-medium transition-all ${
              filter === "warning" ? "bg-warn text-black font-semibold shadow-sm" : "text-muted hover:text-warn hover:bg-warn/10"
            }`}
          >
            Warning ({data?.by_severity.warning ?? 0})
          </button>
        </div>
      </div>

      <div className="mt-4">
        {loading ? (
          <div className="space-y-3">
            {Array.from({ length: 5 }).map((_, i) => (
              <Skeleton key={i} className="h-24 w-full" />
            ))}
          </div>
        ) : !data?.findings.length ? (
          !error && (
            <Card>
              <EmptyState
                icon={<ShieldCheck size={44} className="text-ok" />}
                title="Zero Perimeter Findings Detected"
                hint="No exposed PII, unauthenticated endpoints, or shadow assets found in the current traffic window."
              />
            </Card>
          )
        ) : filtered.length === 0 ? (
          <Card>
            <EmptyState
              title="No matching findings"
              hint="Try adjusting your search criteria or severity filters."
            />
          </Card>
        ) : (
          <Card className="divide-y divide-border/60 overflow-hidden">
            {filtered.map((f, i) => (
              <FindingRow key={`${f.method} ${f.path_template} ${f.finding.code}`} f={f} i={i} />
            ))}
          </Card>
        )}
      </div>
    </div>
  );
}

function FindingRow({ f, i }: { f: Finding; i: number }) {
  const critical = f.finding.severity === "critical";

  return (
    <motion.div
      initial={{ opacity: 0, y: 6 }}
      animate={{ opacity: 1, y: 0 }}
      transition={{ delay: Math.min(i * 0.02, 0.3) }}
      className="group flex flex-wrap items-start gap-4 p-4 transition-colors hover:bg-elevated/40 sm:p-5"
    >
      {/* Severity Indicator Badge */}
      <div className="w-24 shrink-0 pt-0.5">
        <SeverityBadge severity={f.finding.severity} />
      </div>

      {/* Main Details */}
      <div className="min-w-0 flex-1">
        <div className="flex flex-wrap items-center gap-2">
          <MethodBadge method={f.method} />
          <span className="font-mono text-xs font-semibold text-fg tracking-tight">
            {f.path_template}
          </span>
          <CopyButton text={f.path_template} />
          {f.finding.owasp && (
            <span className="rounded border border-accent/25 bg-accent/10 px-2 py-0.5 font-mono text-[10px] font-semibold text-accent">
              {f.finding.owasp}
            </span>
          )}
        </div>

        <h4 className="mt-2 text-sm font-semibold text-fg">{f.finding.title}</h4>
        {f.finding.why && (
          <p className="mt-1 text-xs leading-relaxed text-muted/90 max-w-3xl">
            {f.finding.why}
          </p>
        )}
      </div>

      {/* Risk Score Pill */}
      <div className="flex shrink-0 flex-col items-center justify-center rounded-lg border border-border/70 bg-bg/80 px-3.5 py-2 text-center min-w-[4rem]">
        <div className={`font-mono text-lg font-bold tnum ${critical ? "text-danger" : "text-warn"}`}>
          {f.risk_score}
        </div>
        <div className="font-mono text-[9px] uppercase tracking-wider text-muted/70">RISK SCORE</div>
      </div>
    </motion.div>
  );
}
