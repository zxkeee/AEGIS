import { motion } from "framer-motion";
import { useEffect, useMemo, useRef, useState } from "react";
import {
  ArrowRight,
  ClipboardText,
  Fingerprint,
  Gauge,
  Globe,
  Key,
  ListMagnifyingGlass,
  Lock,
  Prohibit,
  Pulse,
  Robot,
  ShieldCheck,
  ShieldWarning,
  Warning,
  WarningCircle,
} from "@phosphor-icons/react";
import { MethodBadge, SeverityBadge } from "@/components/badges";
import { Delta, PageHeader, StatCard, stagger } from "@/components/PageBits";
import { Badge, Card, CopyButton, EmptyState } from "@/components/ui";
import { api, type BlockEntry, type Effectiveness, type PostureSummary } from "@/lib/api";
import { useData } from "@/lib/hooks";
import { fmt, pct, timeAgo } from "@/lib/utils";

const CONTROL_META: Record<string, { label: string; icon: React.ReactNode; color: string }> = {
  waf: { label: "WAF Core", icon: <ShieldWarning size={14} />, color: "bg-danger" },
  rate_limit: { label: "Rate Limiter", icon: <Gauge size={14} />, color: "bg-warn" },
  ip_guard: { label: "IP Guard", icon: <Prohibit size={14} />, color: "bg-rose-500" },
  behavior: { label: "Anomaly Engine", icon: <Fingerprint size={14} />, color: "bg-purple-500" },
  threatfeed: { label: "Threat Intel", icon: <Globe size={14} />, color: "bg-sky-500" },
  bot: { label: "Bot Mitigation", icon: <Robot size={14} />, color: "bg-amber-500" },
  dlp: { label: "DLP Redaction", icon: <Lock size={14} />, color: "bg-emerald-500" },
};

/** Tracks the increase in a counter between polls, for a delta indicator. */
function useDelta(value: number | undefined) {
  const prev = useRef<number | undefined>(undefined);
  const [delta, setDelta] = useState<number | null>(null);
  useEffect(() => {
    if (value == null) return;
    if (prev.current != null && value > prev.current) setDelta(value - prev.current);
    prev.current = value;
  }, [value]);
  return delta;
}

/** Accumulates real polled values into a short in-memory series. */
function useLiveSeries(value: number | undefined, maxPoints = 50) {
  const [series, setSeries] = useState<number[]>([]);
  const prev = useRef<number | undefined>(undefined);
  useEffect(() => {
    if (value == null) return;
    if (prev.current != null) {
      const d = Math.max(0, value - prev.current);
      setSeries((s) => [...s.slice(-(maxPoints - 1)), d]);
    }
    prev.current = value;
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [value]);
  return series;
}

export function Overview({ onNavigate }: { onNavigate?: (key: string) => void }) {
  const eff = useData<Effectiveness>(() => api.get("/api/effectiveness"), [], 10000);
  const posture = useData<PostureSummary>(() => api.get("/api/posture/summary"), [], 20000);
  const log = useData<BlockEntry[]>(() => api.get("/api/block-log"), [], 10000);

  const blocks = eff.data?.blocks_by_control ?? {};
  const totalBlocks = eff.data?.total_blocks ?? 0;
  const passed = eff.data?.passed_waf ?? 0;
  const coverage = posture.data?.coverage_pct;

  const passedDelta = useDelta(eff.data ? passed : undefined);
  const blocksDelta = useDelta(eff.data ? totalBlocks : undefined);
  const passedSeries = useLiveSeries(eff.data ? passed : undefined);

  const live = !eff.error;

  const criticalCount = useMemo(
    () => log.data?.filter((e) => e.extra?.severity === "critical").length ?? 0,
    [log.data],
  );

  return (
    <div className="space-y-6">
      <PageHeader
        title="Security Overview"
        desc="Real-time perimeter telemetry, active security controls, and endpoint posture."
        badge={
          <Badge tone={live ? "ok" : "danger"} dot className="font-mono text-[10px]">
            {live ? "SYSTEM HEALTHY" : "OFFLINE"}
          </Badge>
        }
        action={
          <div className="flex items-center gap-2 font-mono text-xs text-muted">
            <span className="relative flex h-2 w-2">
              <span className="absolute inline-flex h-full w-full animate-ping rounded-full bg-ok opacity-75" />
              <span className="relative inline-flex h-2 w-2 rounded-full bg-ok" />
            </span>
            <span>POLLED EVERY 10S</span>
          </div>
        }
      />

      {/* Top 4 Telemetry Cards */}
      <motion.div variants={stagger} initial="hidden" animate="show" className="grid grid-cols-2 gap-4 lg:grid-cols-4">
        <StatCard
          label="Requests Ingested"
          value={fmt(passed)}
          icon={<Pulse size={16} />}
          tone="ok"
          loading={eff.loading}
          delta={passedDelta ? <Delta dir="up" context=" since last poll">+{fmt(passedDelta)}</Delta> : <span>clean through the WAF</span>}
        />
        <StatCard
          label="Attacks Blocked"
          value={fmt(totalBlocks)}
          icon={<Prohibit size={16} />}
          tone="danger"
          loading={eff.loading}
          delta={blocksDelta ? <Delta dir="down" context=" new threats mitigated">+{fmt(blocksDelta)}</Delta> : <span>across all engines</span>}
        />
        <StatCard
          label="Catalog Coverage"
          value={pct(coverage)}
          icon={<ShieldCheck size={16} />}
          tone="accent"
          loading={posture.loading}
          hint={posture.data ? `${fmt(posture.data.protected)}/${fmt(posture.data.total)} endpoints shielded` : "protected endpoints"}
        />
        <StatCard
          label="Active Exposures"
          value={fmt(criticalCount || 0)}
          icon={<WarningCircle size={16} />}
          tone={criticalCount > 0 ? "danger" : "fg"}
          loading={log.loading}
          hint="critical severity findings"
        />
      </motion.div>

      {/* Live Traffic Area Chart */}
      <Card className="p-5 sm:p-6">
        <div className="flex flex-wrap items-center justify-between gap-3 border-b border-border/50 pb-4">
          <div>
            <div className="flex items-center gap-2">
              <h3 className="text-sm font-semibold tracking-tight text-fg">Live Gateway Throughput</h3>
              <span className="rounded bg-accent/10 px-1.5 py-0.5 font-mono text-[10px] font-semibold text-accent border border-accent/20">
                REAL-TIME STREAM
              </span>
            </div>
            <p className="mt-0.5 text-xs text-muted">Observed request volume delta per 10-second polling cycle</p>
          </div>
          <div className="flex items-center gap-3 font-mono text-xs">
            <div className="flex items-center gap-1.5 text-muted">
              <span className="h-2 w-2 rounded-full bg-accent" />
              <span>Current rate:</span>
              <span className="font-semibold text-fg tnum">
                {passedSeries.length > 0 ? fmt(passedSeries[passedSeries.length - 1]) : 0} req/poll
              </span>
            </div>
          </div>
        </div>
        <LiveChart series={passedSeries} />
      </Card>

      {/* 3-Column Diagnostic Grid */}
      <div className="grid gap-6 lg:grid-cols-[1.2fr_1fr_1fr]">
        {/* Blocks by Control */}
        <Card className="flex flex-col p-5 sm:p-6">
          <div className="border-b border-border/50 pb-3">
            <h3 className="text-sm font-semibold text-fg">Mitigation Engines</h3>
            <p className="mt-0.5 text-xs text-muted">Threat breakdown by active defence layer</p>
          </div>
          <div className="flex-1">
            <BarList data={blocks} totalBlocks={totalBlocks} />
          </div>
        </Card>

        {/* Posture Donut */}
        <Card className="flex flex-col p-5 sm:p-6">
          <div className="border-b border-border/50 pb-3">
            <h3 className="text-sm font-semibold text-fg">Perimeter Posture</h3>
            <p className="mt-0.5 text-xs text-muted">
              {posture.data ? `${fmt(posture.data.total)} total endpoints cataloged` : "Analyzing catalog..."}
            </p>
          </div>
          <div className="flex flex-1 items-center justify-center py-2">
            <PostureDonut data={posture.data} onNavigate={onNavigate} />
          </div>
        </Card>

        {/* Quick Operator Actions */}
        <Card className="flex flex-col p-5 sm:p-6">
          <div className="border-b border-border/50 pb-3">
            <h3 className="text-sm font-semibold text-fg">Security Operator Actions</h3>
            <p className="mt-0.5 text-xs text-muted">Immediate triage & policy controls</p>
          </div>
          <div className="mt-3 flex flex-1 flex-col justify-center space-y-1">
            <QuickAction
              icon={<Warning size={16} className="text-danger" />}
              title={criticalCount ? `Review ${criticalCount} critical finding${criticalCount === 1 ? "" : "s"}` : "Review OWASP findings"}
              hint="Inspect confirmed IDOR, BOLA, PII exposure"
              onClick={() => onNavigate?.("findings")}
            />
            <QuickAction
              icon={<ClipboardText size={16} className="text-accent" />}
              title="Compliance control matrix"
              hint="Audit export for NIS2, DORA & ISO 27001"
              onClick={() => onNavigate?.("compliance")}
            />
            <QuickAction
              icon={<ListMagnifyingGlass size={16} className="text-warn" />}
              title="Audit API Catalog"
              hint={posture.data ? `${fmt(posture.data.unprotected + posture.data.shadow)} endpoints need review` : "Inspect inventory"}
              onClick={() => onNavigate?.("catalog")}
            />
            <QuickAction
              icon={<Key size={16} className="text-emerald-400" />}
              title="Access & IP Guard"
              hint="Manage IP blocklists & revoke JWT credentials"
              onClick={() => onNavigate?.("access")}
            />
          </div>
        </Card>
      </div>

      {/* Live Activity Stream */}
      <div>
        <div className="mb-3 flex items-center justify-between">
          <div className="flex items-center gap-2">
            <h3 className="text-sm font-semibold text-fg">Live Security Event Log</h3>
            <span className="font-mono text-xs text-muted">({log.data?.length ?? 0} events)</span>
          </div>
          <button
            onClick={() => onNavigate?.("forensics")}
            className="flex items-center gap-1 font-mono text-xs text-accent hover:underline"
          >
            <span>Full forensics</span>
            <ArrowRight size={12} />
          </button>
        </div>

        <Card className="overflow-hidden">
          {!log.data?.length ? (
            <EmptyState title="No security events yet" hint="Blocked requests and authorization abuse detections will stream in here." />
          ) : (
            <div className="divide-y divide-border/50 font-mono text-xs">
              {log.data.slice(0, 7).map((e, i) => {
                const severity = typeof e.extra?.severity === "string" ? e.extra.severity : undefined;
                return (
                  <div
                    key={i}
                    className="flex flex-wrap items-center justify-between gap-3 px-4 py-3 transition-colors hover:bg-elevated/40"
                  >
                    <div className="flex min-w-0 flex-1 items-center gap-3">
                      {severity && <SeverityBadge severity={severity} />}
                      <span className="rounded bg-elevated/80 px-2 py-0.5 text-[11px] font-medium text-fg uppercase tracking-wide border border-border/60">
                        {e.reason.replace(/_/g, " ")}
                      </span>
                      <MethodBadge method={e.method} />
                      <span className="truncate text-muted/90 max-w-sm sm:max-w-md md:max-w-lg" title={e.path}>
                        {e.path}
                      </span>
                      <CopyButton text={e.path} />
                    </div>

                    <div className="flex shrink-0 items-center gap-4 text-xs text-muted">
                      {e.ip && <span className="text-muted/70">{e.ip}</span>}
                      <span className="tnum">{timeAgo(e.timestamp)}</span>
                    </div>
                  </div>
                );
              })}
            </div>
          )}
        </Card>
      </div>
    </div>
  );
}

function QuickAction({
  icon,
  title,
  hint,
  onClick,
}: {
  icon: React.ReactNode;
  title: string;
  hint?: string;
  onClick?: () => void;
}) {
  return (
    <button
      onClick={onClick}
      className="group flex w-full items-center gap-3 rounded-lg border border-transparent p-2.5 text-left transition-all hover:border-border/70 hover:bg-elevated/50"
    >
      <span className="flex h-8 w-8 shrink-0 items-center justify-center rounded-lg border border-border/60 bg-elevated/70 transition-transform group-hover:scale-105">
        {icon}
      </span>
      <span className="min-w-0 flex-1">
        <span className="block truncate text-xs font-semibold text-fg transition-colors group-hover:text-accent">
          {title}
        </span>
        {hint && <span className="block truncate text-[11px] text-muted">{hint}</span>}
      </span>
      <ArrowRight size={13} className="shrink-0 text-muted opacity-40 transition-all group-hover:opacity-100 group-hover:translate-x-0.5" />
    </button>
  );
}

function BarList({ data, totalBlocks }: { data: Record<string, number>; totalBlocks: number }) {
  const entries = Object.entries(data).sort((a, b) => b[1] - a[1]);
  const max = Math.max(1, ...entries.map(([, v]) => v));

  if (entries.every(([, v]) => v === 0)) {
    return <p className="py-12 text-center text-xs text-muted">No blocks recorded yet in this cycle.</p>;
  }

  return (
    <div className="mt-3 space-y-3">
      {entries.map(([k, v], i) => {
        const meta = CONTROL_META[k] ?? { label: k, icon: <ShieldWarning size={14} />, color: "bg-fg" };
        const pctVal = totalBlocks > 0 ? Math.round((v / totalBlocks) * 100) : 0;
        return (
          <div key={k} className="group flex items-center gap-3">
            <div className="flex w-28 shrink-0 items-center gap-2 text-xs text-muted group-hover:text-fg transition-colors">
              <span className="text-muted/80">{meta.icon}</span>
              <span className="truncate">{meta.label}</span>
            </div>

            <div className="relative h-2 flex-1 overflow-hidden rounded-full bg-elevated/70 border border-border/40">
              <motion.div
                initial={{ width: 0 }}
                animate={{ width: `${(v / max) * 100}%` }}
                transition={{ delay: i * 0.04, type: "spring", stiffness: 120, damping: 20 }}
                className={`h-full rounded-full ${meta.color}`}
              />
            </div>

            <div className="flex w-16 shrink-0 items-center justify-end gap-1.5 font-mono text-xs">
              <span className="font-semibold text-fg tnum">{fmt(v)}</span>
              <span className="text-[10px] text-muted/60">({pctVal}%)</span>
            </div>
          </div>
        );
      })}
    </div>
  );
}

function PostureDonut({
  data,
  onNavigate,
}: {
  data?: PostureSummary | null;
  onNavigate?: (key: string) => void;
}) {
  if (!data || data.total === 0) {
    return <div className="flex h-44 items-center justify-center text-xs text-muted">No catalog endpoints discovered yet.</div>;
  }

  const segs = [
    { label: "Protected", n: data.protected, stroke: "stroke-emerald-500", bg: "bg-emerald-500", tone: "ok" },
    { label: "Partial", n: data.partial, stroke: "stroke-amber-500", bg: "bg-amber-500", tone: "warn" },
    { label: "Unprotected", n: data.unprotected, stroke: "stroke-slate-500", bg: "bg-slate-500", tone: "neutral" },
    { label: "Shadow API", n: data.shadow, stroke: "stroke-rose-500", bg: "bg-rose-500", tone: "danger" },
  ];

  const R = 54;
  const C = 2 * Math.PI * R;
  let acc = 0;
  const covPct = Math.round(data.coverage_pct ?? 0);

  return (
    <div className="flex flex-col items-center">
      <div className="relative flex items-center justify-center">
        <svg width="150" height="150" viewBox="0 0 150 150" className="-rotate-90">
          <circle cx="75" cy="75" r={R} className="stroke-elevated/80" strokeWidth="13" fill="none" />
          {segs.map((s) => {
            const frac = s.n / data.total;
            const dash = C * frac;
            const offset = -C * acc;
            acc += frac;
            if (frac === 0) return null;
            return (
              <motion.circle
                key={s.label}
                cx="75"
                cy="75"
                r={R}
                className={s.stroke}
                strokeWidth="13"
                fill="none"
                strokeDasharray={`${dash} ${C - dash}`}
                initial={{ strokeDashoffset: offset, opacity: 0 }}
                animate={{ strokeDashoffset: offset, opacity: 1 }}
                transition={{ duration: 0.8, ease: [0.16, 0.8, 0.3, 1] }}
              />
            );
          })}
        </svg>

        {/* Center Readout */}
        <div className="absolute inset-0 flex flex-col items-center justify-center text-center">
          <span className="font-mono text-2xl font-bold tracking-tight text-fg tnum">{covPct}%</span>
          <span className="font-mono text-[9px] uppercase tracking-wider text-muted">SHIELDED</span>
        </div>
      </div>

      <div className="mt-4 grid grid-cols-2 gap-2 text-xs">
        {segs.map((s) => {
          const pct = data.total > 0 ? Math.round((s.n / data.total) * 100) : 0;
          return (
            <button
              key={s.label}
              onClick={() => onNavigate?.("catalog")}
              className="flex items-center gap-1.5 rounded-md px-2 py-1 text-left font-mono transition-colors hover:bg-elevated/60"
            >
              <span className={`h-2 w-2 rounded-full shrink-0 ${s.bg}`} />
              <span className="truncate text-muted">{s.label}:</span>
              <span className="font-semibold text-fg tnum">{s.n}</span>
              <span className="text-[10px] text-muted/60">({pct}%)</span>
            </button>
          );
        })}
      </div>
    </div>
  );
}

function LiveChart({ series }: { series: number[] }) {
  if (series.length < 2) {
    return (
      <div className="mt-4 flex h-[160px] flex-col items-center justify-center gap-2 rounded-lg border border-dashed border-border/70 text-xs text-muted">
        <Pulse size={20} className="animate-pulse text-accent" />
        <span>Collecting real-time traffic pulses from gateway…</span>
      </div>
    );
  }

  const W = 1000, H = 160, PAD = 10;
  const max = Math.max(1, ...series);
  const step = (W - PAD * 2) / (series.length - 1);
  const pts = series.map((v, i) => [PAD + i * step, H - PAD - (v / max) * (H - PAD * 2)] as const);
  const line = "M" + pts.map((p) => p.join(",")).join(" L");
  const area = line + ` L${pts[pts.length - 1][0]},${H} L${pts[0][0]},${H} Z`;
  const lastPt = pts[pts.length - 1];

  return (
    <div className="relative mt-4">
      <svg className="w-full" viewBox={`0 0 ${W} ${H}`} preserveAspectRatio="none" style={{ height: 160 }}>
        <defs>
          <linearGradient id="areaGradient" x1="0" y1="0" x2="0" y2="1">
            <stop offset="0%" stopColor="hsl(var(--accent))" stopOpacity="0.25" />
            <stop offset="100%" stopColor="hsl(var(--accent))" stopOpacity="0.00" />
          </linearGradient>
        </defs>

        {/* Horizontal gridlines */}
        <line x1={0} y1={PAD} x2={W} y2={PAD} stroke="hsl(var(--border))" strokeOpacity="0.5" strokeDasharray="3 3" />
        <line x1={0} y1={H / 2} x2={W} y2={H / 2} stroke="hsl(var(--border))" strokeOpacity="0.5" strokeDasharray="3 3" />
        <line x1={0} y1={H - PAD} x2={W} y2={H - PAD} stroke="hsl(var(--border))" strokeOpacity="0.5" />

        {/* Area & line */}
        <path d={area} fill="url(#areaGradient)" />
        <path
          d={line}
          className="stroke-accent"
          strokeWidth="2.2"
          fill="none"
          strokeLinejoin="round"
          strokeLinecap="round"
        />

        {/* Pulse beacon on newest point */}
        <circle cx={lastPt[0]} cy={lastPt[1]} r={5} className="fill-accent shadow-glow-accent" />
        <circle cx={lastPt[0]} cy={lastPt[1]} r={9} className="stroke-accent fill-none animate-ping opacity-75" />
      </svg>
    </div>
  );
}
