import { useMemo, useState } from "react";
import { Package, ShareNetwork, Users, Warning } from "@phosphor-icons/react";
import { ErrorNote, PageHeader, StatCard } from "@/components/PageBits";
import { Badge, Card, EmptyState, Skeleton } from "@/components/ui";
import { api, type Graph as GraphData, type GraphNode } from "@/lib/api";
import { useData } from "@/lib/hooks";
import { fmt } from "@/lib/utils";

// Layout constants (absolute px; the SVG scrolls inside its card).
const W = 900;
const PAD = 28;
const ROW = 34;
const R = 6;
const CONSUMER_X = 210;
const ENDPOINT_X = W - 210;

function postureFill(posture?: string): string {
  switch (posture) {
    case "protected":
      return "fill-emerald-400";
    case "partial":
      return "fill-amber-400";
    default:
      return "fill-rose-500"; // unprotected / shadow
  }
}

function kindFill(kind?: string): string {
  switch (kind) {
    case "jwt":
      return "fill-sky-400";
    case "key":
      return "fill-amber-400";
    default:
      return "fill-slate-400"; // ip / anonymous
  }
}

export function Graph() {
  const { data, loading, error } = useData<GraphData>(() => api.get("/api/graph?limit=150"), []);
  const [hover, setHover] = useState<string | null>(null);

  const layout = useMemo(() => {
    if (!data) return null;
    const consumers = data.nodes.filter((n) => n.type === "consumer").sort((a, b) => b.requests - a.requests);
    const endpoints = data.nodes.filter((n) => n.type === "endpoint").sort((a, b) => b.requests - a.requests);
    const pos = new Map<string, { x: number; y: number; node: GraphNode }>();
    consumers.forEach((n, i) => pos.set(n.id, { x: CONSUMER_X, y: PAD + i * ROW + R, node: n }));
    endpoints.forEach((n, i) => pos.set(n.id, { x: ENDPOINT_X, y: PAD + i * ROW + R, node: n }));
    const maxReq = Math.max(1, ...data.edges.map((e) => e.requests));
    const height = PAD * 2 + Math.max(consumers.length, endpoints.length, 1) * ROW;
    // Adjacency for hover highlighting.
    const adj = new Map<string, Set<string>>();
    for (const e of data.edges) {
      (adj.get(e.source) ?? adj.set(e.source, new Set()).get(e.source)!).add(e.target);
      (adj.get(e.target) ?? adj.set(e.target, new Set()).get(e.target)!).add(e.source);
    }
    return { consumers, endpoints, pos, maxReq, height, adj };
  }, [data]);

  const flaggedCount = useMemo(() => (data ? data.nodes.filter((n) => n.flagged).length : 0), [data]);

  const activeSet = useMemo(() => {
    if (!hover || !layout) return null;
    const s = new Set<string>([hover]);
    layout.adj.get(hover)?.forEach((n) => s.add(n));
    return s;
  }, [hover, layout]);

  return (
    <div className="space-y-6">
      <PageHeader
        title="Identity & Service Flow Map"
        desc="Interactive topological flow graph: mapping client callers to destination API endpoints, weighted by runtime throughput."
        badge={
          <Badge tone="accent" className="font-mono text-xs">
            {layout ? `${layout.consumers.length} → ${layout.endpoints.length}` : "FLOW GRAPH"}
          </Badge>
        }
      />

      {!error && (
        <div className="grid grid-cols-2 gap-4 lg:grid-cols-4">
          <StatCard
            label="Active Consumers"
            value={data ? fmt(layout?.consumers.length) : undefined}
            icon={<Users size={16} />}
            tone="accent"
            loading={loading}
          />
          <StatCard
            label="Destination Endpoints"
            value={data ? fmt(layout?.endpoints.length) : undefined}
            icon={<Package size={16} />}
            tone="ok"
            loading={loading}
          />
          <StatCard
            label="Traffic Links (Edges)"
            value={data ? fmt(data.edges.length) : undefined}
            icon={<ShareNetwork size={16} />}
            loading={loading}
          />
          <StatCard
            label="Under Active Abuse"
            value={data ? fmt(flaggedCount) : undefined}
            icon={<Warning size={16} />}
            tone={flaggedCount > 0 ? "danger" : "fg"}
            loading={loading}
            hint="BOLA / BFLA flagged nodes"
          />
        </div>
      )}

      {error ? (
        <ErrorNote error={error} />
      ) : loading ? (
        <Skeleton className="h-[60vh] w-full" />
      ) : !data || data.nodes.length === 0 ? (
        <EmptyState
          icon={<ShareNetwork size={40} />}
          title="No traffic yet"
          hint="Drive requests through the gateway (:8080) so the consumer→endpoint map can build."
        />
      ) : (
        <Card className="p-3">
          <Legend />
          <div className="mt-2 overflow-auto" style={{ maxHeight: "68vh" }}>
            <svg width={W} height={layout!.height} className="min-w-full">
              {/* Edges */}
              {data.edges.map((e, i) => {
                const a = layout!.pos.get(e.source);
                const b = layout!.pos.get(e.target);
                if (!a || !b) return null;
                const dim = activeSet && !(activeSet.has(e.source) && activeSet.has(e.target));
                const midX = (a.x + b.x) / 2;
                const width = 1 + (e.requests / layout!.maxReq) * 3;
                return (
                  <path
                    key={i}
                    d={`M ${a.x} ${a.y} C ${midX} ${a.y}, ${midX} ${b.y}, ${b.x} ${b.y}`}
                    fill="none"
                    className={dim ? "stroke-muted" : "stroke-accent"}
                    strokeWidth={width}
                    strokeOpacity={dim ? 0.06 : activeSet ? 0.7 : 0.18}
                  />
                );
              })}

              {/* Consumer nodes (left) */}
              {layout!.consumers.map((n) => {
                const p = layout!.pos.get(n.id)!;
                const faded = activeSet && !activeSet.has(n.id);
                return (
                  <g
                    key={n.id}
                    onMouseEnter={() => setHover(n.id)}
                    onMouseLeave={() => setHover(null)}
                    style={{ cursor: "pointer", opacity: faded ? 0.3 : 1 }}
                  >
                    <title>{`${n.label}\n${n.kind ?? "?"} · ${n.requests} requests${n.flagged ? `\n⚠ ${n.abuse_count ?? 0} abuse events (BOLA/BFLA)` : ""}`}</title>
                    {n.flagged ? <AbuseHalo x={p.x} y={p.y} /> : null}
                    <text x={p.x - R - 8} y={p.y + 4} textAnchor="end" className={`text-[11px] font-mono ${n.flagged ? "fill-danger font-semibold" : "fill-current"}`} style={{ opacity: n.flagged ? 1 : 0.85 }}>
                      {trunc(n.label, 26)}
                    </text>
                    <circle cx={p.x} cy={p.y} r={R} className={kindFill(n.kind)} />
                  </g>
                );
              })}

              {/* Endpoint nodes (right) */}
              {layout!.endpoints.map((n) => {
                const p = layout!.pos.get(n.id)!;
                const faded = activeSet && !activeSet.has(n.id);
                return (
                  <g
                    key={n.id}
                    onMouseEnter={() => setHover(n.id)}
                    onMouseLeave={() => setHover(null)}
                    style={{ cursor: "pointer", opacity: faded ? 0.3 : 1 }}
                  >
                    <title>{`${n.label}\n${n.posture ?? "?"} · risk ${n.risk ?? 0}${n.pii ? " · PII" : ""} · ${n.requests} requests${n.flagged ? `\n⚠ ${n.abuse_count ?? 0} abuse events (BOLA/BFLA)` : ""}`}</title>
                    {n.flagged ? <AbuseHalo x={p.x} y={p.y} /> : null}
                    {n.pii ? <circle cx={p.x} cy={p.y} r={R + 3} className="fill-none stroke-danger" strokeWidth={1.5} /> : null}
                    <circle cx={p.x} cy={p.y} r={R} className={postureFill(n.posture)} />
                    <text x={p.x + R + 8} y={p.y + 4} textAnchor="start" className={`text-[11px] font-mono ${n.flagged ? "fill-danger font-semibold" : "fill-current"}`} style={{ opacity: n.flagged ? 1 : 0.85 }}>
                      {trunc(n.label, 30)}
                    </text>
                  </g>
                );
              })}
            </svg>
          </div>
        </Card>
      )}
    </div>
  );
}

function trunc(s: string, n: number): string {
  return s.length > n ? s.slice(0, n - 1) + "…" : s;
}

// AbuseHalo is a pulsing red ring (native SMIL, no JS) marking a node that
// appears in recent BOLA/BFLA abuse events — visually ties the map to detection.
function AbuseHalo({ x, y }: { x: number; y: number }) {
  return (
    <circle cx={x} cy={y} className="fill-none stroke-danger" strokeWidth={2}>
      <animate attributeName="r" values={`${R + 3};${R + 9};${R + 3}`} dur="1.6s" repeatCount="indefinite" />
      <animate attributeName="opacity" values="0.9;0.2;0.9" dur="1.6s" repeatCount="indefinite" />
    </circle>
  );
}

function Legend() {
  const items: { cls: string; label: string; ring?: boolean; pulse?: boolean }[] = [
    { cls: "fill-fg", label: "protected / JWT" },
    { cls: "fill-muted", label: "partial / API-key" },
    { cls: "fill-danger", label: "unprotected / shadow" },
    { cls: "fill-muted/50", label: "anonymous IP" },
    { cls: "fill-none stroke-danger", label: "exposes PII", ring: true },
    { cls: "fill-none stroke-danger", label: "under abuse (BOLA/BFLA)", ring: true, pulse: true },
  ];
  return (
    <div className="flex flex-wrap items-center gap-x-4 gap-y-1.5 border-b border-white/5 px-1 pb-2 text-xs text-muted">
      {items.map((it) => (
        <span key={it.label} className="flex items-center gap-1.5">
          <svg width={16} height={16}>
            <circle cx={8} cy={8} r={it.ring ? 5 : 6} className={it.cls} strokeWidth={it.ring ? 1.5 : 0}>
              {it.pulse ? (
                <>
                  <animate attributeName="r" values="4;6.5;4" dur="1.6s" repeatCount="indefinite" />
                  <animate attributeName="opacity" values="0.9;0.3;0.9" dur="1.6s" repeatCount="indefinite" />
                </>
              ) : null}
            </circle>
          </svg>
          {it.label}
        </span>
      ))}
    </div>
  );
}
