import { DownloadSimple, MagnifyingGlass, X } from "@phosphor-icons/react";
import { useMemo, useState } from "react";
import { MethodBadge, PostureBadge, RiskDot } from "@/components/badges";
import { ErrorNote, PageHeader, Row, Table, Td, Th } from "@/components/PageBits";
import { Badge, CopyButton, EmptyState, Input, Skeleton } from "@/components/ui";
import { api, type Endpoint } from "@/lib/api";
import { useData } from "@/lib/hooks";
import { fmt, timeAgo } from "@/lib/utils";

const FILTERS = ["all", "protected", "partial", "unprotected", "shadow"] as const;

export function Catalog() {
  const { data, loading, error } = useData<{ endpoints: Endpoint[]; count: number }>(
    () => api.get("/api/catalog?limit=500"),
    [],
  );
  const [q, setQ] = useState("");
  const [posture, setPosture] = useState<(typeof FILTERS)[number]>("all");

  const counts = useMemo(() => {
    const eps = data?.endpoints ?? [];
    return {
      all: eps.length,
      protected: eps.filter((e) => e.posture === "protected").length,
      partial: eps.filter((e) => e.posture === "partial").length,
      unprotected: eps.filter((e) => e.posture === "unprotected").length,
      shadow: eps.filter((e) => e.posture === "shadow").length,
    };
  }, [data]);

  const rows = useMemo(() => {
    let eps = data?.endpoints ?? [];
    if (posture !== "all") eps = eps.filter((e) => e.posture === posture);
    if (q.trim()) {
      const s = q.toLowerCase();
      eps = eps.filter((e) => e.path_template.toLowerCase().includes(s) || e.method.toLowerCase().includes(s));
    }
    return [...eps].sort((a, b) => b.risk_score - a.risk_score);
  }, [data, q, posture]);

  return (
    <div className="space-y-5">
      <PageHeader
        title="API Inventory & Catalog"
        desc="Dynamic API endpoint discovery, automated parameter profiling, and continuous shadow asset tracking."
        badge={
          <Badge tone="accent" className="font-mono text-xs">
            {fmt(data?.count ?? 0)} ENDPOINTS
          </Badge>
        }
        action={
          data?.endpoints.length ? (
            <a
              href="/api/catalog?format=json"
              download="aegis-catalog.json"
              className="flex items-center gap-1.5 rounded-lg border border-border/80 bg-surface/60 px-3 py-1.5 font-mono text-xs text-muted hover:border-border hover:bg-elevated hover:text-fg transition-all"
            >
              <DownloadSimple size={14} />
              <span>Export JSON</span>
            </a>
          ) : null
        }
      />

      <div className="flex flex-wrap items-center justify-between gap-3">
        {/* Search bar */}
        <div className="relative min-w-[18rem] flex-1 max-w-md">
          <MagnifyingGlass size={15} className="absolute left-3 top-1/2 -translate-y-1/2 text-muted/60" />
          <Input
            value={q}
            onChange={(e) => setQ(e.target.value)}
            placeholder="Search by path or method (e.g. /v1/users, POST)..."
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

        {/* Filter chips with counts */}
        <div className="flex flex-wrap gap-1 rounded-lg border border-border/70 bg-surface/80 p-1">
          {FILTERS.map((f) => {
            const count = counts[f];
            const isSelected = posture === f;
            const isShadow = f === "shadow" && count > 0;
            return (
              <button
                key={f}
                onClick={() => setPosture(f)}
                className={`flex items-center gap-1.5 rounded-md px-2.5 py-1 text-xs capitalize transition-all select-none font-medium ${
                  isSelected
                    ? "bg-accent text-accent-fg shadow-sm"
                    : "text-muted hover:text-fg hover:bg-elevated/70"
                }`}
              >
                {isShadow && <span className="h-1.5 w-1.5 rounded-full bg-danger animate-pulse" />}
                <span>{f}</span>
                <span className="font-mono text-[10px] opacity-75">({count})</span>
              </button>
            );
          })}
        </div>
      </div>

      {error ? (
        <ErrorNote error={error} />
      ) : loading ? (
        <div className="space-y-2">
          {Array.from({ length: 8 }).map((_, i) => (
            <Skeleton key={i} className="h-12 w-full" />
          ))}
        </div>
      ) : rows.length === 0 ? (
        <EmptyState
          title="No endpoints matched"
          hint={q ? "Try adjusting your search query or posture filter." : "Traffic through the gateway populates the catalog automatically."}
        />
      ) : (
        <Table
          head={
            <>
              <Th className="w-[42%]">Endpoint</Th>
              <Th>Posture</Th>
              <Th className="text-right">Risk Score</Th>
              <Th className="hidden text-right md:table-cell">Request Volume</Th>
              <Th className="hidden text-right md:table-cell">PII Fields</Th>
              <Th className="hidden text-right lg:table-cell">Last Seen</Th>
            </>
          }
        >
          {rows.map((e, i) => (
            <Row key={e.id} i={i}>
              <Td>
                <div className="flex items-center gap-2 font-mono text-xs">
                  <MethodBadge method={e.method} />
                  <span className="truncate font-medium text-fg" title={e.path_template}>
                    {e.path_template}
                  </span>
                  <CopyButton text={e.path_template} />
                </div>
              </Td>
              <Td>
                <PostureBadge posture={e.posture} />
              </Td>
              <Td className="text-right">
                <RiskDot score={e.risk_score} />
              </Td>
              <Td className="hidden text-right font-mono text-xs tnum md:table-cell text-fg">
                {fmt(e.request_count)}
              </Td>
              <Td className="hidden text-right md:table-cell">
                {e.pii_count > 0 ? (
                  <Badge tone="danger" dot className="font-mono text-[10px]">
                    {fmt(e.pii_count)} PII
                  </Badge>
                ) : (
                  <span className="font-mono text-xs text-muted/60">—</span>
                )}
              </Td>
              <Td className="hidden text-right font-mono text-xs text-muted lg:table-cell">
                {timeAgo(e.last_seen)}
              </Td>
            </Row>
          ))}
        </Table>
      )}
    </div>
  );
}
