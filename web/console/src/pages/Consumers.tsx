import { useMemo, useState } from "react";
import { Globe, IdentificationBadge, Key, MagnifyingGlass, Users, X } from "@phosphor-icons/react";
import { ErrorNote, PageHeader, Row, Table, Td, Th } from "@/components/PageBits";
import { Badge, CopyButton, EmptyState, Input, Skeleton } from "@/components/ui";
import { api, type Consumer } from "@/lib/api";
import { useData } from "@/lib/hooks";
import { fmt, timeAgo } from "@/lib/utils";

const KIND_META: Record<string, { tone: "accent" | "warn" | "neutral"; icon: React.ReactNode; label: string }> = {
  jwt: { tone: "accent", icon: <IdentificationBadge size={13} />, label: "JWT Client" },
  key: { tone: "warn", icon: <Key size={13} />, label: "API Key" },
  ip: { tone: "neutral", icon: <Globe size={13} />, label: "IP Client" },
};

export function Consumers() {
  const { data, loading, error } = useData<{ consumers: Consumer[]; count: number }>(
    () => api.get("/api/consumers?limit=200"),
    [],
  );
  const [q, setQ] = useState("");

  const rows = useMemo(() => {
    let list = (data?.consumers ?? []).slice().sort((a, b) => b.request_count - a.request_count);
    if (q.trim()) {
      const s = q.toLowerCase();
      list = list.filter(
        (c) =>
          c.id.toLowerCase().includes(s) ||
          (c.label && c.label.toLowerCase().includes(s)) ||
          c.kind.toLowerCase().includes(s),
      );
    }
    return list;
  }, [data, q]);

  return (
    <div className="space-y-6">
      <PageHeader
        title="Client Identities & Consumers"
        desc="Autonomous client discovery, token linkage, API key profiling, and caller behavioral fingerprinting."
        badge={
          <Badge tone="accent" className="font-mono text-xs">
            {data?.count ?? 0} IDENTIFIED CLIENTS
          </Badge>
        }
      />

      <div className="flex items-center justify-between gap-3">
        <div className="relative min-w-[16rem] flex-1 max-w-md">
          <MagnifyingGlass size={15} className="absolute left-3 top-1/2 -translate-y-1/2 text-muted/60" />
          <Input
            value={q}
            onChange={(e) => setQ(e.target.value)}
            placeholder="Search by client ID, label, or auth kind..."
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
          title={q ? "No matching consumers" : "No client consumers yet"}
          hint="Consumers populate automatically as authenticated requests pass through the gateway."
        />
      ) : (
        <Table
          head={
            <>
              <Th>Client Identifier</Th>
              <Th>Auth Mechanism</Th>
              <Th className="text-right">Total Requests</Th>
              <Th className="hidden text-right sm:table-cell">Failed Requests</Th>
              <Th className="hidden text-right md:table-cell">Endpoints Called</Th>
              <Th className="hidden text-right lg:table-cell">Last Active</Th>
            </>
          }
        >
          {rows.map((c, i) => {
            const meta = KIND_META[c.kind] ?? {
              tone: "neutral",
              icon: <Users size={13} />,
              label: c.kind,
            };
            return (
              <Row key={c.id} i={i}>
                <Td className="max-w-[20rem]">
                  <div className="flex items-center gap-1.5 font-mono text-xs">
                    <span className="truncate font-semibold text-fg" title={c.id}>
                      {c.label || c.id}
                    </span>
                    <CopyButton text={c.label || c.id} />
                  </div>
                </Td>
                <Td>
                  <Badge tone={meta.tone} className="gap-1 font-mono text-[10px] uppercase font-semibold">
                    {meta.icon}
                    <span>{meta.label}</span>
                  </Badge>
                </Td>
                <Td className="text-right font-mono text-xs tnum font-semibold text-fg">
                  {fmt(c.request_count)}
                </Td>
                <Td className="hidden text-right font-mono text-xs tnum sm:table-cell">
                  {c.error_count > 0 ? (
                    <span className="font-semibold text-danger">{fmt(c.error_count)}</span>
                  ) : (
                    <span className="text-muted/60">0</span>
                  )}
                </Td>
                <Td className="hidden text-right font-mono text-xs tnum md:table-cell text-muted">
                  {c.endpoints_touched}
                </Td>
                <Td className="hidden text-right font-mono text-xs text-muted lg:table-cell">
                  {timeAgo(c.last_seen)}
                </Td>
              </Row>
            );
          })}
        </Table>
      )}
    </div>
  );
}
