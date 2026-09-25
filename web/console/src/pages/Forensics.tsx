import { useMemo, useState } from "react";
import { MagnifyingGlass, X } from "@phosphor-icons/react";
import { ErrorNote, PageHeader, Row, Table, Td, Th } from "@/components/PageBits";
import { SealIntegrity } from "@/components/SealIntegrity";
import { MethodBadge, SeverityBadge } from "@/components/badges";
import { Badge, CopyButton, EmptyState, Input, Skeleton } from "@/components/ui";
import { api, type BlockEntry } from "@/lib/api";
import { useData } from "@/lib/hooks";
import { timeAgo } from "@/lib/utils";

function isAbuse(reason: string): boolean {
  return /bola|bfla|idor|abuse|owner/.test(reason);
}

function reasonTone(reason: string): "danger" | "warn" | "neutral" {
  if (isAbuse(reason) || /waf|sqli|traversal|xss|rce|ssrf|xxe/.test(reason)) return "danger";
  if (/rate|behavior|bot/.test(reason)) return "warn";
  return "neutral";
}

function str(v: unknown): string | undefined {
  return typeof v === "string" && v.length > 0 ? v : undefined;
}

export function Forensics() {
  const { data, loading, error } = useData<BlockEntry[]>(() => api.get("/api/block-log"), [], 8000);
  const [q, setQ] = useState("");

  const rows = useMemo(() => {
    let list = data ?? [];
    if (q.trim()) {
      const s = q.toLowerCase();
      list = list.filter(
        (e) =>
          e.ip.toLowerCase().includes(s) ||
          e.path.toLowerCase().includes(s) ||
          e.reason.toLowerCase().includes(s) ||
          e.method.toLowerCase().includes(s) ||
          (typeof e.extra?.why === "string" && e.extra.why.toLowerCase().includes(s)),
      );
    }
    return list;
  }, [data, q]);

  return (
    <div className="space-y-6">
      <PageHeader
        title="Forensic Audit Trail"
        desc="Tamper-evident runtime telemetry: signature WAF mitigations, BOLA/IDOR authorization violations, and rate breaches."
        badge={
          <Badge tone="accent" className="font-mono text-xs">
            {data?.length ?? 0} LOGGED INCIDENTS
          </Badge>
        }
      />

      {/* Cryptographic Verification Banner */}
      <SealIntegrity />

      {/* Search Bar */}
      <div className="flex items-center justify-between gap-3">
        <div className="relative min-w-[16rem] flex-1 max-w-md">
          <MagnifyingGlass size={15} className="absolute left-3 top-1/2 -translate-y-1/2 text-muted/60" />
          <Input
            value={q}
            onChange={(e) => setQ(e.target.value)}
            placeholder="Search by IP, endpoint, violation reason..."
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
            <Skeleton key={i} className="h-11 w-full" />
          ))}
        </div>
      ) : rows.length === 0 ? (
        <EmptyState
          title={q ? "No matching forensic events" : "No security incidents logged"}
          hint="Blocked requests, SQL injection attempts, and authorization anomalies appear here."
        />
      ) : (
        <Table
          head={
            <>
              <Th>Incident & Detection Rule</Th>
              <Th>Source IP</Th>
              <Th className="hidden md:table-cell">Target Request</Th>
              <Th className="text-right">HTTP Code</Th>
              <Th className="hidden text-right sm:table-cell">Timestamp</Th>
            </>
          }
        >
          {rows.map((e, i) => {
            const severity = str(e.extra?.severity);
            const why = str(e.extra?.why);

            return (
              <Row key={i} i={i}>
                <Td>
                  <div>
                    <div className="flex flex-wrap items-center gap-1.5 font-mono">
                      {severity ? <SeverityBadge severity={severity} /> : null}
                      <Badge tone={reasonTone(e.reason)} className="uppercase text-[10px] font-semibold">
                        {e.reason.replace(/_/g, " ")}
                      </Badge>
                    </div>
                    {why && (
                      <p
                        className="mt-1 max-w-[28rem] truncate text-xs text-muted/90"
                        title={why}
                      >
                        {why}
                      </p>
                    )}
                  </div>
                </Td>
                <Td>
                  <div className="flex items-center gap-1.5 font-mono text-xs">
                    <span className="font-semibold text-fg">{e.ip}</span>
                    <CopyButton text={e.ip} />
                  </div>
                </Td>
                <Td className="hidden max-w-[22rem] truncate font-mono text-xs md:table-cell">
                  <div className="flex items-center gap-2">
                    <MethodBadge method={e.method} />
                    <span className="truncate text-muted/90" title={e.path}>
                      {e.path}
                    </span>
                    <CopyButton text={e.path} />
                  </div>
                </Td>
                <Td className="text-right font-mono text-xs tnum">
                  <span
                    className={`inline-block rounded px-1.5 py-0.5 font-semibold ${
                      e.code === 403
                        ? "bg-danger/10 text-danger border border-danger/25"
                        : e.code === 429
                        ? "bg-warn/10 text-warn border border-warn/25"
                        : "bg-elevated text-muted"
                    }`}
                  >
                    {e.code}
                  </span>
                </Td>
                <Td className="hidden text-right font-mono text-xs text-muted sm:table-cell">
                  <span title={new Date(e.timestamp).toISOString()}>{timeAgo(e.timestamp)}</span>
                </Td>
              </Row>
            );
          })}
        </Table>
      )}
    </div>
  );
}
