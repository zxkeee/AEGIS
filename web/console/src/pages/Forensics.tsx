import { ErrorNote, PageHeader, Row, Table, Td, Th } from "@/components/PageBits";
import { SealIntegrity } from "@/components/SealIntegrity";
import { MethodBadge, SeverityBadge } from "@/components/badges";
import { Badge, EmptyState, Skeleton } from "@/components/ui";
import { api, type BlockEntry } from "@/lib/api";
import { useData } from "@/lib/hooks";
import { timeAgo } from "@/lib/utils";

// Authorization-abuse detections (BOLA/IDOR, BFLA, enumeration) are the
// high-value findings a signature WAF can't produce — surface them as danger.
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
  const rows = data ?? [];

  return (
    <div>
      <PageHeader
        title="Forensics"
        desc="Recent security events, newest first — WAF blocks and authorization-abuse detections (BOLA/IDOR, BFLA)."
      />

      {/* Whether this record can still be trusted, shown above the record
          itself. The seals were verifiable by nothing reachable until the
          endpoint existed; a check nobody runs is not a check. */}
      <SealIntegrity />

      {error ? (
        <ErrorNote error={error} />
      ) : loading ? (
        <div className="space-y-2">
          {Array.from({ length: 8 }).map((_, i) => (
            <Skeleton key={i} className="h-11 w-full" />
          ))}
        </div>
      ) : rows.length === 0 ? (
        <EmptyState title="No security events" hint="Blocked requests and abuse detections appear here as controls trigger." />
      ) : (
        <Table
          head={
            <>
              <Th>Event</Th>
              <Th>Source IP</Th>
              <Th className="hidden md:table-cell">Request</Th>
              <Th className="text-right">Code</Th>
              <Th className="hidden text-right sm:table-cell">When</Th>
            </>
          }
        >
          {rows.map((e, i) => {
            const severity = str(e.extra?.severity);
            const why = str(e.extra?.why);
            return (
              <Row key={i} i={i}>
                <Td>
                  <div className="flex items-center gap-1.5">
                    {severity ? <SeverityBadge severity={severity} /> : null}
                    <Badge tone={reasonTone(e.reason)}>{e.reason.replace(/_/g, " ")}</Badge>
                  </div>
                  {why ? <p className="mt-1 max-w-[32rem] truncate text-xs text-muted" title={why}>{why}</p> : null}
                </Td>
                <Td className="font-mono text-xs">{e.ip}</Td>
                <Td className="hidden max-w-[20rem] truncate font-mono text-xs md:table-cell">
                  <MethodBadge method={e.method} /> {e.path}
                </Td>
                <Td className="text-right tnum">
                  <span className={e.code >= 500 ? "text-danger" : "text-muted"}>{e.code}</span>
                </Td>
                <Td className="hidden text-right text-xs text-muted sm:table-cell">{timeAgo(e.timestamp)}</Td>
              </Row>
            );
          })}
        </Table>
      )}
    </div>
  );
}
