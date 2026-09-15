import { CheckCircle, Warning } from "@phosphor-icons/react";
import { Badge, Card, Skeleton } from "@/components/ui";
import { ErrorNote } from "@/components/PageBits";
import { DocumentLimits } from "@/components/DocumentLimits";
import { api, type SealReport } from "@/lib/api";
import { useData } from "@/lib/hooks";

// SealIntegrity answers, on the page where an operator reads the log, whether
// that log can still be trusted.
//
// It sits here rather than behind its own navigation entry because the question
// only arises while looking at the record. A separate page is one an operator
// visits after being told to — by which point an auditor has already asked.
export function SealIntegrity() {
  const { data, loading, error } = useData<SealReport>(() => api.get("/api/forensic/seals"), []);

  if (error) {
    // 503 is the honest answer when forensic_dsn is unset: seals are off. That
    // is different from "the log is fine", and must not be rendered as calm.
    return <ErrorNote error={error} />;
  }
  if (loading || !data) return <Skeleton className="h-24 w-full" />;

  const ok = data.intact;
  const chain = data.chain;

  return (
    <Card className="mb-4 p-4">
      <div className="flex items-start gap-3">
        <div className={ok ? "text-ok" : "text-danger"}>
          {ok ? <CheckCircle size={22} weight="fill" /> : <Warning size={22} weight="fill" />}
        </div>

        <div className="min-w-0 flex-1">
          <div className="flex flex-wrap items-center gap-2">
            <h3 className="text-sm font-medium">Log integrity</h3>
            <Badge tone={ok ? "ok" : "danger"}>{ok ? "intact" : "tampered"}</Badge>
            <span className="text-xs text-muted">
              {data.summary.periods} sealed {data.summary.periods === 1 ? "period" : "periods"}
              {data.summary.altered > 0 ? `, ${data.summary.altered} altered` : null}
            </span>
          </div>

          {ok ? (
            <p className="mt-1 text-xs text-muted">
              Every sealed period recomputes, and the chain is complete — nothing has been
              removed from it, including from the end.
            </p>
          ) : (
            <div className="mt-1 space-y-1">
              {chain.detail ? (
                <p className="text-xs text-danger">{chain.detail}</p>
              ) : null}
              {data.seals
                .filter((s) => !s.intact && s.detail)
                .slice(0, 5)
                .map((s, i) => (
                  <p key={i} className="text-xs text-danger">
                    <span className="font-mono">{s.seal.period_start.slice(0, 16).replace("T", " ")}</span>
                    {" — "}
                    {s.detail}
                  </p>
                ))}
            </div>
          )}

          {/* The limits travel with the result. A green badge is exactly what a
              reader over-reads, and "intact" here means something narrower than
              the word suggests. */}
          <DocumentLimits limits={data.limits} />

        </div>
      </div>
    </Card>
  );
}
