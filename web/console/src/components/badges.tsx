import { Badge } from "./ui";
import { cn } from "@/lib/utils";

export function PostureBadge({ posture }: { posture: string }) {
  const p = posture?.toLowerCase();
  if (p === "protected") {
    return <Badge tone="ok" dot>Protected</Badge>;
  }
  if (p === "partial") {
    return <Badge tone="warn" dot>Partial Shield</Badge>;
  }
  if (p === "shadow") {
    return <Badge tone="danger" dot className="animate-pulse">Shadow API</Badge>;
  }
  return <Badge tone="neutral" dot>Unprotected</Badge>;
}

export function SeverityBadge({ severity }: { severity: string }) {
  const s = severity?.toLowerCase();
  const tone = s === "critical" ? "danger" : s === "warning" ? "warn" : "accent";
  return (
    <Badge tone={tone as any} dot className="font-mono uppercase text-[10px] tracking-wider font-semibold">
      {severity}
    </Badge>
  );
}

export function RiskDot({ score }: { score: number }) {
  const isDanger = score >= 70;
  const isWarn = score >= 40 && score < 70;
  const label = isDanger ? "CRITICAL" : isWarn ? "ELEVATED" : "LOW";

  return (
    <span className="inline-flex items-center gap-1.5 font-mono text-xs tnum">
      <span
        className={cn(
          "inline-flex items-center justify-center rounded px-1.5 py-0.5 text-[11px] font-semibold",
          isDanger && "bg-danger/15 text-danger border border-danger/30 shadow-[0_0_8px_hsl(var(--danger)/0.25)]",
          isWarn && "bg-warn/15 text-warn border border-warn/30",
          !isDanger && !isWarn && "bg-ok/15 text-ok border border-ok/30",
        )}
        title={`Risk score: ${score}/100 (${label})`}
      >
        {score}
      </span>
    </span>
  );
}

export function MethodBadge({ method }: { method: string }) {
  const m = (method ?? "GET").toUpperCase();
  const map: Record<string, string> = {
    GET: "bg-emerald-500/10 text-emerald-400 border-emerald-500/25",
    POST: "bg-sky-500/10 text-sky-400 border-sky-500/25",
    PUT: "bg-amber-500/10 text-amber-400 border-amber-500/25",
    PATCH: "bg-purple-500/10 text-purple-400 border-purple-500/25",
    DELETE: "bg-rose-500/10 text-rose-400 border-rose-500/25",
    HEAD: "bg-slate-500/10 text-slate-400 border-slate-500/25",
    OPTIONS: "bg-slate-500/10 text-slate-400 border-slate-500/25",
  };

  const style = map[m] ?? "bg-slate-500/10 text-slate-400 border-slate-500/25";

  return (
    <span
      className={cn(
        "inline-flex items-center justify-center font-mono text-[10.5px] font-semibold tracking-wider px-2 py-0.5 rounded border select-none",
        style,
      )}
    >
      {m}
    </span>
  );
}
