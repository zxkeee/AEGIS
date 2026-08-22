import { Warning, WarningCircle } from "@phosphor-icons/react";
import { api, type LicenseResp } from "@/lib/api";
import { useData } from "@/lib/hooks";
import { cn } from "@/lib/utils";

/** Days below which a still-valid license starts showing a renewal nudge.
 * Matches the operational guidance in docs/licensing.md: monitor days_left
 * and renew ahead of ExpiresAt, since an unrenewed license is a hard boot
 * failure on the next restart, not a graceful degrade. */
const EXPIRY_WARNING_DAYS = 14;

/** LicenseBanner shows nothing for the common case (a plain valid license,
 * well ahead of expiry) — it only speaks up when there's something an
 * operator should actually act on: a hardware-mismatch grace period running
 * down, an approaching renewal, or (defensively; shouldn't happen given
 * loadValidatedConfig's hard boot gate) an outright invalid status. */
export function LicenseBanner() {
  // Five-minute poll: license status changes at most once per hot-reload, so
  // this is about catching a grace window ticking down, not real-time data.
  const { data } = useData<LicenseResp>(api.license, [], 5 * 60 * 1000);
  if (!data) return null;

  if (data.grace) {
    return (
      <Row tone="danger" icon={<WarningCircle size={16} />}>
        <b>Hardware mismatch.</b> This license ({data.licensee ?? "unknown licensee"}) was issued for a
        different machine. Running on a temporary grace period{data.grace_until ? <> until <b>{formatDateTime(data.grace_until)}</b></> : null} —
        the gateway will refuse to start once it ends. Contact the vendor now for a free re-issue.
      </Row>
    );
  }

  if (!data.valid) {
    return (
      <Row tone="danger" icon={<WarningCircle size={16} />}>
        <b>License invalid.</b> {data.reason ?? "No further detail available."}
      </Row>
    );
  }

  if (data.days_left != null && data.days_left <= EXPIRY_WARNING_DAYS) {
    const days = Math.max(data.days_left, 0);
    return (
      <Row tone="warn" icon={<Warning size={16} />}>
        License for <b>{data.licensee ?? "this deployment"}</b> expires in{" "}
        <b>
          {days} day{days === 1 ? "" : "s"}
        </b>
        {data.expires_at ? <> ({data.expires_at})</> : null} — renew before then; an expired license refuses to
        restart.
      </Row>
    );
  }

  return null;
}

function Row({ tone, icon, children }: { tone: "warn" | "danger"; icon: React.ReactNode; children: React.ReactNode }) {
  return (
    <div
      className={cn(
        "flex items-center gap-2.5 border-b px-4 py-2 text-[13px] md:px-6",
        tone === "danger" ? "border-danger/30 bg-danger/10 text-danger" : "border-warn/30 bg-warn/10 text-warn",
      )}
      role="status"
    >
      <span className="shrink-0">{icon}</span>
      <span className="min-w-0 text-fg/90">{children}</span>
    </div>
  );
}

function formatDateTime(iso: string): string {
  try {
    return new Date(iso).toLocaleString();
  } catch {
    return iso;
  }
}
