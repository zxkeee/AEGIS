import { Eye, ArrowsLeftRight } from "@phosphor-icons/react";
import { api, type SessionResp } from "@/lib/api";
import { useData } from "@/lib/hooks";
import { cn } from "@/lib/utils";

/** EnforcementBanner says so when the gateway is not blocking anything.
 *
 * This console is headed "Security Overview" and lists active controls and
 * blocked-looking findings. In observe mode every control still runs and every
 * finding is still raised — but nothing is denied and no response body is
 * modified. In mirror mode the gateway is not in the request path at all.
 * Both are correct, deliberately offered pilot postures, and in both of them
 * the screen used to read exactly like a gateway that was protecting traffic.
 *
 * The mode was already written to the gateway log at boot and on every
 * hot-reload. A log line reaches whoever reads logs. This is for whoever reads
 * the screen, which during a pilot is a different person.
 *
 * Nothing renders while enforcing, and nothing renders when the answer is not
 * known: an absent value must not manufacture a warning, or an operator learns
 * to dismiss the banner that matters. */
export function EnforcementBanner() {
  // Sixty seconds: the mode changes only on a hot-reload, so this is about
  // noticing one within a minute, not polling live data.
  const { data } = useData<SessionResp>(api.session, [], 60 * 1000);
  const mode = data?.enforcement;
  if (!mode || mode.enforcing) return null;

  const mirror = mode.mode === "mirror";
  return (
    <div
      className={cn(
        "flex items-center gap-2.5 border-b px-4 py-2 text-[13px] md:px-6",
        "border-warn/30 bg-warn/10 text-warn",
      )}
      role="status"
    >
      <span className="shrink-0">{mirror ? <ArrowsLeftRight size={16} /> : <Eye size={16} />}</span>
      <span className="min-w-0 text-fg/90">
        <b>{mirror ? "Mirror mode — nothing on this screen is being blocked." : "Observe mode — nothing is being blocked."}</b>{" "}
        {mode.reason}
      </span>
    </div>
  );
}
