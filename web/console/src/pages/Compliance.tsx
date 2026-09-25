import { motion } from "framer-motion";
import { ClipboardText, ShieldCheck, ShieldWarning, Warning, WarningCircle } from "@phosphor-icons/react";
import { ErrorNote, PageHeader, StatCard } from "@/components/PageBits";
import { Badge, Card, EmptyState, Skeleton } from "@/components/ui";
import { DocumentLimits } from "@/components/DocumentLimits";
import { api, type ComplianceFramework, type ComplianceReport } from "@/lib/api";
import { useData } from "@/lib/hooks";
import { fmt } from "@/lib/utils";

export function Compliance() {
  const { data, loading, error } = useData<ComplianceReport>(() => api.get("/api/compliance"), []);
  const hasAny = data && data.frameworks.length > 0;

  return (
    <div className="space-y-6">
      <PageHeader
        title="Regulatory & Compliance Frameworks"
        desc="Runtime evidence mapping against NIS2 Directive (Art. 21), DORA (Art. 8–10), and ISO/IEC 27001:2022 security controls."
        badge={
          <Badge tone="accent" className="font-mono text-xs">
            {data?.frameworks.length ?? 0} FRAMEWORKS MAPPED
          </Badge>
        }
      />

      {error ? (
        <ErrorNote error={error} />
      ) : (
        <div className="grid grid-cols-2 gap-4 lg:grid-cols-4">
          <StatCard
            label="Critical Gaps"
            value={data ? fmt(data.summary.critical) : undefined}
            icon={<WarningCircle size={16} />}
            tone="danger"
            loading={loading}
            hint="immediate compliance risk"
          />
          <StatCard
            label="Warning Issues"
            value={data ? fmt(data.summary.warning) : undefined}
            icon={<Warning size={16} />}
            tone="warn"
            loading={loading}
            hint="policy deviations"
          />
          <StatCard
            label="Controls Impacted"
            value={data ? fmt(data.summary.controls_affected) : undefined}
            icon={<ShieldWarning size={16} />}
            tone="accent"
            loading={loading}
            hint="across active standards"
          />
          <StatCard
            label="Frameworks Mapped"
            value={data ? fmt(data.frameworks.length) : undefined}
            icon={<ClipboardText size={16} />}
            loading={loading}
            hint="NIS2, DORA, ISO 27001"
          />
        </div>
      )}

      {/* A framework mapping is the document most likely to be read as a
          compliance claim, and it is not one. The caveats ship inside the
          signed body; showing them only there would leave them unread by
          everyone who meets the report on this screen. */}
      <DocumentLimits
        limits={data?.limits}
        label="What a mapped control does and does not mean"
        className="mt-3"
      />

      <div className="mt-4">
        {loading ? (
          <div className="space-y-3">
            {Array.from({ length: 3 }).map((_, i) => (
              <Skeleton key={i} className="h-28 w-full" />
            ))}
          </div>
        ) : !hasAny ? (
          !error && (
            <Card>
              <EmptyState
                icon={<ShieldCheck size={40} />}
                title="No mapped findings"
                hint="No exposures or access-control abuse detected to map onto compliance controls. Drive traffic to build the picture."
              />
            </Card>
          )
        ) : (
          <div className="space-y-6">
            {data!.frameworks.map((fw) => (
              <section key={fw.framework}>
                <h3 className="mb-2 text-[13px] font-semibold uppercase tracking-wide text-muted">{fw.framework}</h3>
                <Card className="divide-y divide-border/60">
                  {fw.controls.map((c, i) => (
                    <ControlRow key={c.control} c={c} i={i} />
                  ))}
                </Card>
                {fw.not_evidenced?.length ? <NotEvidenced items={fw.not_evidenced} /> : null}
              </section>
            ))}
            <p className="text-xs text-muted/70">
              Mapping aid across OWASP API Top 10, NIS2 (Art. 21(2)), DORA (Art. 8–10) and ISO/IEC 27001:2022 Annex A —
              not a legal certification.
            </p>
          </div>
        )}
      </div>
    </div>
  );
}

/**
 * The articles a framework requires that AEGIS cannot speak to.
 *
 * Shown next to the mapped controls, not hidden behind a link: a page listing
 * only what it mapped reads as covering the framework, and an auditor who finds
 * the gap unaided stops trusting the rest of the page.
 */
function NotEvidenced({ items }: { items: NonNullable<ComplianceFramework["not_evidenced"]> }) {
  return (
    <div className="mt-2 rounded-lg border border-dashed border-border/70 px-4 py-3">
      <p className="text-[11.5px] font-medium uppercase tracking-wide text-muted">Not evidenced by AEGIS</p>
      <ul className="mt-2 space-y-1.5">
        {items.map((u) => (
          <li key={u.control} className="text-xs text-muted">
            <span className="font-mono text-muted">{u.control}</span>{" "}
            <span className="text-fg/80">{u.title}</span>
            <span className="block text-muted/80">{u.reason}</span>
          </li>
        ))}
      </ul>
    </div>
  );
}

function ControlRow({ c, i }: { c: ComplianceReport["frameworks"][number]["controls"][number]; i: number }) {
  const critical = c.severity === "critical";
  return (
    <motion.div
      initial={{ opacity: 0, y: 6 }}
      animate={{ opacity: 1, y: 0 }}
      transition={{ delay: Math.min(i * 0.03, 0.3) }}
      className="flex items-start gap-4 px-4 py-4 sm:gap-5"
    >
      <span className="w-16 shrink-0 pt-0.5 sm:w-20">
        <span className={`inline-flex items-center gap-1.5 text-[11.5px] font-medium ${critical ? "text-danger" : "text-muted"}`}>
          <span className={`h-1.5 w-1.5 rounded-full ${critical ? "bg-danger" : "bg-muted"}`} />
          <span className="hidden sm:inline">{critical ? "Critical" : "Warning"}</span>
        </span>
      </span>
      <div className="min-w-0 flex-1">
        <div className="flex flex-wrap items-baseline gap-2">
          <span className="font-mono text-xs text-muted">{c.control}</span>
          <span className="text-[13.5px] font-medium text-fg">{c.title}</span>
        </div>
        <ul className="mt-1.5 space-y-0.5">
          {c.issues.map((iss, j) => (
            <li key={j} className="truncate text-xs text-muted" title={iss}>
              · {iss}
            </li>
          ))}
        </ul>
      </div>
      <div className="shrink-0 text-center">
        <div className="text-[17px] font-bold tnum text-fg">{c.count}</div>
        <div className="text-[9.5px] uppercase tracking-wide text-muted">issues</div>
      </div>
    </motion.div>
  );
}
