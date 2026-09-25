import { motion } from "framer-motion";
import { type ReactNode } from "react";
import { Card, Skeleton } from "./ui";
import { cn } from "@/lib/utils";

export const stagger = {
  hidden: { opacity: 0 },
  show: { opacity: 1, transition: { staggerChildren: 0.04 } },
};
export const item = {
  hidden: { opacity: 0, y: 8 },
  show: { opacity: 1, y: 0, transition: { type: "spring", stiffness: 350, damping: 28 } as const },
};

export function StatCard({
  label,
  value,
  icon,
  tone = "fg",
  hint,
  loading,
  delta,
}: {
  label: string;
  value: ReactNode;
  icon?: ReactNode;
  tone?: "fg" | "accent" | "danger" | "warn" | "ok";
  hint?: string;
  loading?: boolean;
  /** Small "+N since last poll" style indicator, shown beside the value. */
  delta?: ReactNode;
}) {
  const toneCls = {
    fg: "text-fg",
    accent: "text-accent",
    danger: "text-danger",
    warn: "text-warn",
    ok: "text-ok",
  }[tone];

  const iconBg = {
    fg: "bg-elevated/70 text-muted border-border/60",
    accent: "bg-accent/10 text-accent border-accent/25",
    danger: "bg-danger/10 text-danger border-danger/25",
    warn: "bg-warn/10 text-warn border-warn/25",
    ok: "bg-ok/10 text-ok border-ok/25",
  }[tone];

  return (
    <motion.div variants={item}>
      <Card className="group relative overflow-hidden p-4 sm:p-5 transition-all duration-200 hover:border-border hover:shadow-card-hover">
        <div className="flex items-start justify-between gap-2">
          <span className="text-[12px] font-medium tracking-wide uppercase text-muted/70">{label}</span>
          {icon && (
            <span
              className={cn(
                "flex h-7 w-7 shrink-0 items-center justify-center rounded-lg border text-sm transition-transform duration-200 group-hover:scale-105",
                iconBg,
              )}
            >
              {icon}
            </span>
          )}
        </div>

        {loading ? (
          <Skeleton className="mt-3 h-8 w-28" />
        ) : (
          <div className="mt-3 text-[26px] font-bold tnum leading-tight tracking-tight">
            <span className={toneCls}>{value}</span>
          </div>
        )}

        <div className="mt-3 flex items-center gap-1.5 text-[11.5px] text-muted">
          {delta ?? (hint && <span className="truncate">{hint}</span>)}
        </div>
      </Card>
    </motion.div>
  );
}

/** High-contrast engineering delta indicator */
export function Delta({
  dir,
  children,
  context,
}: {
  dir: "up" | "down" | "flat";
  children: ReactNode;
  context?: ReactNode;
}) {
  const isUp = dir === "up";
  const isDown = dir === "down";
  const pillCls = isUp
    ? "bg-ok/10 text-ok border border-ok/25"
    : isDown
    ? "bg-danger/10 text-danger border border-danger/25"
    : "bg-elevated text-muted border border-border/60";
  const arrow = isUp ? "↑" : isDown ? "↓" : "→";

  return (
    <span className="inline-flex items-center gap-1.5">
      <span className={cn("inline-flex items-center gap-0.5 rounded px-1.5 py-0.5 font-mono text-[10.5px] font-semibold tnum", pillCls)}>
        <span>{arrow}</span>
        <span>{children}</span>
      </span>
      {context && <span className="text-muted/70 text-[11px]">{context}</span>}
    </span>
  );
}

export function PageHeader({
  title,
  desc,
  badge,
  action,
}: {
  title: string;
  desc?: string;
  badge?: ReactNode;
  action?: ReactNode;
}) {
  return (
    <div className="mb-6 flex flex-wrap items-end justify-between gap-4 border-b border-border/40 pb-4">
      <div>
        <div className="flex items-center gap-2.5">
          <h2 className="text-xl font-bold tracking-tight text-fg sm:text-2xl">{title}</h2>
          {badge}
        </div>
        {desc && <p className="mt-1 text-xs text-muted/80 max-w-2xl">{desc}</p>}
      </div>
      {action && <div className="flex items-center gap-2">{action}</div>}
    </div>
  );
}

export function ErrorNote({ error }: { error: string }) {
  return (
    <Card className="border-danger/30 bg-danger/5 p-4 text-xs font-mono text-danger">
      Failed to load: {error}
    </Card>
  );
}

// Minimal high-density responsive table.
export function Table({ head, children }: { head: ReactNode; children: ReactNode }) {
  return (
    <Card className="overflow-hidden">
      <div className="overflow-x-auto">
        <table className="w-full text-left text-xs">
          <thead>
            <tr className="border-b border-border/80 bg-elevated/40 text-[11px] font-semibold uppercase tracking-wider text-muted/70">
              {head}
            </tr>
          </thead>
          <tbody className="divide-y divide-border/40 font-normal">{children}</tbody>
        </table>
      </div>
    </Card>
  );
}

export function Th({ children, className }: { children?: ReactNode; className?: string }) {
  return <th className={cn("px-4 py-3 font-semibold", className)}>{children}</th>;
}

export function Row({ children, i = 0 }: { children: ReactNode; i?: number }) {
  return (
    <motion.tr
      initial={{ opacity: 0 }}
      animate={{ opacity: 1 }}
      transition={{ delay: Math.min(i * 0.015, 0.25) }}
      className="transition-colors hover:bg-elevated/40"
    >
      {children}
    </motion.tr>
  );
}

export function Td({ children, className }: { children?: ReactNode; className?: string }) {
  return <td className={cn("px-4 py-3 align-middle", className)}>{children}</td>;
}
