import { AnimatePresence, motion } from "framer-motion";
import {
  Pulse,
  Warning,
  Package,
  ClipboardText,
  SquaresFour,
  SignOut,
  Moon,
  ArrowsClockwise,
  Gear as SettingsIcon,
  ShareNetwork,
  ShieldCheck,
  Sun,
  Users,
  LockKey,
} from "@phosphor-icons/react";
import { type ReactNode } from "react";
import { Badge, Button } from "./ui";
import { LicenseBanner } from "./LicenseBanner";
import { useTheme } from "@/lib/theme";
import { type Session } from "@/lib/api";
import { cn } from "@/lib/utils";

export interface NavItem {
  key: string;
  label: string;
  icon: ReactNode;
}

export interface NavGroup {
  label: string;
  items: NavItem[];
}

// Grouped for scannability: what's happening, what needs a decision, and the
// levers an operator can pull. A flat 10-item list reads as a junk drawer.
export const NAV_GROUPS: NavGroup[] = [
  {
    label: "Monitor",
    items: [
      { key: "overview", label: "Overview", icon: <SquaresFour size={18} /> },
      { key: "catalog", label: "Catalog", icon: <Package size={18} /> },
      { key: "posture", label: "Posture", icon: <ShieldCheck size={18} /> },
      { key: "map", label: "Map", icon: <ShareNetwork size={18} /> },
    ],
  },
  {
    label: "Detect",
    items: [
      { key: "findings", label: "Findings", icon: <Warning size={18} /> },
      { key: "forensics", label: "Forensics", icon: <Pulse size={18} /> },
    ],
  },
  {
    label: "Govern",
    items: [
      { key: "compliance", label: "Compliance", icon: <ClipboardText size={18} /> },
      { key: "consumers", label: "Consumers", icon: <Users size={18} /> },
      { key: "access", label: "Access", icon: <LockKey size={18} /> },
    ],
  },
  {
    label: "Admin",
    items: [{ key: "settings", label: "Settings", icon: <SettingsIcon size={18} /> }],
  },
];

export const NAV: NavItem[] = NAV_GROUPS.flatMap((g) => g.items);

export function Shell({
  active,
  onNavigate,
  onRefresh,
  onLogout,
  session,
  children,
}: {
  active: string;
  onNavigate: (k: string) => void;
  onRefresh: () => void;
  onLogout: () => void;
  session: Session;
  children: ReactNode;
}) {
  const { theme, toggle } = useTheme();
  const currentItem = NAV.find((n) => n.key === active);
  const currentGroup = NAV_GROUPS.find((g) => g.items.some((i) => i.key === active))?.label;
  const title = currentItem?.label ?? "";

  return (
    <div className="flex min-h-dvh bg-bg text-fg">
      {/* Sidebar */}
      <aside className="sticky top-0 hidden h-dvh w-64 shrink-0 flex-col border-r border-border/75 bg-surface/75 px-3.5 py-4 backdrop-blur-md md:flex">
        {/* Brand & Health */}
        <div className="mb-5 px-2">
          <div className="flex items-center justify-between">
            <div className="flex items-center gap-2.5">
              <div className="flex h-8 w-8 items-center justify-center rounded-lg bg-accent/15 text-accent border border-accent/30 shadow-[0_0_12px_hsl(var(--accent)/0.25)]">
                <ShieldCheck size={19} weight="bold" />
              </div>
              <div>
                <span className="font-mono text-sm font-extrabold tracking-wider text-fg">AEGIS</span>
                <span className="ml-1.5 rounded bg-elevated/90 px-1.5 py-0.5 font-mono text-[9px] font-bold text-accent uppercase tracking-widest border border-border/60">
                  SEC-GW
                </span>
              </div>
            </div>
          </div>

          {/* Engine health pulse pill */}
          <div className="mt-3 flex items-center justify-between rounded-lg border border-border/60 bg-bg/60 px-2.5 py-1.5 text-[11px]">
            <span className="flex items-center gap-2 font-mono text-muted/80">
              <span className="relative flex h-2 w-2">
                <span className="absolute inline-flex h-full w-full animate-ping rounded-full bg-ok opacity-75" />
                <span className="relative inline-flex h-2 w-2 rounded-full bg-ok shadow-[0_0_8px_hsl(var(--ok))]" />
              </span>
              GATEWAY ACTIVE
            </span>
            <span className="font-mono text-[10px] text-ok/90 font-medium">100%</span>
          </div>
        </div>

        {/* Navigation list */}
        <nav className="flex flex-1 flex-col gap-5 overflow-y-auto pr-1">
          {NAV_GROUPS.map((group) => (
            <div key={group.label}>
              <p className="mb-1.5 px-2.5 font-mono text-[10px] font-semibold uppercase tracking-widest text-muted/60">
                {group.label}
              </p>
              <div className="flex flex-col gap-1">
                {group.items.map((item) => {
                  const on = item.key === active;
                  return (
                    <button
                      key={item.key}
                      onClick={() => onNavigate(item.key)}
                      className={cn(
                        "group relative flex items-center gap-3 rounded-lg px-2.5 py-2 text-xs font-medium transition-all select-none",
                        on
                          ? "text-fg bg-accent/10 border border-accent/25 shadow-sm"
                          : "text-muted hover:text-fg hover:bg-elevated/60 border border-transparent",
                      )}
                    >
                      <span className={cn("transition-colors", on ? "text-accent" : "text-muted group-hover:text-fg")}>
                        {item.icon}
                      </span>
                      <span className="truncate">{item.label}</span>
                      {on && (
                        <span className="ml-auto h-1.5 w-1.5 rounded-full bg-accent shadow-[0_0_6px_hsl(var(--accent))]" />
                      )}
                    </button>
                  );
                })}
              </div>
            </div>
          ))}
        </nav>

        {/* Operator Profile Card */}
        <div className="mt-4 rounded-xl border border-border/75 bg-bg/70 p-3 shadow-card">
          <div className="flex items-center justify-between gap-2">
            <div className="flex min-w-0 items-center gap-2">
              <div className="flex h-7 w-7 shrink-0 items-center justify-center rounded-lg bg-elevated font-mono text-xs font-bold text-accent border border-border/70">
                {(session.tenant || "D")[0].toUpperCase()}
              </div>
              <div className="min-w-0">
                <div className="truncate font-mono text-xs font-semibold text-fg" title={session.tenant ?? "default"}>
                  {session.tenant ?? "default"}
                </div>
                <div className="truncate text-[10.5px] capitalize text-muted/70">
                  {session.role ?? "admin"}
                </div>
              </div>
            </div>
            {session.superAdmin ? (
              <Badge tone="warn" className="font-mono text-[9.5px]">SUPER</Badge>
            ) : (
              <Badge tone="neutral" className="font-mono text-[9.5px]">ADMIN</Badge>
            )}
          </div>
        </div>
      </aside>

      {/* Main Content Area */}
      <div className="flex min-w-0 flex-1 flex-col">
        {/* Top Header */}
        <header className="sticky top-0 z-20 flex h-14 items-center justify-between border-b border-border/75 bg-bg/80 px-4 backdrop-blur-md md:px-6">
          <div className="flex min-w-0 items-center gap-3">
            {/* Mobile nav buttons */}
            <div className="flex gap-1 overflow-x-auto md:hidden">
              {NAV.map((n) => (
                <button
                  key={n.key}
                  onClick={() => onNavigate(n.key)}
                  className={cn("shrink-0 rounded-md p-2", n.key === active ? "text-accent bg-accent/10" : "text-muted")}
                  aria-label={n.label}
                >
                  {n.icon}
                </button>
              ))}
            </div>

            {/* Breadcrumb on Desktop */}
            <div className="hidden items-center gap-2 font-mono text-xs md:flex">
              <span className="text-muted/60">{currentGroup ?? "AEGIS"}</span>
              <span className="text-muted/40">/</span>
              <span className="font-semibold text-fg">{title}</span>
            </div>
          </div>

          {/* Quick Header Actions & Telemetry */}
          <div className="flex items-center gap-2">
            {/* Telemetry pill */}
            <div className="hidden items-center gap-2 rounded-lg border border-border/60 bg-surface/60 px-2.5 py-1 font-mono text-[11px] text-muted lg:flex">
              <span className="h-1.5 w-1.5 rounded-full bg-ok" />
              <span>TLS 1.3 / HTTP 2</span>
              <span className="text-muted/40">•</span>
              <span className="text-ok">P99: 1.2ms</span>
            </div>

            <Button
              variant="outline"
              size="icon"
              onClick={onRefresh}
              aria-label="Refresh telemetry"
              title="Refresh telemetry"
              className="text-muted hover:text-fg"
            >
              <ArrowsClockwise size={16} />
            </Button>

            <Button
              variant="outline"
              size="icon"
              onClick={toggle}
              aria-label="Toggle theme"
              title="Toggle theme"
              className="text-muted hover:text-fg"
            >
              <AnimatePresence mode="wait" initial={false}>
                <motion.span
                  key={theme}
                  initial={{ rotate: -90, opacity: 0 }}
                  animate={{ rotate: 0, opacity: 1 }}
                  exit={{ rotate: 90, opacity: 0 }}
                  transition={{ duration: 0.2 }}
                  className="block"
                >
                  {theme === "dark" ? <Sun size={16} /> : <Moon size={16} />}
                </motion.span>
              </AnimatePresence>
            </Button>

            <Button
              variant="outline"
              size="icon"
              onClick={onLogout}
              aria-label="Sign out"
              title="Sign out of console"
              className="text-muted hover:text-danger hover:border-danger/30"
            >
              <SignOut size={16} />
            </Button>
          </div>
        </header>

        <LicenseBanner />

        <main className="flex-1 px-4 py-6 md:px-8">
          <AnimatePresence mode="wait">
            <motion.div
              key={active}
              initial={{ opacity: 0, y: 6 }}
              animate={{ opacity: 1, y: 0 }}
              exit={{ opacity: 0, y: -6 }}
              transition={{ duration: 0.18, ease: "easeOut" }}
              className="mx-auto max-w-7xl space-y-6"
            >
              {children}
            </motion.div>
          </AnimatePresence>
        </main>
      </div>
    </div>
  );
}
