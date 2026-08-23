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
  const title = NAV.find((n) => n.key === active)?.label ?? "";

  return (
    <div className="flex min-h-dvh">
      {/* Sidebar */}
      <aside className="sticky top-0 hidden h-dvh w-60 shrink-0 flex-col border-r border-border bg-surface/60 px-3 py-5 backdrop-blur md:flex">
        <div className="mb-7 flex items-center gap-2.5 px-2">
          <div className="flex h-8 w-8 items-center justify-center rounded-lg bg-accent/12 text-accent">
            <ShieldCheck size={18} />
          </div>
          <span className="font-serif text-base tracking-tight">AEGIS</span>
        </div>

        <nav className="flex flex-1 flex-col gap-5 overflow-y-auto">
          {NAV_GROUPS.map((group) => (
            <div key={group.label}>
              <p className="mb-1.5 px-3 text-[11px] font-medium uppercase tracking-wide text-muted/60">{group.label}</p>
              <div className="flex flex-col gap-1">
                {group.items.map((item) => {
                  const on = item.key === active;
                  return (
                    <button
                      key={item.key}
                      onClick={() => onNavigate(item.key)}
                      className={cn(
                        "relative flex items-center gap-3 rounded-lg px-3 py-2 text-sm transition-colors",
                        on ? "text-fg" : "text-muted hover:text-fg hover:bg-elevated/60",
                      )}
                    >
                      {on && (
                        <motion.span
                          layoutId="nav-active"
                          className="absolute inset-0 rounded-lg bg-elevated"
                          transition={{ type: "spring", stiffness: 400, damping: 32 }}
                        />
                      )}
                      <span className="relative z-10">{item.icon}</span>
                      <span className="relative z-10">{item.label}</span>
                    </button>
                  );
                })}
              </div>
            </div>
          ))}
        </nav>

        <div className="mt-4 flex items-center gap-2 px-2 text-xs text-muted">
          <div className="min-w-0 flex-1">
            <div className="truncate">{session.tenant ?? "default"}</div>
            <div className="capitalize text-muted/70">{session.role ?? "admin"}</div>
          </div>
          {session.superAdmin && <Badge tone="warn">super</Badge>}
        </div>
      </aside>

      {/* Main */}
      <div className="flex min-w-0 flex-1 flex-col">
        <header className="sticky top-0 z-20 flex h-14 items-center justify-between border-b border-border bg-bg/70 px-4 backdrop-blur md:px-6">
          <div className="flex min-w-0 items-center gap-2">
            {/* Mobile nav */}
            <div className="flex gap-0.5 overflow-x-auto md:hidden">
              {NAV.map((n) => (
                <button
                  key={n.key}
                  onClick={() => onNavigate(n.key)}
                  className={cn("shrink-0 rounded-md p-2", n.key === active ? "text-accent" : "text-muted")}
                  aria-label={n.label}
                >
                  {n.icon}
                </button>
              ))}
            </div>
            <h1 className="hidden text-sm font-semibold md:block">{title}</h1>
          </div>

          <div className="flex items-center gap-1">
            <Button variant="ghost" size="icon" onClick={onRefresh} aria-label="Refresh">
              <ArrowsClockwise size={17} />
            </Button>
            <Button variant="ghost" size="icon" onClick={toggle} aria-label="Toggle theme">
              <AnimatePresence mode="wait" initial={false}>
                <motion.span
                  key={theme}
                  initial={{ rotate: -90, opacity: 0 }}
                  animate={{ rotate: 0, opacity: 1 }}
                  exit={{ rotate: 90, opacity: 0 }}
                  transition={{ duration: 0.2 }}
                  className="block"
                >
                  {theme === "dark" ? <Sun size={17} /> : <Moon size={17} />}
                </motion.span>
              </AnimatePresence>
            </Button>
            <Button variant="ghost" size="icon" onClick={onLogout} aria-label="Sign out">
              <SignOut size={17} />
            </Button>
          </div>
        </header>

        <LicenseBanner />

        <main className="flex-1 px-4 py-6 md:px-6">
          <AnimatePresence mode="wait">
            <motion.div
              key={active}
              initial={{ opacity: 0, y: 8 }}
              animate={{ opacity: 1, y: 0 }}
              exit={{ opacity: 0, y: -8 }}
              transition={{ duration: 0.2, ease: "easeOut" }}
              className="mx-auto max-w-6xl"
            >
              {children}
            </motion.div>
          </AnimatePresence>
        </main>
      </div>
    </div>
  );
}
