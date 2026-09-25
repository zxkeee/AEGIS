import { cva, type VariantProps } from "class-variance-authority";
import { Check, Copy } from "@phosphor-icons/react";
import { forwardRef, useState, type ButtonHTMLAttributes, type HTMLAttributes, type InputHTMLAttributes, type ReactNode } from "react";
import { cn } from "@/lib/utils";

// ── Button ───────────────────────────────────────────────────────────────────
const buttonV = cva(
  "inline-flex items-center justify-center gap-2 rounded-lg text-sm font-medium transition-all focus-visible:outline-none disabled:opacity-40 disabled:pointer-events-none select-none active:scale-[0.98]",
  {
    variants: {
      variant: {
        primary: "bg-accent text-accent-fg hover:bg-accent/90 shadow-sm shadow-accent/25 border border-accent/40",
        ghost: "text-muted hover:text-fg hover:bg-elevated/70 active:bg-elevated",
        outline: "border border-border/80 bg-surface/50 text-fg hover:bg-elevated hover:border-border backdrop-blur-sm",
        secondary: "bg-elevated/80 border border-border/80 text-fg hover:bg-elevated hover:border-border",
        danger: "bg-danger/10 text-danger hover:bg-danger/20 border border-danger/30 hover:border-danger/50",
      },
      size: {
        xs: "h-7 px-2.5 text-xs rounded-md",
        sm: "h-8 px-3 text-xs rounded-md",
        md: "h-9 px-4 text-sm rounded-lg",
        icon: "h-8 w-8 rounded-lg",
      },
    },
    defaultVariants: { variant: "primary", size: "md" },
  },
);

export const Button = forwardRef<
  HTMLButtonElement,
  ButtonHTMLAttributes<HTMLButtonElement> & VariantProps<typeof buttonV>
>(({ className, variant, size, ...props }, ref) => (
  <button
    ref={ref}
    className={cn(buttonV({ variant, size }), className)}
    {...(props as any)}
  />
));
Button.displayName = "Button";

// ── Card ─────────────────────────────────────────────────────────────────────
export function Card({ className, ...props }: HTMLAttributes<HTMLDivElement>) {
  return (
    <div
      className={cn(
        "rounded-xl border border-border/75 bg-surface/90 shadow-card backdrop-blur-sm transition-all duration-200",
        className,
      )}
      {...props}
    />
  );
}

// ── Badge ────────────────────────────────────────────────────────────────────
const badgeV = cva(
  "inline-flex items-center gap-1.5 rounded-md px-2 py-0.5 text-[11px] font-medium tracking-wide transition-colors",
  {
    variants: {
      tone: {
        neutral: "bg-elevated/80 text-muted border border-border/60",
        ok: "bg-ok/10 text-ok border border-ok/25",
        warn: "bg-warn/10 text-warn border border-warn/25",
        danger: "bg-danger/10 text-danger border border-danger/25",
        accent: "bg-accent/10 text-accent border border-accent/25",
      },
    },
    defaultVariants: { tone: "neutral" },
  },
);

export function Badge({
  tone,
  dot,
  className,
  children,
}: VariantProps<typeof badgeV> & { dot?: boolean; className?: string; children: ReactNode }) {
  const dotColor = {
    neutral: "bg-muted/70",
    ok: "bg-ok shadow-[0_0_8px_hsl(var(--ok)/0.8)]",
    warn: "bg-warn shadow-[0_0_8px_hsl(var(--warn)/0.8)]",
    danger: "bg-danger shadow-[0_0_8px_hsl(var(--danger)/0.8)]",
    accent: "bg-accent shadow-[0_0_8px_hsl(var(--accent)/0.8)]",
  }[tone ?? "neutral"];

  return (
    <span className={cn(badgeV({ tone }), className)}>
      {dot && <span className={cn("h-1.5 w-1.5 rounded-full shrink-0", dotColor)} />}
      <span>{children}</span>
    </span>
  );
}

// ── Input ────────────────────────────────────────────────────────────────────
export const Input = forwardRef<HTMLInputElement, InputHTMLAttributes<HTMLInputElement>>(
  ({ className, ...props }, ref) => (
    <input
      ref={ref}
      className={cn(
        "h-9 w-full rounded-lg border border-border/80 bg-bg/90 px-3 text-sm text-fg placeholder:text-muted/60",
        "focus-visible:outline-none focus-visible:ring-1 focus-visible:ring-accent/70 focus-visible:border-accent/80 transition-all",
        className,
      )}
      {...props}
    />
  ),
);
Input.displayName = "Input";

// ── Copy Button ──────────────────────────────────────────────────────────────
export function CopyButton({ text, className }: { text: string; className?: string }) {
  const [copied, setCopied] = useState(false);
  const handleCopy = (e: React.MouseEvent) => {
    e.stopPropagation();
    navigator.clipboard.writeText(text);
    setCopied(true);
    setTimeout(() => setCopied(false), 1600);
  };

  return (
    <button
      onClick={handleCopy}
      type="button"
      title="Copy to clipboard"
      className={cn(
        "inline-flex h-6 w-6 items-center justify-center rounded p-1 text-muted/70 hover:bg-elevated hover:text-fg transition-colors",
        className,
      )}
    >
      {copied ? <Check size={13} className="text-ok" /> : <Copy size={13} />}
    </button>
  );
}

// ── Skeleton ─────────────────────────────────────────────────────────────────
export function Skeleton({ className }: { className?: string }) {
  return (
    <div className={cn("relative overflow-hidden rounded-md bg-elevated/70 border border-border/40", className)}>
      <div className="absolute inset-0 -translate-x-full bg-gradient-to-r from-transparent via-fg/5 to-transparent animate-shimmer" />
    </div>
  );
}

// ── Spinner ──────────────────────────────────────────────────────────────────
export function Spinner({ className }: { className?: string }) {
  return (
    <svg className={cn("h-4 w-4 animate-spin", className)} viewBox="0 0 24 24" fill="none">
      <circle className="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" strokeWidth="3" />
      <path className="opacity-90" d="M12 2a10 10 0 0 1 10 10" stroke="currentColor" strokeWidth="3" strokeLinecap="round" />
    </svg>
  );
}

// ── Empty / error states ─────────────────────────────────────────────────────
export function EmptyState({ icon, title, hint }: { icon?: ReactNode; title: string; hint?: string }) {
  return (
    <div className="flex flex-col items-center justify-center gap-2 py-16 text-center">
      {icon && <div className="text-muted/60">{icon}</div>}
      <p className="text-sm font-medium text-fg">{title}</p>
      {hint && <p className="max-w-sm text-xs text-muted">{hint}</p>}
    </div>
  );
}
