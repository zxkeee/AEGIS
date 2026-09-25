/** @type {import('tailwindcss').Config} */
export default {
  darkMode: "class",
  content: ["./index.html", "./src/**/*.{ts,tsx}"],
  theme: {
    extend: {
      colors: {
        // Semantic tokens mapped to CSS variables, themed per light/dark.
        bg: "hsl(var(--bg) / <alpha-value>)",
        surface: "hsl(var(--surface) / <alpha-value>)",
        elevated: "hsl(var(--elevated) / <alpha-value>)",
        border: "hsl(var(--border) / <alpha-value>)",
        fg: "hsl(var(--fg) / <alpha-value>)",
        muted: "hsl(var(--muted) / <alpha-value>)",
        accent: "hsl(var(--accent) / <alpha-value>)",
        "accent-fg": "hsl(var(--accent-fg) / <alpha-value>)",
        danger: "hsl(var(--danger) / <alpha-value>)",
        warn: "hsl(var(--warn) / <alpha-value>)",
        ok: "hsl(var(--ok) / <alpha-value>)",
        ring: "hsl(var(--accent) / <alpha-value>)",
        faint: "hsl(var(--faint) / <alpha-value>)",
      },
      boxShadow: {
        "glow-accent": "0 0 24px -4px hsl(var(--accent) / 0.3)",
        "glow-danger": "0 0 24px -4px hsl(var(--danger) / 0.3)",
        "glow-ok": "0 0 24px -4px hsl(var(--ok) / 0.3)",
        "card": "0 1px 3px 0 rgba(0, 0, 0, 0.3), inset 0 1px 0 0 rgba(255, 255, 255, 0.06)",
        "card-hover": "0 4px 12px 0 rgba(0, 0, 0, 0.4), inset 0 1px 0 0 rgba(255, 255, 255, 0.09)",
      },
      fontFamily: {
        sans: ['"Inter"', "system-ui", "-apple-system", "Segoe UI", "sans-serif"],
        mono: ['"Fira Code"', "ui-monospace", "SFMono-Regular", "Menlo", "monospace"],
        serif: ['"Libre Baskerville"', "Georgia", "serif"],
      },
      borderRadius: {
        lg: "0.75rem",
        xl: "1rem",
      },
      keyframes: {
        shimmer: {
          "100%": { transform: "translateX(100%)" },
        },
        pulseGlow: {
          "0%, 100%": { opacity: "1", transform: "scale(1)" },
          "50%": { opacity: "0.5", transform: "scale(1.08)" },
        },
      },
      animation: {
        shimmer: "shimmer 1.5s infinite",
        "pulse-glow": "pulseGlow 2s cubic-bezier(0.4, 0, 0.6, 1) infinite",
      },
    },
  },
  plugins: [],
};
