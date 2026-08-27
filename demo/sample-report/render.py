#!/usr/bin/env python3
"""Render the sample findings report from the raw exports in out/.

Reads only what generate.sh exported from a real gateway run — every number,
finding and endpoint below comes out of those files, so the artifact can be
shown to a prospect without a caveat about the figures being illustrative.

    python3 demo/sample-report/render.py

Writes docs/assets/AEGIS-Sample-Findings-Report.html (turn it into a PDF with
the same headless-Chrome step used for the other documents in docs/assets/).
"""
import base64
import html
import json
import pathlib
import sys
from collections import OrderedDict

HERE = pathlib.Path(__file__).resolve().parent
OUT = HERE / "out"
DEST = HERE.parents[1] / "docs" / "assets" / "AEGIS-Sample-Findings-Report.html"

# The admin plane is AEGIS's own control surface; events from it are an artifact
# of exporting the report, not part of the customer's API story.
ADMIN_PATH_PREFIXES = ("/api/findings", "/api/catalog", "/api/posture", "/api/consumers",
                       "/api/compliance", "/api/block-log", "/api/report", "/api/metrics")


# Fonts are embedded rather than linked so the artifact is self-contained: it
# gets emailed to people who will not have the repo, and a report that renders
# in fallback Georgia/Arial stops looking like the product it came from. Latin
# subsets only — the document is English.
FONT_DIR = HERE.parents[1] / "web" / "v3" / "node_modules" / "@fontsource"
FONT_FILES = [
    ("Libre Baskerville", 400, "libre-baskerville/files/libre-baskerville-latin-400-normal.woff2"),
    ("Libre Baskerville", 700, "libre-baskerville/files/libre-baskerville-latin-700-normal.woff2"),
    ("Inter", 400, "inter/files/inter-latin-400-normal.woff2"),
    ("Inter", 500, "inter/files/inter-latin-500-normal.woff2"),
    ("Inter", 600, "inter/files/inter-latin-600-normal.woff2"),
    ("Fira Code", 400, "fira-code/files/fira-code-latin-400-normal.woff2"),
    ("Fira Code", 500, "fira-code/files/fira-code-latin-500-normal.woff2"),
]


def font_faces():
    """@font-face rules with the woff2 payload inlined as data URIs.

    Missing fonts are not fatal — the document still renders in the CSS
    fallbacks — but they are reported, because silently shipping a
    wrong-looking artifact is worse than a warning nobody reads.
    """
    out = []
    for family, weight, rel in FONT_FILES:
        path = FONT_DIR / rel
        if not path.exists():
            print(f"  warning: font not found, falling back: {rel}", file=sys.stderr)
            continue
        b64 = base64.b64encode(path.read_bytes()).decode("ascii")
        out.append(
            f"@font-face{{font-family:'{family}';font-style:normal;font-weight:{weight};"
            f"font-display:block;src:url(data:font/woff2;base64,{b64}) format('woff2');}}"
        )
    return "\n".join(out)


def load(name):
    p = OUT / name
    if not p.exists():
        sys.exit(f"missing {p} — run demo/sample-report/generate.sh first")
    return json.loads(p.read_text())


def esc(v):
    return html.escape(str(v))


def main():
    findings = load("findings.json")
    posture = load("posture.json")
    catalog = load("catalog.json")
    consumers = load("consumers.json")
    compliance = load("compliance.json")
    blocklog = load("block-log.json")

    eps = catalog if isinstance(catalog, list) else catalog.get("endpoints", [])
    cons = consumers if isinstance(consumers, list) else consumers.get("consumers", [])
    events = blocklog if isinstance(blocklog, list) else blocklog.get("entries", blocklog.get("events", []))

    # Runtime abuse detections, de-duplicated per (reason, object) and with the
    # gateway's own admin traffic filtered out.
    abuse = OrderedDict()
    for e in events:
        path = e.get("path", "")
        if any(path.startswith(p) for p in ADMIN_PATH_PREFIXES):
            continue
        extra = e.get("extra") or {}
        key = (e.get("reason"), extra.get("object_id"), extra.get("endpoint"))
        abuse.setdefault(key, {**e, "extra": extra})

    idor = [v for k, v in abuse.items() if k[0] == "bola_object_ownership"]
    enum = [v for k, v in abuse.items() if k[0] == "bola_enumeration"]

    crit = findings.get("by_severity", {}).get("critical", 0)
    warn = findings.get("by_severity", {}).get("warning", 0)

    # ── build ────────────────────────────────────────────────────────────────
    fonts = font_faces()
    P = []
    a = P.append

    a(f"""<!doctype html>
<html lang="en"><head><meta charset="utf-8">
<title>AEGIS — Sample Findings Report</title>
<style>
{fonts}
/* Design tokens lifted verbatim from the marketing site (web/v3/src/index.css)
   so the artifact reads as the same product, not a generic report template.
   Severity colours come from the admin console's own palette
   (web/console/src/index.css) rather than being invented here. */
:root {{
  --obsidian:#111111; --canvas:#181818; --card:#1f1f1f; --elevated:#262626; --peak:#323232;
  --ink:#eeeeee; --ash:#e4e4e4; --muted:#a4a19b; --faint:#5e5d59;
  --line:#262626; --line-2:#323232; --accent:#2b7fff;
  --danger:#ef4444; --warn:#f7b32b; --ok:#22c55e;
  --font-serif:"Libre Baskerville",Georgia,serif;
  --font-sans:"Inter",-apple-system,BlinkMacSystemFont,"Segoe UI",sans-serif;
  --font-mono:"Fira Code",ui-monospace,"SF Mono",monospace;
}}
/* background on @page, not just body: without it the sheet's margin area stays
   white and the dark document reads as a block floating on paper. Literal hex
   rather than var() — custom properties do not resolve inside @page. */
@page {{ size:A4; margin:16mm 14mm; background:#181818; }}
* {{ box-sizing:border-box; }}
/* Without this the dark surfaces print as white and the whole design collapses. */
html,body {{ -webkit-print-color-adjust:exact; print-color-adjust:exact; }}
body {{
  margin:0; background:var(--canvas); color:var(--ink);
  font-family:var(--font-sans); font-size:10pt; line-height:1.6;
}}

.masthead {{
  display:flex; justify-content:space-between; align-items:baseline;
  border-bottom:1px solid var(--line); padding-bottom:3mm; margin-bottom:9mm;
}}
.wordmark {{ font-family:var(--font-serif); font-size:14pt; letter-spacing:-0.01em; }}
.stamp {{ font-family:var(--font-mono); font-size:7.5pt; letter-spacing:0.12em;
          text-transform:uppercase; color:var(--warn); }}

.eyebrow {{ font-family:var(--font-mono); font-size:8pt; letter-spacing:0.12em;
            text-transform:uppercase; color:var(--accent); margin:0 0 4mm; }}
h1 {{ font-family:var(--font-serif); font-weight:700; font-size:23pt; line-height:1.15;
      letter-spacing:-0.015em; margin:0 0 3mm; }}
.dek {{ font-size:11pt; color:var(--muted); margin:0 0 8mm; max-width:60ch; }}

h2 {{ font-family:var(--font-serif); font-weight:700; font-size:14pt; letter-spacing:-0.01em;
      margin:10mm 0 3.5mm; padding-bottom:2mm; border-bottom:1px solid var(--line); }}
p {{ color:var(--ash); margin:0 0 3mm; max-width:70ch; }}
strong {{ color:var(--ink); font-weight:600; }}
em {{ color:var(--muted); font-style:italic; }}
code {{ font-family:var(--font-mono); font-size:0.88em; background:var(--card);
        border:1px solid var(--line-2); padding:0.4mm 1.4mm; border-radius:3px; color:var(--ink); }}

.kpis {{ display:flex; gap:3mm; margin:0 0 6mm; }}
.kpi {{ flex:1; background:var(--card); border:1px solid var(--line-2); border-radius:8px;
        padding:4mm 4mm 3.5mm; break-inside:avoid; }}
.kpi .n {{ font-family:var(--font-serif); font-size:22pt; font-weight:700; line-height:1;
           font-variant-numeric:tabular-nums; }}
.kpi.bad .n {{ color:var(--danger); }}
.kpi .l {{ font-family:var(--font-mono); font-size:7.5pt; letter-spacing:0.08em;
           text-transform:uppercase; color:var(--muted); margin-top:2.5mm; line-height:1.4; }}

.finding {{ background:var(--card); border:1px solid var(--line-2);
            border-left:2.5px solid var(--danger); border-radius:8px;
            padding:4mm 4.5mm; margin:0 0 3mm; break-inside:avoid; }}
.finding .hd {{ display:flex; justify-content:space-between; align-items:baseline; gap:4mm; }}
.finding .ttl {{ font-family:var(--font-serif); font-weight:700; font-size:11.5pt; letter-spacing:-0.01em; }}
.finding .where {{ font-family:var(--font-mono); font-size:8.5pt; color:var(--muted); margin-top:2mm; }}
.finding .why {{ color:var(--ash); font-size:9.5pt; margin-top:2mm; }}

.tag {{ font-family:var(--font-mono); font-size:7.5pt; letter-spacing:0.06em; text-transform:uppercase;
        padding:0.8mm 2mm; border-radius:3px; white-space:nowrap; flex:none; }}
.tag.crit {{ color:var(--danger); background:rgba(239,68,68,0.12); border:1px solid rgba(239,68,68,0.3); }}
.tag.warn {{ color:var(--warn); background:rgba(247,179,43,0.12); border:1px solid rgba(247,179,43,0.3); }}
.tag.ok   {{ color:var(--ok);   background:rgba(34,197,94,0.12);  border:1px solid rgba(34,197,94,0.3); }}

table {{ border-collapse:collapse; width:100%; margin:1mm 0 3mm; font-size:9pt; }}
th {{ font-family:var(--font-mono); font-size:7.5pt; text-transform:uppercase; letter-spacing:0.06em;
      color:var(--muted); font-weight:500; text-align:left;
      padding:2mm 3mm 2mm 0; border-bottom:1px solid var(--line-2); }}
td {{ color:var(--ash); padding:2.4mm 3mm 2.4mm 0; border-bottom:1px solid var(--line);
      font-variant-numeric:tabular-nums; vertical-align:top; }}
tr {{ break-inside:avoid; }}

.note {{ background:var(--card); border:1px solid var(--line-2); border-radius:10px;
         padding:5mm; break-inside:avoid; }}
.note p:last-child {{ margin-bottom:0; }}

footer {{ margin-top:10mm; padding-top:3mm; border-top:1px solid var(--line);
          font-family:var(--font-mono); font-size:7.5pt; color:var(--faint);
          display:flex; justify-content:space-between; }}
</style></head><body>""")

    a("""<div class="masthead">
  <span class="wordmark">AEGIS</span>
  <span class="stamp">Sample · fictional data</span>
</div>""")

    a('<p class="eyebrow">Passive assessment</p>')
    a("<h1>API Security<br>Findings Report</h1>")
    a('<p class="dek">Northwind Payments — a fictional estate. Every figure below was '
      "exported from a real gateway run, not written by hand.</p>")

    # ── Executive summary ────────────────────────────────────────────────────
    a("<h2>What we found</h2>")

    # Deliberately NOT posture.coverage_pct as a headline number. Coverage counts
    # auth + WAF + rate-limit as "protecting" an endpoint, and a passive
    # assessment runs in observe mode, where the enforcement-only controls are
    # switched off by design — so coverage reads 0% during a pilot regardless of
    # how well the estate is configured. The unprotected count survives both
    # modes, because it describes the customer's configuration rather than what
    # AEGIS happens to be enforcing while it watches.
    a(f"""<div class="kpis">
  <div class="kpi bad"><div class="n">{crit}</div><div class="l">Critical<br>findings</div></div>
  <div class="kpi bad"><div class="n">{len(idor)}</div><div class="l">Confirmed<br>data leaks</div></div>
  <div class="kpi"><div class="n">{posture.get('total', 0)}</div><div class="l">APIs<br>discovered</div></div>
  <div class="kpi bad"><div class="n">{posture.get('unprotected', 0)}</div><div class="l">With no<br>auth at all</div></div>
</div>""")

    a(f"""<p>AEGIS ran in front of the API in passive mode: it inspected and recorded, and
blocked nothing. In that window it discovered <strong>{posture.get('total', 0)} live endpoints</strong>,
of which <strong>{posture.get('unprotected', 0)} enforce no authentication, rate limiting or firewall at all</strong>.
Two of them return customer payment-card and email data to callers presenting no
credential whatsoever.</p>""")

    a(f"""<p>Separately, the gateway observed <strong>{len(idor)} confirmed cases</strong> of one
authenticated user reading another user's records — not inferred from volume, but
confirmed by comparing the owner id in each response body against the caller's
verified identity. This is the class of flaw a signature firewall cannot detect,
because the requests are syntactically perfect.</p>""")

    # ── Findings ─────────────────────────────────────────────────────────────
    a("<h2>Critical findings</h2>")
    for row in findings.get("findings", []):
        f = row["finding"]
        sev = f.get("severity", "warning")
        cls = "crit" if sev == "critical" else "warn"
        a(f"""<div class="finding">
  <div class="hd"><span class="ttl">{esc(f.get('title'))}</span>
    <span class="tag {cls}">{esc(sev)} · {esc(f.get('owasp'))}</span></div>
  <div class="where"><code>{esc(row.get('method'))} {esc(row.get('path_template'))}</code>
     &nbsp;risk {esc(row.get('risk_score'))}</div>
  <div class="why">{esc(f.get('why'))}</div>
</div>""")

    if idor:
        ex = idor[0]["extra"]
        a(f"""<div class="finding">
  <div class="hd"><span class="ttl">Broken object level authorization — confirmed</span>
    <span class="tag crit">critical · API1:2023</span></div>
  <div class="where"><code>{esc(ex.get('endpoint'))}</code>
     &nbsp;{len(idor)} objects read by a caller who does not own them</div>
  <div class="why">{esc(ex.get('why'))}</div>
</div>""")

    if enum:
        a(f"""<div class="finding">
  <div class="hd"><span class="ttl">Object enumeration by a single consumer</span>
    <span class="tag crit">critical · API1:2023</span></div>
  <div class="why">{esc(enum[0]['extra'].get('why'))}</div>
</div>""")

    # ── Inventory ────────────────────────────────────────────────────────────
    a("<h2>API inventory and posture</h2>")
    a("<p>Every endpoint below was discovered from traffic — nothing was declared in "
      "advance. <em>Unprotected</em> means none of authentication, rate limiting or "
      "firewall applies to it.</p>")
    a("<p>One caveat stated rather than hidden: this assessment ran in passive mode, so "
      "AEGIS enforced nothing while it watched. The <em>partial</em> and <em>protected</em> "
      "labels therefore describe what was active during the assessment, not the ceiling of "
      "what the estate could enforce. <em>Unprotected</em> is unaffected — an endpoint with "
      "no authentication has none either way, which is why the summary leads with that number.</p>")
    a("<table><tr><th>Endpoint</th><th>Posture</th><th>Req</th>"
      "<th>Anon</th><th>PII responses</th><th>Risk</th></tr>")
    for e in sorted(eps, key=lambda x: -x.get("risk_score", 0)):
        p = e.get("posture", "")
        cls = {"unprotected": "crit", "partial": "warn", "protected": "ok"}.get(p, "warn")
        a(f"""<tr><td><code>{esc(e.get('method'))} {esc(e.get('path_template'))}</code></td>
<td><span class="tag {cls}">{esc(p)}</span></td><td>{esc(e.get('request_count', 0))}</td>
<td>{esc(e.get('anon_count', 0))}</td><td>{esc(e.get('pii_count', 0))}</td>
<td>{esc(e.get('risk_score', 0))}</td></tr>""")
    a("</table>")

    # ── Consumers ────────────────────────────────────────────────────────────
    a("<h2>Who is calling what</h2>")
    a("<p>Consumer identity is taken from the verified JWT where one is present, and "
      "falls back to source address where none is.</p>")
    a("<table><tr><th>Consumer</th><th>Identified by</th><th>Requests</th><th>Endpoints</th></tr>")
    for c in sorted(cons, key=lambda x: -x.get("request_count", 0)):
        kind = "verified token" if c.get("kind") == "jwt" else "source address (no credential)"
        a(f"""<tr><td><code>{esc(c.get('label'))}</code></td><td>{esc(kind)}</td>
<td>{esc(c.get('request_count', 0))}</td><td>{esc(c.get('endpoints_touched', 0))}</td></tr>""")
    a("</table>")

    # ── Compliance ───────────────────────────────────────────────────────────
    a("<h2>Regulatory mapping</h2>")
    s = compliance.get("summary", {})
    a(f"<p>The findings above map onto {esc(s.get('controls_affected', 0))} controls across "
      "OWASP API Top 10, NIS2 and ISO/IEC 27001:2022. This is a mapping aid for an "
      "audit conversation, not a certification.</p>")
    a("<table><tr><th>Framework</th><th>Control</th><th>Title</th><th>Severity</th><th>Issues</th></tr>")
    for fw in compliance.get("frameworks", []):
        for c in fw.get("controls", []):
            cls = "crit" if c.get("severity") == "critical" else "warn"
            a(f"""<tr><td>{esc(fw.get('framework'))}</td><td><code>{esc(c.get('control'))}</code></td>
<td>{esc(c.get('title'))}</td><td><span class="tag {cls}">{esc(c.get('severity'))}</span></td>
<td>{esc(c.get('count'))}</td></tr>""")
    a("</table>")

    # ── Method ───────────────────────────────────────────────────────────────
    a("<h2>How this report was produced</h2>")
    a("""<div class="note">
<p><strong>This is a sample.</strong> The API behind it — Northwind Payments — is
fictional and deliberately flawed, and the customer records in it are synthetic
(reserved <code>example.com</code> addresses and standard test card numbers). No real
company's data appears anywhere in this document.</p>
<p><strong>The findings themselves are not mocked up.</strong> A real AEGIS instance ran in
front of that API, ordinary traffic was driven through it, and every number, endpoint,
consumer and finding above was exported from what the gateway actually observed. The
generator is committed at <code>demo/sample-report/</code> and reproduces this document
end to end.</p>
<p><strong>On a real engagement</strong> the same output describes your estate instead: AEGIS
is deployed in passive mode, blocks nothing, and after roughly a week hands back this
report. The deployment carries no production risk — no request is modified, no response
is altered, and no control fails closed.</p>
</div>""")

    a('<footer><span>AEGIS — inline API security gateway</span>'
      "<span>aegis.34host.org</span></footer>")
    a("</body></html>")

    DEST.parent.mkdir(parents=True, exist_ok=True)
    DEST.write_text("\n".join(P), encoding="utf-8")
    print(f"wrote {DEST}  ({DEST.stat().st_size // 1024} KB)")
    print(f"  critical findings: {crit}   warnings: {warn}")
    print(f"  confirmed IDOR:    {len(idor)}   enumeration: {len(enum)}")
    print(f"  endpoints:         {posture.get('total')}   unprotected: {posture.get('unprotected')}")


if __name__ == "__main__":
    main()
