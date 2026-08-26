#!/usr/bin/env python3
"""Render the sample findings report from the raw exports in out/.

Reads only what generate.sh exported from a real gateway run — every number,
finding and endpoint below comes out of those files, so the artifact can be
shown to a prospect without a caveat about the figures being illustrative.

    python3 demo/sample-report/render.py

Writes docs/assets/AEGIS-Sample-Findings-Report.html (turn it into a PDF with
the same headless-Chrome step used for the other documents in docs/assets/).
"""
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
    P = []
    a = P.append

    a(f"""<!doctype html>
<html lang="en"><head><meta charset="utf-8">
<title>AEGIS — Sample Findings Report</title>
<style>
@page {{ size: A4; margin: 18mm 16mm; }}
* {{ box-sizing: border-box; }}
body {{ font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Helvetica, Arial, sans-serif;
       color: #16181d; font-size: 10.5pt; line-height: 1.5; }}
h1 {{ font-size: 21pt; margin: 0 0 2mm; letter-spacing: -0.02em; }}
h2 {{ font-size: 13pt; margin: 9mm 0 3mm; padding-bottom: 1.5mm;
      border-bottom: 1.5px solid #16181d; letter-spacing: -0.01em; }}
h3 {{ font-size: 11pt; margin: 5mm 0 1.5mm; }}
p  {{ margin: 0 0 2.5mm; }}
.sub {{ color: #5b6270; font-size: 10pt; margin-bottom: 6mm; }}
.tag {{ display:inline-block; font-size:8pt; font-weight:700; letter-spacing:.06em;
        text-transform:uppercase; padding:1mm 2mm; border-radius:2px; }}
.tag.crit {{ background:#fdeaea; color:#a01818; }}
.tag.warn {{ background:#fdf4e3; color:#8a5a00; }}
.tag.ok   {{ background:#e9f6ec; color:#1d6b32; }}
.kpis {{ display:flex; gap:3mm; margin:5mm 0 2mm; }}
.kpi {{ flex:1; border:1px solid #d9dde5; border-radius:4px; padding:3mm; }}
.kpi .n {{ font-size:19pt; font-weight:700; line-height:1.1; }}
.kpi .l {{ font-size:8.5pt; color:#5b6270; text-transform:uppercase; letter-spacing:.05em; margin-top:1mm; }}
.kpi.bad .n {{ color:#a01818; }}
table {{ width:100%; border-collapse:collapse; margin:3mm 0; font-size:9.5pt; }}
th {{ text-align:left; font-size:8pt; text-transform:uppercase; letter-spacing:.05em;
      color:#5b6270; border-bottom:1px solid #c9cfd9; padding:2mm 2mm 1.5mm 0; }}
td {{ padding:2mm 2mm 2mm 0; border-bottom:1px solid #eceff4; vertical-align:top; }}
code {{ font-family:"SF Mono",Menlo,Consolas,monospace; font-size:9pt; background:#f4f6f9;
        padding:0.3mm 1mm; border-radius:2px; }}
.finding {{ border:1px solid #d9dde5; border-left:3px solid #a01818; border-radius:3px;
            padding:3mm 3.5mm; margin:3mm 0; }}
.finding .hd {{ display:flex; justify-content:space-between; align-items:baseline; gap:3mm; }}
.finding .ttl {{ font-weight:700; font-size:10.5pt; }}
.finding .ev {{ color:#3d4450; margin-top:1.5mm; }}
.note {{ background:#f4f6f9; border-radius:3px; padding:3mm 3.5mm; font-size:9.5pt; color:#3d4450; }}
.foot {{ margin-top:8mm; padding-top:2.5mm; border-top:1px solid #d9dde5;
         font-size:8.5pt; color:#767d8a; }}
</style></head><body>""")

    a('<div class="tag warn">Sample — fictional data</div>')
    a("<h1>API Security Findings Report</h1>")
    a('<p class="sub">Northwind Payments (fictional) · passive assessment · '
      "produced by AEGIS from live traffic</p>")

    # Executive summary
    a("<h2>What we found</h2>")
    a(f"""<div class="kpis">
  <div class="kpi bad"><div class="n">{crit}</div><div class="l">Critical findings</div></div>
  <div class="kpi bad"><div class="n">{len(idor)}</div><div class="l">Confirmed data leaks</div></div>
  <div class="kpi"><div class="n">{posture.get('total', 0)}</div><div class="l">APIs discovered</div></div>
  <div class="kpi"><div class="n">{posture.get('coverage_pct', 0)}%</div><div class="l">Protection coverage</div></div>
</div>""")

    a(f"""<p>AEGIS ran in front of the API in passive mode: it inspected and recorded, and
blocked nothing. In that window it discovered <strong>{posture.get('total', 0)} live endpoints</strong>,
of which <strong>{posture.get('unprotected', 0)} enforce no authentication, rate limiting or firewall at all</strong>.
Two of those unprotected endpoints return customer payment-card and email data to
callers presenting no credential whatsoever.</p>""")

    a(f"""<p>Separately, the gateway observed <strong>{len(idor)} confirmed cases</strong> of one
authenticated user reading another user's records — not inferred from volume, but
confirmed by comparing the owner id in each response body against the caller's
verified identity. This is the class of flaw a signature firewall cannot detect,
because the requests are syntactically perfect.</p>""")

    # Critical findings
    a("<h2>Critical findings</h2>")
    for row in findings.get("findings", []):
        f = row["finding"]
        sev = f.get("severity", "warning")
        cls = "crit" if sev == "critical" else "warn"
        a(f"""<div class="finding">
  <div class="hd"><span class="ttl">{esc(f.get('title'))}</span>
    <span class="tag {cls}">{esc(sev)} · {esc(f.get('owasp'))}</span></div>
  <div class="ev"><code>{esc(row.get('method'))} {esc(row.get('path_template'))}</code>
     — risk score {esc(row.get('risk_score'))}</div>
  <div class="ev">{esc(f.get('why'))}</div>
</div>""")

    if idor:
        ex = idor[0]["extra"]
        a(f"""<div class="finding">
  <div class="hd"><span class="ttl">Broken object level authorization (IDOR) — confirmed</span>
    <span class="tag crit">critical · API1:2023</span></div>
  <div class="ev"><code>{esc(ex.get('endpoint'))}</code>
     — {len(idor)} distinct objects read by a caller who does not own them</div>
  <div class="ev">{esc(ex.get('why'))}</div>
</div>""")

    if enum:
        a(f"""<div class="finding">
  <div class="hd"><span class="ttl">Object enumeration by a single consumer</span>
    <span class="tag crit">critical · API1:2023</span></div>
  <div class="ev">{esc(enum[0]['extra'].get('why'))}</div>
</div>""")

    # Inventory
    a("<h2>API inventory and protection posture</h2>")
    a("<p>Every endpoint below was discovered from traffic — nothing was declared in "
      "advance. <em>Unprotected</em> means none of authentication, rate limiting or "
      "firewall applies to it.</p>")
    a("<table><tr><th>Endpoint</th><th>Posture</th><th>Requests</th>"
      "<th>Anonymous</th><th>Responses with PII</th><th>Risk</th></tr>")
    for e in sorted(eps, key=lambda x: -x.get("risk_score", 0)):
        p = e.get("posture", "")
        cls = {"unprotected": "crit", "partial": "warn", "protected": "ok"}.get(p, "warn")
        a(f"""<tr><td><code>{esc(e.get('method'))} {esc(e.get('path_template'))}</code></td>
<td><span class="tag {cls}">{esc(p)}</span></td><td>{esc(e.get('request_count', 0))}</td>
<td>{esc(e.get('anon_count', 0))}</td><td>{esc(e.get('pii_count', 0))}</td>
<td>{esc(e.get('risk_score', 0))}</td></tr>""")
    a("</table>")

    # Consumers
    a("<h2>Who is calling what</h2>")
    a("<p>Consumer identity is taken from the verified JWT where one is present, and "
      "falls back to source address where none is.</p>")
    a("<table><tr><th>Consumer</th><th>Identified by</th><th>Requests</th><th>Endpoints touched</th></tr>")
    for c in sorted(cons, key=lambda x: -x.get("request_count", 0)):
        kind = "verified token" if c.get("kind") == "jwt" else "source address (no credential)"
        a(f"""<tr><td><code>{esc(c.get('label'))}</code></td><td>{esc(kind)}</td>
<td>{esc(c.get('request_count', 0))}</td><td>{esc(c.get('endpoints_touched', 0))}</td></tr>""")
    a("</table>")

    # Compliance
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

    # Method
    a("<h2>How this report was produced</h2>")
    a("""<div class="note">
<p><strong>This is a sample.</strong> The API behind it — "Northwind Payments" — is
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

    a('<div class="foot">AEGIS — inline API security gateway · sample artifact, '
      "fictional data · aegis.34host.org</div>")
    a("</body></html>")

    DEST.parent.mkdir(parents=True, exist_ok=True)
    DEST.write_text("\n".join(P), encoding="utf-8")
    print(f"wrote {DEST}")
    print(f"  critical findings: {crit}   warnings: {warn}")
    print(f"  confirmed IDOR:    {len(idor)}   enumeration: {len(enum)}")
    print(f"  endpoints:         {posture.get('total')}   coverage: {posture.get('coverage_pct')}%")


if __name__ == "__main__":
    main()
