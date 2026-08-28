#!/usr/bin/env python3
"""Render the customer-facing HTML documents in docs/assets/ to PDF.

Why this is a script and not a remembered command line
------------------------------------------------------
Chrome's ``--print-to-pdf`` flag cannot set a header or footer template. Its
only choices are Chrome's default furniture — which stamps a local ``file://``
path and today's date onto a document sent to a customer — or, with
``--no-pdf-header-footer``, nothing at all.

Both of the documents here need a real footer: the NDA is a five-page legal
template where unnumbered pages can be swapped or lost without trace, and the
findings report carries a "fictional data" mark that must appear on every page,
not only the one a reader happens to open. Those footers came from a
``Page.printToPDF`` call over the DevTools protocol that lived in a terminal
scrollback and nowhere else. Re-rendering with the plain CLI flag silently
dropped them from both PDFs (2026-08-28) — the HTML was correct, the PDF beside
it was not, and nothing in the diff said so.

So the templates live here, in the repository, next to the documents they
belong to.

Usage:  scripts/render-pdf.py [file.html ...]     (default: docs/assets/*.html)
        CHROME=/path/to/chrome  to override browser discovery
"""

from __future__ import annotations

import base64
import glob
import json
import os
import pathlib
import shutil
import socket
import subprocess
import sys
import tempfile
import time
import urllib.parse
import urllib.request

try:
    import websocket  # websocket-client
except ImportError:
    sys.exit(
        "ERROR: this needs the websocket-client package (Chrome's PDF options are\n"
        "only reachable over the DevTools protocol, not the command line).\n"
        "  pip3 install websocket-client"
    )

REPO = pathlib.Path(__file__).resolve().parent.parent

CHROME_CANDIDATES = [
    "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome",
    "/Applications/Chromium.app/Contents/MacOS/Chromium",
    "google-chrome",
    "google-chrome-stable",
    "chromium",
    "chromium-browser",
]

# ── Per-document print furniture ──────────────────────────────────────────────
#
# Colours and margins are taken from each document's own @page rule so the
# footer sits in the document's palette rather than on a white strip. Chrome
# draws header/footer templates inside the page margins, so a document whose
# margins are already tight needs them widened here or the footer overlaps the
# body.
#
# Chrome substitutes the classes pageNumber/totalPages/date/title/url; anything
# else is literal. Font sizes must be given in the template — Chrome's default
# for these templates is a tiny unstyled serif.

_REPORT_FOOTER = """
<div style="width:100%;font-size:6.5pt;color:#6e6a63;padding:0 14mm;
            font-family:-apple-system,Segoe UI,Helvetica,Arial,sans-serif;
            display:flex;justify-content:space-between;">
  <span>AEGIS &mdash; sample findings report &middot; fictional data</span>
  <span><span class="pageNumber"></span> / <span class="totalPages"></span></span>
</div>
"""

_NDA_FOOTER = """
<div style="width:100%;font-size:8pt;color:#000;text-align:center;
            font-family:Times New Roman,Times,serif;">
  Page <span class="pageNumber"></span> of <span class="totalPages"></span>
</div>
"""

_EMPTY = "<div></div>"

DOCS = {
    # The report paints its own dark background out to the sheet edge via
    # @page{background}, so the footer needs no backdrop of its own — but it
    # does need a colour that reads on #181818.
    "AEGIS-Sample-Findings-Report.html": {
        "footer": _REPORT_FOOTER,
        "margin_bottom_in": 0.63,  # 16mm, matching the document's @page margin
    },
    "AEGIS-NDA-Template.html": {
        "footer": _NDA_FOOTER,
        "margin_bottom_in": 0.79,  # 20mm, the @page bottom margin
    },
    # The manual is a continuous panelled layout with 9mm margins and a
    # full-bleed first page; a page number would land on top of the panel.
    # Rendered deliberately without furniture.
    "AEGIS-Technical-Manual.html": {
        "footer": None,
    },
}


def find_chrome() -> str:
    if os.environ.get("CHROME"):
        return os.environ["CHROME"]
    for c in CHROME_CANDIDATES:
        if os.path.isfile(c) and os.access(c, os.X_OK):
            return c
        found = shutil.which(c)
        if found:
            return found
    sys.exit("ERROR: no Chrome/Chromium found. Set CHROME=/path/to/chrome.")


def free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


class Chrome:
    """A headless Chrome with its DevTools endpoint, torn down on exit."""

    def __init__(self, binary: str):
        self.port = free_port()
        self.profile = tempfile.mkdtemp(prefix="aegis-pdf-")
        self.proc = subprocess.Popen(
            [
                binary,
                "--headless",
                "--disable-gpu",
                "--no-sandbox",
                "--no-first-run",
                # Chrome rejects a DevTools websocket whose Origin it does not
                # recognise. The endpoint is bound to loopback on an ephemeral
                # port belonging to a browser this script started and kills, so
                # there is no other client to guard against.
                "--remote-allow-origins=*",
                f"--remote-debugging-port={self.port}",
                f"--user-data-dir={self.profile}",
                "about:blank",
            ],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        self._wait_ready()

    def _wait_ready(self, timeout: float = 30.0) -> None:
        deadline = time.time() + timeout
        while time.time() < deadline:
            if self.proc.poll() is not None:
                sys.exit(f"ERROR: Chrome exited early (code {self.proc.returncode})")
            try:
                urllib.request.urlopen(
                    f"http://127.0.0.1:{self.port}/json/version", timeout=1
                ).read()
                return
            except Exception:
                time.sleep(0.1)
        sys.exit("ERROR: Chrome's DevTools endpoint never came up")

    def new_target(self, url: str) -> str:
        req = urllib.request.Request(
            f"http://127.0.0.1:{self.port}/json/new?{urllib.parse.quote(url, safe=':/.-_')}",
            method="PUT",
        )
        with urllib.request.urlopen(req, timeout=10) as r:
            return json.load(r)["webSocketDebuggerUrl"]

    def close(self) -> None:
        self.proc.terminate()
        try:
            self.proc.wait(timeout=10)
        except subprocess.TimeoutExpired:
            self.proc.kill()
        shutil.rmtree(self.profile, ignore_errors=True)


class Session:
    """A DevTools websocket session with synchronous request/response."""

    def __init__(self, ws_url: str):
        # 300s: printToPDF on a long document is the slow call, and a timeout
        # here loses the whole render rather than just being slow.
        self.ws = websocket.create_connection(ws_url, timeout=300)
        self.next_id = 0

    def call(self, method: str, **params):
        self.next_id += 1
        mid = self.next_id
        self.ws.send(json.dumps({"id": mid, "method": method, "params": params}))
        while True:
            msg = json.loads(self.ws.recv())
            if msg.get("id") == mid:
                if "error" in msg:
                    sys.exit(f"ERROR: {method} failed: {msg['error']}")
                return msg.get("result", {})

    def wait_for(self, event: str, timeout: float = 120.0):
        deadline = time.time() + timeout
        while time.time() < deadline:
            msg = json.loads(self.ws.recv())
            if msg.get("method") == event:
                return msg.get("params", {})
        sys.exit(f"ERROR: timed out waiting for {event}")

    def close(self) -> None:
        self.ws.close()


def render(chrome: Chrome, html: pathlib.Path) -> pathlib.Path:
    cfg = DOCS.get(html.name, {})
    footer = cfg.get("footer")

    session = Session(chrome.new_target("about:blank"))
    try:
        session.call("Page.enable")
        session.call("Page.navigate", url=html.resolve().as_uri())
        session.wait_for("Page.loadEventFired")
        # Web fonts and late layout settle after load; without this the first
        # render can paginate against fallback metrics and shift every page.
        time.sleep(1.0)

        params = {
            # preferCSSPageSize honours each document's own @page size and
            # margins — the alternative is restating them here, where they would
            # drift away from the HTML.
            "preferCSSPageSize": True,
            "printBackground": True,
            "displayHeaderFooter": bool(footer),
        }
        if footer:
            params["headerTemplate"] = _EMPTY
            params["footerTemplate"] = footer
            params["marginBottom"] = cfg["margin_bottom_in"]

        result = session.call("Page.printToPDF", **params)
    finally:
        session.close()

    pdf = html.with_suffix(".pdf")
    data = base64.b64decode(result["data"])
    if not data.startswith(b"%PDF-"):
        sys.exit(f"ERROR: {html.name} produced something that is not a PDF")
    pdf.write_bytes(data)
    return pdf


def main() -> None:
    args = sys.argv[1:]
    if args:
        files = [pathlib.Path(a) for a in args]
    else:
        files = sorted(pathlib.Path(p) for p in glob.glob(str(REPO / "docs/assets/*.html")))
    if not files:
        sys.exit("ERROR: no HTML documents to render")

    missing = [f for f in files if not f.is_file()]
    if missing:
        sys.exit(f"ERROR: no such file: {missing[0]}")

    # A document with no entry in DOCS would silently render without the footer
    # it may well need — the exact failure this script exists to prevent.
    unknown = [f.name for f in files if f.name not in DOCS]
    if unknown:
        sys.exit(
            f"ERROR: no print furniture defined for {', '.join(unknown)}.\n"
            "Add an entry to DOCS in this script (use footer=None for a document "
            "that genuinely wants no page furniture)."
        )

    chrome = Chrome(find_chrome())
    try:
        for html in files:
            pdf = render(chrome, html)
            kb = pdf.stat().st_size // 1024
            mark = "footer" if DOCS[html.name].get("footer") else "no footer"
            print(f"  {pdf.name}  ({kb} KB, {mark})")
    finally:
        chrome.close()


if __name__ == "__main__":
    main()
