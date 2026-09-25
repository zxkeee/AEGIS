#!/usr/bin/env python3
"""Fail when a translated static page stops matching the English one structurally.

The React site keeps its copy in one dictionary per language, and check-i18n
compares those. The static pages cannot work that way: each language is its own
HTML file, so every edit to the English page has to be repeated twice by hand.
That is sixteen files where there used to be eight, and the drift it invites is
the same one this repository has fought four times in documents.

So the skeleton is compared instead of the words: section ids in order, heading
count, table rows, list items, and the identifiers that must never be
translated — a middleware name is what an operator greps for, and a chain that
reads "TenantResolve" in English and something else in Polish is a page that
cannot be checked against the code.

What this does NOT do: judge the translation. A page can pass here and read
badly. It catches the failure that nobody would otherwise see — an English page
gaining a section, a warning or a row that the other two silently lack.
"""

import os
import re
import sys

# Translated variants live in a language directory beside the English original.
LANGS = ("pl", "uk")

SECTION_RE = re.compile(r'<section id="([a-z0-9-]+)"')
H2_RE = re.compile(r"<h2[ >]")
TR_RE = re.compile(r"<tr[ >]")
LI_RE = re.compile(r"<li[ >]")
ROW_RE = re.compile(r'class="check-row"')
# Identifiers that are code, not prose: they must appear verbatim in every
# language or the page stops being checkable against the source.
STEP_RE = re.compile(r'<span class="t">([A-Za-z]+)</span>')


def skeleton(text):
    return {
        "sections": SECTION_RE.findall(text),
        "h2": len(H2_RE.findall(text)),
        "table rows": len(TR_RE.findall(text)),
        "list items": len(LI_RE.findall(text)),
        "check rows": len(ROW_RE.findall(text)),
        "middleware names": STEP_RE.findall(text),
    }


def english_pages():
    """Every English page under public/, as a path relative to public/.

    Walks subdirectories: the articles live in public/articles/, and a check
    that only looked at the top level would have left six translated pages per
    language unguarded — which is most of them.
    """
    out = []
    root = "web/v3/public"
    for dirpath, dirnames, files in os.walk(root):
        dirnames[:] = [d for d in dirnames if d not in LANGS]
        for name in files:
            if name.endswith(".html"):
                out.append(os.path.relpath(os.path.join(dirpath, name), root))
    return sorted(out)


def main():
    failures = []
    checked = 0

    for name in english_pages():
        src = os.path.join("web/v3/public", name)
        with open(src, encoding="utf-8") as fh:
            base = skeleton(fh.read())

        for lang in LANGS:
            path = os.path.join("web/v3/public", lang, name)
            if not os.path.exists(path):
                # Not every page is translated, and saying so is allowed — the
                # site labels those links. A missing file is not a failure; a
                # divergent one is.
                continue
            checked += 1
            with open(path, encoding="utf-8") as fh:
                got = skeleton(fh.read())

            for key in base:
                if base[key] == got[key]:
                    continue
                if isinstance(base[key], list):
                    missing = [x for x in base[key] if x not in got[key]]
                    added = [x for x in got[key] if x not in base[key]]
                    detail = []
                    if missing:
                        detail.append(f"missing {missing}")
                    if added:
                        detail.append(f"unexpected {added}")
                    if not detail:
                        detail.append(f"same items, different order: {base[key]} vs {got[key]}")
                    failures.append(
                        f"{path}: {key} do not match {src} — " + "; ".join(detail))
                else:
                    failures.append(
                        f"{path}: {key} = {got[key]}, {src} has {base[key]}. The English "
                        f"page gained or lost something this translation did not.")

    if failures:
        print("ERROR: a translated page has drifted from the English original.\n")
        for f in failures:
            print(f"  {f}\n")
        print(f"check-page-parity: FAILED ({len(failures)} finding(s))")
        return 1

    print(f"check-page-parity: OK ({checked} translated page(s) match their English original)")
    return 0


if __name__ == "__main__":
    os.chdir(os.path.join(os.path.dirname(os.path.abspath(__file__)), ".."))
    sys.exit(main())
