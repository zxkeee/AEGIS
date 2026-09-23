#!/usr/bin/env python3
"""Fail when a planning table lists the same thing twice.

A duplicated row is not a typo, it is a state where two rows disagree about one
subject and a reader believes whichever they read first. Both instances found so
far were produced the same way: a batch of edits applied to a document, one
replacement in the middle failing, the script exiting before writing — and the
author concluding that all of them had landed.

handoff.md already records that lesson in prose. This is the mechanical version,
because a lesson written down is a lesson repeated: the second duplicate
appeared in the same file, in the same session, after the first was recorded.

What it checks: within one markdown table, no two rows may share a first cell.
That is narrow on purpose. It does not judge whether a row is accurate, current,
or says anything sensible — a wrong row passes, and a stale row passes. Those
need a person reading the code, and the value of this check is precisely that it
covers the part a person is worst at.
"""

import re
import sys

DOCS = ["ROADMAP.md", "RELEASE-CHECKLIST.md", "docs/PRODUCT.md"]

# A separator row: |---|---| with optional alignment colons.
SEP = re.compile(r"^\|[\s:|-]+\|$")


def first_cell(line):
    parts = line.split("|")
    if len(parts) < 3:
        return None
    return parts[1].strip()


def check(path):
    try:
        lines = open(path, encoding="utf-8").read().splitlines()
    except OSError:
        # A document that is not in this checkout is not a failure; the file
        # list is shared with other checks and one of them may be optional.
        return []

    findings = []
    seen = {}
    in_table = False
    for i, line in enumerate(lines, 1):
        if not line.startswith("|"):
            in_table = False
            seen = {}
            continue
        if SEP.match(line):
            # The separator starts the body; the header above it is not a row.
            in_table = True
            seen = {}
            continue
        if not in_table:
            continue
        cell = first_cell(line)
        # Empty first cells are a deliberate layout in this repository's
        # two-column "| | |" tables, where the left cell is a label that is
        # sometimes blank. Nothing to deduplicate.
        if not cell or cell in ("#", "|"):
            continue
        if cell in seen:
            findings.append(
                "%s:%d: the table already has a row for %s (line %d) — "
                "two rows about one subject disagree, and a reader believes "
                "whichever they read first" % (path, i, cell, seen[cell])
            )
        else:
            seen[cell] = i
    return findings


def main():
    findings = []
    for doc in DOCS:
        findings.extend(check(doc))
    if findings:
        print("ERROR: a planning document lists the same thing twice.")
        for f in findings:
            print("  " + f)
        return 1
    print("check-plan-tables: OK (%d documents, no duplicated rows)" % len(DOCS))
    return 0


if __name__ == "__main__":
    sys.exit(main())
