#!/usr/bin/env python3
"""Fail when handoff.md contradicts the repository it claims to describe.

handoff.md is the document a session reads before touching anything, and it
drifted further than any of the ones a buyer reads: on 2026-09-18 it described
main as of #71 while main carried #79, called a merged PR unmerged, pointed at
two fixed defects as places to look next, and opened its work queue with two
tasks that were already done.

check-doc-drift.py (#77) was built against exactly this class of failure, but it
watches README, ROADMAP, PRODUCT and the release checklist — the documents a
buyer reads. Nothing watched the one an author reads, which is the one that
decides what the next session spends its day on.

Three mechanical checks. None of them judges whether the prose is any good:

  1. A PR the file calls unmerged must not have a merge commit.
  2. "влито по #N включительно" must not name an N that later merges exceed.
  3. The date in the heading must not predate the file's own last change.

What this does NOT check, so a pass is not read as more than it is: whether any
sentence is accurate, current, or honest about limits. A wrong sentence passes.
"""

import re
import subprocess
import sys

HANDOFF = "handoff.md"


def git(*args):
    try:
        return subprocess.run(
            ["git", *args], capture_output=True, text=True, check=True
        ).stdout
    except (OSError, subprocess.CalledProcessError):
        return ""


def merged_pr_numbers():
    """Every #N that appears in the subject of a merge commit."""
    subjects = git("log", "--merges", "--pretty=%s")
    return {int(n) for n in re.findall(r"#(\d+)", subjects)}


def last_changed():
    """The date handoff.md last changed: today when it has uncommitted edits,
    otherwise the date of the commit that last touched it."""
    dirty = subprocess.run(["git", "diff", "--quiet", "--", HANDOFF]).returncode != 0
    if dirty:
        return subprocess.run(
            ["date", "+%Y-%m-%d"], capture_output=True, text=True
        ).stdout.strip()
    return git("log", "-1", "--format=%cs", "--", HANDOFF).strip()


# A document that records its own past mistakes quotes them, and this project's
# convention for that is guillemets: §5 of handoff.md contains the literal
# strings «влито по #71 включительно» and «PR #70, не влит» as the description
# of a drift that was found and fixed. Reading a quotation as a live claim is
# how a check like this turns into noise that gets disabled — so quoted spans
# are removed before anything is matched. Replaced by a space rather than
# deleted, so the 80-character windows below cannot close over the gap.
QUOTED = re.compile(r"«[^»]{0,400}»", re.DOTALL)


def strip_quotations(text):
    return QUOTED.sub(" ", text)


def check(text, merged):
    text = strip_quotations(text)
    findings = []

    # 1. A PR called unmerged that has a merge commit.
    #    Matches "#70, не влит" and "(PR #70, не влит)"; the window is bounded
    #    and stops at a newline or a table cell so it cannot reach across rows.
    for m in re.finditer(r"#(\d+)[^\n|]{0,80}?не влит", text):
        n = int(m.group(1))
        if n in merged:
            findings.append(
                "calls #%d unmerged, but a merge commit for it exists" % n
            )

    # 2. "merged up to #N inclusive" while later merges exist.
    for m in re.finditer(r"влито по #(\d+) включительно", text):
        n = int(m.group(1))
        later = sorted(x for x in merged if x > n)
        if later:
            findings.append(
                "says main is merged up to #%d, but #%s came after"
                % (n, ", #".join(str(x) for x in later[:6]))
            )

    # 3. The heading date is older than the file's own last change.
    head = re.search(r"состояние на (\d{4}-\d{2}-\d{2})", text)
    if head:
        stated, changed = head.group(1), last_changed()
        if changed and changed > stated:
            findings.append(
                "heading says %s but the file changed on %s" % (stated, changed)
            )

    return findings


def main():
    try:
        text = open(HANDOFF, encoding="utf-8").read()
    except OSError:
        # Not every checkout has it, and its absence is not a regression.
        print("check-handoff: skipped (%s not present)" % HANDOFF)
        return 0

    merged = merged_pr_numbers()
    if not merged:
        # Exit 2, not 0: "I could not check" is a third state, distinct from
        # pass and from fail. A shallow clone has no merge commits, so returning
        # 0 here would make this check pass loudest exactly where it sees least
        # — the same defect the coverage gate had when unavailable stores made
        # it green (handoff §0e).
        print("check-handoff: INCOMPLETE — no merge commits are reachable.")
        print("       This is a checkout problem, not a document problem:")
        print("       a shallow clone cannot answer what was merged.")
        print("       In CI, set fetch-depth: 0; locally, unshallow the clone.")
        return 2

    findings = check(text, merged)
    if findings:
        print("ERROR: %s contradicts the repository it describes." % HANDOFF)
        print("       This is the document the next session trusts before reading code.")
        for f in findings:
            print("  %s: %s" % (HANDOFF, f))
        return 1

    print("check-handoff: OK (agrees with %d merged PRs)" % len(merged))
    return 0


if __name__ == "__main__":
    sys.exit(main())
