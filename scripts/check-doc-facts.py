#!/usr/bin/env python3
"""Fail when a document names an environment variable the gateway does not read,
or a Go version the toolchain is not pinned to.

check-doc-drift.py answers "is this capability missing from the docs". It says
so itself: it does not check whether the text is accurate, and a wrong sentence
passes. This checks two things that CAN be checked mechanically, chosen because
both went wrong in a document written for investors and grant assessors:

  docs/ARCHITECTURE_DEEP_DIVE.md listed AEGIS_LISTEN, AEGIS_ADMIN_LISTEN,
  AEGIS_REDIS_ADDR, AEGIS_POSTGRES_DSN and AEGIS_OBSERVE as the environment
  variables of first necessity. The gateway reads none of them — listen,
  admin_listen, redis.addr, observe and the DSN come from YAML, and the DSN is
  AEGIS_FORENSIC_DSN. A deployment guide that does not deploy is worse than no
  guide: somebody follows it in front of the person they are trying to convince.

  The same document put the language at "Go 1.22+" while go.mod pins 1.26.

Deliberately narrow. A regex over prose that guesses at counts ("22 steps")
produces false positives, and a check that cries wolf gets muted — which costs
more than it saves. These two have exactly one right answer each.

A document may name a variable that does NOT exist, on purpose — saying so is
often the point. Declare it, per file:

    <!-- doc-facts: ignore-env AEGIS_LISTEN AEGIS_OBSERVE -->

The directive is per file, explicit and greppable; nobody adds one by accident.
"""

import os
import re
import sys

CODE_ROOTS = ("internal", "cmd")
ENV_RE = re.compile(r"\bAEGIS_[A-Z0-9_]+\b")
GO_VER_RE = re.compile(r"\bGo\s+1\.(\d+)\b")
IGNORE_RE = re.compile(r"<!--\s*doc-facts:\s*ignore-env\s+([A-Z0-9_\s]+?)\s*-->")


def docs_to_check():
    out = []
    for path in ("README.md", "CLAUDE.md", "handoff.md"):
        if os.path.exists(path):
            out.append(path)
    for root, dirs, files in os.walk("docs"):
        dirs[:] = [d for d in dirs if not d.startswith(".")]
        out.extend(os.path.join(root, f) for f in files if f.endswith(".md"))
    return sorted(out)


def env_vars_in_code():
    found = set()
    for root_dir in CODE_ROOTS:
        for root, dirs, files in os.walk(root_dir):
            dirs[:] = [d for d in dirs if not d.startswith(".")]
            for f in files:
                if not f.endswith(".go"):
                    continue
                with open(os.path.join(root, f), encoding="utf-8", errors="replace") as fh:
                    found.update(ENV_RE.findall(fh.read()))
    return found


def pinned_go_minor():
    with open("go.mod", encoding="utf-8") as fh:
        for line in fh:
            m = re.match(r"^go 1\.(\d+)", line.strip())
            if m:
                return int(m.group(1))
    return None


def main():
    known = env_vars_in_code()
    if not known:
        print("ERROR: found no AEGIS_* variables in the code at all — the scan is broken,")
        print("       and a scan that finds nothing would pass every document silently.")
        return 1
    go_minor = pinned_go_minor()

    failures = []
    for doc in docs_to_check():
        with open(doc, encoding="utf-8", errors="replace") as fh:
            text = fh.read()
        ignored = set()
        for m in IGNORE_RE.finditer(text):
            ignored.update(m.group(1).split())

        for name in sorted(set(ENV_RE.findall(text))):
            if name in known or name in ignored:
                continue
            failures.append(
                f"{doc}: names {name}, which the gateway never reads. Either the "
                f"variable was renamed and the document was not, or it was never "
                f"real. If the document means to say it does NOT exist, declare it:\n"
                f"      <!-- doc-facts: ignore-env {name} -->"
            )

        if go_minor is not None:
            # Reported per line: four identical sentences with no location is a
            # report you have to grep the repo to act on.
            stale = []
            for i, line in enumerate(text.splitlines(), 1):
                for m in GO_VER_RE.finditer(line):
                    if int(m.group(1)) != go_minor:
                        stale.append(f"{i}: {line.strip()}")
            if stale:
                failures.append(
                    f"{doc}: claims a Go version go.mod does not pin (1.{go_minor}). A "
                    f"stale toolchain version is the cheapest possible thing for a "
                    f"reviewer to catch, and catching one makes them check the rest.\n"
                    + "\n".join(f"      {s}" for s in stale)
                )

    if failures:
        print("ERROR: a document states something the code contradicts.\n")
        for f in failures:
            print(f"  {f}\n")
        print(f"check-doc-facts: FAILED ({len(failures)} finding(s))")
        return 1

    print(f"check-doc-facts: OK ({len(docs_to_check())} documents, "
          f"{len(known)} env vars, Go 1.{go_minor})")
    return 0


if __name__ == "__main__":
    os.chdir(os.path.join(os.path.dirname(os.path.abspath(__file__)), ".."))
    sys.exit(main())
