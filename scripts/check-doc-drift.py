#!/usr/bin/env python3
"""Fail when a capability that exists in the code is missing from, or contradicted
by, the documents that describe the product.

Four instances of this in one session, each found by a person reading two files
side by side:

  #73  README (2247 lines) contained no mention of mirror mode, seals, NIS2 or
       DORA. The sales offer led with the first; two sessions of work had gone
       into the rest. A buyer reading the front door saw a different product.
  #73  ROADMAP listed the out-of-band sensor as "4-8 weeks, not started" after
       mirror_sink had shipped and the offer was already selling it.
  #74  ROADMAP's P1 table called integrations and OpenAPI drift untouched while
       its own phase tables, further down the same file, marked both done.
  #75  The release checklist listed traffic mirroring as an open item for the
       same reason as the roadmap.

Noticing is not a control. This is.

The manifest (docs/capabilities.json) answers one question per capability: what
in the CODE settles whether it exists. If that proof is present, then:

  1. every document in must_mention has to mention it, and
  2. no release-checklist item may still list it as open.

What this does NOT check, so a pass is not read as more than it is: whether the
text is accurate, current, or says the right thing about limits. It checks that
the subject is not missing and not contradicted. A wrong sentence passes.
"""

import json
import os
import re
import sys

MANIFEST = "docs/capabilities.json"


def read(path):
    try:
        with open(path, encoding="utf-8") as fh:
            return fh.read()
    except OSError as exc:
        return exc


def main():
    raw = read(MANIFEST)
    if isinstance(raw, OSError):
        print(f"ERROR: cannot read {MANIFEST}: {raw}")
        return 1
    caps = json.loads(raw)["capabilities"]

    failures = []
    checked = 0

    for cap in caps:
        name = cap["name"]
        proof = cap["proof"]
        src = read(proof["file"])
        if isinstance(src, OSError):
            failures.append(
                f'{MANIFEST}: capability "{name}" points at {proof["file"]}, which does not '
                f"exist. Either the code moved and the manifest did not, or the capability "
                f"was removed and the docs still promise it."
            )
            continue
        if proof["contains"] not in src:
            # Not a doc problem: the manifest claims something the code no longer
            # says. Left as a failure because the alternative is a manifest that
            # quietly stops checking anything.
            failures.append(
                f'{MANIFEST}: capability "{name}" is proved by {proof["contains"]!r} in '
                f'{proof["file"]}, which is no longer there. Update the proof, or remove '
                f"the capability and everything that claims it."
            )
            continue

        checked += 1
        keywords = cap["keywords"]

        for doc in cap["must_mention"]:
            text = read(doc)
            if isinstance(text, OSError):
                failures.append(f"{doc}: cannot read ({text})")
                continue
            low = text.lower()
            if not any(k.lower() in low for k in keywords):
                failures.append(
                    f'{doc}: never mentions "{name}", which exists in the code '
                    f'({proof["file"]}). A document that describes the product and omits a '
                    f"shipped capability is describing a different product. Looked for: "
                    f"{', '.join(keywords)}"
                )

        # A shipped capability must not still be listed as an open checklist item.
        # This is the exact shape of #73 and #75: work that landed, with the gate
        # still counting it as todo.
        checklist = read("RELEASE-CHECKLIST.md")
        if not isinstance(checklist, OSError):
            for i, line in enumerate(checklist.splitlines(), 1):
                if not re.match(r"^\s*- \[ \]", line):
                    continue
                low = line.lower()
                if any(k.lower() in low for k in keywords):
                    failures.append(
                        f'RELEASE-CHECKLIST.md:{i}: still lists "{name}" as an open item, '
                        f'but it exists in the code ({proof["file"]}). Either it shipped and '
                        f"the gate was not updated, or the line means something narrower and "
                        f"should say so:\n      {line.strip()}"
                    )

    if failures:
        print("ERROR: the documents and the code disagree about what exists.\n")
        for f in failures:
            print(f"  {f}\n")
        print(f"check-doc-drift: FAILED ({len(failures)} finding(s))")
        return 1

    print(f"check-doc-drift: OK ({checked} capabilities, docs agree)")
    return 0


if __name__ == "__main__":
    os.chdir(os.path.join(os.path.dirname(os.path.abspath(__file__)), ".."))
    sys.exit(main())
