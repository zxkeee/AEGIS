#!/usr/bin/env python3
"""Drive genuine, read-only browsing of a public Forgejo through AEGIS.

The point is that NOTHING here is adversarial. Every request is something an
ordinary user, a CI job or a code-search indexer would send. Whatever AEGIS
reports afterwards is therefore a false positive unless it describes a real
property of the API.

Paced deliberately (4 req/s, single threaded) — Codeberg is a volunteer-run
service and this is someone else's infrastructure.
"""

import json
import os
import sys
import time
import urllib.error
import urllib.request

GW = sys.argv[1].rstrip("/")
UA = "AEGIS-fp-assessment/1.0 (measuring false positives; read-only)"
PACE = 0.25

stats = {"ok": 0, "err": 0, "by_status": {}}

# Every path actually requested, in order — the dataset the learner's tests
# replay. Fitting thresholds against invented paths is how the first attempt got
# them wrong.
REQUESTED = []


def get(path, persona):
    url = f"{GW}{path}"
    req = urllib.request.Request(url, headers={
        "User-Agent": UA,
        "Accept": "application/json",
        # A realistic client identifies itself; AEGIS has no JWT to read here,
        # which is itself part of what this run measures.
        "X-Persona": persona,
        # Each persona carries its own opaque credential, the way three real
        # clients of a token-authenticated API would. Codeberg ignores an
        # unknown key for public reads; AEGIS is what has to tell them apart.
        "X-API-Key": f"opaque-key-{persona}",
    })
    REQUESTED.append(path.split("?")[0])
    time.sleep(PACE)
    try:
        with urllib.request.urlopen(req, timeout=25) as r:
            body = r.read()
            stats["ok"] += 1
            stats["by_status"][r.status] = stats["by_status"].get(r.status, 0) + 1
            try:
                return json.loads(body)
            except Exception:
                return None
    except urllib.error.HTTPError as e:
        stats["err"] += 1
        stats["by_status"][e.code] = stats["by_status"].get(e.code, 0) + 1
        return None
    except Exception:
        stats["err"] += 1
        stats["by_status"]["net"] = stats["by_status"].get("net", 0) + 1
        return None


def main():
    print("  открываю каталог репозиториев…")
    repos = []
    for page in range(1, 13):
        d = get(f"/api/v1/repos/search?limit=25&page={page}&sort=updated", "developer")
        if d and d.get("data"):
            repos += [(r["owner"]["login"], r["name"]) for r in d["data"]]
    repos = repos[:250]
    print(f"  найдено репозиториев: {len(repos)}")

    # ── Persona 1: a developer reading a handful of projects properly ─────────
    print("  разработчик читает проекты…")
    for owner, name in repos[:60]:
        base = f"/api/v1/repos/{owner}/{name}"
        get(base, "developer")
        get(f"{base}/branches", "developer")
        get(f"{base}/tags", "developer")
        get(f"{base}/releases", "developer")
        get(f"{base}/languages", "developer")
        issues = get(f"{base}/issues?limit=5&state=all", "developer")
        if isinstance(issues, list):
            for it in issues[:4]:
                get(f"{base}/issues/{it['number']}", "developer")
                get(f"{base}/issues/{it['number']}/comments", "developer")

    # ── Persona 2: an indexer walking the estate ─────────────────────────────
    # Exactly the shape that trips naive enumeration detection, and exactly the
    # shape a code-search crawler or a nightly sync job actually has.
    print("  индексатор обходит репозитории…")
    for owner, name in repos:
        get(f"/api/v1/repos/{owner}/{name}", "indexer")
        get(f"/api/v1/repos/{owner}/{name}/commits?limit=1", "indexer")

    # ── Persona 3: profile browsing ──────────────────────────────────────────
    print("  просмотр профилей…")
    seen = []
    for owner, _ in repos:
        if owner not in seen:
            seen.append(owner)
    for owner in seen[:80]:
        get(f"/api/v1/users/{owner}", "profile")
        get(f"/api/v1/users/{owner}/repos?limit=5", "profile")

    out = os.path.join(os.path.dirname(os.path.abspath(__file__)), "out")
    os.makedirs(out, exist_ok=True)
    with open(os.path.join(out, "requested.txt"), "w") as fh:
        fh.write("\n".join(REQUESTED))
    print(f"  записано путей: {len(REQUESTED)}")
    print(f"\n  запросов ок: {stats['ok']}  ошибок: {stats['err']}")
    print(f"  по статусам: {stats['by_status']}")


if __name__ == "__main__":
    main()
