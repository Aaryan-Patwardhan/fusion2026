#!/usr/bin/env python3
"""
main.py — Hyron AI FastAPI application.

Serves the React dashboard and exposes JSON API endpoints:
  GET  /                          → React dashboard (index.html)
  GET  /api/summary               → high-level scan summary
  GET  /api/blast?q=CVE-XXXX      → blast radius for one CVE/OSV id
  GET  /api/top?n=25              → top N findings by risk
  GET  /api/projects              → per-project finding counts
  GET  /api/patch?project=&n=30   → ordered patch plan (with tier: AUTO/REVIEW/ESCALATE)
  GET  /api/brief?cve=&project=   → evidence-backed incident brief
  GET  /api/brief/top             → brief for highest-risk finding
  POST /api/scan                  → trigger pipeline scan

Run:
  pip install -r backend/requirements.txt
  cd Fusion2K26
  uvicorn backend.main:app --reload --port 8000

Offline demo:
  OFFLINE=1 uvicorn backend.main:app --port 8000

Hyron AI · FUSION 2026 · CSB-03
"""

import json
import sys
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

import networkx as nx
from fastapi import FastAPI
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles

from backend.routes.graph   import router as graph_router
from backend.routes.reports import router as reports_router
from backend.routes.scan    import router as scan_router
from backend.services.manifest_parser    import load_projects
from backend.services.vulnerability_scanner import (
    CACHE, fetch_all_details, kev_set, epss_scores,
    osv_ids, osv_detail, parse_vuln, save_cache,
)
from backend.services.risk_engine  import compute_risk
from backend.services.patch_planner import build_patch_plan

# ---------- app setup ----------
app = FastAPI(
    title="Hyron AI — Supply-Chain Blast Radius",
    description=(
        "Local-first dependency incident daemon: from package alert to a "
        "risk-ranked, evidence-backed action plan. FUSION 2026 · CSB-03"
    ),
    version="1.0.0",
)

# Serve React build output at /static; raw static assets at /assets
STATIC_DIR = Path(__file__).parent.parent / "frontend" / "dist"
if STATIC_DIR.exists():
    app.mount("/assets", StaticFiles(directory=str(STATIC_DIR / "assets")), name="assets")

# Fallback: serve the legacy static folder (cytoscape.min.js etc.)
LEGACY_STATIC = Path("static")
if LEGACY_STATIC.exists():
    app.mount("/static", StaticFiles(directory="static"), name="static")

# ---------- register routers ----------
app.include_router(graph_router,   prefix="/api")
app.include_router(reports_router, prefix="/api")
app.include_router(scan_router,    prefix="/api")


@app.get("/", include_in_schema=False)
def index():
    """Serve the React dashboard (or legacy static HTML if no build present)."""
    react_index = STATIC_DIR / "index.html"
    if react_index.exists():
        return FileResponse(str(react_index))
    legacy = LEGACY_STATIC / "index.html"
    if legacy.exists():
        return FileResponse(str(legacy))
    return {"message": "Hyron AI is running. Build the frontend or run the pipeline first."}


# ---------- pipeline (importable by scan route) ----------

def run_pipeline(paths: list[str]) -> tuple[nx.DiGraph, list[dict]]:
    """
    Full scan pipeline:
      lockfiles → graph → OSV → EPSS/KEV → risk scores → patch plan
      writes findings.json, patch_plan.json, .osv_cache.json

    Args:
        paths: List of package-lock.json file paths

    Returns:
        (G, rows) — composed NetworkX graph and sorted findings list
    """
    G = load_projects(paths)
    pkg_nodes = [(n, d) for n, d in G.nodes(data=True) if d.get("kind") == "pkg"]

    # OSV lookups (batched, cached)
    id_map = osv_ids({(d["name"], d["version"]) for _, d in pkg_nodes})
    hits = {k: ids for k, ids in id_map.items() if ids}

    vids = {vid for ids in hits.values() for vid in ids}
    fetch_all_details(vids)

    # Parse advisories
    parsed: dict = {}
    for k, ids in hits.items():
        for vid in ids:
            parsed[(k, vid)] = parse_vuln(osv_detail(vid), k[0])

    # Exploit signals
    all_cves = {p["cve"] for p in parsed.values()}
    epss = epss_scores(all_cves)
    kev  = kev_set()

    # Build finding rows
    rows: list[dict] = []
    for n, d in pkg_nodes:
        key = (d["name"], d["version"])
        for vid in hits.get(key, []):
            v    = parsed[(key, vid)]
            top  = f"proj:{d['proj']}"

            try:
                path = nx.shortest_path(G, top, n)
            except nx.NetworkXNoPath:
                path = [top, n]

            labels = [G.nodes[x]["label"] for x in path]
            risk   = compute_risk(v["cvss"], v["cve"], d["dev"], epss, kev)

            rows.append(dict(
                project=d["proj"],
                package=f"{d['name']}@{d['version']}",
                vuln=vid,
                cve=v["cve"],
                summary=v["summary"],
                cvss=v["cvss"],
                epss=epss.get(v["cve"] or "", 0.0),
                kev=(v["cve"] in kev) if v["cve"] else False,
                dev=d["dev"],
                direct=G.has_edge(top, n),
                depth=len(path) - 1,
                via=" > ".join(labels[1:]),
                path=labels,
                fixed=v["fixed"],
                risk=risk,
                osv_url=v.get("osv_url", f"https://osv.dev/vulnerability/{vid}"),
            ))

    # Deduplicate: keep shortest path per (project, package, vuln)
    best: dict = {}
    for r in sorted(rows, key=lambda r: r["depth"]):
        k = (r["project"], r["package"], r["vuln"])
        if k in best:
            best[k]["instances"] = best[k].get("instances", 1) + 1
        else:
            best[k] = {**r, "instances": 1}

    rows = sorted(best.values(), key=lambda r: -r["risk"])
    patch_plan = build_patch_plan(rows)

    # Write outputs
    Path("findings.json").write_text(json.dumps(rows, indent=1))
    Path("patch_plan.json").write_text(json.dumps(patch_plan, indent=1))
    save_cache()

    return G, rows


# ---------- CLI entry point ----------
if __name__ == "__main__":
    import uvicorn
    if len(sys.argv) > 1:
        # Called as: python -m backend.main corpus/*/package-lock.json
        _, scan_rows = run_pipeline(sys.argv[1:])
        print(f"{len(scan_rows)} findings across {len({r['project'] for r in scan_rows})} projects")
        for r in scan_rows[:10]:
            print(
                f'{r["risk"]:6}  {r["project"]:18}  {r["package"]:26}  '
                f'{r["cve"] or r["vuln"]:20}  via {r["via"]}'
            )
    else:
        uvicorn.run("backend.main:app", host="0.0.0.0", port=8000, reload=True)
