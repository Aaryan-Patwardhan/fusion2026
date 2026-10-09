#!/usr/bin/env python3
"""
main.py — FastAPI Application & Pipeline Orchestrator

What:
    Core server and CLI entry point orchestrating the 9-stage dependency analysis pipeline.
    Serves the React dashboard and exposes validated JSON REST endpoints.
Why:
    Serves as the central operational bridge between lockfile parsing, OSV.dev intel,
    risk prioritization, patch planning, and user interface delivery.
Inputs:
    Command-line paths to package-lock.json files, or HTTP client requests.
Outputs:
    findings.json, patch_plan.json, .osv_cache.json, and interactive API responses.
Called by:
    python -m backend.main [paths], uvicorn backend.main:app, tests
"""

import argparse
import glob
import json
import sys
from pathlib import Path
from typing import Optional

import networkx as nx
from fastapi import FastAPI
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles

from backend.routes.graph   import router as graph_router
from backend.routes.reports import router as reports_router
from backend.routes.scan    import router as scan_router
from backend.services.manifest_parser import load_projects
from backend.services.vulnerability_scanner import (
    fetch_all_details, kev_set, epss_scores,
    osv_ids, osv_detail, parse_vuln, save_cache,
)
from backend.services.risk_engine import compute_risk
from backend.services.patch_planner import build_patch_plan

# ---------- FastAPI app setup ----------
app = FastAPI(
    title="Hyron AI — Supply-Chain Blast Radius",
    description=(
        "Local-first dependency incident daemon: from package alert to a "
        "risk-ranked, evidence-backed action plan. FUSION 2026 · CSB-03"
    ),
    version="1.0.0",
)

# Serve compiled React build output if present
STATIC_DIR = Path(__file__).parent.parent / "frontend" / "dist"
if STATIC_DIR.exists():
    app.mount("/assets", StaticFiles(directory=str(STATIC_DIR / "assets")), name="assets")

# Fallback: serve legacy static assets (Cytoscape.js, standalone HTML)
LEGACY_STATIC = Path("static")
if LEGACY_STATIC.exists():
    app.mount("/static", StaticFiles(directory="static"), name="static")

# Register modular API routers
app.include_router(graph_router,   prefix="/api")
app.include_router(reports_router, prefix="/api")
app.include_router(scan_router,    prefix="/api")


@app.get("/", include_in_schema=False)
def index():
    """Serve the React dashboard, or fallback static index.html if frontend is not built."""
    react_index = STATIC_DIR / "index.html"
    if react_index.exists():
        return FileResponse(str(react_index))
    legacy = LEGACY_STATIC / "index.html"
    if legacy.exists():
        return FileResponse(str(legacy))
    return {
        "status": "ok",
        "message": "Hyron AI API running. Build the frontend or view docs at /docs.",
    }


# ---------- 9-Stage Pipeline Orchestrator ----------

def run_pipeline(paths: list[str]) -> tuple[nx.DiGraph, list[dict]]:
    """
    Execute the full 9-stage dependency analysis pipeline across specified lockfiles.

    Stages executed:
      01 Watch -> 02 Parse -> 03 Graph -> 04 Scan (OSV) -> 05 Enrich (EPSS/KEV) ->
      06 Score -> 07 Plan -> 08 Verify -> 09 Gate
    Outputs written:
      findings.json, patch_plan.json, .osv_cache.json
    """
    # Stage 02 & 03: Parse lockfiles and build composed directed graph
    G = load_projects(paths)
    pkg_nodes = [(n, d) for n, d in G.nodes(data=True) if d.get("kind") == "pkg"]

    # Stage 04: Batch-query OSV.dev for vulnerabilities (cached locally)
    id_map = osv_ids({(d["name"], d["version"]) for _, d in pkg_nodes})
    hits = {k: ids for k, ids in id_map.items() if ids}

    # Fetch full advisory details concurrently
    vids = {vid for ids in hits.values() for vid in ids}
    fetch_all_details(vids)

    parsed: dict = {}
    for k, ids in hits.items():
        for vid in ids:
            parsed[(k, vid)] = parse_vuln(osv_detail(vid), k[0])

    # Stage 05: Enrich with exploit signals (FIRST EPSS + CISA KEV)
    all_cves = {p["cve"] for p in parsed.values()}
    epss = epss_scores(all_cves)
    kev  = kev_set()

    # Stage 06: Score each finding using the explainable heuristic
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

    # Why: In npm dependency trees, the same package@version can be installed at multiple paths.
    # We collapse duplicates by keeping the shortest path to represent the most direct blast radius while counting instances.
    best: dict = {}
    for r in sorted(rows, key=lambda r: r["depth"]):
        k = (r["project"], r["package"], r["vuln"])
        if k in best:
            best[k]["instances"] = best[k].get("instances", 1) + 1
        else:
            best[k] = {**r, "instances": 1}

    # Stage 07, 08, 09: Plan fixed versions, verify semver, and classify into action tiers
    rows = sorted(best.values(), key=lambda r: -r["risk"])
    patch_plan = build_patch_plan(rows)

    # Persist outputs to disk
    Path("findings.json").write_text(json.dumps(rows, indent=1))
    Path("patch_plan.json").write_text(json.dumps(patch_plan, indent=1))
    save_cache()

    return G, rows


# ---------- CLI Entry Point ----------

def _parse_cli():
    """Parse command-line arguments with usage examples."""
    parser = argparse.ArgumentParser(
        prog="python -m backend.main",
        description="Hyron AI — Supply-Chain Vulnerability Propagation Pipeline (FUSION 2026 · CSB-03)",
        epilog=(
            "Examples:\n"
            "  python -m backend.main corpus/*/package-lock.json\n"
            "  env OFFLINE=1 python -m backend.main corpus/*/package-lock.json\n"
            "  uvicorn backend.main:app --reload --port 8000\n"
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument(
        "paths",
        nargs="*",
        help="Path(s) or glob pattern(s) to package-lock.json files to analyze.",
    )
    return parser.parse_args()


if __name__ == "__main__":
    args = _parse_cli()

    if args.paths:
        # Expand any glob patterns passed
        expanded = []
        for p in args.paths:
            matches = glob.glob(p)
            if matches:
                expanded.extend(matches)
            elif Path(p).exists():
                expanded.append(p)

        if not expanded:
            print(
                f"Error: No lockfiles found matching: {' '.join(args.paths)}\n"
                "Tip: Generate a sample corpus first with: python -m backend.make_corpus 25\n"
                "Then run: python -m backend.main corpus/*/package-lock.json",
                file=sys.stderr,
            )
            sys.exit(1)

        _, scan_rows = run_pipeline(expanded)
        print(f"{len(scan_rows)} findings across {len({r['project'] for r in scan_rows})} projects")
        for r in scan_rows[:10]:
            print(
                f'{r["risk"]:6}  {r["project"]:18}  {r["package"]:26}  '
                f'{r["cve"] or r["vuln"]:20}  via {r["via"]}'
            )
    else:
        import uvicorn
        print("Starting Hyron AI API and Dashboard on http://localhost:8000 (Ctrl+C to quit)...")
        uvicorn.run("backend.main:app", host="0.0.0.0", port=8000, reload=True)
