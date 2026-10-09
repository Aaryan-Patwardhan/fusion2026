#!/usr/bin/env python3
"""
bench.py — Benchmarking Pipeline Stages

Measures wall-clock time for each stage of the Hyron AI pipeline:
  1. Lockfile parsing and NetworkX graph construction
  2. OSV batch ID query
  3. Advisory details retrieval
  4. Exploit signal enrichment (EPSS / KEV)
  5. Shortest path traversal and risk score calculation
"""

import glob
import sys
import time
from pathlib import Path

# Ensure repo root is on sys.path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from backend.services.manifest_parser import load_projects
from backend.services.vulnerability_scanner import (
    CACHE, fetch_all_details, kev_set, epss_scores,
    osv_ids, osv_detail, parse_vuln,
)
from backend.services.risk_engine import compute_risk
from backend.services.patch_planner import build_patch_plan
import networkx as nx


def run_benchmark(paths: list[str]) -> dict:
    timings = {}

    # 1. Lockfile parse
    t0 = time.perf_counter()
    G = load_projects(paths)
    timings["01_lockfile_parse_sec"] = time.perf_counter() - t0

    pkg_nodes = [(n, d) for n, d in G.nodes(data=True) if d.get("kind") == "pkg"]
    pairs = {(d["name"], d["version"]) for _, d in pkg_nodes}

    # 2. OSV batch query
    t0 = time.perf_counter()
    id_map = osv_ids(pairs)
    timings["02_osv_batch_query_sec"] = time.perf_counter() - t0

    hits = {k: ids for k, ids in id_map.items() if ids}
    vids = {vid for ids in hits.values() for vid in ids}

    # 3. Advisory detail fetch
    t0 = time.perf_counter()
    fetch_all_details(vids)
    parsed = {}
    for k, ids in hits.items():
        for vid in ids:
            parsed[(k, vid)] = parse_vuln(osv_detail(vid), k[0])
    timings["03_advisory_fetch_sec"] = time.perf_counter() - t0

    # 4. Exploit signals
    t0 = time.perf_counter()
    all_cves = {p["cve"] for p in parsed.values()}
    epss = epss_scores(all_cves)
    kev = kev_set()
    timings["04_exploit_signals_sec"] = time.perf_counter() - t0

    # 5. Path traversal & scoring
    t0 = time.perf_counter()
    rows = []
    for n, d in pkg_nodes:
        key = (d["name"], d["version"])
        for vid in hits.get(key, []):
            v = parsed[(key, vid)]
            top = f"proj:{d['proj']}"
            try:
                path = nx.shortest_path(G, top, n)
            except nx.NetworkXNoPath:
                path = [top, n]
            labels = [G.nodes[x]["label"] for x in path]
            risk = compute_risk(v["cvss"], v["cve"], d["dev"], epss, kev)
            rows.append({
                "project": d["proj"],
                "package": f"{d['name']}@{d['version']}",
                "vuln": vid,
                "cve": v["cve"],
                "summary": v["summary"],
                "cvss": v["cvss"],
                "epss": epss.get(v["cve"] or "", 0.0),
                "kev": (v["cve"] in kev) if v["cve"] else False,
                "dev": d["dev"],
                "direct": G.has_edge(top, n),
                "depth": len(path) - 1,
                "via": " > ".join(labels[1:]),
                "path": labels,
                "fixed": v["fixed"],
                "risk": risk,
            })
    timings["05_path_and_scoring_sec"] = time.perf_counter() - t0

    # 6. Planning & dedupe
    t0 = time.perf_counter()
    best = {}
    for r in sorted(rows, key=lambda r: r["depth"]):
        k = (r["project"], r["package"], r["vuln"])
        if k in best:
            best[k]["instances"] = best[k].get("instances", 1) + 1
        else:
            best[k] = {**r, "instances": 1}
    rows = sorted(best.values(), key=lambda r: -r["risk"])
    patch_plan = build_patch_plan(rows)
    timings["06_plan_and_dedupe_sec"] = time.perf_counter() - t0

    timings["total_pipeline_sec"] = sum(timings.values())
    timings["projects_count"] = len({r["project"] for r in rows})
    timings["findings_count"] = len(rows)
    timings["graph_nodes"] = G.number_of_nodes()
    timings["graph_edges"] = G.number_of_edges()

    return timings


if __name__ == "__main__":
    paths = glob.glob("corpus/*/package-lock.json")
    print(f"Benchmarking Hyron AI on {len(paths)} projects (corpus/*/package-lock.json)...")
    results = run_benchmark(paths)
    print("\nBenchmark Results:")
    print("-" * 55)
    for k, v in results.items():
        if isinstance(v, float):
            print(f"  {k:30}: {v * 1000:8.2f} ms ({v:6.3f} s)")
        else:
            print(f"  {k:30}: {v}")
    print("-" * 55)
