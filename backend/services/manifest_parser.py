#!/usr/bin/env python3
"""
manifest_parser.py — Parses npm package-lock.json (v2/v3) into a per-project
directed NetworkX dependency graph using npm's nearest-node_modules resolution.

Credits: OSV.dev, FIRST.org EPSS, CISA KEV, networkx, cvss, FastAPI, Cytoscape.js
Hyron AI · FUSION 2026 · CSB-03
"""

import json
from pathlib import Path

import networkx as nx


# ---------- npm resolution helpers ----------

def _parent_scope(path: str) -> str:
    """Walk one level up in the npm nested node_modules hierarchy."""
    return path.rsplit("/node_modules/", 1)[0] if "/node_modules/" in path else ""


def _resolve(pkgs: dict, frm: str, dep: str) -> str | None:
    """npm resolution: nearest node_modules/<dep> walking up from the requiring package."""
    base = frm
    while True:
        cand = f"{base}/node_modules/{dep}" if base else f"node_modules/{dep}"
        if cand in pkgs:
            return cand
        if not base:
            return None
        base = _parent_scope(base)


# ---------- public API ----------

def load_project(path: str | Path) -> nx.DiGraph:
    """
    Parse a single package-lock.json (v2/v3) and return a directed graph where:
      - project node  kind="project"  label=<folder name>
      - package nodes kind="pkg"      label=<name@version>
      - edges represent requires/installs relationships
    """
    path = Path(path)
    lock = json.loads(path.read_text())
    proj = path.parent.name  # folder name = project name (must be unique)

    pk = lock.get("packages")
    if not pk:
        raise ValueError(
            f"{path}: lockfileVersion 1 unsupported; run `npm install --package-lock-only`"
        )

    root = pk.get("", {})
    direct = (
        set(root.get("dependencies", {}))
        | set(root.get("devDependencies", {}))
        | set(root.get("optionalDependencies", {}))
    )

    nodes = {p: m for p, m in pk.items() if p and m.get("version") and not m.get("link")}
    top = f"proj:{proj}"

    G = nx.DiGraph()
    G.add_node(top, kind="project", name=proj, label=proj)

    for p, m in nodes.items():
        name = m.get("name") or p.split("node_modules/")[-1]
        G.add_node(
            f"{proj}:{p}",
            kind="pkg",
            proj=proj,
            version=m["version"],
            dev=bool(m.get("dev")),
            name=name,
            label=f"{name}@{m['version']}",
        )

    for d in direct:
        t = _resolve(nodes, "", d)
        if t:
            G.add_edge(top, f"{proj}:{t}")

    for p, m in nodes.items():
        for d in {**m.get("dependencies", {}), **m.get("optionalDependencies", {})}:
            t = _resolve(nodes, p, d)
            if t:
                G.add_edge(f"{proj}:{p}", f"{proj}:{t}")

    return G


def load_projects(paths: list[str | Path]) -> nx.DiGraph:
    """Compose multiple project graphs into one combined graph."""
    graphs = [load_project(p) for p in paths]
    return nx.compose_all(graphs)
