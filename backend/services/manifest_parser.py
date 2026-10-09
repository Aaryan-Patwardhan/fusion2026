#!/usr/bin/env python3
"""
manifest_parser.py — npm Lockfile Resolver & Graph Builder

What:
    Parses npm package-lock.json (versions 2 and 3) into a directed dependency graph.
Why:
    Stage 02 (Parse) of the 9-stage pipeline. Lockfiles describe the exact hoisted
    dependency tree. Building a graph is required to trace paths and blast radius.
Inputs:
    Filesystem path(s) to package-lock.json files.
Outputs:
    NetworkX DiGraph with project nodes (kind="project") and package nodes (kind="pkg").
Called by:
    backend.main.run_pipeline(), tests.test_parser
"""

import json
from pathlib import Path
from typing import Optional

import networkx as nx


# ---------- npm resolution helpers ----------

def _parent_scope(path: str) -> str:
    """Walk one level up in the nested node_modules directory hierarchy."""
    return path.rsplit("/node_modules/", 1)[0] if "/node_modules/" in path else ""


def _resolve(pkgs: dict, frm: str, dep: str) -> Optional[str]:
    """
    Resolve a required dependency to its installed package path in the lockfile.

    Why: npm uses a hoisted nested directory layout. When package A requires
    dependency B, npm looks in A/node_modules/B first. If not found, it walks up
    the scope hierarchy until it finds the hoisted copy at root node_modules/B.
    """
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
    """Parse one package-lock.json file and return its directed dependency graph."""
    path = Path(path)
    lock = json.loads(path.read_text())
    proj = path.parent.name  # folder name = project identifier

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

    # Add edges from project root to directly declared dependencies
    for d in direct:
        t = _resolve(nodes, "", d)
        if t:
            G.add_edge(top, f"{proj}:{t}")

    # Add transitive dependency edges between packages
    for p, m in nodes.items():
        for d in {**m.get("dependencies", {}), **m.get("optionalDependencies", {})}:
            t = _resolve(nodes, p, d)
            if t:
                G.add_edge(f"{proj}:{p}", f"{proj}:{t}")

    return G


def load_projects(paths: list[str | Path]) -> nx.DiGraph:
    """Compose multiple individual project graphs into one unified dependency graph."""
    graphs = [load_project(p) for p in paths]
    return nx.compose_all(graphs)
