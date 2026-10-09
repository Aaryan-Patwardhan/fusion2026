#!/usr/bin/env python3
"""
dependency_graph.py — Graph utilities for blast-radius analysis.

Wraps NetworkX graph operations needed by the API routes:
  - Serialize graph to Cytoscape.js-compatible JSON
  - Find shortest/all paths from a project to a vulnerable package
  - Extract subgraph for a given CVE blast radius

Hyron AI · FUSION 2026 · CSB-03
"""

from collections import defaultdict

import networkx as nx


def to_cytoscape(G: nx.DiGraph, highlight_nodes: set[str] | None = None) -> dict:
    """
    Serialize a NetworkX DiGraph to Cytoscape.js elements format.

    Args:
        G: The dependency graph
        highlight_nodes: Set of node ids to mark as 'bad' (vulnerable)

    Returns:
        {"nodes": [...], "edges": [...]} ready for cytoscape()
    """
    highlight_nodes = highlight_nodes or set()
    nodes = []
    for n, d in G.nodes(data=True):
        node_type = "root" if d.get("kind") == "project" else (
            "bad" if n in highlight_nodes else "mid"
        )
        nodes.append({
            "data": {
                "id": n,
                "label": d.get("label", n),
                "kind": d.get("kind", "pkg"),
                "type": node_type,
                "proj": d.get("proj", ""),
                "dev": d.get("dev", False),
            }
        })

    edges = [
        {"data": {"id": f"e_{i}", "source": u, "target": v}}
        for i, (u, v) in enumerate(G.edges())
    ]

    return {"nodes": nodes, "edges": edges}


def blast_subgraph(G: nx.DiGraph, vuln_node: str) -> dict:
    """
    Build a minimal subgraph showing all projects that reach `vuln_node`,
    including the dependency paths. Returns Cytoscape-ready JSON.
    """
    relevant_nodes: set[str] = {vuln_node}
    project_nodes = [n for n, d in G.nodes(data=True) if d.get("kind") == "project"]
    paths_found = []

    for proj_node in project_nodes:
        try:
            path = nx.shortest_path(G, proj_node, vuln_node)
            relevant_nodes.update(path)
            paths_found.append(path)
        except (nx.NetworkXNoPath, nx.NodeNotFound):
            pass

    sub = G.subgraph(relevant_nodes)
    return to_cytoscape(sub, highlight_nodes={vuln_node})


def paths_to_node(G: nx.DiGraph, proj_node: str, vuln_node: str) -> list[list[str]]:
    """Return all simple dependency paths from a project node to a vulnerable node."""
    try:
        return list(nx.all_simple_paths(G, proj_node, vuln_node, cutoff=10))
    except (nx.NetworkXNoPath, nx.NodeNotFound):
        return []


def shortest_path_labels(G: nx.DiGraph, source: str, target: str) -> list[str]:
    """Return human-readable labels along the shortest path."""
    try:
        path = nx.shortest_path(G, source, target)
        return [G.nodes[n].get("label", n) for n in path]
    except (nx.NetworkXNoPath, nx.NodeNotFound):
        return [G.nodes.get(source, {}).get("label", source),
                G.nodes.get(target, {}).get("label", target)]


def project_impact_map(G: nx.DiGraph, vuln_nodes: list[str]) -> dict[str, list[str]]:
    """
    For a list of vulnerable package nodes, return {project_name: [vuln_node, ...]}
    showing which projects are affected and by which packages.
    """
    impact: dict = defaultdict(list)
    project_nodes = {n: d for n, d in G.nodes(data=True) if d.get("kind") == "project"}

    for proj_node, proj_data in project_nodes.items():
        proj_name = proj_data.get("name", proj_node)
        for vn in vuln_nodes:
            try:
                nx.shortest_path(G, proj_node, vn)
                impact[proj_name].append(vn)
            except (nx.NetworkXNoPath, nx.NodeNotFound):
                pass

    return dict(impact)
