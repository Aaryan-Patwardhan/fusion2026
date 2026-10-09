#!/usr/bin/env python3
"""
dependency_graph.py — Graph Traversal & Blast Radius Serialization

What:
    Provides graph traversal, blast radius path extraction, and Cytoscape.js JSON serialization.
Why:
    Stage 03 (Graph) of the 9-stage pipeline. Converts in-memory NetworkX directed graphs into
    visualizable tree structures and traces paths from project roots to vulnerable packages.
Inputs:
    networkx.DiGraph instance, node strings, source/target pairs.
Outputs:
    Cytoscape.js JSON dicts (nodes and edges), lists of path strings, project impact mappings.
Called by:
    backend.routes.graph, backend.main, frontend UI requests
"""

from collections import defaultdict
from typing import Optional
import networkx as nx


def to_cytoscape(G: nx.DiGraph, highlight_nodes: Optional[set[str]] = None) -> dict:
    """Serialize a NetworkX DiGraph into Cytoscape.js nodes and edges format."""
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
    """Extract a minimal subgraph showing all projects reaching a vulnerable package node."""
    relevant_nodes: set[str] = {vuln_node}
    project_nodes = [n for n, d in G.nodes(data=True) if d.get("kind") == "project"]

    for proj_node in project_nodes:
        try:
            path = nx.shortest_path(G, proj_node, vuln_node)
            relevant_nodes.update(path)
        except (nx.NetworkXNoPath, nx.NodeNotFound):
            pass

    sub = G.subgraph(relevant_nodes)
    return to_cytoscape(sub, highlight_nodes={vuln_node})


def paths_to_node(G: nx.DiGraph, proj_node: str, vuln_node: str) -> list[list[str]]:
    """Return all simple dependency paths from a project root to a target package node."""
    try:
        return list(nx.all_simple_paths(G, proj_node, vuln_node, cutoff=10))
    except (nx.NetworkXNoPath, nx.NodeNotFound):
        return []


def shortest_path_labels(G: nx.DiGraph, source: str, target: str) -> list[str]:
    """Return human-readable node labels along the shortest path between two nodes."""
    try:
        path = nx.shortest_path(G, source, target)
        return [G.nodes[n].get("label", n) for n in path]
    except (nx.NetworkXNoPath, nx.NodeNotFound):
        return [
            G.nodes.get(source, {}).get("label", source),
            G.nodes.get(target, {}).get("label", target),
        ]


def project_impact_map(G: nx.DiGraph, vuln_nodes: list[str]) -> dict[str, list[str]]:
    """Map project names to lists of reachable vulnerable package nodes."""
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
