#!/usr/bin/env python3
"""
risk_engine.py — Explainable risk scoring for Hyron AI.

Formula (transparent prototype heuristic — not a security standard):
  exploit_signal = 1.0 if CVE is in CISA KEV else EPSS probability
  runtime_factor = 0.4 for dev-only dependencies, otherwise 1.0
  risk = 100 × (CVSS / 10) × (0.2 + 0.8 × exploit_signal) × runtime_factor

Illustrative examples (from pitch deck):
  CVSS 9.8 · KEV-listed · production  → ~98
  CVSS 7.5 · EPSS 0.10 · dev-only     → ~8.4

Show the CVSS, EPSS, KEV membership, and dev/prod proxy beside the score so
engineers can inspect the evidence. Unknown exposure is labelled "Unknown".

Hyron AI · FUSION 2026 · CSB-03
"""

import networkx as nx


def compute_risk(cvss: float, cve: str | None, is_dev: bool,
                 epss_map: dict[str, float], kev: set[str]) -> float:
    """
    Compute the Hyron AI risk score (0–100).

    Args:
        cvss:     CVSS base score (0–10)
        cve:      CVE identifier or None
        is_dev:   True if the dependency is dev-only
        epss_map: {cve_id: epss_probability} mapping
        kev:      Set of CISA KEV CVE ids

    Returns:
        Rounded risk score (float, 0–100)
    """
    exploit_signal = 1.0 if cve in kev else epss_map.get(cve or "", 0.0)
    runtime_factor = 0.4 if is_dev else 1.0
    return round(100 * (cvss / 10) * (0.2 + 0.8 * exploit_signal) * runtime_factor, 1)


def blast_radius(G: nx.DiGraph, vuln_node: str) -> dict:
    """
    Compute blast-radius context for a given vulnerable package node.

    Returns a dict with:
      - affected_projects: list of project names that reach this node
      - path_count: total number of dependency paths
    """
    affected_projects = []
    path_count = 0

    project_nodes = [n for n, d in G.nodes(data=True) if d.get("kind") == "project"]
    for proj_node in project_nodes:
        try:
            paths = list(nx.all_simple_paths(G, proj_node, vuln_node, cutoff=10))
            if paths:
                proj_name = G.nodes[proj_node].get("name", proj_node)
                affected_projects.append(proj_name)
                path_count += len(paths)
        except (nx.NetworkXNoPath, nx.NodeNotFound):
            pass

    return {
        "affected_projects": affected_projects,
        "path_count": path_count,
    }


def tier_label(risk_score: float, target: str | None, major_jump: bool) -> str:
    """
    Classify a finding into AUTO / REVIEW / ESCALATE tiers.

    AUTO:     Low-risk, fix available, same-major update.
    REVIEW:   Fix available but requires override / constraint change.
    ESCALATE: No fix, major jump, or uncertain resolution.
    """
    if target is None:
        return "ESCALATE"   # No fixed version published
    if major_jump:
        return "ESCALATE"   # Major version bump — needs human review
    if risk_score < 30:
        return "AUTO"       # Low risk, safe same-major fix
    return "REVIEW"         # Moderate/high risk — propose fix, human approves
