#!/usr/bin/env python3
"""
risk_engine.py — Explainable Heuristic Risk Engine & Action Tier Gate

What:
    Calculates explainable risk scores combining CVSS severity with CISA KEV and EPSS signals,
    and assigns findings to AUTO, REVIEW, or ESCALATE action tiers.
Why:
    Stage 06 (Score) and Stage 09 (Gate) of the 9-stage pipeline. Severity alone causes
    alert fatigue; weighting by active exploitation evidence produces actionable triage.
Inputs:
    cvss (float), cve (str | None), is_dev (bool), epss_map (dict), kev (set).
Outputs:
    Risk score (float 0–100), tier label ("AUTO" | "REVIEW" | "ESCALATE").
Called by:
    backend.main.run_pipeline(), backend.triage, tests.test_scanner
"""

from typing import Optional
import networkx as nx


def compute_risk(
    cvss: float,
    cve: Optional[str],
    is_dev: bool,
    epss_map: dict[str, float],
    kev: set[str],
) -> float:
    """Calculate the transparent prototype risk score (0.0 to 100.0) using exploit evidence."""
    # Exploit signal: KEV takes precedence as confirmed weaponized exploit; otherwise EPSS probability
    exploit_signal = 1.0 if cve in kev else epss_map.get(cve or "", 0.0)
    # Dev-only proxy: dependencies used only at build/test time carry lower runtime exposure
    runtime_factor = 0.4 if is_dev else 1.0
    return round(100 * (cvss / 10) * (0.2 + 0.8 * exploit_signal) * runtime_factor, 1)


def blast_radius(G: nx.DiGraph, vuln_node: str) -> dict:
    """Calculate the project-level blast radius and path count for a vulnerable node."""
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


def tier_label(risk_score: float, target: Optional[str], major_jump: bool) -> str:
    """Classify remediation action into AUTO, REVIEW, or ESCALATE policy tiers."""
    # If no fix is published, manual mitigation or package replacement is required
    if target is None:
        return "ESCALATE"
    # Major version jump has high likelihood of breaking API changes
    if major_jump:
        return "ESCALATE"
    # Low-risk same-major update qualifies for automated temp-copy validation
    if risk_score < 30:
        return "AUTO"
    # Moderate/high risk requires explicit engineer review before applying
    return "REVIEW"
