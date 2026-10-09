#!/usr/bin/env python3
"""
triage.py — Event-triggered triage and decision-tier assignment for Hyron AI.

Groups findings by CVE/package/project, computes affected-project lists and paths,
and decides AUTO / REVIEW / ESCALATE according to the policy defined in the
VulnGraph AI architecture:

  AUTO:     Low-risk candidate satisfies constraints; temp-copy re-scan queued.
  REVIEW:   Fix exists but requires override or constraint change.
  ESCALATE: Major upgrade, no fixed version, malicious package, or ambiguous resolution.

The daemon (daemon.py) calls triage after each scan to produce an incident report.

Hyron AI · FUSION 2026 · CSB-03
"""

from collections import defaultdict


def group_by_cve(findings: list[dict]) -> dict[str, list[dict]]:
    """Group findings by CVE/advisory id."""
    out: dict = defaultdict(list)
    for f in findings:
        key = f.get("cve") or f.get("vuln", "UNKNOWN")
        out[key].append(f)
    return dict(out)


def group_by_project(findings: list[dict]) -> dict[str, list[dict]]:
    """Group findings by project name."""
    out: dict = defaultdict(list)
    for f in findings:
        out[f["project"]].append(f)
    return dict(out)


def triage_cve(cve_id: str, findings: list[dict], patch_plan: list[dict]) -> dict:
    """
    Build a triage summary for one CVE across all affected projects.

    Returns:
        {
          cve, summary, cvss, epss, kev,
          affected_projects: [ {project, risk, paths, tier, action} ],
          blast_radius: int,          # number of affected projects
          max_risk: float,
          recommended_action: str,    # human-readable overall recommendation
        }
    """
    affected = []
    kev      = any(f.get("kev") for f in findings)
    cvss     = max((f.get("cvss", 0) for f in findings), default=0)
    epss     = max((f.get("epss", 0) for f in findings), default=0)
    summary  = next((f.get("summary", "") for f in findings if f.get("summary")), "")

    by_proj: dict = defaultdict(list)
    for f in findings:
        by_proj[f["project"]].append(f)

    for proj, proj_findings in by_proj.items():
        max_risk = max(f["risk"] for f in proj_findings)
        paths    = [f["path"] for f in proj_findings]

        # Find patch plan entry for this project/CVE
        pkg_names = {f["package"].rsplit("@", 1)[0] for f in proj_findings}
        patch_entries = [
            p for p in patch_plan
            if p["project"] == proj and p["package"] in pkg_names
        ]
        tier   = patch_entries[0]["tier"] if patch_entries else "ESCALATE"
        action = patch_entries[0]["action"] if patch_entries else "No patch plan entry"

        affected.append({
            "project": proj,
            "risk":    max_risk,
            "paths":   paths,
            "tier":    tier,
            "action":  action,
        })

    affected.sort(key=lambda x: -x["risk"])

    # Overall recommendation
    all_tiers = {a["tier"] for a in affected}
    if "ESCALATE" in all_tiers:
        rec = "ESCALATE: Manual review required for one or more affected projects."
    elif "REVIEW" in all_tiers:
        rec = "REVIEW: Proposed fixes require human approval before applying."
    else:
        rec = "AUTO: Low-risk patches queued for temp-copy validation."

    return {
        "cve":                cve_id,
        "summary":            summary,
        "cvss":               cvss,
        "epss":               epss,
        "kev":                kev,
        "affected_projects":  affected,
        "blast_radius":       len(affected),
        "max_risk":           max(a["risk"] for a in affected) if affected else 0.0,
        "recommended_action": rec,
    }


def run_triage(findings: list[dict], patch_plan: list[dict]) -> list[dict]:
    """
    Run full triage on all findings.

    Returns a list of per-CVE triage summaries, sorted by max_risk descending.
    """
    by_cve = group_by_cve(findings)
    results = [
        triage_cve(cve_id, cve_findings, patch_plan)
        for cve_id, cve_findings in by_cve.items()
    ]
    return sorted(results, key=lambda r: -r["max_risk"])
