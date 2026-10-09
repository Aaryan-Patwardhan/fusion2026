#!/usr/bin/env python3
"""
triage.py — CVE Aggregation & Decision-Tier Triage Engine

What:
    Groups findings by CVE/advisory, computes cross-project blast radius, and assigns
    overall policy recommendations (AUTO, REVIEW, or ESCALATE).
Why:
    Stage 09 (Gate) of the 9-stage pipeline. Security teams triage by vulnerability
    incident across the entire organization, not just one isolated file at a time.
Inputs:
    findings (list[dict]): Finding rows from the scan pipeline.
    patch_plan (list[dict]): Corresponding patch actions from patch_plan.json.
Outputs:
    list[dict]: CVE-centric triage summaries with affected projects, blast radius, and recommended actions.
Called by:
    backend.daemon, reports, incident review
"""

from collections import defaultdict


def group_by_cve(findings: list[dict]) -> dict[str, list[dict]]:
    """Group flat finding rows into a mapping keyed by CVE or advisory identifier."""
    out: dict = defaultdict(list)
    for f in findings:
        key = f.get("cve") or f.get("vuln", "UNKNOWN")
        out[key].append(f)
    return dict(out)


def group_by_project(findings: list[dict]) -> dict[str, list[dict]]:
    """Group flat finding rows into a mapping keyed by project name."""
    out: dict = defaultdict(list)
    for f in findings:
        out[f["project"]].append(f)
    return dict(out)


def triage_cve(cve_id: str, findings: list[dict], patch_plan: list[dict]) -> dict:
    """Build a comprehensive triage summary for a single CVE across all affected projects."""
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

    # Determine overall organizational recommendation
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
    """Execute triage across all findings and return summaries sorted by maximum risk descending."""
    by_cve = group_by_cve(findings)
    results = [
        triage_cve(cve_id, cve_findings, patch_plan)
        for cve_id, cve_findings in by_cve.items()
    ]
    return sorted(results, key=lambda r: -r["max_risk"])
