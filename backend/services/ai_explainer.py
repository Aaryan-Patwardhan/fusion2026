#!/usr/bin/env python3
"""
ai_explainer.py — Deterministic Template-Based Incident Brief Generator

What:
    Constructs factual, structured incident briefs from deterministic scan facts.
    NOTE: This module is strictly template-based and deterministic; it does NOT make
    external LLM calls or invent unverified diagnosis.
Why:
    Produces clear, auditable incident briefs for engineers citing verified fields:
    advisory ID, CVSS, EPSS, CISA KEV status, dependency path, and recommended version.
Inputs:
    finding (dict): A row from findings.json.
    patch_entry (dict | None): Corresponding row from patch_plan.json.
    rescan_result (str): Lockfile re-scan outcome in temporary copy ("not run" | "CVE gone").
Outputs:
    str: Plain-text factual incident brief paragraph.
Called by:
    backend.routes.reports, backend.triage
"""

from typing import Optional


def build_incident_brief(
    finding: dict,
    patch_entry: Optional[dict] = None,
    rescan_result: str = "not run",
) -> str:
    """Generate a structured, evidence-backed incident brief string from scan facts."""
    cve_id    = finding.get("cve") or finding.get("vuln", "Unknown")
    pkg       = finding.get("package", "unknown")
    project   = finding.get("project", "unknown")
    via       = finding.get("via", "direct")
    cvss      = finding.get("cvss", "N/A")
    epss      = finding.get("epss")
    kev       = finding.get("kev", False)
    risk      = finding.get("risk", "N/A")
    summary   = finding.get("summary", "")

    # Exploit evidence sentence
    epss_str = f"{epss:.3f}" if epss is not None else "unavailable"
    kev_str  = "YES — exploited in the wild (CISA KEV)" if kev else "No"

    evidence = f"CVSS {cvss}, EPSS {epss_str}, CISA KEV {kev_str}."

    # Priority reasoning based deterministically on evidence thresholds
    if kev:
        reason = "this CVE is on the CISA Known Exploited Vulnerabilities list"
    elif epss and epss > 0.3:
        reason = f"EPSS exploitation probability is high ({epss_str})"
    elif cvss and float(cvss) >= 9.0:
        reason = f"CVSS score {cvss} is Critical"
    elif cvss and float(cvss) >= 7.0:
        reason = f"CVSS score {cvss} is High severity"
    else:
        reason = f"risk score {risk} based on severity and exploit signals"

    # Remediation recommendation from patch planner
    if patch_entry:
        target = patch_entry.get("target")
        tier   = patch_entry.get("tier", "REVIEW")
        action_cmd = patch_entry.get("action", "Review manually")

        if target:
            fix_str = f"Recommended target: {pkg.rsplit('@', 1)[0]}@{target}."
        else:
            fix_str = "No fixed version published."

        if tier == "AUTO":
            daemon_str = "The daemon proposed an automatic change (low-risk, same-major fix, temp-copy re-scan queued)."
        elif tier == "ESCALATE":
            daemon_str = "The daemon did NOT propose an automatic change (major upgrade, no fix, or uncertain resolution — requires human decision)."
        else:
            daemon_str = "The daemon proposed this fix for human review (REVIEW tier — override or constraint change required)."

        action_str = f"Suggested action: {action_cmd}"
    else:
        fix_str    = "Patch plan not yet generated."
        daemon_str = "Automatic remediation not attempted."
        action_str = "Run the patch planner to get a recommended action."

    # Verification status: only describes lockfile re-scan outcome
    if rescan_result == "not run":
        verify_str = "Verification: temp-copy re-scan not yet run. Functional tests and runtime reachability not verified."
    elif rescan_result == "CVE gone":
        verify_str = "Verification: temp-copy re-scan confirms the CVE is no longer reported. Functional tests and runtime reachability still require human verification."
    else:
        verify_str = f"Verification: temp-copy re-scan result — {rescan_result}. Human review required."

    summary_str = f'Advisory: "{summary}"' if summary else ""

    parts = [
        f"INCIDENT: {cve_id} affects {pkg} in project '{project}' via {via}.",
        summary_str,
        f"Evidence: {evidence}",
        f"Priority: {risk}/100 because {reason}.",
        fix_str,
        daemon_str,
        verify_str,
        action_str,
    ]

    return "\n".join(p for p in parts if p)


def brief_for_top_finding(findings: list[dict], patch_plan: list[dict]) -> str:
    """Generate a structured incident brief for the single highest-risk finding."""
    if not findings:
        return "No findings to report."

    top = findings[0]
    pkg_name = top["package"].rsplit("@", 1)[0]
    patch = next(
        (p for p in patch_plan if p["project"] == top["project"] and p["package"] == pkg_name),
        None,
    )
    return build_incident_brief(top, patch)
