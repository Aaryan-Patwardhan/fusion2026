#!/usr/bin/env python3
"""
ai_explainer.py — Incident brief generator for Hyron AI.

Produces concise, evidence-backed incident briefs from deterministic scan facts.
The brief format is defined in the VulnGraph AI architecture doc:

  "Incident: {CVE/advisory} affects {package@version} in {project(s)} via
   {dependency path(s)}. Evidence: CVSS {score}, EPSS {probability or unavailable},
   CISA KEV {yes/no}. The current priority is {score/tier} because
   {evidence-backed reason}. Recommended target: {fixed version or no fix published}.
   The daemon {did/did not} propose an automatic change because {reason}.
   Verification status: {rescan result}. Suggested next action: {action}."

An optional LLM may rewrite the facts for readability in a later version,
but the evidence, version target, and action tier MUST come from deterministic logic.

Hyron AI · FUSION 2026 · CSB-03
"""


def build_incident_brief(
    finding: dict,
    patch_entry: dict | None = None,
    rescan_result: str = "not run",
) -> str:
    """
    Build a plain-text incident brief from a scan finding and patch plan entry.

    Args:
        finding:      A finding dict from the scan pipeline (one row of findings.json)
        patch_entry:  Corresponding patch plan entry (from patch_plan.json), or None
        rescan_result: Result of temp-copy re-scan, e.g. "CVE gone", "new findings", "not run"

    Returns:
        A human-readable incident brief string.
    """
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

    evidence = (
        f"CVSS {cvss}, EPSS {epss_str}, CISA KEV {kev_str}."
    )

    # Priority reasoning
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

    # Patch info
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

    # Rescan status
    if rescan_result == "not run":
        verify_str = "Verification: temp-copy re-scan not yet run. Functional tests and runtime reachability not verified."
    elif rescan_result == "CVE gone":
        verify_str = "Verification: re-scan confirms the CVE is no longer reported. Functional tests and runtime reachability still require human verification."
    else:
        verify_str = f"Verification: re-scan result — {rescan_result}. Human review required."

    # Advisory summary
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
    """Return an incident brief for the highest-risk finding."""
    if not findings:
        return "No findings to report."

    top = findings[0]
    pkg_name = top["package"].rsplit("@", 1)[0]
    patch = next(
        (p for p in patch_plan if p["project"] == top["project"] and p["package"] == pkg_name),
        None,
    )
    return build_incident_brief(top, patch)
