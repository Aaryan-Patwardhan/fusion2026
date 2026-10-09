#!/usr/bin/env python3
"""
patch_planner.py — Semver-Aware Remediation Planner

What:
    Identifies the smallest safe published fixed version for each vulnerable package,
    orders remediation actions by total risk removed, and categorizes them into action tiers.
Why:
    Stage 07 (Plan) of the 9-stage pipeline. Blindly upgrading to latest often causes
    breaking changes; selecting the smallest safe version above current minimizes build breakage.
Inputs:
    rows (list[dict]): Finding rows output by the scan pipeline.
Outputs:
    list[dict]: Ranked remediation plan sorted by risk_removed descending.
Called by:
    backend.main.run_pipeline(), backend.routes.reports, tests.test_graph
"""

from typing import Optional
from packaging.version import InvalidVersion, Version

from backend.services.risk_engine import tier_label


# ---------- helpers ----------

def _v(s: str) -> Optional[Version]:
    """Parse a version string into a comparable packaging.version.Version object or None."""
    try:
        return Version(s)
    except InvalidVersion:
        return None


def pick_fix(current: str, fixed: list[str]) -> tuple[Optional[str], bool]:
    """
    Select the safest published fixed version above the currently installed version.

    Why: In semver, upgrading across a major version boundary (or minor boundary in 0.x)
    frequently introduces breaking API changes. We prioritize candidate versions within
    the same major release series, choosing the lowest version that fixes the vulnerability.
    """
    c = _v(current)
    if c is None:
        return None, False

    candidates = [f for f in fixed if _v(f) and _v(f) > c]
    if not candidates:
        return None, False

    # Prefer same major version to minimize breaking changes
    same_major = [f for f in candidates if _v(f).major == c.major]
    pool = same_major or candidates
    target = min(pool, key=_v)
    is_major_jump = _v(target).major != c.major
    return target, is_major_jump


# ---------- public API ----------

def build_patch_plan(rows: list[dict]) -> list[dict]:
    """Build an ordered remediation plan from vulnerability scan findings."""
    plan: dict = {}

    for r in rows:
        name, cur = r["package"].rsplit("@", 1)
        key = (r["project"], name, cur)

        entry = plan.setdefault(key, dict(
            project=r["project"],
            package=name,
            current=cur,
            target=None,
            is_major_jump=False,
            direct=r["direct"],
            via=r["via"],
            risk_removed=0.0,
            vulns=[],
        ))
        entry["risk_removed"] = round(entry["risk_removed"] + r["risk"], 1)
        entry["vulns"].append(r["cve"] or r["vuln"])

        target, major_jump = pick_fix(cur, r["fixed"])
        if target:
            # If multiple vulns exist for the same package, select the highest fix target
            if entry["target"] is None or _v(target) > _v(entry["target"]):
                entry["target"] = target
                entry["is_major_jump"] = major_jump

    out = sorted(plan.values(), key=lambda e: -e["risk_removed"])

    for i, e in enumerate(out, 1):
        e["order"] = i
        target = e["target"]
        major_jump = e.pop("is_major_jump")

        if not target:
            e["action"] = "No fixed version published — replace the package or apply a mitigation"
            e["tier"] = "ESCALATE"
        elif major_jump:
            e["action"] = (
                f"Major upgrade required: {e['package']}@{e['current']} → {target}. "
                "Review breaking changes before applying."
            )
            e["tier"] = "ESCALATE"
        elif e["direct"]:
            e["action"] = f"npm install {e['package']}@{target}"
            e["tier"] = tier_label(e["risk_removed"], target, major_jump)
        else:
            e["action"] = (
                f'Upgrade the parent package, or add overrides: '
                f'{{"{e["package"]}": "{target}"}}'
            )
            e["tier"] = tier_label(e["risk_removed"], target, major_jump)

    return out
