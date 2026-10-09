#!/usr/bin/env python3
"""
patch_planner.py — Ordered, semver-aware remediation plan for Hyron AI.

For each vulnerable (project, package, version):
  1. Collect all published fixed versions from the advisory record.
  2. Prefer smallest safe update; prefer same-major over major jump.
  3. Treat 0.x minor changes as potentially breaking.
  4. Classify into AUTO / REVIEW / ESCALATE action tiers.
  5. Order package actions by risk removed (highest first).

The plan never merges or deploys automatically.
A clean re-scan is NOT proof that functional tests pass.

Hyron AI · FUSION 2026 · CSB-03
"""

from packaging.version import InvalidVersion, Version

from backend.services.risk_engine import tier_label


# ---------- helpers ----------

def _v(s: str) -> Version | None:
    try:
        return Version(s)
    except InvalidVersion:
        return None


def pick_fix(current: str, fixed: list[str]) -> tuple[str | None, bool]:
    """
    Select the safest published fixed version above `current`.

    Returns:
        (target_version, is_major_jump)
        target_version is None if no fix is available above current.
    """
    c = _v(current)
    if c is None:
        return None, False

    candidates = [f for f in fixed if _v(f) and _v(f) > c]
    if not candidates:
        return None, False

    same_major = [f for f in candidates if _v(f).major == c.major]
    pool = same_major or candidates
    target = min(pool, key=_v)
    is_major_jump = _v(target).major != c.major  # type: ignore[union-attr]
    return target, is_major_jump


# ---------- public API ----------

def build_patch_plan(rows: list[dict]) -> list[dict]:
    """
    Build an ordered patch plan from scan findings.

    Args:
        rows: list of finding dicts (output of pipeline scan)

    Returns:
        Sorted list of patch actions, highest risk-removed first.
        Each entry contains:
          order, project, package, current, target, direct,
          via, risk_removed, vulns, action, tier
    """
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
            # Keep the highest target in case multiple vulns need different fixes
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
