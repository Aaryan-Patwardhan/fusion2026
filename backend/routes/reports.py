#!/usr/bin/env python3
"""
routes/reports.py — Patch plan and incident brief endpoints for Hyron AI.
Hyron AI · FUSION 2026 · CSB-03
"""

import json
from pathlib import Path

from fastapi import APIRouter, HTTPException

from backend.services.ai_explainer import build_incident_brief, brief_for_top_finding

router = APIRouter()

FINDINGS_FILE   = Path("findings.json")
PATCH_PLAN_FILE = Path("patch_plan.json")


def _rows() -> list[dict]:
    if not FINDINGS_FILE.exists():
        raise HTTPException(status_code=503, detail="findings.json not found. Run the pipeline first.")
    return json.loads(FINDINGS_FILE.read_text())


def _plan() -> list[dict]:
    if not PATCH_PLAN_FILE.exists():
        raise HTTPException(status_code=503, detail="patch_plan.json not found. Run the pipeline first.")
    return json.loads(PATCH_PLAN_FILE.read_text())


@router.get("/patch")
def patch(project: str | None = None, n: int = 30):
    """
    Ordered patch plan (highest risk-removed first).
    Filter by project name with ?project=<name>.
    Each entry shows the action tier: AUTO | REVIEW | ESCALATE.
    """
    plan = _plan()
    if project:
        plan = [p for p in plan if p["project"] == project]
    return plan[:n]


@router.get("/brief")
def incident_brief(cve: str | None = None, project: str | None = None):
    """
    Generate an evidence-backed incident brief.
    If cve is provided, brief is for the highest-risk finding matching that CVE.
    If project is also provided, scoped to that project.
    Otherwise, brief covers the top overall finding.
    """
    rows = _rows()
    plan = _plan()

    filtered = rows
    if cve:
        filtered = [r for r in filtered if r.get("cve") == cve or r.get("vuln") == cve]
    if project:
        filtered = [r for r in filtered if r["project"] == project]

    if not filtered:
        raise HTTPException(status_code=404, detail="No findings match the given filters.")

    top = filtered[0]  # already sorted by risk descending
    pkg_name = top["package"].rsplit("@", 1)[0]
    patch_entry = next(
        (p for p in plan if p["project"] == top["project"] and p["package"] == pkg_name),
        None,
    )
    brief_text = build_incident_brief(top, patch_entry)
    return {
        "finding": top,
        "patch": patch_entry,
        "brief": brief_text,
        "disclaimer": (
            "This brief is generated from deterministic scan evidence. "
            "It does NOT confirm the vulnerable code path is reachable, "
            "nor that a proposed fix passes functional tests."
        ),
    }


@router.get("/brief/top")
def top_brief():
    """Incident brief for the single highest-risk finding in the last scan."""
    rows = _rows()
    plan = _plan()
    return {
        "brief": brief_for_top_finding(rows, plan),
        "disclaimer": (
            "Generated from scan evidence only. "
            "Functional tests and runtime reachability not verified."
        ),
    }
