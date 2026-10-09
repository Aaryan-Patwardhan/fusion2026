#!/usr/bin/env python3
"""
routes/reports.py — Patch Plan & Incident Brief API Routes

What:
    REST endpoints serving the prioritized remediation plan and deterministic incident briefs.
Why:
    Provides developers and security teams with copy-pasteable patch commands, safety tiers,
    and factual incident briefs without requiring manual advisory synthesis.
Inputs:
    GET query parameters (project: str, cve: str, n: int limit).
Outputs:
    JSON responses containing patch action lists and structured incident briefs.
Called by:
    FastAPI router in backend.main, frontend PatchPlan component, incident brief view
"""

import json
from pathlib import Path
from typing import Optional

from fastapi import APIRouter, HTTPException

from backend.services.ai_explainer import build_incident_brief, brief_for_top_finding

router = APIRouter()

FINDINGS_FILE   = Path("findings.json")
PATCH_PLAN_FILE = Path("patch_plan.json")

_FINDINGS_CACHE: dict = {"mtime": 0.0, "data": []}
_PLAN_CACHE: dict = {"mtime": 0.0, "data": []}


def _rows() -> list[dict]:
    """Read and return finding rows from findings.json, cached in memory by file mtime."""
    if not FINDINGS_FILE.exists():
        raise HTTPException(
            status_code=503,
            detail="findings.json not found. Run the scan pipeline first.",
        )
    mtime = FINDINGS_FILE.stat().st_mtime
    if _FINDINGS_CACHE["mtime"] != mtime or not _FINDINGS_CACHE["data"]:
        _FINDINGS_CACHE["mtime"] = mtime
        _FINDINGS_CACHE["data"] = json.loads(FINDINGS_FILE.read_text())
    return _FINDINGS_CACHE["data"]


def _plan() -> list[dict]:
    """Read and return patch plan rows from patch_plan.json, cached in memory by file mtime."""
    if not PATCH_PLAN_FILE.exists():
        raise HTTPException(
            status_code=503,
            detail="patch_plan.json not found. Run the scan pipeline first.",
        )
    mtime = PATCH_PLAN_FILE.stat().st_mtime
    if _PLAN_CACHE["mtime"] != mtime or not _PLAN_CACHE["data"]:
        _PLAN_CACHE["mtime"] = mtime
        _PLAN_CACHE["data"] = json.loads(PATCH_PLAN_FILE.read_text())
    return _PLAN_CACHE["data"]


@router.get("/patch")
def patch(project: Optional[str] = None, n: int = 30) -> list[dict]:
    """Return the ordered remediation plan, optionally filtered to a specific project."""
    plan = _plan()
    if project:
        plan = [p for p in plan if p["project"] == project]
    return plan[:n]


@router.get("/brief")
def incident_brief(cve: Optional[str] = None, project: Optional[str] = None) -> dict:
    """Return a factual, evidence-backed incident brief for a given CVE or top finding."""
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
def top_brief() -> dict:
    """Return an incident brief for the single highest-risk finding across all projects."""
    rows = _rows()
    plan = _plan()
    return {
        "brief": brief_for_top_finding(rows, plan),
        "disclaimer": (
            "Generated from scan evidence only. "
            "Functional tests and runtime reachability not verified."
        ),
    }
