#!/usr/bin/env python3
"""
routes/scan.py — Scan trigger endpoint for Hyron AI.
POST /api/scan  →  runs the full pipeline on provided lockfile paths.
Hyron AI · FUSION 2026 · CSB-03
"""

import json
from pathlib import Path

from fastapi import APIRouter, HTTPException
from pydantic import BaseModel

router = APIRouter()

FINDINGS_FILE   = Path("findings.json")
PATCH_PLAN_FILE = Path("patch_plan.json")


class ScanRequest(BaseModel):
    paths: list[str]  # glob patterns or explicit paths to package-lock.json files


@router.post("/scan")
def trigger_scan(req: ScanRequest):
    """
    Trigger a full pipeline scan on the provided lockfile paths.

    This runs: manifest_parser → OSV lookup → risk scoring → patch plan
    and writes findings.json + patch_plan.json.

    NOTE: For large corpora this may take 30–90 seconds (network-bound).
    Use OFFLINE=1 env var to use cached data only.
    """
    import glob
    from backend.main import run_pipeline

    expanded = []
    for pattern in req.paths:
        matched = glob.glob(pattern, recursive=True)
        if not matched:
            expanded.append(pattern)  # let pipeline raise the error
        else:
            expanded.extend(matched)

    if not expanded:
        raise HTTPException(status_code=400, detail="No lockfile paths provided")

    try:
        _, rows = run_pipeline(expanded)
        return {
            "status": "ok",
            "findings": len(rows),
            "projects": len({r["project"] for r in rows}),
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))
