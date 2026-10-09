#!/usr/bin/env python3
"""
routes/scan.py — Scan Trigger API Route

What:
    HTTP POST endpoint to trigger the full 9-stage analysis pipeline on demand.
Why:
    Allows frontend clients or CI/CD pipelines to initiate lockfile scans dynamically.
Inputs:
    POST /api/scan with JSON { "paths": ["corpus/*/package-lock.json"] }.
Outputs:
    JSON response { "status": "ok", "findings": int, "projects": int }.
Called by:
    FastAPI router in backend.main, frontend UploadPanel
"""

import glob
from fastapi import APIRouter, HTTPException
from pydantic import BaseModel

router = APIRouter()


class ScanRequest(BaseModel):
    """Request payload containing lockfile paths or glob patterns to analyze."""
    paths: list[str]


@router.post("/scan")
def trigger_scan(req: ScanRequest) -> dict:
    """Trigger an end-to-end pipeline scan on the requested lockfile paths."""
    from backend.main import run_pipeline

    expanded = []
    for pattern in req.paths:
        matched = glob.glob(pattern, recursive=True)
        if not matched:
            expanded.append(pattern)
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
