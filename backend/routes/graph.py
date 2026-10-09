#!/usr/bin/env python3
"""
routes/graph.py — Graph Metrics & Blast Radius Endpoints

What:
    REST endpoints providing high-level scan summaries, CVE-specific blast radius mapping,
    top risk findings, and project overviews.
Why:
    Powers the primary dashboard views: summary tiles, CVE search blast radius,
    and the interactive Cytoscape.js dependency path visualizer.
Inputs:
    GET query parameters (q: advisory/CVE id, n: integer count limit).
Outputs:
    JSON responses with scan statistics, affected projects, paths, and OSV links.
Called by:
    FastAPI router in backend.main, frontend dashboard components
"""

import json
from collections import defaultdict
from pathlib import Path

from fastapi import APIRouter, HTTPException

router = APIRouter()

FINDINGS_FILE = Path("findings.json")


def _rows() -> list[dict]:
    """Read and return finding rows from the persisted findings.json file."""
    if not FINDINGS_FILE.exists():
        raise HTTPException(
            status_code=503,
            detail="findings.json not found. Run the scan pipeline first.",
        )
    return json.loads(FINDINGS_FILE.read_text())


@router.get("/summary")
def summary() -> dict:
    """Return high-level metrics: project count, findings, KEV hits, and direct/transitive split."""
    r = _rows()
    return dict(
        projects=len({x["project"] for x in r}),
        findings=len(r),
        kev=len([x for x in r if x["kev"]]),
        direct=len([x for x in r if x["direct"]]),
        transitive=len([x for x in r if not x["direct"]]),
        vulns=sorted({x["cve"] or x["vuln"] for x in r}),
        dataset="https://osv.dev",
        dataset_name="Open Source Vulnerabilities (OSV.dev)",
    )


@router.get("/blast")
def blast(q: str) -> dict:
    """Return the cross-project blast radius and dependency paths for a specific CVE or advisory."""
    rows = _rows()
    hit = [x for x in rows if q in (x["cve"], x["vuln"])]
    if not hit:
        raise HTTPException(status_code=404, detail=f"No findings for query: {q}")

    by: dict = defaultdict(list)
    for x in hit:
        by[x["project"]].append(x)

    return dict(
        query=q,
        projects=len(by),
        results=[
            dict(
                project=p,
                risk=max(i["risk"] for i in v),
                direct=any(i["direct"] for i in v),
                via=[i["via"] for i in v],
                fixed=v[0]["fixed"],
                summary=v[0]["summary"],
                kev=v[0]["kev"],
                epss=v[0]["epss"],
                cvss=v[0]["cvss"],
                paths=[i["path"] for i in v],
                vuln=v[0].get("vuln"),
                cve=v[0].get("cve"),
                osv_url=v[0].get("osv_url", f"https://osv.dev/vulnerability/{v[0]['vuln']}"),
            )
            for p, v in sorted(by.items(), key=lambda kv: -max(i["risk"] for i in kv[1]))
        ],
    )


@router.get("/top")
def top(n: int = 25) -> list[dict]:
    """Return the top N highest-risk findings across all scanned projects."""
    return _rows()[:n]


@router.get("/projects")
def projects() -> list[dict]:
    """Return project summaries showing finding counts, KEV hits, and max risk per project."""
    rows = _rows()
    by_proj: dict = defaultdict(list)
    for r in rows:
        by_proj[r["project"]].append(r)

    return [
        dict(
            project=p,
            findings=len(v),
            kev=sum(1 for x in v if x["kev"]),
            max_risk=max(x["risk"] for x in v),
        )
        for p, v in sorted(by_proj.items(), key=lambda kv: -max(x["risk"] for x in kv[1]))
    ]
