#!/usr/bin/env python3
"""
scan_result.py — Pydantic Schemas for API Serialization & Validation

What:
    Data schemas validating REST request payloads and response bodies across all routes.
Why:
    Guarantees strict API data contracts, auto-generates OpenAPI / Swagger docs at /docs,
    and prevents unexpected field types from propagating to the frontend.
Inputs:
    Python dictionaries from pipeline outputs and client requests.
Outputs:
    Pydantic BaseModel instances (Finding, PatchEntry, ScanSummary, BlastResult, IncidentBrief).
Called by:
    backend.routes, backend.main
"""

from __future__ import annotations
from typing import Optional
from pydantic import BaseModel, Field


class Finding(BaseModel):
    """One vulnerable package instance in a project along its shortest dependency path."""
    project:   str
    package:   str        # name@version
    vuln:      str        # OSV advisory id
    cve:       Optional[str]
    summary:   str
    cvss:      float
    epss:      float
    kev:       bool
    dev:       bool
    direct:    bool
    depth:     int
    via:       str        # human-readable dependency path
    path:      list[str]  # list of node labels from project to package
    fixed:     list[str]  # published fixed versions
    risk:      float      # 0–100 heuristic risk score
    instances: int = 1    # count of paths to this pkg in the project
    osv_url:   Optional[str] = None  # direct reference link to https://osv.dev/vulnerability/<id>


class PatchEntry(BaseModel):
    """Recommended remediation action for one (project, package) pair."""
    order:        int
    project:      str
    package:      str
    current:      str
    target:       Optional[str]
    direct:       bool
    via:          str
    risk_removed: float
    vulns:        list[str]
    action:       str
    tier:         str = Field(..., pattern="^(AUTO|REVIEW|ESCALATE)$")


class ScanSummary(BaseModel):
    """High-level summary metrics of a completed scan."""
    projects:     int
    findings:     int
    kev:          int
    direct:       int
    transitive:   int
    vulns:        list[str]
    dataset:      str = "https://osv.dev"
    dataset_name: str = "Open Source Vulnerabilities (OSV.dev)"


class BlastResult(BaseModel):
    """Blast-radius response for a specific CVE or advisory query."""
    query:    str
    projects: int
    results:  list[dict]


class IncidentBrief(BaseModel):
    """Structured incident brief output for one finding."""
    finding:       Finding
    patch:         Optional[PatchEntry]
    brief_text:    str
    rescan_status: str = "not run"
