# Hyron AI — Supply-Chain Blast Radius

> **FUSION 2026 · Problem CSB-03 · Team: Daemon X**

## What It Does in 3 Sentences

Hyron AI is a local-first dependency security daemon that continuously detects known vulnerabilities in resolved software packages and maps their direct and transitive blast radius across projects. It enriches findings with live exploit evidence from OSV.dev, FIRST EPSS, and CISA KEV to rank real-world risk rather than relying on raw severity scores. Finally, it generates an ordered, semver-aware remediation plan categorized into safety tiers alongside factual, evidence-backed incident briefs.

---

## Quick Start (Fish Shell)

Run these 3 commands in your Fish shell:

```fish
source .venv/bin/activate.fish; pip install -r backend/requirements.txt
env OFFLINE=1 python -m backend.main corpus/*/package-lock.json
uvicorn backend.main:app --port 8000
```
Open **http://localhost:8000** to view the interactive dashboard.

---

## How It Works in 5 Minutes (Following a Real Finding)

To see the 9-stage pipeline in action, follow one real finding from our scan of `corpus/app-01`: **`ejs@3.0.1`**.

1. **Watch**: The background daemon monitors lockfiles for modifications or checks on schedule.
2. **Parse**: `manifest_parser.py` parses `corpus/app-01/package-lock.json` using npm's nearest-`node_modules` algorithm and finds `ejs@3.0.1`.
3. **Graph**: `dependency_graph.py` builds the directed graph edge: `app-01` $\rightarrow$ `ejs@3.0.1` (`depth = 1`, direct production dependency).
4. **Scan**: `vulnerability_scanner.py` queries OSV.dev and finds advisory `GHSA-phwq-j96m-2c2q` (`CVE-2022-29078`: *"ejs template injection vulnerability"*).
5. **Enrich**: Exploit feeds provide CVSS **`9.8`**, EPSS **`0.32808`** (32.8% 30-day exploit likelihood), and CISA KEV **`false`**.
6. **Score**: `risk_engine.py` applies the transparent heuristic:
   $$\text{Risk} = 100 \times \left(\frac{9.8}{10}\right) \times (0.2 + 0.8 \times 0.32808) \times 1.0 = \mathbf{45.3}$$
7. **Plan**: `patch_planner.py` extracts published fixes (`3.1.7`) and selects `3.1.7` (smallest safe fix above current, preserving major version 3).
8. **Verify**: Temporary-copy re-scan validates that updating to `3.1.7` eliminates the CVE without introducing new known flaws.
9. **Gate**: Classified as **`REVIEW`** (risk score $\ge 30$; requires engineer approval before applying to production).
   - Generates deterministic incident brief: *"INCIDENT: CVE-2022-29078 affects ejs@3.0.1 in project 'app-01' via ejs@3.0.1. Evidence: CVSS 9.8, EPSS 0.328, CISA KEV No..."*

---

## Risk Score: Worked Examples

The risk engine computes a transparent prototype score (0–100) using:
$$\text{exploit\_signal} = 1.0 \text{ if in CISA KEV, else EPSS probability}$$
$$\text{runtime\_factor} = 0.4 \text{ if dev-only, else } 1.0$$
$$\text{Risk} = 100 \times \left(\frac{\text{CVSS}}{10}\right) \times (0.2 + 0.8 \times \text{exploit\_signal}) \times \text{runtime\_factor}$$

### Example 1: Critical Production Vulnerability Exploited in the Wild
- **Inputs**: CVSS = 9.8, In CISA KEV = Yes (exploit = 1.0), Production dependency (factor = 1.0)
- **Calculation**: $100 \times (9.8 / 10) \times (0.2 + 0.8 \times 1.0) \times 1.0 = 98 \times 1.0 = \mathbf{98.0}$

### Example 2: High Severity Dev-Only Dependency with Low Exploit Likelihood
- **Inputs**: CVSS = 7.5, EPSS = 0.10, In CISA KEV = No, Dev-only dependency (factor = 0.4)
- **Calculation**: $100 \times (7.5 / 10) \times (0.2 + 0.8 \times 0.10) \times 0.4 = 75 \times 0.28 \times 0.4 = \mathbf{8.4}$

Every score displays the underlying CVSS, EPSS, KEV, and dev/prod proxy directly beside it so engineers can inspect the evidence.

---

## Glossary

- **Lockfile**: A file (`package-lock.json`) recording the exact versions and dependency tree resolved by a package manager.
- **Direct vs. Transitive**: A *direct* dependency is declared explicitly in `package.json`; a *transitive* dependency is brought in by another dependency down the tree.
- **CVE**: Common Vulnerabilities and Exposures — standard dictionary identifier for known security flaws (e.g., `CVE-2022-29078`).
- **GHSA**: GitHub Security Advisory — advisory database identifier tracked in OSV.dev (e.g., `GHSA-phwq-j96m-2c2q`).
- **CVSS**: Common Vulnerability Scoring System (0.0 to 10.0) measuring technical severity.
- **EPSS**: Exploit Prediction Scoring System — probability (0.0 to 1.0) that a CVE will be exploited in the wild within 30 days.
- **CISA KEV**: CISA Known Exploited Vulnerabilities catalog — definitive list of flaws confirmed to be actively weaponized by adversaries.
- **Blast Radius**: The full set of projects, applications, and dependency paths reached by a given vulnerable package.
- **AUTO**: Low-risk candidate that satisfies semver constraints; eligible for automated temp-copy validation.
- **REVIEW**: Fixed version exists, but applying it requires changing parent constraints or adding lockfile overrides.
- **ESCALATE**: Requires human decision because of a major version bump, no published fix, or suspected malicious package.

---

## Troubleshooting

- **Offline Cache Miss**: If you see `"offline: no cached detail"` or empty findings under `env OFFLINE=1`, run one online scan first (`python -m backend.main corpus/*/package-lock.json`) to seed `.osv_cache.json`.
- **Lockfile Version 1 Error**: If an error states `lockfileVersion 1 unsupported`, regenerate the lockfile with modern npm format: `npm install --package-lock-only`.
- **Port 8000 in Use**: If Uvicorn reports port 8000 is occupied, run on another port: `uvicorn backend.main:app --port 8080`.

---

## Honest Limitations

- **npm lockfiles only**: The current MVP parses npm `package-lock.json` (v2/v3). PyPI and Maven require separate ecosystem resolvers and remain on the future roadmap.
- **Presence $\neq$ Reachability**: "Affected" means the vulnerable package version exists in the dependency tree. It does **not** prove that the vulnerable function or code path is executed at runtime.
- **Verified $\neq$ Tests Passed**: "Verified" means the updated package was re-scanned in a temporary copy and confirmed clean. It does **not** mean your application's functional test suite was run or passed.
- **Heuristic Risk Model**: The risk score is an explainable prototype prioritization formula, not a validated universal security standard.
- **Deterministic Briefs**: `ai_explainer.py` uses deterministic Python string templates based strictly on scan facts. It does **not** make calls to external LLMs or invent unverified diagnosis.
