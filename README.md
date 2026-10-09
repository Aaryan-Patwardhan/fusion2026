# Hyron AI — Supply-Chain Blast Radius

> **Local-first dependency incident daemon: from package alert to a risk-ranked, evidence-backed action plan.**
>
> **FUSION 2026 · CSB-03 · Team: Daemon X**

---

## What It Does

Modern applications depend on hundreds of open-source packages. When one is found vulnerable, traditional scanners flag it project-by-project — they don't show the **cross-project blast radius**.

Hyron AI:

1. **Watches** lockfiles on a schedule, on change, or when a new advisory is received.
2. **Maps** direct + transitive dependency paths in a NetworkX graph.
3. **Ranks** findings with OSV advisory data, FIRST EPSS exploit probability, and CISA KEV (known-exploited) signals.
4. **Acts** safely: generates an ordered patch plan, classifies each fix into `AUTO / REVIEW / ESCALATE`, and produces an evidence-backed incident brief.

Source code stays local. Public lookups use only package name + version. A disk cache enables offline/demo-day operation.

---

## Quick Start

### 1. Backend setup

```bash
cd Fusion2K26
python -m venv .venv && source .venv/bin/activate
pip install -r backend/requirements.txt
```

### 2. Generate the sample corpus (needs npm on PATH)

```bash
python -m backend.make_corpus 25   # creates corpus/app-01…app-25 with real lockfiles
```

### 3. Run the pipeline (online)

```bash
python -m backend.main corpus/*/package-lock.json
# → writes findings.json, patch_plan.json, .osv_cache.json
```

### 4. Start the API server

```bash
uvicorn backend.main:app --reload --port 8000
# → http://localhost:8000
```

### 5. Frontend (React + Vite)

```bash
cd frontend
npm install
npm run dev      # → http://localhost:5173 (proxies /api → :8000)
# OR build for production:
npm run build    # → frontend/dist/ (served by FastAPI at /)
```

### 6. Demo-day offline mode

After one online run, use the local cache:

```bash
OFFLINE=1 python -m backend.main corpus/*/package-lock.json
OFFLINE=1 uvicorn backend.main:app --port 8000
```

### 7. Background daemon

```bash
python -m backend.daemon --corpus corpus --interval 300
```

---

## API Endpoints

| Method | Path | Description |
|--------|------|-------------|
| `GET` | `/` | Dashboard (React build or fallback HTML) |
| `GET` | `/api/summary` | High-level scan summary |
| `GET` | `/api/blast?q=CVE-XXXX` | Blast radius for one CVE / OSV id |
| `GET` | `/api/top?n=25` | Top N findings by risk score |
| `GET` | `/api/projects` | Per-project finding counts |
| `GET` | `/api/patch?project=&n=30` | Ordered patch plan with tiers |
| `GET` | `/api/brief?cve=&project=` | Evidence-backed incident brief |
| `GET` | `/api/brief/top` | Brief for highest-risk finding |
| `POST`| `/api/scan` | Trigger pipeline from the UI |
| `GET` | `/docs` | Interactive FastAPI documentation |

---

## Risk Score Formula

```
exploit_signal = 1.0 if CVE is in CISA KEV else EPSS probability
runtime_factor = 0.4 for dev-only dependencies, otherwise 1.0
risk = 100 × (CVSS / 10) × (0.2 + 0.8 × exploit_signal) × runtime_factor
```

This is a **transparent prototype heuristic, not a security standard.**
CVSS, EPSS, KEV flag, and dev/prod proxy are always shown beside the score.

---

## Action Tiers

| Tier | Condition | What happens |
|------|-----------|--------------|
| `AUTO` | Low risk, same-major fix | Temp-copy re-scan queued (human still approves) |
| `REVIEW` | Fix available but needs override | Proposed fix shown; human must apply |
| `ESCALATE` | No fix, major jump, or malicious | Incident brief only; no auto-change |

A clean re-scan is NOT proof that functional tests pass. Hyron AI never deploys to production.

---

## Project Structure

```
Fusion2K26/
├── backend/
│   ├── main.py               # FastAPI app + pipeline entry point
│   ├── daemon.py             # Background file-watcher + scheduler
│   ├── triage.py             # CVE grouping + tier assignment
│   ├── make_corpus.py        # Sample npm corpus generator
│   ├── requirements.txt
│   ├── .env
│   ├── routes/
│   │   ├── scan.py           # POST /api/scan
│   │   ├── graph.py          # GET /api/summary, /blast, /top, /projects
│   │   └── reports.py        # GET /api/patch, /brief
│   ├── services/
│   │   ├── manifest_parser.py       # lockfile → NetworkX graph
│   │   ├── vulnerability_scanner.py # OSV + EPSS + KEV lookups
│   │   ├── risk_engine.py           # risk formula + tier logic
│   │   ├── patch_planner.py         # semver-aware patch plan
│   │   ├── dependency_graph.py      # graph utils + Cytoscape serialiser
│   │   └── ai_explainer.py          # incident brief generator
│   └── schemas/
│       └── scan_result.py    # Pydantic models
├── frontend/
│   ├── package.json
│   ├── vite.config.js
│   ├── index.html
│   └── src/
│       ├── App.jsx
│       ├── api.js            # fetch wrapper for all endpoints
│       ├── index.css
│       ├── pages/
│       │   └── Dashboard.jsx # main dashboard page
│       └── components/
│           ├── SummaryCards.jsx
│           ├── UploadPanel.jsx
│           ├── RiskTable.jsx
│           ├── DependencyGraph.jsx  # Cytoscape.js graph
│           └── PatchPlan.jsx
├── sample_data/              # example inputs (npm, pip, maven)
├── tests/
│   ├── test_parser.py        # manifest parser unit tests
│   ├── test_scanner.py       # risk engine unit tests
│   └── test_graph.py         # patch planner unit tests
├── .gitignore
└── README.md
```

---

## Tech Stack

| Layer | Tech | Why |
|-------|------|-----|
| Backend | Python · FastAPI | Graph/data problem; no GPU needed. FastAPI gives validated REST + `/docs`. |
| Graph | NetworkX | Directed graph for direct/transitive path tracing and blast radius. |
| Vuln data | OSV.dev | Advisories, affected ranges, fixed versions. |
| Exploit signals | FIRST EPSS · CISA KEV | Exploit probability and known-exploitation evidence. |
| Frontend | React · Cytoscape.js | Interactive dependency graph + dashboard. |
| Daemon | watchdog | Cross-platform file-system events for lockfile change detection. |
| Cache | Disk JSON | Offline/demo-day operation; last-updated time shown. |

---

## Dataset & Reference: OSV.dev

Hyron AI uses **[OSV.dev](https://osv.dev/)** (Open Source Vulnerabilities database by Google and the OpenSSF) as its primary dataset and vulnerability intelligence reference.

- **Batch Vulnerability Detection**: Queries `POST https://api.osv.dev/v1/querybatch` with resolved `(package, version)` tuples from dependency lockfiles.
- **Advisory Details**: Queries `GET https://api.osv.dev/v1/vulns/{id}` to extract:
  - Aliases (CVE, GHSA)
  - CVSS v3 severity vectors and database-specific severities
  - Affected semver version ranges and exact `fixed` version events
  - Advisory summaries and descriptions
- **Canonical Portal Links**: Findings link directly to `https://osv.dev/vulnerability/{id}` in the dashboard for instant engineer inspection.
- **Offline Resilience & Caching**: All OSV records are cached locally in `.osv_cache.json` ensuring demo-day reliability even without internet connectivity (`OFFLINE=1`).

---

## Limitations (Honest)

- **npm only** in this MVP. PyPI (pip) and Maven (pom.xml) need ecosystem-specific resolvers.
- "Affected" means the vulnerable version is present in the resolved tree — not that the vulnerable code path is reachable.
- Risk score is a configurable heuristic. Show it as evidence, not as a guarantee.
- Corpus is **generated**. Lockfiles, dependency trees, and CVE data are real when fetched live.
- A clean re-scan does not confirm that functional tests pass.

---

## Demo Checklist

1. Run one online scan to populate `.osv_cache.json`; then test `OFFLINE=1`.
2. Start FastAPI, verify `/`, `/api/summary`, `/api/blast`, `/api/top`, `/api/patch`.
3. Show one real finding and its dependency path; state whether the corpus is synthetic.
4. Show the highest-priority findings and the evidence that makes them urgent.
5. Show patch targets and state explicitly: "target version ≠ verified production-safe change."
6. Do NOT claim the solution passed tests unless you actually ran them.

---

## Credits

OSV.dev · FIRST.org EPSS · CISA KEV · NetworkX · cvss · FastAPI · Cytoscape.js · React · Vite
