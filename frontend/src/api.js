/**
 * api.js — Hyron AI API client
 * All fetch calls to the FastAPI backend.
 * Hyron AI · FUSION 2026 · CSB-03
 */

const BASE = import.meta.env.VITE_API_BASE || '';

async function get(path) {
  const res = await fetch(`${BASE}${path}`);
  if (!res.ok) throw new Error(`API error ${res.status}: ${path}`);
  return res.json();
}

export const api = {
  /** High-level scan summary */
  summary: () => get('/api/summary'),

  /** Blast-radius for a specific CVE or OSV id */
  blast: (q) => get(`/api/blast?q=${encodeURIComponent(q)}`),

  /** Top N findings by risk score */
  top: (n = 25) => get(`/api/top?n=${n}`),

  /** Per-project overview */
  projects: () => get('/api/projects'),

  /** Ordered patch plan (optionally filtered to one project) */
  patch: (project = null, n = 30) => {
    const qs = project
      ? `?project=${encodeURIComponent(project)}&n=${n}`
      : `?n=${n}`;
    return get(`/api/patch${qs}`);
  },

  /** Evidence-backed incident brief */
  brief: ({ cve, project } = {}) => {
    const params = new URLSearchParams();
    if (cve)     params.set('cve', cve);
    if (project) params.set('project', project);
    const qs = params.toString() ? `?${params}` : '';
    return get(`/api/brief${qs}`);
  },

  /** Brief for the highest-risk finding */
  topBrief: () => get('/api/brief/top'),
};
