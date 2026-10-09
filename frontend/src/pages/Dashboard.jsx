/**
 * Dashboard.jsx — Main Hyron AI dashboard page.
 *
 * Layout:
 *   Header + summary tiles
 *   CVE search bar  (UploadPanel)
 *   [Blast-radius table] [Dependency graph]
 *   Patch plan table
 *   Incident brief panel
 *
 * Hyron AI · FUSION 2026 · CSB-03
 */

import { useState, useEffect } from 'react';
import { api } from '../api.js';
import SummaryCards   from '../components/SummaryCards.jsx';
import UploadPanel    from '../components/UploadPanel.jsx';
import RiskTable      from '../components/RiskTable.jsx';
import DependencyGraph from '../components/DependencyGraph.jsx';
import PatchPlan      from '../components/PatchPlan.jsx';

export default function Dashboard() {
  const [summary,         setSummary]         = useState(null);
  const [blastResults,    setBlastResults]     = useState([]);
  const [currentQuery,    setCurrentQuery]     = useState('');
  const [selectedResult,  setSelectedResult]   = useState(null);
  const [patchPlan,       setPatchPlan]        = useState([]);
  const [brief,           setBrief]            = useState(null);
  const [error,           setError]            = useState(null);
  const [loading,         setLoading]          = useState(false);

  // Load summary + full patch plan on mount
  useEffect(() => {
    api.summary()
      .then(s => {
        setSummary(s);
        // Auto-search first vuln for demo-day
        if (s.vulns?.length) handleSearch(s.vulns[0]);
      })
      .catch(e => setError('Could not load summary. Is the pipeline run? ' + e.message));

    api.patch(null, 50)
      .then(setPatchPlan)
      .catch(() => {});
  }, []);

  async function handleSearch(q) {
    setCurrentQuery(q);
    setSelectedResult(null);
    setBrief(null);
    setLoading(true);
    setError(null);
    try {
      const data = await api.blast(q);
      setBlastResults(data.results || []);
      if (data.results?.length) {
        setSelectedResult(data.results[0]);
        loadBrief(q, data.results[0].project);
        loadPatch(data.results[0].project);
      }
    } catch (e) {
      setError(`No results for "${q}". ${e.message}`);
      setBlastResults([]);
    } finally {
      setLoading(false);
    }
  }

  function handleSelectRow(result) {
    setSelectedResult(result);
    loadBrief(currentQuery, result.project);
    loadPatch(result.project);
  }

  function loadPatch(project) {
    api.patch(project, 30).then(setPatchPlan).catch(() => {});
  }

  function loadBrief(cve, project) {
    api.brief({ cve, project })
      .then(b => setBrief(b))
      .catch(() => setBrief(null));
  }

  return (
    <div style={{ maxWidth: 1400, margin: '0 auto', padding: '20px 16px' }}>
      {/* Header */}
      <h1>Hyron AI</h1>
      <p style={{ color: 'var(--mut)', margin: '0 0 16px' }}>
        Local-first dependency incident daemon — Watch · Map · Prioritise · Act
        <span style={{ marginLeft: 12, fontSize: 11, background: 'var(--card)', border: '1px solid var(--line)', borderRadius: 99, padding: '1px 10px' }}>
          FUSION 2026 · CSB-03
        </span>
        <a
          href="https://osv.dev"
          target="_blank"
          rel="noopener noreferrer"
          style={{ marginLeft: 8, fontSize: 11, background: 'var(--card)', border: '1px solid var(--line)', borderRadius: 99, padding: '1px 10px', color: 'var(--acc)' }}
        >
          Dataset: OSV.dev ↗
        </a>
      </p>

      {/* Summary */}
      {summary && <div style={{ marginBottom: 12 }}><SummaryCards summary={summary} /></div>}

      {/* Search */}
      <UploadPanel
        vulns={summary?.vulns || []}
        onSearch={handleSearch}
      />

      {/* Error */}
      {error && (
        <div className="card" style={{ marginBottom: 12, borderColor: 'var(--bad)', color: 'var(--bad)' }}>
          {error}
        </div>
      )}

      {/* Blast radius + graph */}
      {currentQuery && (
        <div style={{ display: 'flex', gap: 12, marginBottom: 0, flexWrap: 'wrap' }}>
          <RiskTable
            results={blastResults}
            query={currentQuery}
            selectedProject={selectedResult?.project}
            onSelect={handleSelectRow}
          />
          <DependencyGraph blastResult={selectedResult} />
        </div>
      )}

      {/* Patch plan */}
      <PatchPlan plan={patchPlan} project={selectedResult?.project} />

      {/* Incident brief */}
      {brief && (
        <div className="card" style={{ marginTop: 12 }}>
          <h2>Incident Brief</h2>
          <pre style={{
            whiteSpace: 'pre-wrap', margin: 0, fontFamily: 'inherit',
            fontSize: 13, color: 'var(--tx)', lineHeight: 1.6,
          }}>
            {brief.brief}
          </pre>
          {brief.disclaimer && (
            <p style={{ color: 'var(--mut)', fontSize: 11, marginTop: 10, borderTop: '1px solid var(--line)', paddingTop: 8 }}>
              ⚠ {brief.disclaimer}
            </p>
          )}
        </div>
      )}
    </div>
  );
}
