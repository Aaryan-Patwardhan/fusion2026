/**
 * RiskTable.jsx — Blast-radius results table for one CVE query.
 * Shows affected projects, risk score, CISA KEV flag, direct/transitive, path, and fix.
 * Includes tooltips on security jargon and an expandable "Why this score?" calculation view.
 * Hyron AI · FUSION 2026 · CSB-03
 */

import React, { useState } from 'react';

function riskClass(risk) {
  if (risk >= 70) return 'risk-high';
  if (risk >= 30) return 'risk-medium';
  return 'risk-low';
}

export default function RiskTable({ results = [], query, selectedProject, onSelect }) {
  const [expandedRow, setExpandedRow] = useState(null);

  if (!query) {
    return (
      <div className="card" style={{ flex: '1.2', textAlign: 'center', color: 'var(--mut)', padding: 32 }}>
        Enter a CVE or advisory ID above to view affected projects and blast radius.
      </div>
    );
  }

  function toggleWhy(e, index) {
    e.stopPropagation();
    setExpandedRow(expandedRow === index ? null : index);
  }

  return (
    <div className="card" style={{ flex: '1.2' }}>
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 8 }}>
        <h2 style={{ margin: 0 }}>{query}: {results.length} project(s) affected</h2>
        <a
          href={results[0]?.osv_url || `https://osv.dev/vulnerability/${query}`}
          target="_blank"
          rel="noopener noreferrer"
          style={{ fontSize: 12, color: 'var(--acc)', textDecoration: 'none' }}
          title="Open official advisory record on OSV.dev"
        >
          View on OSV.dev ↗
        </a>
      </div>
      <div className="scroll-x">
        <table>
          <thead>
            <tr>
              <th>Project</th>
              <th title="Explainable risk score (0–100) combining CVSS severity, EPSS/KEV exploit likelihood, and runtime factor.">
                Risk (?)
              </th>
              <th title="Dependency relationship: direct (declared in package.json) or transitive (nested down tree).">
                Type (?)
              </th>
              <th>Via (direct parent)</th>
              <th>Fix</th>
              <th>Score Details</th>
            </tr>
          </thead>
          <tbody>
            {results.map((r, i) => {
              const exploitVal = r.kev ? 1.0 : (r.epss ? Number(r.epss) : 0.0);
              const exploitLabel = r.kev ? '1.0 (CISA KEV)' : `${exploitVal.toFixed(3)} (EPSS)`;
              const runtimeVal = r.dev ? 0.4 : 1.0;
              const runtimeLabel = r.dev ? '0.4 (dev-only)' : '1.0 (production)';

              return (
                <React.Fragment key={r.project}>
                  <tr
                    onClick={() => onSelect(r)}
                    style={{
                      cursor: 'pointer',
                      background: r.project === selectedProject ? '#18273a' : undefined,
                    }}
                  >
                    <td><strong>{r.project}</strong></td>
                    <td>
                      <span className={riskClass(r.risk)}>
                        <strong>{r.risk}</strong>
                      </span>
                    </td>
                    <td>
                      {r.direct ? (
                        <span
                          className="pill pill-direct"
                          title="Direct dependency declared explicitly in project package.json."
                        >
                          direct
                        </span>
                      ) : (
                        <span
                          className="pill"
                          title="Transitive dependency inherited through another package."
                        >
                          transitive
                        </span>
                      )}
                      {r.kev && (
                        <>
                          {' '}
                          <span
                            className="pill pill-kev"
                            title="CISA KEV: Confirmed actively exploited in the wild by adversaries."
                          >
                            KEV
                          </span>
                        </>
                      )}
                    </td>
                    <td>
                      <code>{r.via?.[0] || '—'}</code>
                    </td>
                    <td>
                      {r.fixed?.length ? (
                        <code>{r.fixed.slice(0, 2).join(', ')}</code>
                      ) : (
                        <span style={{ color: 'var(--bad)' }}>No fix</span>
                      )}
                    </td>
                    <td>
                      <button
                        type="button"
                        onClick={(e) => toggleWhy(e, i)}
                        style={{
                          background: 'transparent',
                          border: '1px solid var(--line)',
                          borderRadius: 4,
                          color: 'var(--mut)',
                          cursor: 'pointer',
                          fontSize: 11,
                          padding: '2px 6px',
                        }}
                      >
                        {expandedRow === i ? 'Hide' : 'Why this score?'}
                      </button>
                    </td>
                  </tr>
                  {expandedRow === i && (
                    <tr style={{ background: '#0e1620' }}>
                      <td colSpan={6} style={{ padding: '10px 14px', fontSize: 12 }}>
                        <div style={{ color: 'var(--acc)', fontWeight: 600, marginBottom: 4 }}>
                          Score Breakdown for {r.project} ({query}):
                        </div>
                        <div style={{ color: 'var(--tx)', fontFamily: 'monospace', fontSize: 12 }}>
                          Risk = 100 × (CVSS / 10) × (0.2 + 0.8 × Exploit Signal) × Runtime Factor
                        </div>
                        <div style={{ color: 'var(--mut)', marginTop: 4 }}>
                          = 100 × ({r.cvss ?? '5.0'} / 10) × (0.2 + 0.8 × {exploitLabel}) × {runtimeLabel}
                          {' = '}
                          <strong style={{ color: 'var(--tx)' }}>{r.risk}</strong>
                        </div>
                        <div style={{ color: 'var(--mut)', fontSize: 11, marginTop: 4 }}>
                          CVSS: {r.cvss ?? 'N/A'} (severity) | EPSS: {r.epss ? (r.epss * 100).toFixed(1) + '%' : 'N/A'} (exploit likelihood) | KEV: {r.kev ? 'Yes' : 'No'}
                        </div>
                      </td>
                    </tr>
                  )}
                </React.Fragment>
              );
            })}
            {results.length === 0 && (
              <tr>
                <td colSpan={6} style={{ color: 'var(--mut)', textAlign: 'center', padding: 24 }}>
                  No affected projects found for &quot;{query}&quot;.
                </td>
              </tr>
            )}
          </tbody>
        </table>
      </div>
    </div>
  );
}
