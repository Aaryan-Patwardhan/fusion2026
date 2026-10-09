/**
 * RiskTable.jsx — Blast-radius results table for one CVE query.
 * Shows affected projects, risk score, CISA KEV flag, direct/transitive, path, and fix.
 * Clicking a row selects it and triggers the dependency graph draw.
 * Hyron AI · FUSION 2026 · CSB-03
 */

function riskClass(risk) {
  if (risk >= 70) return 'risk-high';
  if (risk >= 30) return 'risk-medium';
  return 'risk-low';
}

export default function RiskTable({ results = [], query, selectedProject, onSelect }) {
  if (!query) return null;

  return (
    <div className="card" style={{ flex: '1.2' }}>
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 8 }}>
        <h2 style={{ margin: 0 }}>{query}: {results.length} project(s) affected</h2>
        <a
          href={results[0]?.osv_url || `https://osv.dev/vulnerability/${query}`}
          target="_blank"
          rel="noopener noreferrer"
          style={{ fontSize: 12, color: 'var(--acc)', textDecoration: 'none' }}
        >
          View on OSV.dev ↗
        </a>
      </div>
      <div className="scroll-x">
        <table>
          <thead>
            <tr>
              <th>Project</th>
              <th>Risk</th>
              <th>Type</th>
              <th>Via (direct parent)</th>
              <th>Fix</th>
            </tr>
          </thead>
          <tbody>
            {results.map((r, i) => (
              <tr
                key={r.project}
                onClick={() => onSelect(r)}
                style={{
                  cursor: 'pointer',
                  background: r.project === selectedProject ? '#18273a' : undefined,
                }}
              >
                <td><strong>{r.project}</strong></td>
                <td><span className={riskClass(r.risk)}><strong>{r.risk}</strong></span></td>
                <td>
                  {r.direct
                    ? <span className="pill pill-direct">direct</span>
                    : <span className="pill">transitive</span>}
                  {r.kev && <> <span className="pill pill-kev">KEV</span></>}
                </td>
                <td>
                  <code>{r.via?.[0] || '—'}</code>
                </td>
                <td>
                  {r.fixed?.length
                    ? <code>{r.fixed.slice(0, 2).join(', ')}</code>
                    : <span style={{ color: 'var(--bad)' }}>No fix</span>}
                </td>
              </tr>
            ))}
            {results.length === 0 && (
              <tr><td colSpan={5} style={{ color: 'var(--mut)', textAlign: 'center', padding: 24 }}>
                No affected projects found.
              </td></tr>
            )}
          </tbody>
        </table>
      </div>
    </div>
  );
}
