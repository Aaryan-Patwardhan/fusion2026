/**
 * UploadPanel.jsx — CVE / OSV id search input for blast-radius lookup.
 * Hyron AI · FUSION 2026 · CSB-03
 */

import { useState } from 'react';

export default function UploadPanel({ vulns = [], onSearch }) {
  const [query, setQuery] = useState('');

  function handleSearch(e) {
    e.preventDefault();
    const q = query.trim();
    if (q) onSearch(q);
  }

  function handleSelect(e) {
    const q = e.target.value;
    setQuery(q);
    if (q) onSearch(q);
  }

  return (
    <div className="card" style={{ marginBottom: 12 }}>
      <h2>Search by CVE or Advisory ID</h2>
      <form onSubmit={handleSearch} style={{ display: 'flex', gap: 8 }}>
        <input
          type="text"
          value={query}
          onChange={e => setQuery(e.target.value)}
          placeholder="e.g. CVE-2024-45590 or GHSA-xxxx"
          list="vuln-list"
          autoComplete="off"
        />
        <datalist id="vuln-list">
          {vulns.map(v => <option key={v} value={v} />)}
        </datalist>
        <button
          type="submit"
          style={{
            padding: '9px 18px', borderRadius: 8, border: 'none',
            background: 'var(--acc)', color: '#0b1118', fontWeight: 700,
            cursor: 'pointer', whiteSpace: 'nowrap',
          }}
        >
          Blast Radius
        </button>
      </form>
      {vulns.length > 0 && (
        <div style={{ marginTop: 8 }}>
          <select onChange={handleSelect} defaultValue="" style={{ maxWidth: 360 }}>
            <option value="" disabled>Quick-select a known vulnerability…</option>
            {vulns.map(v => <option key={v} value={v}>{v}</option>)}
          </select>
        </div>
      )}
    </div>
  );
}
