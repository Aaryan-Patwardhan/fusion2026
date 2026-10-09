/**
 * SummaryCards.jsx — Top-level stat tiles for the Hyron AI dashboard.
 * Shows: projects scanned, total findings, CISA KEV hits, direct/transitive split.
 * Hyron AI · FUSION 2026 · CSB-03
 */

export default function SummaryCards({ summary }) {
  if (!summary) return null;

  const tiles = [
    { value: summary.projects,    label: 'Projects' },
    { value: summary.findings,    label: 'Findings' },
    { value: summary.kev,         label: 'CISA KEV' },
    { value: summary.direct,      label: 'Direct' },
    { value: summary.transitive,  label: 'Transitive' },
  ];

  return (
    <div className="tiles">
      {tiles.map(({ value, label }) => (
        <div key={label} className="card tile">
          <span className="value">{value}</span>
          <span className="label">{label}</span>
        </div>
      ))}
    </div>
  );
}
