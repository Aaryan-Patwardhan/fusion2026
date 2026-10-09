/**
 * SummaryCards.jsx — Top-level stat tiles for the Hyron AI dashboard.
 * Shows: projects scanned, total findings, CISA KEV hits, direct/transitive split.
 * Hyron AI · FUSION 2026 · CSB-03
 */

export default function SummaryCards({ summary }) {
  if (!summary) return null;

  const tiles = [
    {
      value: summary.projects,
      label: 'Projects',
      tooltip: 'Total number of repository projects analyzed in the workspace.',
    },
    {
      value: summary.findings,
      label: 'Findings',
      tooltip: 'Total vulnerability instances detected across all dependency paths.',
    },
    {
      value: summary.kev,
      label: 'CISA KEV',
      tooltip: 'CISA Known Exploited Vulnerabilities: confirmed actively weaponized in the wild.',
    },
    {
      value: summary.direct,
      label: 'Direct',
      tooltip: 'Direct dependencies explicitly declared in project package.json.',
    },
    {
      value: summary.transitive,
      label: 'Transitive',
      tooltip: 'Transitive dependencies inherited through other packages down the dependency tree.',
    },
  ];

  return (
    <div className="tiles">
      {tiles.map(({ value, label, tooltip }) => (
        <div key={label} className="card tile" title={tooltip}>
          <span className="value">{value}</span>
          <span className="label">{label}</span>
        </div>
      ))}
    </div>
  );
}
