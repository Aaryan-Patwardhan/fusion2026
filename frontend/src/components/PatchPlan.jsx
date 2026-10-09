/**
 * PatchPlan.jsx — Ordered remediation plan table.
 * Shows: order, project, package, current → target, risk removed, tier, action command.
 *
 * Action tiers:
 *   AUTO     = low-risk, same-major fix, temp-copy re-scan queued
 *   REVIEW   = fix exists but requires human approval
 *   ESCALATE = major jump, no fix, or malicious/ambiguous — do NOT auto-change
 *
 * Hyron AI · FUSION 2026 · CSB-03
 */

function tierPill(tier) {
  const cls = `pill pill-${tier?.toLowerCase()}`;
  let tooltip = '';
  if (tier === 'AUTO') {
    tooltip = 'AUTO: Low risk, same-major fix. Automatically validated in temp copy via lockfile re-scan.';
  } else if (tier === 'REVIEW') {
    tooltip = 'REVIEW: Fix exists but requires override or constraint change. Requires human approval.';
  } else if (tier === 'ESCALATE') {
    tooltip = 'ESCALATE: Major version bump, no published fix, or ambiguous resolution. Manual decision needed.';
  }

  return (
    <span className={cls} title={tooltip} style={{ cursor: 'help' }}>
      {tier}
    </span>
  );
}

export default function PatchPlan({ plan = [], project }) {
  const filtered = project ? plan.filter(p => p.project === project) : plan;

  return (
    <div className="card" style={{ marginTop: 12 }}>
      <h2>
        Patch Order — Highest Risk Removed First
        {project && <span style={{ color: 'var(--acc)', marginLeft: 8 }}>({project})</span>}
      </h2>
      <div className="scroll-x">
        <table>
          <thead>
            <tr>
              <th>#</th>
              <th>Project</th>
              <th>Package</th>
              <th>Fix To</th>
              <th title="Total risk points eliminated by applying this upgrade target.">
                Risk Removed (?)
              </th>
              <th title="Policy gate tier: AUTO (safe low-risk), REVIEW (needs approval), or ESCALATE (breaking/no fix).">
                Tier (?)
              </th>
              <th>Action Command</th>
            </tr>
          </thead>
          <tbody>
            {filtered.map(p => (
              <tr key={`${p.project}-${p.package}-${p.order}`}>
                <td style={{ color: 'var(--mut)' }}>{p.order}</td>
                <td>{p.project}</td>
                <td>
                  <code>{p.package}@{p.current}</code>
                </td>
                <td>
                  {p.target
                    ? <code style={{ color: 'var(--acc)' }}>{p.target}</code>
                    : <span style={{ color: 'var(--bad)' }}>—</span>}
                </td>
                <td style={{ color: p.risk_removed >= 70 ? 'var(--bad)' : p.risk_removed >= 30 ? 'var(--warn)' : 'var(--acc)' }}>
                  <strong>{p.risk_removed}</strong>
                </td>
                <td>{tierPill(p.tier)}</td>
                <td style={{ maxWidth: 360 }}>
                  <code style={{ fontSize: 11 }}>{p.action}</code>
                </td>
              </tr>
            ))}
            {filtered.length === 0 && (
              <tr>
                <td colSpan={7} style={{ color: 'var(--mut)', textAlign: 'center', padding: 24 }}>
                  No patch plan entries available. Run the scan pipeline to generate remediation plan.
                </td>
              </tr>
            )}
          </tbody>
        </table>
      </div>
      <p style={{ color: 'var(--mut)', fontSize: 11, marginTop: 8 }}>
        ⚠ AUTO tier queues a temp-copy re-scan only. It does NOT deploy to production.
        A clean re-scan is not proof that functional tests pass.
        Human approval is always required before merging.
      </p>
    </div>
  );
}
