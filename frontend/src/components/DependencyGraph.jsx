/**
 * DependencyGraph.jsx — Cytoscape.js graph for dependency path visualisation.
 * Renders the direct + transitive path from project nodes to the vulnerable package.
 *
 * Node colour legend:
 *   Blue   = project root
 *   Teal   = intermediate package
 *   Red    = vulnerable package
 *
 * Hyron AI · FUSION 2026 · CSB-03
 */

import { useEffect, useRef } from 'react';
import cytoscape from 'cytoscape';

const STYLE = [
  {
    selector: 'node',
    style: {
      label: 'data(id)',
      'font-size': 8,
      color: '#e6edf5',
      'text-valign': 'bottom',
      'text-margin-y': 4,
      'background-color': '#3dd6c6',
      width: 14,
      height: 14,
    },
  },
  {
    selector: 'node[type="root"]',
    style: { 'background-color': '#7aa2ff', width: 22, height: 22 },
  },
  {
    selector: 'node[type="bad"]',
    style: { 'background-color': '#ff5d5d', width: 22, height: 22 },
  },
  {
    selector: 'edge',
    style: {
      width: 1.5,
      'line-color': '#415a77',
      'target-arrow-color': '#415a77',
      'target-arrow-shape': 'triangle',
      'curve-style': 'bezier',
    },
  },
];

function buildElements(blastResult) {
  if (!blastResult) return [];

  const nodes = new Map();
  const edges = [];

  blastResult.paths.forEach((path) => {
    const ids = [blastResult.project, ...path.slice(1)];
    ids.forEach((label, i) => {
      const id = label;
      if (!nodes.has(id)) {
        const type =
          i === 0 ? 'root'
          : i === ids.length - 1 ? 'bad'
          : 'mid';
        nodes.set(id, type);
      }
      if (i > 0) {
        edges.push({ source: ids[i - 1], target: id });
      }
    });
  });

  return [
    ...[...nodes.entries()].map(([id, type]) => ({ data: { id, type } })),
    ...edges.map(({ source, target }, i) => ({ data: { id: `e${i}`, source, target } })),
  ];
}

export default function DependencyGraph({ blastResult }) {
  const containerRef = useRef(null);
  const cyRef = useRef(null);

  useEffect(() => {
    if (!containerRef.current) return;
    if (cyRef.current) cyRef.current.destroy();

    const elements = buildElements(blastResult);
    if (!elements.length) return;

    cyRef.current = cytoscape({
      container: containerRef.current,
      elements,
      style: STYLE,
      layout: {
        name: 'breadthfirst',
        directed: true,
        padding: 20,
        spacingFactor: 1.25,
      },
      userZoomingEnabled: true,
      userPanningEnabled: true,
    });

    return () => {
      if (cyRef.current) cyRef.current.destroy();
    };
  }, [blastResult]);

  return (
    <div className="card" style={{ flex: '1', minWidth: 0 }}>
      <h2>Dependency Path (click a project row)</h2>
      <div id="cy-container" ref={containerRef} />
      {!blastResult && (
        <p style={{ color: 'var(--mut)', textAlign: 'center', marginTop: 12 }}>
          Search for a CVE to see the dependency graph.
        </p>
      )}
    </div>
  );
}
