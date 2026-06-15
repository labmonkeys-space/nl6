/*
 * Copyright 2026 Ronny Trommer <ronny@no42.org>
 * SPDX-License-Identifier: Apache-2.0
 *
 * Node test for the pure topology-visualization logic. No framework — run
 * with `node topology_logic.test.js`. Covers model building, deterministic
 * layout, structure/state diffing, click-to-flap target resolution, and the
 * scale guard. The DOM/sigma glue (app_topology.js) is verified in a browser.
 */
'use strict';
const assert = require('node:assert');
const T = require('./topology_logic.js');

// Sample /topology/graph response: 3 devices, 2 links, one inactive.
const sample = {
  nodes: [
    { ip: '10.0.0.1', sysName: 'core1', type: 'Cisco CRS-X', degree: 1 },
    { ip: '10.0.0.2', sysName: 'spine1', type: 'Arista 7280R3', degree: 2 },
    { ip: '10.0.0.3', degree: 1, missing: true }
  ],
  edges: [
    { a: { ip: '10.0.0.1', ifindex: 1, ifName: 'Hu0/1' }, b: { ip: '10.0.0.2', ifindex: 2, ifName: 'Eth1' }, active: true },
    { a: { ip: '10.0.0.2', ifindex: 3 }, b: { ip: '10.0.0.3', ifindex: 1 }, active: false, downEnd: 'b' }
  ]
};

let pass = 0;
function ok(name, fn) { fn(); pass++; console.log('  ok -', name); }

ok('buildModel maps nodes/edges and flags missing', () => {
  const m = T.buildModel(sample);
  assert.strictEqual(m.nodes.length, 3);
  assert.strictEqual(m.edges.length, 2);
  assert.strictEqual(m.nodeIndex['10.0.0.3'].missing, true);
  assert.match(m.nodes[0].label, /core1.*Cisco CRS-X/);
  // Missing node falls back to ip-as-label.
  assert.match(m.nodeIndex['10.0.0.3'].label, /10\.0\.0\.3/);
});

ok('edgeKey / structureKey are stable and order-independent', () => {
  const m = T.buildModel(sample);
  const k1 = T.structureKey(m);
  // Reverse the arrays → same structure key (sorted internally).
  const rev = T.buildModel({ nodes: [...sample.nodes].reverse(), edges: [...sample.edges].reverse() });
  assert.strictEqual(T.structureKey(rev), k1);
});

ok('structureKey changes on add/remove, NOT on state flip', () => {
  const m = T.buildModel(sample);
  const base = T.structureKey(m);
  // Flip the active state of an edge → structure unchanged.
  const flipped = JSON.parse(JSON.stringify(sample));
  flipped.edges[0].active = false; flipped.edges[0].downEnd = 'a';
  assert.strictEqual(T.structureKey(T.buildModel(flipped)), base);
  // Add a node+edge → structure changes.
  const grown = JSON.parse(JSON.stringify(sample));
  grown.nodes.push({ ip: '10.0.0.4', sysName: 'leaf1', degree: 1 });
  grown.edges.push({ a: { ip: '10.0.0.2', ifindex: 4 }, b: { ip: '10.0.0.4', ifindex: 1 }, active: true });
  assert.notStrictEqual(T.structureKey(T.buildModel(grown)), base);
});

ok('forceLayout is deterministic and produces finite, in-bounds coords', () => {
  const m = T.buildModel(sample);
  const a = T.forceLayout(m, { width: 800, height: 600, seed: 42, iterations: 60 });
  const b = T.forceLayout(m, { width: 800, height: 600, seed: 42, iterations: 60 });
  assert.deepStrictEqual(a, b, 'same seed → identical layout');
  for (const id of Object.keys(a)) {
    assert.ok(Number.isFinite(a[id].x) && Number.isFinite(a[id].y), 'finite');
    assert.ok(a[id].x >= 0 && a[id].x <= 800 && a[id].y >= 0 && a[id].y <= 600, 'in bounds');
  }
  // Different seed → different placement (very high probability).
  const c = T.forceLayout(m, { width: 800, height: 600, seed: 7, iterations: 60 });
  assert.notDeepStrictEqual(a, c);
});

ok('forceLayout handles 0 and 1 node', () => {
  assert.deepStrictEqual(T.forceLayout(T.buildModel({ nodes: [], edges: [] }), {}), {});
  const one = T.forceLayout(T.buildModel({ nodes: [{ ip: '10.0.0.9', degree: 0 }], edges: [] }), { width: 100, height: 100 });
  assert.deepStrictEqual(one['10.0.0.9'], { x: 50, y: 50 });
});

ok('edgeToggleOps: active → down A; inactive → both up', () => {
  const m = T.buildModel(sample);
  const activeEdge = m.edges[0];
  const down = T.edgeToggleOps(activeEdge);
  assert.deepStrictEqual(down, [{ ip: '10.0.0.1', ifindex: 1, status: 'DOWN' }]);
  const inactiveEdge = m.edges[1];
  const up = T.edgeToggleOps(inactiveEdge);
  assert.strictEqual(up.length, 2);
  assert.ok(up.every(o => o.status === 'UP'));
});

ok('nodeFailOps downs every incident local interface of the device', () => {
  const m = T.buildModel(sample);
  // 10.0.0.2 is the hub: a-side of edge0? no — it is b on edge0 (ifindex 2) and a on edge1 (ifindex 3).
  const ops = T.nodeFailOps(m, '10.0.0.2');
  assert.strictEqual(ops.length, 2);
  assert.ok(ops.every(o => o.ip === '10.0.0.2' && o.status === 'DOWN'));
  const ifs = ops.map(o => o.ifindex).sort();
  assert.deepStrictEqual(ifs, [2, 3]);
});

ok('scaleDecision respects 500/2000 caps', () => {
  assert.strictEqual(T.scaleDecision(12, 18).render, true);
  assert.strictEqual(T.scaleDecision(500, 2000).render, true);
  assert.strictEqual(T.scaleDecision(501, 100).render, false);
  assert.strictEqual(T.scaleDecision(100, 2001).render, false);
});

console.log(`\n${pass} checks passed.`);
