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
  // Label is the sysName only (type kept as a field, not appended).
  assert.strictEqual(m.nodes[0].label, 'core1');
  assert.strictEqual(m.nodes[0].type, 'Cisco CRS-X');
  // Missing node falls back to ip-as-label.
  assert.strictEqual(m.nodeIndex['10.0.0.3'].label, '10.0.0.3');
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

ok('needsRelayout: relayout on first render + structure change, recolor on state-only', () => {
  const base = T.structureKey(T.buildModel(sample));
  assert.strictEqual(T.needsRelayout(null, base), true, 'first render relayouts');
  assert.strictEqual(T.needsRelayout(base, base), false, 'unchanged structure → recolor');
  // State flip keeps the same structureKey → recolor (no relayout).
  const flipped = JSON.parse(JSON.stringify(sample));
  flipped.edges[0].active = false; flipped.edges[0].downEnd = 'a';
  assert.strictEqual(T.needsRelayout(base, T.structureKey(T.buildModel(flipped))), false);
  // Adding a node changes the key → relayout.
  const grown = JSON.parse(JSON.stringify(sample));
  grown.nodes.push({ ip: '10.0.0.4', sysName: 'leaf1', degree: 1 });
  grown.edges.push({ a: { ip: '10.0.0.2', ifindex: 4 }, b: { ip: '10.0.0.4', ifindex: 1 }, active: true });
  assert.strictEqual(T.needsRelayout(base, T.structureKey(T.buildModel(grown))), true);
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

ok('forceLayout fits the frame (binding dimension fills the usable area)', () => {
  const m = T.buildModel(sample);
  const w = 800, h = 600, mx = w * 0.08, my = h * 0.08;
  const p = T.forceLayout(m, { width: w, height: h, seed: 3 });
  const xs = Object.values(p).map(q => q.x), ys = Object.values(p).map(q => q.y);
  const xRange = Math.max(...xs) - Math.min(...xs);
  const yRange = Math.max(...ys) - Math.min(...ys);
  // Uniform scale → the tighter-fitting axis fills its usable span (~1.0).
  const fill = Math.max(xRange / (w - 2 * mx), yRange / (h - 2 * my));
  assert.ok(fill > 0.9, `layout fills the frame (got ${fill.toFixed(2)})`);
  // And every node stays within the margins.
  for (const id of Object.keys(p)) {
    assert.ok(p[id].x >= mx - 1 && p[id].x <= w - mx + 1, 'x within margins');
    assert.ok(p[id].y >= my - 1 && p[id].y <= h - my + 1, 'y within margins');
  }
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

ok('nodeIsDown / nodeRestoreOps reflect incident link state', () => {
  const m = T.buildModel(sample);
  // sample: edge0 (.1↔.2) active; edge1 (.2↔.3) inactive.
  assert.strictEqual(T.nodeIsDown(m, '10.0.0.2'), false, 'has an active incident link → up');
  assert.strictEqual(T.nodeIsDown(m, '10.0.0.3'), true, 'only incident link inactive → down');
  assert.strictEqual(T.nodeIsDown(m, '10.0.0.99'), false, 'no incident links → not down');
  const up = T.nodeRestoreOps(m, '10.0.0.2');
  assert.strictEqual(up.length, 2);
  assert.ok(up.every(o => o.ip === '10.0.0.2' && o.status === 'UP'));
  assert.deepStrictEqual(up.map(o => o.ifindex).sort(), [2, 3]);
});

ok('scaleDecision respects 500/2000 caps', () => {
  assert.strictEqual(T.scaleDecision(12, 18).render, true);
  assert.strictEqual(T.scaleDecision(500, 2000).render, true);
  assert.strictEqual(T.scaleDecision(501, 100).render, false);
  assert.strictEqual(T.scaleDecision(100, 2001).render, false);
});

// --- tieredLayout ----------------------------------------------------------

// Helper: count distinct y-bands and return the y for a given node id.
function tieredOf(graph, opts) {
  return T.tieredLayout(T.buildModel(graph), Object.assign({ width: 800, height: 600 }, opts || {}));
}

ok('tieredLayout: 5-stage-clos mix compacts to 4 ordered bands', () => {
  // Core router → DC switch → campus switch → server (the clos category mix).
  const g = {
    nodes: [
      { ip: '10.0.0.1', sysName: 'super1', type: 'Cisco CRS-X', degree: 1 },
      { ip: '10.0.0.2', sysName: 'spine1', type: 'Arista 7280R3', degree: 2 },
      { ip: '10.0.0.3', sysName: 'leaf1', type: 'Cisco Catalyst 9500', degree: 2 },
      { ip: '10.0.0.4', sysName: 'host1', type: 'Linux Server', degree: 1 }
    ],
    edges: [
      { a: { ip: '10.0.0.1', ifindex: 1 }, b: { ip: '10.0.0.2', ifindex: 1 }, active: true },
      { a: { ip: '10.0.0.2', ifindex: 2 }, b: { ip: '10.0.0.3', ifindex: 1 }, active: true },
      { a: { ip: '10.0.0.3', ifindex: 2 }, b: { ip: '10.0.0.4', ifindex: 1 }, active: true }
    ]
  };
  const pos = tieredOf(g);
  const ys = ['10.0.0.1', '10.0.0.2', '10.0.0.3', '10.0.0.4'].map(id => pos[id].y);
  const bands = [...new Set(ys)].sort((a, b) => a - b);
  assert.strictEqual(bands.length, 4, 'four distinct bands');
  // sigma is y-up: top tier = LARGEST y. Superspine highest → host lowest.
  assert.ok(ys[0] > ys[1] && ys[1] > ys[2] && ys[2] > ys[3], 'tiers ordered top→bottom');
});

ok('tieredLayout: a missing middle category leaves no empty band', () => {
  // Only ranks 0 (core) and 3 (campus) present → must compact to 2 bands.
  const g = {
    nodes: [
      { ip: '10.0.0.1', sysName: 'core1', type: 'Cisco CRS-X', degree: 1 },
      { ip: '10.0.0.2', sysName: 'acc1', type: 'Cisco Catalyst 9500', degree: 1 }
    ],
    edges: [{ a: { ip: '10.0.0.1', ifindex: 1 }, b: { ip: '10.0.0.2', ifindex: 1 }, active: true }]
  };
  const pos = tieredOf(g);
  const bands = [...new Set([pos['10.0.0.1'].y, pos['10.0.0.2'].y])];
  assert.strictEqual(bands.length, 2, 'two bands, no empty row between');
  // Mid-band of a 2-band layout sits at 1/4 and 3/4 of usable height — verify
  // the core band is the top one (y-up: larger y) and no third empty band.
  assert.ok(pos['10.0.0.1'].y > pos['10.0.0.2'].y, 'core above campus');
});

ok('tieredLayout: untyped node lands below its highest-tier neighbour', () => {
  // A typed core (rank 0) with an untyped neighbour → neighbour one band below.
  const g = {
    nodes: [
      { ip: '10.0.0.1', sysName: 'core1', type: 'Cisco CRS-X', degree: 1 },
      { ip: '10.0.0.2', degree: 1, missing: true } // no type
    ],
    edges: [{ a: { ip: '10.0.0.1', ifindex: 1 }, b: { ip: '10.0.0.2', ifindex: 1 }, active: true }]
  };
  const pos = tieredOf(g);
  // y-up: "below" the core means a smaller y than the core.
  assert.ok(pos['10.0.0.2'].y < pos['10.0.0.1'].y, 'untyped sits below the core, not at the top');
});

ok('tieredLayout is deterministic', () => {
  const g = {
    nodes: [
      { ip: '10.0.0.1', sysName: 'super1', type: 'Cisco CRS-X', degree: 1 },
      { ip: '10.0.0.2', sysName: 'spine1', type: 'Arista 7280R3', degree: 2 },
      { ip: '10.0.0.3', sysName: 'leaf1', type: 'Cisco Catalyst 9500', degree: 1 }
    ],
    edges: [
      { a: { ip: '10.0.0.1', ifindex: 1 }, b: { ip: '10.0.0.2', ifindex: 1 }, active: true },
      { a: { ip: '10.0.0.2', ifindex: 2 }, b: { ip: '10.0.0.3', ifindex: 1 }, active: true }
    ]
  };
  const a = tieredOf(g);
  const b = tieredOf(g);
  assert.deepStrictEqual(a, b, 'same model → identical layout');
  for (const id of Object.keys(a)) {
    assert.ok(Number.isFinite(a[id].x) && Number.isFinite(a[id].y), 'finite');
    assert.ok(a[id].x >= 0 && a[id].x <= 800 && a[id].y >= 0 && a[id].y <= 600, 'in bounds');
  }
});

ok('tieredLayout: barycenter ordering avoids the obvious crossing', () => {
  // Two same-band cores over two same-band servers, cross-wired (a–d, b–c).
  // Naive (sysName) order would cross; barycenter must align endpoints so
  // (x[a]-x[b]) and (x[d]-x[c]) share a sign (no crossing).
  const g = {
    nodes: [
      { ip: '10.0.0.1', sysName: 'a', type: 'Cisco CRS-X', degree: 1 },
      { ip: '10.0.0.2', sysName: 'b', type: 'Cisco ASR 9000', degree: 1 },
      { ip: '10.0.0.3', sysName: 'c', type: 'Linux Server', degree: 1 },
      { ip: '10.0.0.4', sysName: 'd', type: 'Dell PowerEdge R750', degree: 1 }
    ],
    edges: [
      { a: { ip: '10.0.0.1', ifindex: 1 }, b: { ip: '10.0.0.4', ifindex: 1 }, active: true },
      { a: { ip: '10.0.0.2', ifindex: 1 }, b: { ip: '10.0.0.3', ifindex: 1 }, active: true }
    ]
  };
  const pos = tieredOf(g);
  const crossMetric = (pos['10.0.0.1'].x - pos['10.0.0.2'].x) * (pos['10.0.0.4'].x - pos['10.0.0.3'].x);
  assert.ok(crossMetric > 0, 'edges a–d and b–c do not cross after barycenter');
});

ok('tieredLayout handles 0 and 1 node', () => {
  assert.deepStrictEqual(T.tieredLayout(T.buildModel({ nodes: [], edges: [] }), {}), {});
  const one = T.tieredLayout(T.buildModel({ nodes: [{ ip: '10.0.0.9', degree: 0 }], edges: [] }), { width: 100, height: 100 });
  assert.deepStrictEqual(one['10.0.0.9'], { x: 50, y: 50 });
});

// --- Clos fabric generator -------------------------------------------------

ok('buildClosFabric: k=20 parity with gen-clos.py (2500 devices, 6000 links)', () => {
  const f = T.buildClosFabric(20, '10.42.0.0/16');
  const byKey = Object.fromEntries(f.tiers.map(t => [t.key, t]));
  assert.strictEqual(byKey.core.count, 100, 'core (k/2)^2');
  assert.strictEqual(byKey.agg.count, 200, 'agg k*k/2');
  assert.strictEqual(byKey.edge.count, 200, 'edge k*k/2');
  assert.strictEqual(byKey.host.count, 2000, 'hosts k^3/4');
  const devices = f.tiers.reduce((s, t) => s + t.count, 0);
  assert.strictEqual(devices, 2500, 'total devices');
  assert.strictEqual(f.links.length, 6000, 'total links');
  // closCounts agrees with the built fabric.
  const c = T.closCounts(20);
  assert.strictEqual(c.devices, 2500);
  assert.strictEqual(c.links, 6000);
});

ok('buildClosFabric: per-relationship link counts each equal k*(k/2)^2', () => {
  const k = 8, half = k / 2, expect = k * half * half; // 8*16 = 128 each
  const f = T.buildClosFabric(k, '10.42.0.0/16');
  // Bucket links by which tier-pair they connect, via the fixed tier bases.
  const base = ip => {
    const o = T.ipToInt(ip) - T.ipToInt('10.42.0.0');
    if (o >= 4097) return 'host'; if (o >= 2049) return 'edge';
    if (o >= 1025) return 'agg'; return 'core';
  };
  const tally = {};
  f.links.forEach(l => {
    const pair = [base(l.a.ip), base(l.b.ip)].sort().join('-');
    tally[pair] = (tally[pair] || 0) + 1;
  });
  assert.strictEqual(tally['agg-edge'], expect, 'edge↔agg');
  assert.strictEqual(tally['agg-core'], expect, 'agg↔core');
  assert.strictEqual(tally['edge-host'], expect, 'edge↔host');
  assert.strictEqual(f.links.length, 3 * expect, 'three relationships');
});

ok('closKError: even 2..32 accepted; odd / <2 / >32 / non-int rejected', () => {
  assert.strictEqual(T.closKError(2), null);
  assert.strictEqual(T.closKError(20), null);
  assert.strictEqual(T.closKError(32), null);
  assert.ok(T.closKError(0), 'k=0 rejected');
  assert.ok(T.closKError(1), 'k<2 rejected');
  assert.ok(T.closKError(21), 'odd rejected');
  assert.ok(T.closKError(34), 'k>32 rejected');
  assert.ok(T.closKError(4.5), 'non-integer rejected');
  // buildClosFabric throws on an invalid k.
  assert.throws(() => T.buildClosFabric(21, '10.42.0.0/16'), /even/);
  assert.throws(() => T.buildClosFabric(34, '10.42.0.0/16'), /<= 32/);
});

ok('buildClosFabric is deterministic (same k+subnet → identical output)', () => {
  const a = T.buildClosFabric(8, '10.42.0.0/16');
  const b = T.buildClosFabric(8, '10.42.0.0/16');
  assert.deepStrictEqual(a, b, 'byte-identical tiers + links');
});

ok('buildClosFabric: tier start IPs + a sample link match the gen-clos formula', () => {
  const f = T.buildClosFabric(20, '10.42.0.0/16');
  const byKey = Object.fromEntries(f.tiers.map(t => [t.key, t]));
  assert.strictEqual(byKey.core.start_ip, '10.42.0.1');
  assert.strictEqual(byKey.agg.start_ip, '10.42.4.1');
  assert.strictEqual(byKey.edge.start_ip, '10.42.8.1');
  assert.strictEqual(byKey.host.start_ip, '10.42.16.1');
  assert.strictEqual(f.netmask, '16');
  // First edge↔agg link: pod 0, edge 0 (ifIndex 1) ↔ agg 0 (ifIndex 1).
  // edge base 10.42.8.1 + edge_id(0,0)=0 → 10.42.8.1; agg base 10.42.4.1 → 10.42.4.1.
  const first = f.links[0];
  assert.deepStrictEqual(first.a, { ip: '10.42.8.1', ifindex: 1 });
  assert.deepStrictEqual(first.b, { ip: '10.42.4.1', ifindex: 1 });
  // A custom base subnet shifts the whole plan.
  const g = T.buildClosFabric(8, '10.50.0.0/16');
  assert.strictEqual(Object.fromEntries(g.tiers.map(t => [t.key, t.start_ip])).core, '10.50.0.1');
});

ok('buildClosFabric: agg↔core / edge↔host port assignments match gen-clos', () => {
  // Counts alone can't catch a port-math regression. Link order is fixed:
  // edge↔agg block first (k·(k/2)² = 128 for k=8), then agg↔core (128 more),
  // then edge↔host. Pin specific endpoints in each later block.
  const k = 8, half = k / 2; // 4
  const edgeAgg = k * half * half; // 128
  const f = T.buildClosFabric(k, '10.42.0.0/16');

  // First agg↔core link (pod 0, agg 0, core-member 0): agg uplink port half+1=5,
  // core port = pod+1 = 1.
  const ac0 = f.links[edgeAgg];
  assert.deepStrictEqual(ac0.a, { ip: '10.42.4.1', ifindex: half + 1 }, 'agg uplink port half+1');
  assert.deepStrictEqual(ac0.b, { ip: '10.42.0.1', ifindex: 1 }, 'core port = pod+1');

  // agg↔core for pod 3 (a=0,i=0) → index edgeAgg + 3·half²: core port must be 4.
  const acPod3 = f.links[edgeAgg + 3 * half * half];
  assert.strictEqual(acPod3.b.ifindex, 4, 'core port reflects pod index (pod+1)');

  // First edge↔host link (pod 0, edge 0, host 0): edge downlink port half+1=5,
  // host uses eth0 = ifIndex 2.
  const eh0 = f.links[2 * edgeAgg];
  assert.deepStrictEqual(eh0.a, { ip: '10.42.8.1', ifindex: half + 1 }, 'edge downlink port half+1');
  assert.deepStrictEqual(eh0.b, { ip: '10.42.16.1', ifindex: 2 }, 'host eth0 = ifIndex 2');
});

ok('closSubnetError: requires dotted IPv4 and a /16 (or no) prefix', () => {
  assert.strictEqual(T.closSubnetError('10.42.0.0/16'), null);
  assert.strictEqual(T.closSubnetError('10.42.0.0'), null, 'bare IP defaults to /16');
  assert.ok(T.closSubnetError(''), 'empty rejected');
  assert.ok(T.closSubnetError('999.1.1.1/16'), 'octet > 255 rejected');
  assert.ok(T.closSubnetError('10.42.0.0/24'), 'non-/16 prefix rejected');
  assert.ok(T.closSubnetError('10.42.0.0/99'), 'out-of-range prefix rejected');
  assert.ok(T.closSubnetError('10.42.0/16'), 'three octets rejected');
  // buildClosFabric rejects a bad subnet and normalizes host bits to the /16 network.
  assert.throws(() => T.buildClosFabric(8, '10.42.0.0/24'), /\/16/);
  const f = T.buildClosFabric(8, '10.42.5.7/16');
  assert.strictEqual(Object.fromEntries(f.tiers.map(t => [t.key, t.start_ip])).core, '10.42.0.1',
    'host bits normalized to the /16 network');
});

ok('closDeviceBatches: splits a tier into contiguous batches covering every IP', () => {
  // Host tier of a k=32 fabric: 8192 devices from 10.42.16.1.
  const tier = { start_ip: '10.42.16.1', count: 8192, resource_file: 'linux_server.json' };
  const batches = T.closDeviceBatches(tier, 100);
  assert.strictEqual(batches.length, 82, 'ceil(8192/100) batches');
  assert.deepStrictEqual(batches[0], { start_ip: '10.42.16.1', count: 100 });
  // Counts sum to the tier total; last batch is the remainder.
  assert.strictEqual(batches.reduce((s, b) => s + b.count, 0), 8192);
  assert.strictEqual(batches[batches.length - 1].count, 8192 - 81 * 100); // 92
  // Batches are contiguous: each start_ip = previous start + previous count,
  // so the union is exactly the IPs one {start_ip, count} request would create.
  for (let i = 1; i < batches.length; i++) {
    const expected = T.intToIp(T.ipToInt(batches[i - 1].start_ip) + batches[i - 1].count);
    assert.strictEqual(batches[i].start_ip, expected, `batch ${i} contiguous`);
  }
  // Spot-check the carry across the third octet: batch[2] starts at .16.1 + 200.
  assert.strictEqual(batches[2].start_ip, T.intToIp(T.ipToInt('10.42.16.1') + 200));
});

ok('closDeviceBatches: small tier stays a single batch; exact multiple has no remainder', () => {
  assert.deepStrictEqual(T.closDeviceBatches({ start_ip: '10.42.0.1', count: 16 }, 100),
    [{ start_ip: '10.42.0.1', count: 16 }]);
  const exact = T.closDeviceBatches({ start_ip: '10.42.4.1', count: 200 }, 100);
  assert.strictEqual(exact.length, 2);
  assert.deepStrictEqual(exact.map(b => b.count), [100, 100]);
});

console.log(`\n${pass} checks passed.`);
