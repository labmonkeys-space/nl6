/*
 * Copyright 2026 Ronny Trommer <ronny@no42.org>
 * SPDX-License-Identifier: Apache-2.0
 *
 * Pure, DOM-free logic for the topology visualization: model building,
 * deterministic force layout, structure/state diffing, click-to-flap target
 * resolution, and the scale guard. Kept free of sigma/graphology/DOM so it
 * can be unit-tested under node (see topology_logic.test.js). Exposed as the
 * `TopologyLogic` global in the browser via the UMD wrapper.
 */
(function (root, factory) {
  if (typeof module === 'object' && module.exports) {
    module.exports = factory();
  } else {
    root.TopologyLogic = factory();
  }
})(typeof self !== 'undefined' ? self : this, function () {
  'use strict';

  // Scale guard ceilings (decision: 500 nodes / 2000 edges).
  var SCALE_CAP = { nodes: 500, edges: 2000 };

  // edgeKey is the stable identity of a link across polls — both endpoints
  // and their ifindexes. Used as the graphology edge key so recolor/diff can
  // match a polled edge to the rendered one.
  function edgeKey(e) {
    return e.a.ip + ':' + e.a.ifindex + '--' + e.b.ip + ':' + e.b.ifindex;
  }

  // buildModel normalizes a GET /topology/graph response into the internal
  // model the renderer consumes. Returns {nodes, edges, nodeIndex}.
  function buildModel(graph) {
    var nodes = (graph && graph.nodes ? graph.nodes : []).map(function (n) {
      // The sysName already encodes the device type (e.g.
      // "lion-29-cisco-crs-x"), so the label is just sysName (or IP for a
      // missing/dangling node) — appending "(type)" only doubles the text
      // and worsens overlap. `type` is kept for tooltips/legend.
      return {
        id: n.ip,
        label: n.sysName || n.ip,
        type: n.type || '',
        degree: n.degree || 0,
        missing: !!n.missing
      };
    });
    var edges = (graph && graph.edges ? graph.edges : []).map(function (e) {
      return {
        key: edgeKey(e),
        a: { ip: e.a.ip, ifindex: e.a.ifindex, ifName: e.a.ifName || '' },
        b: { ip: e.b.ip, ifindex: e.b.ifindex, ifName: e.b.ifName || '' },
        active: !!e.active,
        downEnd: e.downEnd || ''
      };
    });
    var nodeIndex = {};
    nodes.forEach(function (n) { nodeIndex[n.id] = n; });
    return { nodes: nodes, edges: edges, nodeIndex: nodeIndex };
  }

  // structureKey is a stable fingerprint of the graph's *structure* (which
  // nodes and edges exist), independent of live state (active/downEnd). The
  // renderer relayouts only when this changes; otherwise it just recolors.
  function structureKey(model) {
    var ns = model.nodes.map(function (n) { return n.id; }).sort();
    var es = model.edges.map(function (e) { return e.key; }).sort();
    return ns.join(',') + '|' + es.join(',');
  }

  // mulberry32 is a tiny deterministic PRNG so a given (graph, seed) always
  // lays out identically — no node teleporting across cold renders.
  function mulberry32(seed) {
    var a = seed >>> 0;
    return function () {
      a |= 0; a = (a + 0x6d2b79f5) | 0;
      var t = Math.imul(a ^ (a >>> 15), 1 | a);
      t = (t + Math.imul(t ^ (t >>> 7), 61 | t)) ^ t;
      return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
    };
  }

  // forceLayout runs a deterministic Fruchterman-Reingold layout and returns
  // { id: {x, y} } in [0,width]×[0,height]. Pure: same inputs → same output.
  function forceLayout(model, opts) {
    opts = opts || {};
    var width = opts.width || 1000;
    var height = opts.height || 700;
    var iterations = opts.iterations || 200;
    var rand = mulberry32(opts.seed || 1);
    // Keep nodes off the frame edge so labels (which extend to the right of
    // a node) stay on-canvas.
    var mx = width * 0.06, my = height * 0.06;

    var nodes = model.nodes;
    var n = nodes.length;
    var pos = {};
    if (n === 0) return pos;
    if (n === 1) { pos[nodes[0].id] = { x: width / 2, y: height / 2 }; return pos; }

    var area = width * height;
    var k = Math.sqrt(area / n);          // ideal edge length
    var P = nodes.map(function (nd) {
      return { id: nd.id, x: rand() * width, y: rand() * height };
    });
    var idx = {};
    P.forEach(function (p, i) { idx[p.id] = i; });

    var edges = model.edges
      .filter(function (e) { return idx[e.a.ip] != null && idx[e.b.ip] != null; })
      .map(function (e) { return [idx[e.a.ip], idx[e.b.ip]]; });

    var temp = width / 10;
    var cool = temp / (iterations + 1);

    for (var it = 0; it < iterations; it++) {
      var disp = P.map(function () { return { x: 0, y: 0 }; });
      // Repulsion (all pairs).
      for (var i = 0; i < n; i++) {
        for (var j = i + 1; j < n; j++) {
          var dx = P[i].x - P[j].x, dy = P[i].y - P[j].y;
          var dist = Math.sqrt(dx * dx + dy * dy) || 0.01;
          var rep = (k * k) / dist;
          var ux = dx / dist, uy = dy / dist;
          disp[i].x += ux * rep; disp[i].y += uy * rep;
          disp[j].x -= ux * rep; disp[j].y -= uy * rep;
        }
      }
      // Attraction (along edges).
      for (var e = 0; e < edges.length; e++) {
        var s = edges[e][0], t = edges[e][1];
        var ex = P[s].x - P[t].x, ey = P[s].y - P[t].y;
        var ed = Math.sqrt(ex * ex + ey * ey) || 0.01;
        var att = (ed * ed) / k;
        var ax = ex / ed, ay = ey / ed;
        disp[s].x -= ax * att; disp[s].y -= ay * att;
        disp[t].x += ax * att; disp[t].y += ay * att;
      }
      // Apply, bounded by temperature, clamped to the frame.
      for (var p = 0; p < n; p++) {
        var d = Math.sqrt(disp[p].x * disp[p].x + disp[p].y * disp[p].y) || 0.01;
        var lim = Math.min(d, temp);
        P[p].x += (disp[p].x / d) * lim;
        P[p].y += (disp[p].y / d) * lim;
        P[p].x = Math.min(width - mx, Math.max(mx, P[p].x));
        P[p].y = Math.min(height - my, Math.max(my, P[p].y));
      }
      temp -= cool;
    }
    P.forEach(function (p) { pos[p.id] = { x: p.x, y: p.y }; });
    return pos;
  }

  // edgeToggleOps returns the oper-status mutations for a click-to-flap toggle
  // (sticky). Active link → down one endpoint (the A side). Inactive link →
  // bring BOTH ends up (idempotent restore regardless of which was down).
  function edgeToggleOps(edge) {
    if (edge.active) {
      return [{ ip: edge.a.ip, ifindex: edge.a.ifindex, status: 'DOWN' }];
    }
    return [
      { ip: edge.a.ip, ifindex: edge.a.ifindex, status: 'UP' },
      { ip: edge.b.ip, ifindex: edge.b.ifindex, status: 'UP' }
    ];
  }

  // nodeFailOps returns the oper-status DOWN mutations to fail a whole device:
  // every local interface of `nodeId` that backs an incident link.
  function nodeFailOps(model, nodeId) {
    var ops = [];
    model.edges.forEach(function (e) {
      if (e.a.ip === nodeId) ops.push({ ip: nodeId, ifindex: e.a.ifindex, status: 'DOWN' });
      if (e.b.ip === nodeId) ops.push({ ip: nodeId, ifindex: e.b.ifindex, status: 'DOWN' });
    });
    return ops;
  }

  // scaleDecision decides whether to render the graph or show a summary.
  function scaleDecision(nodeCount, edgeCount, caps) {
    caps = caps || SCALE_CAP;
    if (nodeCount > caps.nodes || edgeCount > caps.edges) {
      return {
        render: false,
        reason: 'Topology too large to render (' + nodeCount + ' nodes / ' +
          edgeCount + ' links, cap ' + caps.nodes + '/' + caps.edges + ').'
      };
    }
    return { render: true, reason: '' };
  }

  return {
    SCALE_CAP: SCALE_CAP,
    edgeKey: edgeKey,
    buildModel: buildModel,
    structureKey: structureKey,
    forceLayout: forceLayout,
    edgeToggleOps: edgeToggleOps,
    nodeFailOps: nodeFailOps,
    scaleDecision: scaleDecision
  };
});
