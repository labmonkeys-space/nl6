/*
 * Copyright 2026 Ronny Trommer <ronny@no42.org>
 * SPDX-License-Identifier: Apache-2.0
 *
 * Topology visualization: the DOM/sigma glue. Gated on a deployed topology
 * (configured_links > 0), renders GET /api/v1/topology/graph with sigma.js,
 * recolors edges by liveness on the poll cadence (relayout only on structure
 * change), and provides click-to-flap (edge toggle / node device-failure)
 * via the existing oper-status endpoint. Pure logic lives in
 * topology_logic.js (TopologyLogic, node-tested); rendering/interaction here
 * requires a browser and is verified there.
 *
 * sigma v3 / graphology API assumptions (verify in browser):
 *  - new graphology.Graph({type:'undirected', multi:true})
 *  - new Sigma(graph, container, { enableEdgeEvents:true, ... })
 *  - renderer.on('clickEdge', ({edge})) / .on('clickNode', ({node}))
 *  - graph.setEdgeAttribute(key,'color',c) + renderer.refresh()
 */
(function () {
  'use strict';

  var POLL_MS = 5000;
  var COLOR = {
    edgeUp: '#2e9e5b', edgeDown: '#d64545',
    node: '#4361ee', nodeMissing: '#9aa0a6'
  };

  var state = {
    renderer: null,
    graph: null,
    model: null,
    structureKey: null,
    scaleOverride: false,
    inFlight: false,
    refetchQueued: false, // a refetch requested while a poll was in flight
    started: false,
    hoveredEdge: null   // fattened for an easy click target
  };

  var EDGE_SIZE = 3;        // base thickness (thin lines are hard to click)
  var EDGE_SIZE_HOVER = 6;  // fatten on hover → bigger hit area + clear affordance

  function el(id) { return document.getElementById(id); }
  function section() { return el('topologySection'); }

  // ---- API helpers (reuse the console's apiCall) ----------------------------

  function postOperStatus(ip, ifindex, status) {
    return apiCall('/devices/' + ip + '/interfaces/' + ifindex + '/oper-status', {
      method: 'POST',
      body: JSON.stringify({ status: status })
    });
  }

  async function applyOps(ops, label) {
    var results = await Promise.allSettled(ops.map(function (o) {
      return postOperStatus(o.ip, o.ifindex, o.status);
    }));
    var failed = results.filter(function (r) { return r.status === 'rejected'; }).length;
    if (failed) {
      showAlert(label + ': ' + failed + '/' + ops.length + ' operations failed', 'error');
    } else {
      showAlert(label + ' (' + ops.length + ' interface' + (ops.length === 1 ? '' : 's') + ')', 'success');
    }
    await pollTopology(); // immediate refetch so the canvas reflects the change
  }

  // ---- interaction ----------------------------------------------------------

  function onEdgeClick(edgeKeyClicked) {
    if (!state.model) return;
    var edge = state.model.edges.find(function (e) { return e.key === edgeKeyClicked; });
    if (!edge) return;
    var ops = TopologyLogic.edgeToggleOps(edge);
    var verb = edge.active ? 'Downing link' : 'Restoring link';
    applyOps(ops, verb + ' ' + edge.a.ip + '/' + edge.a.ifindex + '–' + edge.b.ip + '/' + edge.b.ifindex);
  }

  function onNodeClick(nodeId) {
    if (!state.model) return;
    var ops = TopologyLogic.nodeFailOps(state.model, nodeId);
    if (!ops.length) return;
    var node = state.model.nodeIndex[nodeId];
    var name = (node && node.label) || nodeId;
    // Node failure is the highest-blast-radius click — confirm first.
    if (!window.confirm('Fail device ' + name + '?\nThis downs all ' + ops.length + ' of its links.')) return;
    applyOps(ops, 'Failed device ' + nodeId);
  }

  // ---- rendering ------------------------------------------------------------

  function edgeColor(active) { return active ? COLOR.edgeUp : COLOR.edgeDown; }
  function nodeColor(n) { return n.missing ? COLOR.nodeMissing : COLOR.node; }
  function nodeSize(n) { return 6 + Math.min(10, (n.degree || 0)); }

  function rebuild(model) {
    var container = el('topologyCanvas');
    if (!container) return;
    if (state.renderer) { state.renderer.kill(); state.renderer = null; }
    container.innerHTML = '';

    var graph = new graphology.Graph({ type: 'undirected', multi: true });
    var pos = TopologyLogic.forceLayout(model, {
      width: container.clientWidth || 1000,
      height: container.clientHeight || 600, // matches the canvas's inline height
      seed: 1
    });
    model.nodes.forEach(function (n) {
      var p = pos[n.id] || { x: 0, y: 0 };
      graph.addNode(n.id, {
        x: p.x, y: p.y, size: nodeSize(n),
        label: n.label, color: nodeColor(n),
        // `title` shows the type + degree on hover without crowding the label.
        title: n.type ? (n.type + ' · degree ' + n.degree) : ('degree ' + n.degree)
      });
    });
    model.edges.forEach(function (e) {
      if (!graph.hasNode(e.a.ip) || !graph.hasNode(e.b.ip)) return;
      if (graph.hasEdge(e.key)) return;
      graph.addEdgeWithKey(e.key, e.a.ip, e.b.ip, { size: EDGE_SIZE, color: edgeColor(e.active) });
    });

    state.graph = graph;
    state.renderer = new Sigma(graph, container, {
      enableEdgeEvents: true,
      renderEdgeLabels: false,
      // Labels were dark-on-dark by default — set a light color + readable
      // size, and let sigma's label grid thin overlapping labels when the
      // graph is crowded (hover/zoom still reveals hidden ones).
      labelColor: { color: '#c8ccd4' },
      labelSize: 12,
      labelWeight: '500',
      labelFont: 'Inter, system-ui, sans-serif',
      labelDensity: 0.7,
      labelGridCellSize: 140,
      labelRenderedSizeThreshold: 0,
      // Fatten the hovered edge so the thin line becomes an easy click target.
      edgeReducer: function (edgeKey, attrs) {
        if (edgeKey === state.hoveredEdge) {
          return Object.assign({}, attrs, { size: EDGE_SIZE_HOVER });
        }
        return attrs;
      }
    });
    state.renderer.on('clickEdge', function (e) { onEdgeClick(e.edge); });
    state.renderer.on('clickNode', function (e) { onNodeClick(e.node); });
    // Hover affordance: fatten the edge + show a pointer cursor.
    state.renderer.on('enterEdge', function (e) {
      state.hoveredEdge = e.edge;
      container.style.cursor = 'pointer';
      state.renderer.refresh();
    });
    state.renderer.on('leaveEdge', function () {
      state.hoveredEdge = null;
      container.style.cursor = 'default';
      state.renderer.refresh();
    });
  }

  function recolor(model) {
    if (!state.graph) return;
    model.edges.forEach(function (e) {
      if (state.graph.hasEdge(e.key)) {
        state.graph.setEdgeAttribute(e.key, 'color', edgeColor(e.active));
      }
    });
    model.nodes.forEach(function (n) {
      if (state.graph.hasNode(n.id)) {
        state.graph.setNodeAttribute(n.id, 'color', nodeColor(n));
      }
    });
    if (state.renderer) state.renderer.refresh();
  }

  function showCanvas(show) {
    var c = el('topologyCanvas'), s = el('topologySummary');
    if (c) c.style.display = show ? 'block' : 'none';
    if (s) s.style.display = show ? 'none' : 'block';
  }

  function renderSummary(model, msg) {
    if (state.renderer) { state.renderer.kill(); state.renderer = null; state.structureKey = null; }
    var active = model.edges.filter(function (e) { return e.active; }).length;
    var missing = model.nodes.filter(function (n) { return n.missing; }).length;
    var s = el('topologySummary');
    if (!s) return;
    s.innerHTML =
      '<p>' + model.nodes.length + ' devices · ' + model.edges.length + ' links · ' +
      active + ' active' + (missing ? ' · ' + missing + ' unresolved' : '') + '</p>' +
      (msg ? '<p class="topology-note">' + msg + '</p>' +
        '<button id="topologyRenderAnyway" class="btn btn-secondary btn-small">Render anyway</button>' : '');
    showCanvas(false);
    var btn = el('topologyRenderAnyway');
    if (btn) btn.addEventListener('click', function () { state.scaleOverride = true; pollTopology(); });
  }

  function render(model) {
    state.model = model;
    var decision = TopologyLogic.scaleDecision(model.nodes.length, model.edges.length);
    if (!decision.render && !state.scaleOverride) {
      renderSummary(model, decision.reason);
      return;
    }
    showCanvas(true);
    var sk = TopologyLogic.structureKey(model);
    if (!state.renderer || TopologyLogic.needsRelayout(state.structureKey, sk)) {
      rebuild(model);            // structure changed → (re)layout
      state.structureKey = sk;
    } else {
      recolor(model);            // state-only change → recolor in place
    }
  }

  // ---- poll loop ------------------------------------------------------------

  async function pollTopology() {
    // Coalesce: a refetch requested mid-poll (e.g. the immediate refresh after
    // a click-to-flap) is queued and run when the in-flight poll finishes, so
    // the post-mutation state always lands without waiting a full poll tick.
    if (state.inFlight) { state.refetchQueued = true; return; }
    state.inFlight = true;
    try {
      var status = await apiCall('/topology/status');
      if (!status || !status.configured_links) {
        // No topology deployed → hide the section entirely.
        if (state.renderer) { state.renderer.kill(); state.renderer = null; state.structureKey = null; }
        if (section()) section().hidden = true;
        return;
      }
      if (section()) section().hidden = false;
      var graph = await apiCall('/topology/graph');
      render(TopologyLogic.buildModel(graph));
    } catch (err) {
      console.error('topology poll failed:', err);
    } finally {
      state.inFlight = false;
      if (state.refetchQueued) { state.refetchQueued = false; pollTopology(); }
    }
  }

  function start() {
    if (state.started) return;
    // Required globals — bail quietly if the vendored libs failed to load.
    if (typeof graphology === 'undefined' || typeof Sigma === 'undefined' || typeof TopologyLogic === 'undefined') {
      console.error('topology viz: required libraries not loaded');
      return;
    }
    state.started = true;
    pollTopology();
    var whenVisible = (typeof window.whenVisible === 'function')
      ? window.whenVisible
      : function (fn) { return fn; };
    setInterval(whenVisible(pollTopology), POLL_MS);
  }

  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', start);
  } else {
    start();
  }
})();
