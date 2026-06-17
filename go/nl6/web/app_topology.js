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
    hoveredEdge: null,  // fattened for an easy click target
    hoveredNode: null,  // enlarged for a click affordance, mirroring edges
    layout: 'tiered'    // 'tiered' (default, fabric bands) | 'force' (organic)
  };

  var EDGE_SIZE = 3;        // base thickness (thin lines are hard to click)
  var EDGE_SIZE_HOVER = 6;  // fatten on hover → bigger hit area + clear affordance
  var NODE_HOVER_GROW = 1.4; // enlarge the hovered node → clear click affordance

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

  // confirmDialog shows an app-styled modal (reusing .modal-scrim) and resolves
  // true/false. Used only for the destructive (shutdown / fail) direction —
  // bringing links back up is unconfirmed. Esc/backdrop = cancel, Enter = OK.
  function confirmDialog(opts) {
    return new Promise(function (resolve) {
      var scrim = document.createElement('div');
      scrim.className = 'modal-scrim';
      scrim.innerHTML =
        '<div class="confirm-dialog" role="dialog" aria-modal="true">' +
          '<div class="modal-body">' +
            '<p class="confirm-title"></p>' +
            '<p class="confirm-msg"></p>' +
          '</div>' +
          '<div class="modal-foot">' +
            '<div class="modal-foot-actions">' +
              '<button type="button" class="btn btn-small" data-act="cancel">Cancel</button>' +
              '<button type="button" class="btn btn-small btn-danger" data-act="ok"></button>' +
            '</div>' +
          '</div>' +
        '</div>';
      scrim.querySelector('.confirm-title').textContent = opts.title || '';
      scrim.querySelector('.confirm-msg').textContent = opts.message || '';
      scrim.querySelector('[data-act="ok"]').textContent = opts.confirmLabel || 'Confirm';

      function close(result) {
        document.removeEventListener('keydown', onKey);
        scrim.remove();
        resolve(result);
      }
      function onKey(e) {
        if (e.key === 'Escape') close(false);
        else if (e.key === 'Enter') close(true);
      }
      scrim.addEventListener('click', function (e) {
        var act = e.target.getAttribute && e.target.getAttribute('data-act');
        if (act === 'ok') close(true);
        else if (act === 'cancel' || e.target === scrim) close(false);
      });
      document.addEventListener('keydown', onKey);
      document.body.appendChild(scrim);
      var ok = scrim.querySelector('[data-act="ok"]');
      if (ok) ok.focus();
    });
  }

  function onEdgeClick(edgeKeyClicked) {
    if (!state.model) return;
    var edge = state.model.edges.find(function (e) { return e.key === edgeKeyClicked; });
    if (!edge) return;
    var ops = TopologyLogic.edgeToggleOps(edge);
    // Restoring a link is unconfirmed; shutting one down asks first.
    if (!edge.active) {
      applyOps(ops, 'Restoring link ' + edgePortLabel(edge));
      return;
    }
    confirmDialog({
      title: 'Shut down link?',
      message: edgePortLabel(edge),
      confirmLabel: 'Shut down'
    }).then(function (ok) {
      if (ok) applyOps(ops, 'Downing link ' + edgePortLabel(edge));
    });
  }

  function onNodeClick(nodeId) {
    if (!state.model) return;
    var node = state.model.nodeIndex[nodeId];
    var name = (node && node.label) || nodeId;
    // Re-enabling a failed device is unconfirmed; failing one asks first.
    if (TopologyLogic.nodeIsDown(state.model, nodeId)) {
      var upOps = TopologyLogic.nodeRestoreOps(state.model, nodeId);
      if (upOps.length) applyOps(upOps, 'Restored device ' + name);
      return;
    }
    var ops = TopologyLogic.nodeFailOps(state.model, nodeId);
    if (!ops.length) return;
    confirmDialog({
      title: 'Fail device ' + name + '?',
      message: 'This downs all ' + ops.length + ' of its link' + (ops.length === 1 ? '' : 's') + '.',
      confirmLabel: 'Fail device'
    }).then(function (ok) {
      if (ok) applyOps(ops, 'Failed device ' + name);
    });
  }

  // ---- rendering ------------------------------------------------------------

  function edgeColor(active) { return active ? COLOR.edgeUp : COLOR.edgeDown; }
  function nodeColor(n) { return n.missing ? COLOR.nodeMissing : COLOR.node; }
  function nodeSize(n) { return 6 + Math.min(10, (n.degree || 0)); }

  // ---- edge port tooltip ----------------------------------------------------

  var lastMouse = { x: 0, y: 0 }; // viewport coords, for positioning the tip

  // portName is the device's ifDescr (e.g. "GigabitEthernet0/1"), falling back
  // to the ifIndex when the device/name can't be resolved.
  function portName(end) { return end.ifName || ('ifIndex ' + end.ifindex); }
  function edgePortLabel(edge) { return portName(edge.a) + '  ↔  ' + portName(edge.b); }

  function positionTip(clientX, clientY) {
    var tip = el('topologyTip'), stage = el('topologyStage');
    if (!tip || !stage) return;
    var r = stage.getBoundingClientRect();
    tip.style.left = (clientX - r.left) + 'px';
    tip.style.top = (clientY - r.top) + 'px';
  }

  function showEdgeTip(edgeKey) {
    var tip = el('topologyTip');
    if (!tip || !state.model) return;
    var edge = state.model.edges.find(function (x) { return x.key === edgeKey; });
    if (!edge) return;
    tip.textContent = edgePortLabel(edge);
    positionTip(lastMouse.x, lastMouse.y);
    tip.hidden = false;
  }

  function hideEdgeTip() { var tip = el('topologyTip'); if (tip) tip.hidden = true; }

  // Label background: theme-aware canvas background colour, cached per theme so
  // getComputedStyle runs only when the theme actually changes (not per frame).
  var LABEL_BG_ALPHA = 0.88;
  var _bgCache = { theme: null, color: '#0f1218' };
  function labelBg() {
    var theme = document.documentElement.getAttribute('data-theme') || '';
    if (theme !== _bgCache.theme) {
      var cs = getComputedStyle(document.documentElement);
      var c = (cs.getPropertyValue('--surface') || cs.getPropertyValue('--bg') || '').trim();
      _bgCache = { theme: theme, color: c || '#0f1218' };
    }
    return _bgCache.color;
  }

  function roundRect(ctx, x, y, w, h, r) {
    ctx.beginPath();
    ctx.moveTo(x + r, y);
    ctx.arcTo(x + w, y, x + w, y + h, r);
    ctx.arcTo(x + w, y + h, x, y + h, r);
    ctx.arcTo(x, y + h, x, y, r);
    ctx.arcTo(x, y, x + w, y, r);
    ctx.closePath();
  }

  // drawNodeLabel paints a filled rounded-rect in the theme background colour
  // behind the label so text stays legible over edges/nodes, then the text on
  // top. Positioning mirrors sigma's default label renderer (x + size + 3,
  // baseline y + size/3) so labels line up exactly. Used for both the resting
  // label and the hover label so the two states match.
  function drawNodeLabel(context, data, settings) {
    if (!data.label) return;
    var size = settings.labelSize, font = settings.labelFont, weight = settings.labelWeight;
    context.font = weight + ' ' + size + 'px ' + font;
    var textW = context.measureText(data.label).width;
    var labelX = data.x + data.size + 3;
    var baseline = data.y + size / 3;
    var padX = 5, padY = 3;
    var boxTop = baseline - size * 0.78 - padY;
    var boxH = size * 0.98 + padY * 2;
    context.save();
    context.globalAlpha = LABEL_BG_ALPHA;
    context.fillStyle = labelBg();
    roundRect(context, labelX - padX, boxTop, textW + padX * 2, boxH, 4);
    context.fill();
    context.restore();
    context.fillStyle = (settings.labelColor && settings.labelColor.color) || '#c8ccd4';
    context.fillText(data.label, labelX, baseline);
  }

  function rebuild(model) {
    var container = el('topologyCanvas');
    if (!container) return;
    if (state.renderer) { state.renderer.kill(); state.renderer = null; }
    // Killing the renderer mid-hover means leaveEdge/leaveNode never fire; clear
    // the hover state and tooltip so a relayout doesn't leave a stale tip stuck.
    state.hoveredEdge = null;
    state.hoveredNode = null;
    hideEdgeTip();
    container.innerHTML = '';

    var graph = new graphology.Graph({ type: 'undirected', multi: true });
    var layoutFn = (state.layout === 'force')
      ? TopologyLogic.forceLayout
      : TopologyLogic.tieredLayout;
    var pos = layoutFn(model, {
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
      // Finer mouse-wheel zoom steps (default 1.7 is a big jump per tick).
      zoomingRatio: 1.25,
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
      // Draw labels (and hover labels) over a theme-coloured background box so
      // text stays legible where edges/nodes cross it.
      defaultDrawNodeLabel: drawNodeLabel,
      defaultDrawNodeHover: drawNodeLabel,
      // Fatten the hovered edge so the thin line becomes an easy click target.
      edgeReducer: function (edgeKey, attrs) {
        if (edgeKey === state.hoveredEdge) {
          return Object.assign({}, attrs, { size: EDGE_SIZE_HOVER });
        }
        return attrs;
      },
      // Enlarge the hovered node, mirroring the edge affordance.
      nodeReducer: function (nodeKey, attrs) {
        if (nodeKey === state.hoveredNode) {
          return Object.assign({}, attrs, { size: attrs.size * NODE_HOVER_GROW });
        }
        return attrs;
      }
    });
    state.renderer.on('clickEdge', function (e) { onEdgeClick(e.edge); });
    state.renderer.on('clickNode', function (e) { onNodeClick(e.node); });
    // Hover affordance: fatten the edge, show a pointer cursor, and reveal the
    // port names on both ends in a tooltip near the cursor.
    state.renderer.on('enterEdge', function (e) {
      state.hoveredEdge = e.edge;
      container.style.cursor = 'pointer';
      showEdgeTip(e.edge);
      state.renderer.refresh();
    });
    state.renderer.on('leaveEdge', function () {
      state.hoveredEdge = null;
      container.style.cursor = 'default';
      hideEdgeTip();
      state.renderer.refresh();
    });
    // Same affordance for nodes: enlarge + pointer cursor on hover.
    state.renderer.on('enterNode', function (e) {
      state.hoveredNode = e.node;
      container.style.cursor = 'pointer';
      state.renderer.refresh();
    });
    state.renderer.on('leaveNode', function () {
      state.hoveredNode = null;
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
    // Toggle the whole stage (canvas + zoom overlay) so the zoom buttons don't
    // float over the summary view when the scale guard hides the graph.
    var stage = el('topologyStage'), s = el('topologySummary');
    if (stage) stage.style.display = show ? 'block' : 'none';
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

  // ---- layout toggle --------------------------------------------------------

  function updateLayoutButtons() {
    [['topologyLayoutTiered', 'tiered'], ['topologyLayoutForce', 'force']].forEach(function (pair) {
      var b = el(pair[0]);
      if (!b) return;
      var on = state.layout === pair[1];
      b.classList.toggle('is-active', on);
      b.setAttribute('aria-pressed', on ? 'true' : 'false');
    });
  }

  function setLayout(name) {
    if ((name !== 'force' && name !== 'tiered') || state.layout === name) return;
    state.layout = name;
    updateLayoutButtons();
    // Switching layout is a structural-render trigger, not a recolor: relayout
    // the current model in place (only when the graph is actually drawn).
    if (state.model && state.renderer) {
      rebuild(state.model);
      state.structureKey = TopologyLogic.structureKey(state.model);
    }
  }

  function wireLayoutToggle() {
    var t = el('topologyLayoutTiered'), f = el('topologyLayoutForce');
    if (t) t.addEventListener('click', function () { setLayout('tiered'); });
    if (f) f.addEventListener('click', function () { setLayout('force'); });
    updateLayoutButtons();
  }

  // ---- zoom controls --------------------------------------------------------

  var ZOOM_FACTOR = 1.3; // per-button-press zoom step

  // The camera is per-renderer (recreated on every rebuild), so resolve it at
  // click time; the buttons no-op while the summary (no renderer) is shown.
  function camera() { return state.renderer ? state.renderer.getCamera() : null; }

  // Track the cursor over the stage so the edge tooltip follows it, and keep
  // the tip pinned to the cursor while an edge stays hovered.
  function wireEdgeTip() {
    var stage = el('topologyStage');
    if (!stage) return;
    stage.addEventListener('mousemove', function (ev) {
      lastMouse.x = ev.clientX; lastMouse.y = ev.clientY;
      if (state.hoveredEdge) positionTip(ev.clientX, ev.clientY);
    });
  }

  function wireZoomControls() {
    var fit = el('topologyFit'), zin = el('topologyZoomIn'), zout = el('topologyZoomOut');
    if (zin) zin.addEventListener('click', function () {
      var c = camera(); if (c) c.animatedZoom({ duration: 200, factor: ZOOM_FACTOR });
    });
    if (zout) zout.addEventListener('click', function () {
      var c = camera(); if (c) c.animatedUnzoom({ duration: 200, factor: ZOOM_FACTOR });
    });
    if (fit) fit.addEventListener('click', function () {
      var c = camera(); if (c) c.animatedReset({ duration: 300 });
    });
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
    wireLayoutToggle();
    wireZoomControls();
    wireEdgeTip();
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
