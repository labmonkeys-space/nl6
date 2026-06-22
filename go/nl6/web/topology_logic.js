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

  // needsRelayout decides whether a poll requires a full relayout (structure
  // changed) vs an in-place recolor (state-only change). True when there is no
  // prior render (prevKey null) or the structure fingerprint changed.
  function needsRelayout(prevKey, nextKey) {
    return prevKey == null || prevKey !== nextKey;
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

  // forceLayout runs a deterministic Fruchterman-Reingold layout (with mild
  // centering gravity) and returns { id: {x, y} } in [0,width]×[0,height]. Pure:
  // same inputs → same output. Nodes move freely during simulation (no per-step
  // frame clamp, which used to smear clusters against the walls); a final
  // fit-to-frame pass uniform-scales and centers the result into the margins, so
  // the graph fills the canvas without distortion regardless of force magnitude.
  function forceLayout(model, opts) {
    opts = opts || {};
    var width = opts.width || 1000;
    var height = opts.height || 700;
    var rand = mulberry32(opts.seed || 1);
    // Margins keep nodes (and their right-extending labels) off the frame edge.
    var mx = width * 0.08, my = height * 0.08;

    var nodes = model.nodes;
    var n = nodes.length;
    // This is a synchronous O(n^2) all-pairs pass; scale iterations down as the
    // graph grows so a near-cap (500-node) layout doesn't freeze the tab.
    var iterations = opts.iterations || (n <= 60 ? 300 : n <= 200 ? 150 : 80);
    var pos = {};
    if (n === 0) return pos;
    if (n === 1) { pos[nodes[0].id] = { x: width / 2, y: height / 2 }; return pos; }

    var area = width * height;
    var k = Math.sqrt(area / n);          // ideal edge length
    var cx = width / 2, cy = height / 2;
    var gravity = 0.04;                   // mild pull to center (keeps it whole)

    // Deterministic circular seeding (+ tiny jitter) converges faster and
    // tangles less than scattering nodes uniformly across the whole frame.
    var P = nodes.map(function (nd, i) {
      var ang = (2 * Math.PI * i) / n;
      var r = k * (0.5 + 0.5 * rand());
      return { id: nd.id, x: cx + r * Math.cos(ang) + (rand() - 0.5), y: cy + r * Math.sin(ang) + (rand() - 0.5) };
    });
    var idx = {};
    P.forEach(function (p, i) { idx[p.id] = i; });

    var edges = model.edges
      .filter(function (e) { return idx[e.a.ip] != null && idx[e.b.ip] != null; })
      .map(function (e) { return [idx[e.a.ip], idx[e.b.ip]]; });

    var temp = Math.max(width, height) * 0.1;
    var cool = 0.96;                      // multiplicative cooling

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
      // Gravity: pull every node toward the center so disconnected components
      // (and dangling nodes) stay together instead of repelling to infinity.
      for (var g = 0; g < n; g++) {
        disp[g].x += (cx - P[g].x) * gravity;
        disp[g].y += (cy - P[g].y) * gravity;
      }
      // Apply, bounded by temperature. No frame clamp — fit-to-frame at the end.
      for (var p = 0; p < n; p++) {
        var d = Math.sqrt(disp[p].x * disp[p].x + disp[p].y * disp[p].y) || 0.01;
        var lim = Math.min(d, temp);
        P[p].x += (disp[p].x / d) * lim;
        P[p].y += (disp[p].y / d) * lim;
      }
      temp *= cool;
    }

    // Fit-to-frame: uniform-scale the converged bounding box and center it into
    // the usable area, so the layout fills the canvas and is guaranteed in-bounds.
    var minX = Infinity, minY = Infinity, maxX = -Infinity, maxY = -Infinity;
    P.forEach(function (p) {
      if (p.x < minX) minX = p.x; if (p.x > maxX) maxX = p.x;
      if (p.y < minY) minY = p.y; if (p.y > maxY) maxY = p.y;
    });
    var bw = (maxX - minX) || 1, bh = (maxY - minY) || 1;
    var availW = width - 2 * mx, availH = height - 2 * my;
    var scale = Math.min(availW / bw, availH / bh);
    var offX = mx + (availW - bw * scale) / 2;
    var offY = my + (availH - bh * scale) / 2;
    P.forEach(function (p) {
      pos[p.id] = { x: offX + (p.x - minX) * scale, y: offY + (p.y - minY) * scale };
    });
    return pos;
  }

  // TIER_RANK maps a device model label (the `type` field on a graph node,
  // e.g. "Cisco CRS-X") to a fabric tier rank — lower = higher in the diagram.
  // It mirrors the category grouping in device_profiles.go (deviceProfileMap)
  // projected through the model-label map (deviceTypeLabels in
  // field_resolver.go). Keyed by label because the graph endpoint emits the
  // human-readable model string, not the slug. Labels absent here fall back to
  // a structural band (see tieredLayout); a renamed/new model degrades to the
  // fallback rather than crashing.
  var TIER_RANK = {
    // Core routers
    'Cisco CRS-X': 0, 'Cisco ASR 9000': 0, 'Huawei NE8000': 0,
    'Nokia 7750 SR-12': 0, 'Juniper MX960': 0,
    // Data-center switches
    'Cisco Nexus 9500': 1, 'Arista 7280R3': 1,
    // Edge routers
    'Juniper MX240': 2, 'NEC IX3315': 2, 'Cisco IOS': 2,
    // Campus switches
    'Cisco Catalyst 9500': 3, 'Extreme VSP 4450': 3, 'D-Link DGS-3630': 3,
    // Firewalls
    'Palo Alto PA-3220': 4, 'Fortinet FortiGate 600E': 4,
    'SonicWall NSA 6700': 4, 'Check Point 15600': 4,
    // Servers / GPU / storage (fabric hosts)
    'Dell PowerEdge R750': 5, 'HPE ProLiant DL380': 5, 'IBM Power S922': 5,
    'NVIDIA DGX A100': 5, 'NVIDIA DGX H100': 5, 'NVIDIA HGX H200': 5,
    'Linux Server': 5, 'AWS S3': 5, 'Dell EMC Unity': 5,
    'NetApp ONTAP': 5, 'Pure Storage FlashArray': 5
  };

  // median returns the middle value of a numeric array (mean of the two middle
  // values for an even length), or null for an empty array.
  function median(arr) {
    if (!arr.length) return null;
    var s = arr.slice().sort(function (a, b) { return a - b; });
    var m = Math.floor(s.length / 2);
    return (s.length % 2) ? s[m] : (s[m - 1] + s[m]) / 2;
  }

  // tieredLayout places nodes in horizontal tiers (a "tiered fabric" layout)
  // and returns { id: {x, y} } in [0,width]×[0,height]. Pure & deterministic:
  // same inputs → same output, no PRNG. Tier rank comes from the device model
  // label (TIER_RANK); untyped/missing nodes fall to a structural band one
  // below their highest-tier typed neighbour (isolated → the bottom band).
  // Ranks present are compacted to dense bands (no empty rows), and within-band
  // order is refined with barycenter sweeps to reduce edge crossings.
  function tieredLayout(model, opts) {
    opts = opts || {};
    var width = opts.width || 1000;
    var height = opts.height || 700;
    var mx = width * 0.06, my = height * 0.06;
    var nodes = model.nodes;
    var n = nodes.length;
    var pos = {};
    if (n === 0) return pos;
    if (n === 1) { pos[nodes[0].id] = { x: width / 2, y: height / 2 }; return pos; }

    // Adjacency over present node ids only (drop dangling endpoints).
    var present = {};
    nodes.forEach(function (nd) { present[nd.id] = nd; });
    var adj = {};
    nodes.forEach(function (nd) { adj[nd.id] = []; });
    model.edges.forEach(function (e) {
      if (present[e.a.ip] == null || present[e.b.ip] == null) return;
      adj[e.a.ip].push(e.b.ip);
      adj[e.b.ip].push(e.a.ip);
    });

    // Raw rank: typed nodes get their exact tier; untyped are deferred (null).
    var rawRank = {};
    var typedRanks = [];
    nodes.forEach(function (nd) {
      var r = TIER_RANK[nd.type];
      if (r == null) { rawRank[nd.id] = null; }
      else { rawRank[nd.id] = r; typedRanks.push(r); }
    });
    var maxTyped = typedRanks.length ? Math.max.apply(null, typedRanks) : 0;

    // Structural fallback for untyped/missing nodes: one band below the highest
    // typed neighbour (may form a new bottom band); isolated → the bottom band.
    nodes.forEach(function (nd) {
      if (rawRank[nd.id] != null) return;
      var nbrTyped = adj[nd.id]
        .map(function (id) { return rawRank[id]; })
        .filter(function (r) { return r != null; });
      rawRank[nd.id] = nbrTyped.length ? (Math.max.apply(null, nbrTyped) + 1) : maxTyped;
    });

    // Compaction: distinct ranks present → dense band indices 0..B-1 (no gaps).
    var uniqSorted = nodes
      .map(function (nd) { return rawRank[nd.id]; })
      .filter(function (v, i, a) { return a.indexOf(v) === i; })
      .sort(function (a, b) { return a - b; });
    var bandOf = {};
    uniqSorted.forEach(function (r, i) { bandOf[r] = i; });
    var B = uniqSorted.length;

    var band = {};
    var bands = [];
    for (var bi = 0; bi < B; bi++) bands.push([]);
    nodes.forEach(function (nd) {
      var b = bandOf[rawRank[nd.id]];
      band[nd.id] = b;
      bands[b].push(nd.id);
    });

    // Deterministic ordering key (label then id) for stable tie-breaks.
    var sortKey = {};
    nodes.forEach(function (nd) { sortKey[nd.id] = (nd.label || '') + ' ' + nd.id; });
    function byLabel(a, b) { return sortKey[a] < sortKey[b] ? -1 : sortKey[a] > sortKey[b] ? 1 : 0; }
    bands.forEach(function (ids) { ids.sort(byLabel); });

    // Spread a band's ids evenly across the usable width at their current order.
    var px = {};
    function spread(ids) {
      var m = ids.length;
      ids.forEach(function (id, i) {
        px[id] = (m === 1) ? width / 2 : mx + ((i + 0.5) / m) * (width - 2 * mx);
      });
    }
    bands.forEach(spread);

    // Barycenter sweeps: order each band by the median x of its inter-band
    // neighbours, alternating top→down / bottom→up. Deterministic tie-break.
    var passes = opts.passes || 4;
    for (var p = 0; p < passes; p++) {
      for (var s = 0; s < B; s++) {
        var bandIdx = (p % 2 === 0) ? s : (B - 1 - s);
        var ids = bands[bandIdx];
        var key = {};
        ids.forEach(function (id) {
          var xs = adj[id]
            .filter(function (nb) { return band[nb] !== bandIdx; })
            .map(function (nb) { return px[nb]; });
          var bc = median(xs);
          key[id] = (bc == null) ? px[id] : bc;
        });
        ids.sort(function (a, b) {
          return (key[a] !== key[b]) ? (key[a] - key[b]) : byLabel(a, b);
        });
        spread(ids);
      }
    }

    // sigma uses a y-up coordinate system (smaller y renders lower), so the top
    // tier (band 0) must map to the LARGEST y to appear at the top of the canvas.
    nodes.forEach(function (nd) {
      var b = band[nd.id];
      var y = my + (((B - 1 - b) + 0.5) / B) * (height - 2 * my);
      pos[nd.id] = { x: px[nd.id], y: y };
    });
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

  // nodeIsDown reports whether a device is currently "failed": it has incident
  // links and every one of them is inactive. Lets the UI decide whether a node
  // click fails the device (needs confirmation) or restores it (no confirmation).
  function nodeIsDown(model, nodeId) {
    var incident = model.edges.filter(function (e) { return e.a.ip === nodeId || e.b.ip === nodeId; });
    if (!incident.length) return false;
    return incident.every(function (e) { return !e.active; });
  }

  // nodeRestoreOps returns the oper-status UP mutations to bring a device back:
  // every local interface of `nodeId` that backs an incident link.
  function nodeRestoreOps(model, nodeId) {
    var ops = [];
    model.edges.forEach(function (e) {
      if (e.a.ip === nodeId) ops.push({ ip: nodeId, ifindex: e.a.ifindex, status: 'UP' });
      if (e.b.ip === nodeId) ops.push({ ip: nodeId, ifindex: e.b.ifindex, status: 'UP' });
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

  // --- Clos fabric generator -----------------------------------------------
  //
  // A browser twin of examples/large-clos/gen-clos.py: builds a classic
  // Al-Fares folded 3-tier fat-tree from a single even parameter k. Kept
  // pure/DOM-free so the wizard's live preview and its submit fan-out call the
  // same code (they can never disagree) and it is node-testable. See gen-clos.py
  // for the canonical formulae and the rationale behind MAX_K.

  // MAX_K mirrors gen-clos.py: the aggregation-tier resource (Arista 7280R3)
  // has 32 ports — the tightest interface table — so k > 32 would reference
  // ports that don't exist on the agg switches.
  var CLOS_MAX_K = 32;

  // Per-tier base IP offset (from the base-subnet network address) and resource
  // file, fixed to gen-clos.py's BASE / RES. Default base 10.42.0.0/16 →
  // core 10.42.0.1, agg 10.42.4.1, edge 10.42.8.1, host 10.42.16.1.
  var CLOS_TIERS = [
    { key: 'core', offset: 1,    resource: 'cisco_crs_x.json',         label: 'core (Tier 1)' },
    { key: 'agg',  offset: 1025, resource: 'arista_7280r3.json',       label: 'aggregation (Tier 2)' },
    { key: 'edge', offset: 2049, resource: 'cisco_catalyst_9500.json', label: 'edge (Tier 3)' },
    { key: 'host', offset: 4097, resource: 'linux_server.json',        label: 'hosts' }
  ];

  function ipToInt(ip) {
    var p = String(ip).split('.');
    return (((+p[0]) << 24) >>> 0) + ((+p[1]) << 16) + ((+p[2]) << 8) + (+p[3]);
  }
  function intToIp(n) {
    n = n >>> 0;
    return [(n >>> 24) & 255, (n >>> 16) & 255, (n >>> 8) & 255, n & 255].join('.');
  }

  // closKError returns a human-readable error string when k is not a valid
  // fabric size (even integer in 2..MAX_K), or null when k is valid.
  function closKError(k) {
    if (!Number.isInteger(k)) return 'k must be an integer';
    if (k < 2) return 'k must be at least 2';
    if (k % 2 !== 0) return 'k must be even';
    if (k > CLOS_MAX_K) return 'k must be <= ' + CLOS_MAX_K + ' (Arista 7280R3 has ' + CLOS_MAX_K + ' ports)';
    return null;
  }

  // closSubnetError validates a fabric base subnet string. It must be a dotted
  // IPv4 address with an optional prefix that, if present, must be /16: the
  // fixed tier offsets span up to ~12k addresses (a /16), so any smaller prefix
  // would put device IPs outside the declared subnet (design.md D5 fixes the
  // per-tier netmask at /16). Returns an error string, or null when valid.
  function closSubnetError(baseSubnet) {
    baseSubnet = String(baseSubnet || '').trim();
    if (!baseSubnet) return 'base subnet is required';
    var slash = baseSubnet.indexOf('/');
    var ipPart = slash >= 0 ? baseSubnet.slice(0, slash) : baseSubnet;
    var prefix = slash >= 0 ? baseSubnet.slice(slash + 1) : '16';
    var quad = ipPart.split('.');
    if (quad.length !== 4 || quad.some(function (o) { return !/^\d{1,3}$/.test(o) || +o > 255; })) {
      return 'base subnet must be a dotted IPv4 address';
    }
    if (!/^\d{1,2}$/.test(prefix) || +prefix !== 16) {
      return 'fabric base subnet must be a /16';
    }
    return null;
  }

  // closCounts returns the per-tier device counts plus totals for a valid k,
  // computed analytically (no link build) — feeds the wizard's live preview.
  // Returns null when k is invalid.
  function closCounts(k) {
    if (closKError(k)) return null;
    var half = k / 2;
    var core = half * half;          // (k/2)^2
    var agg = k * half;              // k pods * k/2
    var edge = k * half;            // k pods * k/2
    var host = k * half * half;      // k^3 / 4
    return {
      k: k, core: core, agg: agg, edge: edge, host: host,
      devices: core + agg + edge + host,
      links: 3 * k * half * half     // edge↔agg + agg↔core + edge↔host
    };
  }

  // buildClosFabric builds the full fabric: per-tier device batches and the
  // undirected inter-device LLDP link graph. Throws on an invalid k or an
  // unparsable base subnet. baseSubnet is "A.B.C.D" or "A.B.C.D/NN" (the prefix
  // becomes the netmask for every tier's device-creation request; default 16).
  function buildClosFabric(k, baseSubnet) {
    var kerr = closKError(k);
    if (kerr) throw new Error(kerr);
    var serr = closSubnetError(baseSubnet);
    if (serr) throw new Error(serr);
    var half = k / 2;

    baseSubnet = String(baseSubnet || '10.42.0.0/16').trim();
    var slash = baseSubnet.indexOf('/');
    var ipPart = slash >= 0 ? baseSubnet.slice(0, slash) : baseSubnet;
    // Netmask is fixed at /16 (design.md D5): the fabric's tier offsets span a
    // /16, so every tier's device-creation request uses /16 regardless of the
    // operator's input. Normalize the base to its /16 network address so host
    // bits in the typed address don't shift the whole plan.
    var netmask = '16';
    var baseInt = (ipToInt(ipPart) & 0xFFFF0000) >>> 0;

    // Per-tier base int + a closure to resolve a tier-relative index to an IP.
    var counts = closCounts(k);
    var baseOf = {};
    var tiers = CLOS_TIERS.map(function (t) {
      baseOf[t.key] = baseInt + t.offset;
      return {
        key: t.key,
        label: t.label,
        resource_file: t.resource,
        start_ip: intToIp(baseInt + t.offset),
        count: counts[t.key]
      };
    });
    function ip(tier, idx) { return intToIp(baseOf[tier] + idx); }

    function coreId(j, i) { return j * half + i; }   // core group j, member i
    function aggId(p, a) { return p * half + a; }     // pod p, agg switch a
    function edgeId(p, e) { return p * half + e; }    // pod p, edge switch e
    function hostId(p, e, h) { return (p * half + e) * half + h; }

    var links = [];
    // Edge <-> aggregation: full mesh inside each pod. Edge uplink ports
    // 1..k/2, aggregation downlink ports 1..k/2.
    for (var p = 0; p < k; p++) {
      for (var e = 0; e < half; e++) {
        for (var a = 0; a < half; a++) {
          links.push({
            a: { ip: ip('edge', edgeId(p, e)), ifindex: 1 + a },
            b: { ip: ip('agg', aggId(p, a)), ifindex: 1 + e }
          });
        }
      }
    }
    // Aggregation <-> core: agg switch a connects to core group a; agg uplink
    // ports k/2+1..k; each core uses port (pod+1), one per pod.
    for (var p2 = 0; p2 < k; p2++) {
      for (var a2 = 0; a2 < half; a2++) {
        for (var i2 = 0; i2 < half; i2++) {
          links.push({
            a: { ip: ip('agg', aggId(p2, a2)), ifindex: half + 1 + i2 },
            b: { ip: ip('core', coreId(a2, i2)), ifindex: 1 + p2 }
          });
        }
      }
    }
    // Edge <-> host: each edge switch fans out to k/2 hosts on downlink ports
    // k/2+1..k; the host uses eth0 (ifIndex 2).
    for (var p3 = 0; p3 < k; p3++) {
      for (var e3 = 0; e3 < half; e3++) {
        for (var h3 = 0; h3 < half; h3++) {
          links.push({
            a: { ip: ip('edge', edgeId(p3, e3)), ifindex: half + 1 + h3 },
            b: { ip: ip('host', hostId(p3, e3, h3)), ifindex: 2 }
          });
        }
      }
    }

    return { tiers: tiers, links: links, netmask: netmask };
  }

  // closDeviceBatches splits one fabric tier into contiguous device-creation
  // batches of at most chunkSize each ({start_ip, count}), preserving the exact
  // IP set a single {tier.start_ip, tier.count} request would create. Device
  // creation is synchronous server-side, and the HTTP server enforces a 30s
  // WriteTimeout — a single huge tier (e.g. 8192 hosts, ~5 min) blocks one
  // request far past that deadline, so the server drops the response and the
  // wizard mis-reads a fully-successful create as a failure. Small batches keep
  // every POST /devices well under the deadline. Pure/testable.
  function closDeviceBatches(tier, chunkSize) {
    var batches = [];
    var baseInt = ipToInt(tier.start_ip);
    for (var off = 0; off < tier.count; off += chunkSize) {
      batches.push({
        start_ip: intToIp(baseInt + off),
        count: Math.min(chunkSize, tier.count - off)
      });
    }
    return batches;
  }

  return {
    CLOS_MAX_K: CLOS_MAX_K,
    closKError: closKError,
    closSubnetError: closSubnetError,
    closCounts: closCounts,
    buildClosFabric: buildClosFabric,
    closDeviceBatches: closDeviceBatches,
    ipToInt: ipToInt,
    intToIp: intToIp,
    SCALE_CAP: SCALE_CAP,
    edgeKey: edgeKey,
    buildModel: buildModel,
    structureKey: structureKey,
    needsRelayout: needsRelayout,
    forceLayout: forceLayout,
    tieredLayout: tieredLayout,
    edgeToggleOps: edgeToggleOps,
    nodeFailOps: nodeFailOps,
    nodeIsDown: nodeIsDown,
    nodeRestoreOps: nodeRestoreOps,
    scaleDecision: scaleDecision
  };
});
