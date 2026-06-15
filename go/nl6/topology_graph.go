/*
 * Copyright 2026 Ronny Trommer <ronny@no42.org>
 * SPDX-License-Identifier: Apache-2.0
 */

package main

import (
	"bytes"
	"encoding/json"
	"net"
	"net/http"
	"sort"
)

// graphEndpoint is one end of an edge in the viz-ready graph.
type graphEndpoint struct {
	IP      string `json:"ip"`
	IfIndex int    `json:"ifindex"`
	IfName  string `json:"ifName,omitempty"`
}

// graphEdge is one undirected link with server-computed live state.
// DownEnd names which endpoint(s) are down when Active is false:
// "a" | "b" | "both"; it is omitted when the edge is active.
type graphEdge struct {
	A       graphEndpoint `json:"a"`
	B       graphEndpoint `json:"b"`
	Active  bool          `json:"active"`
	DownEnd string        `json:"downEnd,omitempty"`
}

// graphNode is one device in the viz-ready graph. Missing is true when a
// link references an IP that has no live device (a dangling endpoint),
// which the visualization renders as an unresolved node.
type graphNode struct {
	IP      string `json:"ip"`
	SysName string `json:"sysName,omitempty"`
	Type    string `json:"type,omitempty"`
	Degree  int    `json:"degree"`
	Missing bool   `json:"missing,omitempty"`
}

// topologyGraph is the GET /api/v1/topology/graph response.
type topologyGraph struct {
	Nodes []graphNode `json:"nodes"`
	Edges []graphEdge `json:"edges"`
}

// endpointUp reports whether an endpoint is resolvable and operationally up.
// snapshotDevicesByIP returns an `ip → device` map and an `ip → type-label`
// map built under a single RLock. The graph handler resolves every node and
// edge against these snapshots so it never calls the O(N) FindDeviceByIP per
// endpoint — one lock acquisition per request instead of ~4·edges + nodes —
// and so the whole response sees one consistent device set (no active-edge /
// missing-node skew from a delete mid-build).
func (sm *SimulatorManager) snapshotDevicesByIP() (map[string]*DeviceSimulator, map[string]string) {
	sm.mu.RLock()
	defer sm.mu.RUnlock()
	byIP := make(map[string]*DeviceSimulator, len(sm.devices))
	for _, d := range sm.devices {
		byIP[d.IP.String()] = d
	}
	typeByIP := make(map[string]string, len(sm.deviceTypesByIP))
	for ip, slug := range sm.deviceTypesByIP {
		typeByIP[ip] = modelLabelForSlug(slug)
	}
	return byIP, typeByIP
}

// topologyGraphHandler implements GET /api/v1/topology/graph — the
// viz-ready join of the topology graph with device identity and live
// per-link state. Returns {"nodes":[],"edges":[]} when no topology exists.
//
// Notes on the graph's shape: it is edge-driven — nodes are exactly the
// distinct endpoints of configured links, so a device with no links does not
// appear. Edges are returned in configured (insertion) order, not sorted;
// nodes are sorted by IP for stable output. A link endpoint with no live
// device is emitted as a node with `missing:true` (and makes its edge
// inactive), which surfaces dangling references for topology reconciliation.
func topologyGraphHandler(w http.ResponseWriter, r *http.Request) {
	out := topologyGraph{Nodes: []graphNode{}, Edges: []graphEdge{}}
	if manager == nil || manager.topology == nil {
		writeJSON(w, out)
		return
	}

	links := manager.topology.ListLinks()
	byIP, typeByIP := manager.snapshotDevicesByIP()

	// Resolve liveness and ifName against the single snapshot.
	up := func(ip string, ifIndex int) bool {
		d := byIP[ip]
		return d != nil && operUp(d, ifIndex)
	}
	ifName := func(ip string, ifIndex int) string {
		if d := byIP[ip]; d != nil {
			return devIfDescr(d, ifIndex)
		}
		return ""
	}

	degree := map[string]int{}
	for _, l := range links {
		degree[l.A.IP]++
		degree[l.B.IP]++

		aUp := up(l.A.IP, l.A.IfIndex)
		bUp := up(l.B.IP, l.B.IfIndex)
		edge := graphEdge{
			A:      graphEndpoint{IP: l.A.IP, IfIndex: l.A.IfIndex, IfName: ifName(l.A.IP, l.A.IfIndex)},
			B:      graphEndpoint{IP: l.B.IP, IfIndex: l.B.IfIndex, IfName: ifName(l.B.IP, l.B.IfIndex)},
			Active: aUp && bUp,
		}
		if !edge.Active {
			switch {
			case !aUp && !bUp:
				edge.DownEnd = "both"
			case !aUp:
				edge.DownEnd = "a"
			default:
				edge.DownEnd = "b"
			}
		}
		out.Edges = append(out.Edges, edge)
	}

	// Build nodes from the distinct endpoint IPs, in a stable order.
	ips := make([]string, 0, len(degree))
	for ip := range degree {
		ips = append(ips, ip)
	}
	sort.Slice(ips, func(i, j int) bool {
		// Stable numeric order by IP; unparseable IPs fall back to string order.
		a, b := net.ParseIP(ips[i]), net.ParseIP(ips[j])
		if a != nil && b != nil {
			return bytes.Compare(a.To16(), b.To16()) < 0
		}
		return ips[i] < ips[j]
	})
	for _, ip := range ips {
		n := graphNode{IP: ip, Degree: degree[ip]}
		if _, ok := byIP[ip]; ok {
			n.SysName = byIP[ip].sysName
			n.Type = typeByIP[ip]
		} else {
			n.Missing = true
		}
		out.Nodes = append(out.Nodes, n)
	}

	writeJSON(w, out)
}

// writeJSON writes v as a JSON response with the correct content type.
func writeJSON(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(v)
}
