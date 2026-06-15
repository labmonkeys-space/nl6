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
// A missing device (no live device at the IP) is down; otherwise liveness is
// the interface-state oper-status (no-engine treated up, per operUp).
func (sm *SimulatorManager) endpointUp(ip string, ifIndex int) bool {
	d := sm.FindDeviceByIP(ip)
	if d == nil {
		return false
	}
	return operUp(d, ifIndex)
}

// topologyGraphHandler implements GET /api/v1/topology/graph — the
// viz-ready join of the topology graph with device identity and live
// per-link state. Returns {"nodes":[],"edges":[]} when no topology exists.
func topologyGraphHandler(w http.ResponseWriter, r *http.Request) {
	out := topologyGraph{Nodes: []graphNode{}, Edges: []graphEdge{}}
	if manager == nil || manager.topology == nil {
		writeJSON(w, out)
		return
	}

	links := manager.topology.ListLinks()
	degree := map[string]int{}

	for _, l := range links {
		degree[l.A.IP]++
		degree[l.B.IP]++

		aUp := manager.endpointUp(l.A.IP, l.A.IfIndex)
		bUp := manager.endpointUp(l.B.IP, l.B.IfIndex)
		edge := graphEdge{
			A:      graphEndpoint{IP: l.A.IP, IfIndex: l.A.IfIndex, IfName: ifNameFor(manager, l.A.IP, l.A.IfIndex)},
			B:      graphEndpoint{IP: l.B.IP, IfIndex: l.B.IfIndex, IfName: ifNameFor(manager, l.B.IP, l.B.IfIndex)},
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
		if d := manager.FindDeviceByIP(ip); d != nil {
			n.SysName = d.sysName
			n.Type = manager.Model(ip)
		} else {
			n.Missing = true
		}
		out.Nodes = append(out.Nodes, n)
	}

	writeJSON(w, out)
}

// ifNameFor resolves an endpoint's ifDescr (falling back to a synthesized
// name) for display, or "" when the device is unresolvable.
func ifNameFor(sm *SimulatorManager, ip string, ifIndex int) string {
	if d := sm.FindDeviceByIP(ip); d != nil {
		return devIfDescr(d, ifIndex)
	}
	return ""
}

// writeJSON writes v as a JSON response with the correct content type.
func writeJSON(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(v)
}
