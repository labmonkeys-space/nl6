/*
 * Copyright 2026 Ronny Trommer <ronny@no42.org>
 * SPDX-License-Identifier: Apache-2.0
 */

package main

import (
	"encoding/json"
	"net/http"
	"testing"
)

func getGraph(t *testing.T, router http.Handler) topologyGraph {
	t.Helper()
	w := doReq(t, router, http.MethodGet, "/api/v1/topology/graph", "")
	if w.Code != http.StatusOK {
		t.Fatalf("graph status = %d", w.Code)
	}
	var g topologyGraph
	if err := json.Unmarshal(w.Body.Bytes(), &g); err != nil {
		t.Fatalf("graph body: %v", err)
	}
	return g
}

func edgeFor(g topologyGraph, ip string, ifIndex int) (graphEdge, bool) {
	for _, e := range g.Edges {
		if (e.A.IP == ip && e.A.IfIndex == ifIndex) || (e.B.IP == ip && e.B.IfIndex == ifIndex) {
			return e, true
		}
	}
	return graphEdge{}, false
}

func nodeFor(g topologyGraph, ip string) (graphNode, bool) {
	for _, n := range g.Nodes {
		if n.IP == ip {
			return n, true
		}
	}
	return graphNode{}, false
}

func TestTopologyGraph_Empty(t *testing.T) {
	newLLDPFixture(t)
	g := getGraph(t, setupRoutes())
	if len(g.Nodes) != 0 || len(g.Edges) != 0 {
		t.Fatalf("empty topology graph = %d nodes / %d edges, want 0/0", len(g.Nodes), len(g.Edges))
	}
}

func TestTopologyGraph_NodesEdgesAndDegree(t *testing.T) {
	f := newLLDPFixture(t)
	a := f.addDevice(t, 1, 4, "alpha")
	b := f.addDevice(t, 2, 4, "bravo")
	c := f.addDevice(t, 3, 4, "charlie")
	// b is the hub: linked to both a and c → degree 2.
	must(t, f.mgr.topology.AddLink(ep(a.IP.String(), 1), ep(b.IP.String(), 2)))
	must(t, f.mgr.topology.AddLink(ep(b.IP.String(), 3), ep(c.IP.String(), 1)))

	g := getGraph(t, setupRoutes())
	if len(g.Nodes) != 3 || len(g.Edges) != 2 {
		t.Fatalf("graph = %d nodes / %d edges, want 3/2", len(g.Nodes), len(g.Edges))
	}
	bn, ok := nodeFor(g, b.IP.String())
	if !ok || bn.Degree != 2 || bn.SysName != "bravo" {
		t.Errorf("hub node = %+v, want degree 2 sysName bravo", bn)
	}
	an, _ := nodeFor(g, a.IP.String())
	if an.Degree != 1 || an.Missing {
		t.Errorf("leaf node = %+v, want degree 1, present", an)
	}
	// Edge carries ifName from ifDescr on both endpoints.
	e, ok := edgeFor(g, a.IP.String(), 1)
	if !ok || !e.Active || e.A.IfName == "" || e.B.IfName == "" {
		t.Errorf("edge a/1 = %+v", e)
	}
}

func TestTopologyGraph_ActiveAndDownEnd(t *testing.T) {
	f := newLLDPFixture(t)
	a := f.addDevice(t, 1, 4, "alpha")
	b := f.addDevice(t, 2, 4, "bravo")
	must(t, f.mgr.topology.AddLink(ep(a.IP.String(), 1), ep(b.IP.String(), 2)))

	g := getGraph(t, setupRoutes())
	e, _ := edgeFor(g, a.IP.String(), 1)
	if !e.Active || e.DownEnd != "" {
		t.Fatalf("edge should start active, got %+v", e)
	}

	// Down the a-side → edge inactive, downEnd identifies a.
	setOper(a, 1, false)
	g = getGraph(t, setupRoutes())
	e, _ = edgeFor(g, a.IP.String(), 1)
	if e.Active {
		t.Errorf("edge should be inactive after a-side down")
	}
	// Endpoint ordering in the edge isn't guaranteed; downEnd must point at
	// whichever side carries alpha/if1.
	downIsA := e.A.IP == a.IP.String() && e.A.IfIndex == 1
	want := "a"
	if !downIsA {
		want = "b"
	}
	if e.DownEnd != want {
		t.Errorf("downEnd = %q, want %q (alpha side)", e.DownEnd, want)
	}
}

func TestTopologyGraph_MissingEndpointNode(t *testing.T) {
	f := newLLDPFixture(t)
	a := f.addDevice(t, 1, 4, "alpha")
	// Link to a peer that does not exist → dangling endpoint.
	must(t, f.mgr.topology.AddLink(ep(a.IP.String(), 1), ep("10.42.0.250", 7)))

	g := getGraph(t, setupRoutes())
	if len(g.Nodes) != 2 {
		t.Fatalf("nodes = %d, want 2 (alpha + missing peer)", len(g.Nodes))
	}
	miss, ok := nodeFor(g, "10.42.0.250")
	if !ok || !miss.Missing {
		t.Errorf("missing peer node = %+v, want Missing=true", miss)
	}
	e, _ := edgeFor(g, a.IP.String(), 1)
	if e.Active || e.DownEnd == "" {
		t.Errorf("edge to missing peer should be inactive with a downEnd, got %+v", e)
	}
}
