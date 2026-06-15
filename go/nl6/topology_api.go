/*
 * Copyright 2026 Ronny Trommer <ronny@no42.org>
 * SPDX-License-Identifier: Apache-2.0
 */

package main

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
)

// topologyMaxBody caps the topology request body. Generous for the schema;
// a few KiB covers hundreds of links.
const topologyMaxBody = 1 << 20 // 1 MiB

// topologyStatus is the GET /api/v1/topology/status body. Mirrors the
// subsystem_active convention of the flow / trap / syslog / gNMI status
// endpoints. ConfiguredLinks counts every undirected link; ActiveLinks
// counts those whose both endpoints are resolvable and operationally up.
type topologyStatus struct {
	SubsystemActive bool `json:"subsystem_active"`
	ConfiguredLinks int  `json:"configured_links"`
	ActiveLinks     int  `json:"active_links"`
}

// decodeTopologyBody reads and strictly-decodes a topology document from
// an HTTP request body (unknown fields rejected).
func decodeTopologyBody(r *http.Request) (TopologyDocJSON, error) {
	data, err := io.ReadAll(io.LimitReader(r.Body, topologyMaxBody))
	if err != nil {
		return TopologyDocJSON{}, err
	}
	return decodeTopologyDoc(data)
}

// createTopologyHandler implements POST /api/v1/topology. Adds one or more
// links synchronously and returns 201. A syntactic validation failure on
// any link returns 400 and rolls back every link added in this request, so
// the graph is never left partially mutated.
func createTopologyHandler(w http.ResponseWriter, r *http.Request) {
	if manager == nil || manager.topology == nil {
		sendErrorResponse(w, "topology subsystem unavailable", http.StatusServiceUnavailable)
		return
	}
	doc, err := decodeTopologyBody(r)
	if err != nil {
		sendErrorResponse(w, "invalid topology body: "+err.Error(), http.StatusBadRequest)
		return
	}
	if len(doc.Links) == 0 {
		sendErrorResponse(w, "no links in request", http.StatusBadRequest)
		return
	}

	// AddLinks validates and commits the whole batch under one lock —
	// atomic all-or-nothing even against concurrent topology requests.
	if err := manager.topology.AddLinks(doc.Links); err != nil {
		sendErrorResponse(w, err.Error(), http.StatusBadRequest)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	_ = json.NewEncoder(w).Encode(TopologyDocJSON{Links: doc.Links})
}

// listTopologyHandler implements GET /api/v1/topology → 200 {"links":[...]}.
func listTopologyHandler(w http.ResponseWriter, r *http.Request) {
	if manager == nil || manager.topology == nil {
		sendErrorResponse(w, "topology subsystem unavailable", http.StatusServiceUnavailable)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(TopologyDocJSON{Links: manager.topology.ListLinks()})
}

// deleteTopologyHandler implements DELETE /api/v1/topology. The body
// identifies a single link by its two endpoints. Returns 204 on removal,
// 404 when no matching link exists, 400 on a malformed body.
func deleteTopologyHandler(w http.ResponseWriter, r *http.Request) {
	if manager == nil || manager.topology == nil {
		sendErrorResponse(w, "topology subsystem unavailable", http.StatusServiceUnavailable)
		return
	}
	data, err := io.ReadAll(io.LimitReader(r.Body, topologyMaxBody))
	if err != nil {
		sendErrorResponse(w, "read body: "+err.Error(), http.StatusBadRequest)
		return
	}
	var link LinkJSON
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&link); err != nil {
		sendErrorResponse(w, "invalid topology body: "+err.Error(), http.StatusBadRequest)
		return
	}
	if manager.topology.RemoveLink(link.A, link.B) {
		w.WriteHeader(http.StatusNoContent)
		return
	}
	sendErrorResponse(w, "link not found", http.StatusNotFound)
}

// topologyStatusHandler implements GET /api/v1/topology/status.
func topologyStatusHandler(w http.ResponseWriter, r *http.Request) {
	st := topologyStatus{SubsystemActive: manager != nil && manager.topology != nil}
	if st.SubsystemActive {
		links := manager.topology.ListLinks()
		st.ConfiguredLinks = len(links)
		for _, l := range links {
			if manager.linkActive(l) {
				st.ActiveLinks++
			}
		}
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(st)
}

// linkActive reports whether both endpoints of an undirected link are
// resolvable (the devices exist) and operationally up — i.e. the link
// would currently produce an lldpRemTable row on both sides.
func (sm *SimulatorManager) linkActive(l LinkJSON) bool {
	da := sm.FindDeviceByIP(l.A.IP)
	db := sm.FindDeviceByIP(l.B.IP)
	if da == nil || db == nil {
		return false
	}
	return operUp(da, l.A.IfIndex) && operUp(db, l.B.IfIndex)
}
