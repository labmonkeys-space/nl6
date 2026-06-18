/*
 * Copyright 2026 Ronny Trommer <ronny@no42.org>
 * SPDX-License-Identifier: Apache-2.0
 */

package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"sort"
	"sync"
)

// linkEndpoint identifies one end of an inter-device link: a device by
// its IPv4 string and a local interface index. The pair (IP, IfIndex) is
// the unit of uniqueness — one link per local port (point-to-point).
type linkEndpoint struct {
	IP      string
	IfIndex int
}

// topoLink is one undirected link between two endpoints. Stored once in
// the canonical list; adjacency for both devices is derived from it.
type topoLink struct {
	A linkEndpoint
	B linkEndpoint
}

// localLink is a device-centric view of a link: the local interface, the
// peer's IP, and the peer's interface index. Returned by LinksFor so the
// LLDP provider can build local-port and remote-table rows without
// re-deriving direction.
type localLink struct {
	LocalIfIndex int
	PeerIP       string
	PeerIfIndex  int
}

// Topology is the simulator-wide inter-device link graph owned by
// SimulatorManager. It is the single source of truth for who-connects-to-whom.
//
// Validation at add time is syntactic only (well-formed, no self-loop, no
// duplicate, one link per local port). Device existence and ifIndex
// ownership are NOT checked here — they resolve lazily at SNMP-serve time
// (see lldp_table.go). This dissolves the load-vs-async-device-creation
// ordering race: -topology-config may reference devices that the
// background auto-start goroutine has not created yet.
type Topology struct {
	mu    sync.RWMutex
	links []topoLink
	// adj is the device-centric adjacency index: device IP → its local
	// links. It mirrors `links` (each undirected link contributes an entry
	// to BOTH endpoints) and exists so LinksFor is O(degree) instead of
	// O(total links). The LLDP walk hot path calls LinksFor once per walk
	// step, so an O(N) scan over a large fabric (thousands of links) turned
	// a single GETBULK walk into O(steps × N). Maintained incrementally on
	// AddLinks and rebuilt wholesale on the rare Remove/Prune/Clear paths.
	// Entries are NOT pre-sorted; LinksFor sorts its O(degree) copy on read.
	adj map[string][]localLink
}

// NewTopology returns an empty graph.
func NewTopology() *Topology {
	return &Topology{adj: make(map[string][]localLink)}
}

// indexLink adds both device-centric views of an undirected link to the
// adjacency index. Caller holds t.mu.
func (t *Topology) indexLink(l topoLink) {
	if t.adj == nil {
		t.adj = make(map[string][]localLink)
	}
	t.adj[l.A.IP] = append(t.adj[l.A.IP], localLink{LocalIfIndex: l.A.IfIndex, PeerIP: l.B.IP, PeerIfIndex: l.B.IfIndex})
	t.adj[l.B.IP] = append(t.adj[l.B.IP], localLink{LocalIfIndex: l.B.IfIndex, PeerIP: l.A.IP, PeerIfIndex: l.A.IfIndex})
}

// rebuildAdj reconstructs the adjacency index from t.links. Caller holds
// t.mu. Used by the remove/prune paths where incremental deletion across
// both endpoints' slices would be more error-prone than a clean rebuild
// (these paths are rare relative to LinksFor reads).
func (t *Topology) rebuildAdj() {
	t.adj = make(map[string][]localLink, len(t.adj))
	for _, l := range t.links {
		t.indexLink(l)
	}
}

// LinkEndpointJSON is the wire shape of one endpoint.
type LinkEndpointJSON struct {
	IP      string `json:"ip"`
	IfIndex int    `json:"ifindex"`
}

// LinkJSON is the wire shape of one undirected link.
type LinkJSON struct {
	A LinkEndpointJSON `json:"a"`
	B LinkEndpointJSON `json:"b"`
}

// TopologyDocJSON is the wire shape of the -topology-config file and the
// POST/GET/DELETE /api/v1/topology body: {"links":[{"a":{...},"b":{...}}]}.
type TopologyDocJSON struct {
	Links []LinkJSON `json:"links"`
}

// normEndpoint validates and normalises a wire endpoint into the internal
// form. The IP must parse as IPv4 and is stored as its canonical dotted
// quad so "10.0.0.1" and "10.000.000.001" compare equal.
func normEndpoint(e LinkEndpointJSON) (linkEndpoint, error) {
	ip := net.ParseIP(e.IP)
	if ip == nil || ip.To4() == nil {
		return linkEndpoint{}, fmt.Errorf("invalid IPv4 %q", e.IP)
	}
	if e.IfIndex < 1 {
		return linkEndpoint{}, fmt.Errorf("ifindex must be >= 1, got %d", e.IfIndex)
	}
	return linkEndpoint{IP: ip.To4().String(), IfIndex: e.IfIndex}, nil
}

// AddLink validates and inserts a single undirected link. See AddLinks for
// the batch form; this is a thin wrapper for single-link callers.
func (t *Topology) AddLink(a, b LinkEndpointJSON) error {
	return t.AddLinks([]LinkJSON{{A: a, B: b}})
}

// AddLinks validates and inserts a batch of undirected links atomically:
// the entire batch is validated and committed under a single lock, and if
// any link is rejected the whole batch is rolled back (no partial mutation,
// even under concurrent callers). Syntactic rejections: self-loop (both
// ends identical), exact duplicate (same undirected pair already present,
// including earlier in this same batch), and reused local port (either
// endpoint already used — point-to-point only). Device existence / ifIndex
// ownership are deliberately NOT checked (lazy resolution).
func (t *Topology) AddLinks(links []LinkJSON) error {
	pending := make([]topoLink, 0, len(links))
	for _, l := range links {
		ae, err := normEndpoint(l.A)
		if err != nil {
			return fmt.Errorf("endpoint a: %w", err)
		}
		be, err := normEndpoint(l.B)
		if err != nil {
			return fmt.Errorf("endpoint b: %w", err)
		}
		if ae == be {
			return fmt.Errorf("self-loop rejected: %s/%d linked to itself", ae.IP, ae.IfIndex)
		}
		pending = append(pending, topoLink{A: ae, B: be})
	}

	t.mu.Lock()
	defer t.mu.Unlock()

	start := len(t.links)
	for _, nl := range pending {
		if err := t.validateAgainstLinks(nl); err != nil {
			t.links = t.links[:start] // roll back the whole batch
			return err
		}
		t.links = append(t.links, nl)
	}
	// Commit succeeded for the whole batch — only now touch the adjacency
	// index so a mid-batch rollback never leaves it half-populated.
	for _, nl := range pending {
		t.indexLink(nl)
	}
	return nil
}

// validateAgainstLinks checks a normalised link against the current link
// set (including any added earlier in the same batch). Caller holds t.mu.
func (t *Topology) validateAgainstLinks(nl topoLink) error {
	for _, l := range t.links {
		if (l.A == nl.A && l.B == nl.B) || (l.A == nl.B && l.B == nl.A) {
			return fmt.Errorf("duplicate link %s/%d <-> %s/%d", nl.A.IP, nl.A.IfIndex, nl.B.IP, nl.B.IfIndex)
		}
		if l.A == nl.A || l.B == nl.A {
			return fmt.Errorf("port already linked: %s/%d", nl.A.IP, nl.A.IfIndex)
		}
		if l.A == nl.B || l.B == nl.B {
			return fmt.Errorf("port already linked: %s/%d", nl.B.IP, nl.B.IfIndex)
		}
	}
	return nil
}

// Clear removes every link. Used when all devices are deleted so no
// dangling edges survive.
func (t *Topology) Clear() {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.links = nil
	t.adj = make(map[string][]localLink)
}

// RemoveLink removes the undirected link identified by its two endpoints.
// Returns true if a matching link was found and removed, false otherwise.
func (t *Topology) RemoveLink(a, b LinkEndpointJSON) bool {
	ae, err := normEndpoint(a)
	if err != nil {
		return false
	}
	be, err := normEndpoint(b)
	if err != nil {
		return false
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	for i, l := range t.links {
		if (l.A == ae && l.B == be) || (l.A == be && l.B == ae) {
			t.links = append(t.links[:i], t.links[i+1:]...)
			t.rebuildAdj()
			return true
		}
	}
	return false
}

// PruneDevice removes every link with an endpoint on the given device IP.
// Called from DeleteDevice so a deleted device leaves no dangling edges.
func (t *Topology) PruneDevice(ip string) {
	parsed := net.ParseIP(ip)
	if parsed == nil || parsed.To4() == nil {
		return
	}
	norm := parsed.To4().String()
	t.mu.Lock()
	defer t.mu.Unlock()
	kept := t.links[:0]
	for _, l := range t.links {
		if l.A.IP == norm || l.B.IP == norm {
			continue
		}
		kept = append(kept, l)
	}
	t.links = kept
	t.rebuildAdj()
}

// LinksFor returns the device-centric links touching the given IP, in
// ascending local-ifIndex order so LLDP walk enumeration is deterministic.
func (t *Topology) LinksFor(ip string) []localLink {
	parsed := net.ParseIP(ip)
	if parsed == nil || parsed.To4() == nil {
		return nil
	}
	norm := parsed.To4().String()
	t.mu.RLock()
	defer t.mu.RUnlock()
	entries := t.adj[norm]
	if len(entries) == 0 {
		return nil
	}
	// Copy so the caller can't mutate (or observe a later mutation of) the
	// index slice, then sort the O(degree) copy by local ifIndex for
	// deterministic LLDP walk enumeration.
	out := make([]localLink, len(entries))
	copy(out, entries)
	sort.Slice(out, func(i, j int) bool { return out[i].LocalIfIndex < out[j].LocalIfIndex })
	return out
}

// ListLinks returns a copy of every undirected link as wire JSON, for
// GET /api/v1/topology.
func (t *Topology) ListLinks() []LinkJSON {
	t.mu.RLock()
	defer t.mu.RUnlock()
	out := make([]LinkJSON, 0, len(t.links))
	for _, l := range t.links {
		out = append(out, LinkJSON{
			A: LinkEndpointJSON{IP: l.A.IP, IfIndex: l.A.IfIndex},
			B: LinkEndpointJSON{IP: l.B.IP, IfIndex: l.B.IfIndex},
		})
	}
	return out
}

// Count returns the number of configured undirected links.
func (t *Topology) Count() int {
	t.mu.RLock()
	defer t.mu.RUnlock()
	return len(t.links)
}

// decodeTopologyDoc parses a topology document, rejecting unknown JSON
// fields so typo'd keys fail loudly rather than silently dropping links.
func decodeTopologyDoc(data []byte) (TopologyDocJSON, error) {
	var doc TopologyDocJSON
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&doc); err != nil {
		return TopologyDocJSON{}, err
	}
	return doc, nil
}

// LoadFromFile reads a -topology-config JSON file and adds every link.
// Returns an error on parse failure or the first syntactic validation
// failure (the caller turns this into a fatal startup error).
func (t *Topology) LoadFromFile(path string) error {
	data, err := os.ReadFile(path)
	if err != nil {
		return fmt.Errorf("read topology config %q: %w", path, err)
	}
	doc, err := decodeTopologyDoc(data)
	if err != nil {
		return fmt.Errorf("parse topology config %q: %w", path, err)
	}
	if err := t.AddLinks(doc.Links); err != nil {
		return fmt.Errorf("topology config %q: %w", path, err)
	}
	return nil
}
