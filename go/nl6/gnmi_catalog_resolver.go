/*
 * Copyright 2026 Ronny Trommer <ronny@no42.org>
 * SPDX-License-Identifier: Apache-2.0
 */

package main

import (
	"log"
	"sort"
	"time"

	gnmipb "github.com/openconfig/gnmi/proto/gnmi"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// catalogNotification is one list entry's worth of resolved leaves.
// Prefix is nil under `prefix: flat`, in which case Updates carry
// absolute paths.
type catalogNotification struct {
	Prefix  *gnmipb.Path
	Updates []resolvedUpdate
}

// catalogResolver answers gNMI paths from a per-type catalogue. One
// catalogue is shared by every device of the type; the resolver holds
// only the device pointer and a reverse ifDescr map.
type catalogResolver struct {
	dev          *DeviceSimulator
	cat          *gnmiCatalog
	descrToIndex map[string]int
	start        time.Time
}

func newCatalogResolver(d *DeviceSimulator, cat *gnmiCatalog) *catalogResolver {
	r := &catalogResolver{dev: d, cat: cat, descrToIndex: map[string]int{}, start: time.Now()}
	if d == nil || d.metricsCycler == nil {
		return r
	}
	if ic := d.metricsCycler.ifCounters.Load(); ic != nil {
		for _, idx := range ic.IfIndices() {
			if name := lookupIfDescr(d, idx); name != "" {
				if prev, dup := r.descrToIndex[name]; !dup || idx < prev {
					r.descrToIndex[name] = idx
				}
			}
		}
	}
	return r
}

// originAccepted reports whether the request origin is one the
// catalogue serves, and returns the catalogue origin it maps to.
func (r *catalogResolver) originAccepted(origin string) (string, bool) {
	n := r.cat.Notification
	switch origin {
	case "", n.Origin:
		return n.Origin, true
	case n.NativeOrigin:
		if n.NativeOrigin != "" {
			return n.NativeOrigin, true
		}
	}
	return "", false
}

// elemMatches reports whether request element q matches concrete
// element c: same name, and every key q carries is "*" or equal.
func elemMatches(q, c *gnmipb.PathElem) bool {
	if q.GetName() != c.GetName() {
		return false
	}
	for k, v := range q.GetKey() {
		cv := c.GetKey()[k]
		// "*" on either side matches: the request may wildcard, and an
		// unexpanded catalogue entry still carries "*" during the
		// shape-only candidate check.
		if v == "*" || cv == "*" {
			continue
		}
		if cv != v {
			return false
		}
	}
	return true
}

// pathCovers reports whether request elems q (possibly shorter) match
// concrete leaf elems c element-wise.
func pathCovers(q, c []*gnmipb.PathElem) bool {
	if len(q) > len(c) {
		return false
	}
	for i := range q {
		if !elemMatches(q[i], c[i]) {
			return false
		}
	}
	return true
}

// subtreeCandidate reports whether a request could touch a subtree
// without expanding keys: wildcard entry keys match anything.
func subtreeCandidate(q []*gnmipb.PathElem, st *gnmiCatalogSubtree) bool {
	for _, leaf := range st.Leaves {
		full := append(append([]*gnmipb.PathElem{}, st.elems...), leaf.elems...)
		if pathCovers(q, full) {
			return true
		}
	}
	return false
}

// Match is the shape-only check Get and Subscribe use to decide
// whether the catalogue owns a path.
func (r *catalogResolver) Match(p *gnmipb.Path) bool {
	origin, ok := r.originAccepted(p.GetOrigin())
	if !ok {
		return false
	}
	for _, st := range r.cat.Subtrees {
		if st.Origin == origin && subtreeCandidate(p.GetElem(), st) {
			return true
		}
	}
	return false
}

// entry is one concrete list entry: the key values in catalogue key
// order and the compiled entry path.
type catalogEntry struct {
	keys    []string
	ifIndex int
	elems   []*gnmipb.PathElem
}

// expandEntries builds the cartesian product of a subtree's key
// sources. The first key source decides ifIndex when it is
// `interfaces`.
func (r *catalogResolver) expandEntries(st *gnmiCatalogSubtree) ([]catalogEntry, error) {
	entries := []catalogEntry{{}}
	for _, k := range st.Keys {
		var names []string
		switch k.Source {
		case gnmiKeySourceInterfaces:
			if r.dev == nil || r.dev.metricsCycler == nil || r.dev.metricsCycler.ifCounters.Load() == nil {
				return nil, status.Error(codes.Unavailable, "interface counters not initialized")
			}
			for _, idx := range r.dev.metricsCycler.ifCounters.Load().IfIndices() {
				n := lookupIfDescr(r.dev, idx)
				if n == "" {
					n = synthIfName(idx)
				}
				names = append(names, n)
			}
		case gnmiKeySourceComponents:
			for _, c := range r.cat.components(k.Filter) {
				names = append(names, c.Name)
			}
		case gnmiKeySourceNeighbors:
			for _, n := range r.cat.Neighbors {
				names = append(names, n.Address)
			}
		case gnmiKeySourceStatic:
			names = k.Names
		}
		var next []catalogEntry
		for _, e := range entries {
			for _, n := range names {
				ne := catalogEntry{keys: append(append([]string{}, e.keys...), n), ifIndex: e.ifIndex}
				if len(ne.keys) == 1 && k.Source == gnmiKeySourceInterfaces {
					ne.ifIndex = r.descrToIndex[n]
					if ne.ifIndex == 0 {
						ne.ifIndex = 0
					}
				}
				next = append(next, ne)
			}
		}
		entries = next
	}
	// Fill wildcard keys in the entry path, in order.
	for i := range entries {
		ki := 0
		elems := make([]*gnmipb.PathElem, len(st.elems))
		for j, e := range st.elems {
			ne := &gnmipb.PathElem{Name: e.Name}
			if len(e.Key) > 0 {
				ne.Key = map[string]string{}
				keyNames := make([]string, 0, len(e.Key))
				for kn := range e.Key {
					keyNames = append(keyNames, kn)
				}
				sort.Strings(keyNames) // deterministic fill order for multi-key elements
				for _, kn := range keyNames {
					kv := e.Key[kn]
					if kv == "*" {
						kv = entries[i].keys[ki]
						ki++
					}
					ne.Key[kn] = kv
				}
			}
			elems[j] = ne
		}
		entries[i].elems = elems
	}
	return entries, nil
}

// Resolve returns one catalogNotification per list entry the request
// touches, with leaves narrowed to the request.
func (r *catalogResolver) Resolve(p *gnmipb.Path, now time.Time) ([]catalogNotification, error) {
	origin, ok := r.originAccepted(p.GetOrigin())
	if !ok {
		return nil, status.Errorf(codes.InvalidArgument, "origin %q not served by this device", p.GetOrigin())
	}
	q := p.GetElem()
	t := now.Sub(r.start).Seconds()
	var out []catalogNotification
	touched := false
	for _, st := range r.cat.Subtrees {
		if st.Origin != origin || !subtreeCandidate(q, st) {
			continue
		}
		touched = true
		entries, err := r.expandEntries(st)
		if err != nil {
			return nil, err
		}
		for _, e := range entries {
			var updates []resolvedUpdate
			for _, leaf := range st.Leaves {
				full := append(append([]*gnmipb.PathElem{}, e.elems...), leaf.elems...)
				if !pathCovers(q, full) {
					continue
				}
				ctx := &gnmiGenCtx{dev: r.dev, cat: r.cat, keys: e.keys, ifIndex: e.ifIndex, t: t, now: now}
				raw, ok := leaf.gen(ctx)
				if !ok {
					continue
				}
				v, err := castGnmiLeaf(raw, leaf.Type)
				if err != nil {
					log.Printf("gNMI catalog: %s leaf %s: %v (skipping)", st.Path, leaf.Name, err)
					continue
				}
				var up resolvedUpdate
				if r.cat.Notification.Prefix == gnmiPrefixListEntry {
					up = resolvedUpdate{Path: &gnmipb.Path{Elem: leaf.elems}, Value: v}
				} else {
					up = resolvedUpdate{Path: &gnmipb.Path{Origin: origin, Elem: full}, Value: v}
				}
				updates = append(updates, up)
			}
			if len(updates) == 0 {
				continue
			}
			n := catalogNotification{Updates: updates}
			if r.cat.Notification.Prefix == gnmiPrefixListEntry {
				// A root subtree ("/") yields a prefix with the origin only,
				// which is what Junos sends for /system/state.
				n.Prefix = &gnmipb.Path{Origin: origin, Elem: e.elems}
			}
			out = append(out, n)
		}
	}
	if !touched {
		return nil, status.Errorf(codes.NotFound, "path %s not served by catalogue", pathToString(p))
	}
	if len(out) == 0 {
		return nil, status.Errorf(codes.NotFound, "path %s matches no entry", pathToString(p))
	}
	return out, nil
}

// AllLeafPaths lists every served leaf with wildcard keys, for the
// manifest test.
func (r *catalogResolver) AllLeafPaths() []string {
	var out []string
	for _, st := range r.cat.Subtrees {
		for _, leaf := range st.Leaves {
			full := append(append([]*gnmipb.PathElem{}, st.elems...), leaf.elems...)
			out = append(out, pathToString(&gnmipb.Path{Elem: full}))
		}
	}
	return out
}

// Models returns the catalogue's advertised models.
func (r *catalogResolver) Models() []*gnmipb.ModelData {
	out := make([]*gnmipb.ModelData, 0, len(r.cat.Models))
	for _, m := range r.cat.Models {
		out = append(out, &gnmipb.ModelData{Name: m.Name, Organization: m.Organization, Version: m.Version})
	}
	return out
}
