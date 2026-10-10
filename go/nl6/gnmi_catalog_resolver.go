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
// only the device pointer. start is the fallback epoch for a device
// without an interface counter cycler; see epoch.
type catalogResolver struct {
	dev   *DeviceSimulator
	cat   *gnmiCatalog
	start time.Time
}

// epoch is the device's time base: the interface counter cycler's
// start, which SNMP, sFlow and the legacy gNMI resolver also use, so a
// counter read at one instant agrees across surfaces and a gNMI server
// restart does not reset counters or boot timestamps.
func (r *catalogResolver) epoch() time.Time {
	if r.dev != nil && r.dev.metricsCycler != nil {
		if ic := r.dev.metricsCycler.ifCounters.Load(); ic != nil {
			return ic.startTime
		}
	}
	return r.start
}

func newCatalogResolver(d *DeviceSimulator, cat *gnmiCatalog) *catalogResolver {
	return &catalogResolver{dev: d, cat: cat, start: time.Now()}
}

// originAccepted reports whether the request origin is one the
// catalogue serves, and returns the catalogue origin it maps to.
func (r *catalogResolver) originAccepted(origin string) (string, bool) {
	n := r.cat.Notification
	if target, ok := n.OriginAliases[origin]; ok {
		origin = target
	}
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

// Canonicalize returns p with an aliased origin rewritten to the
// catalogue origin it stands for, so the legacy resolver behind the
// catalogue sees the same origin the catalogue would (nl6#770 review:
// an aliased origin on a path the catalogue does not own fell through
// to a resolver that refused the spelling). Unaliased paths are
// returned as-is, no copy.
func (r *catalogResolver) Canonicalize(p *gnmipb.Path) *gnmipb.Path {
	target, ok := r.cat.Notification.OriginAliases[p.GetOrigin()]
	if !ok {
		return p
	}
	cp := &gnmipb.Path{Origin: target, Elem: p.GetElem(), Target: p.GetTarget()}
	return cp
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

// elemsEqual reports whether a and b are the same path: same names and
// identical keys.
func elemsEqual(a, b []*gnmipb.PathElem) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i].GetName() != b[i].GetName() || len(a[i].GetKey()) != len(b[i].GetKey()) {
			return false
		}
		for k, v := range a[i].GetKey() {
			if bv, ok := b[i].GetKey()[k]; !ok || bv != v {
				return false
			}
		}
	}
	return true
}

// aliasSubtree returns the subtree one of whose aliases equals p, or
// nil. The request origin must be empty or the subtree's origin.
func (r *catalogResolver) aliasSubtree(p *gnmipb.Path) *gnmiCatalogSubtree {
	origin, ok := r.originAccepted(p.GetOrigin())
	if p.GetOrigin() != "" && !ok {
		return nil
	}
	for _, st := range r.cat.Subtrees {
		if p.GetOrigin() != "" && origin != st.Origin {
			continue
		}
		for _, a := range st.aliases {
			if elemsEqual(p.GetElem(), a) {
				return st
			}
		}
	}
	return nil
}

// Match is the shape-only check Get and Subscribe use to decide
// whether the catalogue owns a path.
func (r *catalogResolver) Match(p *gnmipb.Path) bool {
	if r.aliasSubtree(p) != nil {
		return true
	}
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
// sources. The `interfaces` key source, when present, sets ifIndex.
func (r *catalogResolver) expandEntries(st *gnmiCatalogSubtree) ([]catalogEntry, error) {
	entries := []catalogEntry{{}}
	for _, k := range st.Keys {
		type keyVal struct {
			name string
			idx  int
		}
		var vals []keyVal
		switch k.Source {
		case gnmiKeySourceInterfaces:
			var ic *IfCounterCycler
			if r.dev != nil && r.dev.metricsCycler != nil {
				ic = r.dev.metricsCycler.ifCounters.Load()
			}
			if ic == nil {
				return nil, status.Error(codes.Unavailable, "interface counters not initialized")
			}
			for _, idx := range ic.IfIndices() {
				n := lookupIfDescr(r.dev, idx)
				if n == "" {
					n = synthIfName(idx)
				}
				vals = append(vals, keyVal{n, idx})
			}
		default:
			names, _ := r.cat.keyValues(k) // parse rejected unknown sources
			for _, n := range names {
				vals = append(vals, keyVal{name: n})
			}
		}
		var next []catalogEntry
		for _, e := range entries {
			for _, v := range vals {
				ne := catalogEntry{keys: append(append([]string{}, e.keys...), v.name), ifIndex: e.ifIndex}
				if k.Source == gnmiKeySourceInterfaces {
					ne.ifIndex = v.idx
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
// touches, with leaves narrowed to the request. A request for a
// subtree alias returns that whole subtree.
func (r *catalogResolver) Resolve(p *gnmipb.Path, now time.Time) ([]catalogNotification, error) {
	if st := r.aliasSubtree(p); st != nil {
		return r.resolveSubtrees(p, st.Origin, nil, []*gnmiCatalogSubtree{st}, now)
	}
	origin, ok := r.originAccepted(p.GetOrigin())
	if !ok {
		return nil, status.Errorf(codes.InvalidArgument, "origin %q not served by this device", p.GetOrigin())
	}
	return r.resolveSubtrees(p, origin, p.GetElem(), r.cat.Subtrees, now)
}

// resolveSubtrees resolves request elems q (nil for everything) against
// the subtrees of the given origin. p is the client's path, for errors.
func (r *catalogResolver) resolveSubtrees(p *gnmipb.Path, origin string, q []*gnmipb.PathElem, subtrees []*gnmiCatalogSubtree, now time.Time) ([]catalogNotification, error) {
	t := now.Sub(r.epoch()).Seconds()
	var out []catalogNotification
	touched := false
	for _, st := range subtrees {
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
				if leaf.filterNames != nil && !leaf.filterNames[e.keys[st.componentKey]] {
					continue
				}
				full := append(append([]*gnmipb.PathElem{}, e.elems...), leaf.elems...)
				if !pathCovers(q, full) {
					continue
				}
				ctx := &gnmiGenCtx{dev: r.dev, cat: r.cat, keys: e.keys, ifIndex: e.ifIndex,
					componentKey: st.componentKey, neighborKey: st.neighborKey, t: t, now: now}
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
