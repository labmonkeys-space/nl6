/*
 * Copyright 2026 Ronny Trommer <ronny@no42.org>
 * SPDX-License-Identifier: Apache-2.0
 */

package main

import (
	"fmt"
	"log"
	"sort"
	"strconv"
	"time"

	gnmipb "github.com/openconfig/gnmi/proto/gnmi"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// pathResolver translates gNMI paths under
// `/interfaces/interface[name=*]/state/...` into a flat list of
// (path, typed-value) updates sourced from the device's
// IfCounterCycler. Coverage and value sources are locked in
// design.md §D10.
//
// The resolver is read-only and stateless aside from its back-references
// to the per-device cycler and ifDescr lookup. Every Resolve call
// captures a single timestamp so all returned values are coherent — the
// same property the SNMP and sFlow paths rely on (see
// IfCounterCycler.GetDynamicAt doc).
//
// descrToIndex is a precomputed `ifDescr → ifIndex` map used for O(1)
// reverse-lookup when a client asks for a specific interface name (P20).
// Duplicate ifDescr values are logged once at resolver construction
// (P19) — the lower ifIndex wins so the lookup is deterministic.
type pathResolver struct {
	device       *DeviceSimulator
	descrToIndex map[string]int
}

// newPathResolver builds a pathResolver for d. It precomputes the
// ifDescr → ifIndex reverse-lookup table once so per-Resolve work is
// O(1) rather than O(N) (P20). Duplicate ifDescr values across
// ifIndices are logged at construction time (P19) — the smaller
// ifIndex wins for the reverse lookup.
//
// Safe to call when the device's IfCounterCycler hasn't been
// initialised yet — the map will be empty and Resolve will surface the
// "interface counters not initialized" error at request time.
func newPathResolver(d *DeviceSimulator) *pathResolver {
	r := &pathResolver{device: d, descrToIndex: map[string]int{}}
	if d == nil || d.metricsCycler == nil {
		return r
	}
	ic := d.metricsCycler.ifCounters.Load()
	if ic == nil {
		return r
	}
	indices := ic.IfIndices()
	// Sort to make the duplicate-detection deterministic: the lower
	// ifIndex always wins, and shadowing warnings always name the same
	// pair regardless of map iteration order.
	sorted := make([]int, len(indices))
	copy(sorted, indices)
	sort.Ints(sorted)
	devIP := ""
	if d.IP != nil {
		devIP = d.IP.String()
	}
	for _, ifIndex := range sorted {
		descr := lookupIfDescr(d, ifIndex)
		if descr == "" {
			continue
		}
		if prev, ok := r.descrToIndex[descr]; ok {
			log.Printf("gNMI: duplicate ifDescr %q on device %s shadowing ifIndex %d→%d", descr, devIP, prev, ifIndex)
			continue
		}
		r.descrToIndex[descr] = ifIndex
	}
	return r
}

// gnmiVersion advertised in CapabilityResponse. Tracks the gNMI proto
// shipped by the pinned `github.com/openconfig/gnmi` module — bump when
// upgrading that dependency if the proto's spec-version banner moves.
const gnmiVersion = "0.10.0"

// gnmiCounterLeaves enumerates the 12 counter leaves under
// `/interfaces/interface[name=*]/state/counters/`. Order is the order
// emitted when a subtree subscribe lands on `state/counters`.
var gnmiCounterLeaves = []struct {
	leaf      string
	prefix    string // ifTablePrefix or ifXTablePrefix
	column    int
}{
	{"in-octets", ifXTablePrefix, colIfHCInOctets},
	{"out-octets", ifXTablePrefix, colIfHCOutOctets},
	{"in-unicast-pkts", ifXTablePrefix, colIfHCInUcastPkts},
	{"in-multicast-pkts", ifXTablePrefix, colIfHCInMulticastPkts},
	{"in-broadcast-pkts", ifXTablePrefix, colIfHCInBroadcastPkts},
	{"out-unicast-pkts", ifXTablePrefix, colIfHCOutUcastPkts},
	{"out-multicast-pkts", ifXTablePrefix, colIfHCOutMulticastPkts},
	{"out-broadcast-pkts", ifXTablePrefix, colIfHCOutBroadcastPkts},
	{"in-discards", ifTablePrefix, colIfInDiscards},
	{"in-errors", ifTablePrefix, colIfInErrors},
	{"out-discards", ifTablePrefix, colIfOutDiscards},
	{"out-errors", ifTablePrefix, colIfOutErrors},
}

// gnmiStateLeaves enumerates the 4 non-counter leaves under
// `/interfaces/interface[name=*]/state/`. Counter leaves are listed
// separately in gnmiCounterLeaves.
var gnmiStateLeaves = []string{"name", "ifindex", "oper-status", "admin-status"}

// resolvedUpdate is the resolver's intermediate value type. It carries
// a fully-formed gNMI Path plus a typed Go value. The handler converts
// the value into a TypedValue per the requested encoding.
type resolvedUpdate struct {
	Path *gnmipb.Path
	// Value is one of: string, uint32, uint64. The gNMI encoder branches
	// on the dynamic type.
	Value interface{}
}

// Resolve walks p and returns one resolvedUpdate per concrete leaf the
// path covers. Wildcard `interface[name=*]` expands to every known
// ifIndex; specific names resolve via reverse ifDescr lookup; subtree
// paths flatten to all leaves under that subtree.
//
// Out-of-scope paths return codes.NotFound. Unknown specific names
// return codes.NotFound.
func (r *pathResolver) Resolve(p *gnmipb.Path, t time.Time) ([]resolvedUpdate, error) {
	if p == nil {
		return nil, status.Error(codes.NotFound, "empty gNMI path")
	}
	// DF3: only the OpenConfig namespace is served. Empty origin is the
	// conventional default → OpenConfig. Any other non-empty origin (e.g.
	// "junos", "cisco-iosxr") would be a vendor model the simulator does
	// not expose; return NotFound rather than silently serving OpenConfig
	// data labelled with the requested origin.
	if origin := p.GetOrigin(); origin != "" && origin != "openconfig" {
		return nil, status.Errorf(codes.NotFound, "origin %q not supported (only openconfig)", origin)
	}
	// P5: capture the IfCounterCycler once per Resolve so every value
	// in the response is read from the same cycler instance. This
	// preserves the SNMP/sFlow byte-identity invariant (a swap of the
	// underlying cycler mid-call would otherwise interleave samples).
	if r.device == nil || r.device.metricsCycler == nil {
		return nil, status.Error(codes.Unavailable, "interface counters not initialized")
	}
	ic := r.device.metricsCycler.ifCounters.Load()
	if ic == nil {
		return nil, status.Error(codes.Unavailable, "interface counters not initialized")
	}

	elems := p.GetElem()
	// Path must start `/interfaces/interface[...]`.
	if len(elems) < 2 || elems[0].GetName() != "interfaces" || elems[1].GetName() != "interface" {
		return nil, status.Errorf(codes.NotFound, "path %q is not under /interfaces/interface", pathToString(p))
	}

	// Resolve ifIndex set. The `name` key is required to be present; an
	// explicit empty value is rejected (P13) so wildcard intent is
	// always made explicit via name=*. A missing `name` key (no key map
	// at all on the `interface` PathElem) is treated as wildcard for
	// client-compat with tools that elide keys when the list is the
	// only entry being requested.
	keys := elems[1].GetKey()
	var nameKey string
	if keys == nil {
		nameKey = "*"
	} else {
		v, ok := keys["name"]
		switch {
		case !ok:
			nameKey = "*"
		case v == "":
			return nil, status.Error(codes.InvalidArgument, "interface name key must not be empty (use name=* for wildcard)")
		default:
			nameKey = v
		}
	}
	ifIndices, err := r.expandInterfaceKey(ic, nameKey)
	if err != nil {
		return nil, err
	}

	// Walk the rest of the path. Supported shapes:
	//   /interfaces/interface[name=...]                                -> subtree under state/
	//   /interfaces/interface[name=...]/state                          -> all 4 state leaves + 12 counter leaves
	//   /interfaces/interface[name=...]/state/<leaf>                   -> single leaf
	//   /interfaces/interface[name=...]/state/counters                 -> 12 counter leaves
	//   /interfaces/interface[name=...]/state/counters/<leaf>          -> single counter leaf
	rest := elems[2:]

	// Collapse to the canonical "list of leaves to emit" form.
	leaves, err := r.expandLeafSelector(rest)
	if err != nil {
		return nil, err
	}

	// Emit (ifIndex, leaf) pairs. Use the cycler captured above so all
	// counter reads share the same `t` reference.
	tSec := t.Sub(ic.startTime).Seconds()
	out := make([]resolvedUpdate, 0, len(ifIndices)*len(leaves))
	for _, ifIndex := range ifIndices {
		for _, leaf := range leaves {
			upd, ok := r.resolveLeaf(ic, ifIndex, leaf, tSec)
			if !ok {
				continue
			}
			out = append(out, upd)
		}
	}
	return out, nil
}

// Capabilities returns the static CapabilityResponse advertised by the
// gNMI server. Encodings: JSON_IETF + PROTO. Models: openconfig-interfaces.
func (r *pathResolver) Capabilities() *gnmipb.CapabilityResponse {
	return &gnmipb.CapabilityResponse{
		SupportedModels: []*gnmipb.ModelData{
			{
				Name:         "openconfig-interfaces",
				Organization: "OpenConfig working group",
				Version:      "3.0.0",
			},
		},
		SupportedEncodings: []gnmipb.Encoding{
			gnmipb.Encoding_JSON_IETF,
			gnmipb.Encoding_PROTO,
		},
		GNMIVersion: gnmiVersion,
	}
}

// expandInterfaceKey turns the `name=` key value into a slice of
// ifIndex values. `*` wildcards over IfIndices(). Any other value uses
// the precomputed descrToIndex map (P20) for an O(1) reverse lookup.
// Empty `name` was already rejected by Resolve (P13); this function
// never sees it.
func (r *pathResolver) expandInterfaceKey(ic *IfCounterCycler, name string) ([]int, error) {
	if name == "*" {
		// IfIndices() is read-only; copy avoids accidental mutation.
		all := ic.IfIndices()
		dst := make([]int, len(all))
		copy(dst, all)
		return dst, nil
	}
	if idx, ok := r.descrToIndex[name]; ok {
		return []int{idx}, nil
	}
	return nil, status.Errorf(codes.NotFound, "unknown interface name %q", name)
}

// expandLeafSelector translates the trailing path segments
// (everything after `interface[name=...]`) into the set of state leaves
// to emit. See Resolve for the supported shapes.
func (r *pathResolver) expandLeafSelector(rest []*gnmipb.PathElem) ([]string, error) {
	// Empty rest → emit every state leaf + counter leaf.
	if len(rest) == 0 {
		return r.allLeaves(), nil
	}
	// Anything not under `state` is out of scope (config/, subinterfaces/, …).
	if rest[0].GetName() != "state" {
		return nil, status.Errorf(codes.NotFound, "only /interfaces/interface[]/state is supported, got %q", rest[0].GetName())
	}
	rest = rest[1:]
	// `/state` with no further leaves → all 16 leaves.
	if len(rest) == 0 {
		return r.allLeaves(), nil
	}
	// `/state/counters` (subtree) or `/state/counters/<leaf>`.
	if rest[0].GetName() == "counters" {
		rest = rest[1:]
		if len(rest) == 0 {
			leaves := make([]string, 0, len(gnmiCounterLeaves))
			for _, c := range gnmiCounterLeaves {
				leaves = append(leaves, "counters/"+c.leaf)
			}
			return leaves, nil
		}
		if len(rest) > 1 {
			return nil, status.Errorf(codes.NotFound, "unexpected path depth under /state/counters")
		}
		// Validate the named counter leaf is one we know.
		for _, c := range gnmiCounterLeaves {
			if c.leaf == rest[0].GetName() {
				return []string{"counters/" + c.leaf}, nil
			}
		}
		return nil, status.Errorf(codes.NotFound, "unknown counter leaf %q", rest[0].GetName())
	}
	// Single state leaf (name | ifindex | oper-status | admin-status).
	if len(rest) > 1 {
		return nil, status.Errorf(codes.NotFound, "unexpected path depth under /state")
	}
	for _, leaf := range gnmiStateLeaves {
		if leaf == rest[0].GetName() {
			return []string{leaf}, nil
		}
	}
	return nil, status.Errorf(codes.NotFound, "unknown state leaf %q", rest[0].GetName())
}

// allLeaves returns every leaf under /state (4 simple + 12 counter).
func (r *pathResolver) allLeaves() []string {
	out := make([]string, 0, len(gnmiStateLeaves)+len(gnmiCounterLeaves))
	out = append(out, gnmiStateLeaves...)
	for _, c := range gnmiCounterLeaves {
		out = append(out, "counters/"+c.leaf)
	}
	return out
}

// resolveLeaf converts one (ifIndex, leaf) pair into a typed update.
// `ok=false` is returned when the cycler has no value for the OID
// (defensive — should be rare given the wildcard expander only walks
// known indices). Static enum leaves (oper-status, admin-status) always
// produce the OpenConfig identityref form `openconfig-interfaces:UP`
// (P11, RFC 7951 §6.8) — the namespace prefix is part of the value the
// client receives, not metadata.
//
// `ic` is captured by Resolve so all counter reads share the same
// cycler instance (P5). `ifIndex`'s ifDescr is looked up exactly once
// per call (P21) and reused for the path-building.
func (r *pathResolver) resolveLeaf(ic *IfCounterCycler, ifIndex int, leaf string, tSec float64) (resolvedUpdate, bool) {
	ifName := lookupIfDescr(r.device, ifIndex)
	if ifName == "" {
		ifName = synthIfName(ifIndex)
	}

	var (
		path  *gnmipb.Path
		value interface{}
	)

	switch leaf {
	case "name":
		path = buildStateLeafPath(ifName, "name")
		value = ifName
	case "ifindex":
		path = buildStateLeafPath(ifName, "ifindex")
		value = uint32(ifIndex)
	case "oper-status":
		path = buildStateLeafPath(ifName, "oper-status")
		value = "openconfig-interfaces:UP"
	case "admin-status":
		path = buildStateLeafPath(ifName, "admin-status")
		value = "openconfig-interfaces:UP"
	default:
		// Counter leaf — leaf has form "counters/<name>".
		if len(leaf) <= len("counters/") || leaf[:len("counters/")] != "counters/" {
			return resolvedUpdate{}, false
		}
		counterName := leaf[len("counters/"):]
		var col struct {
			prefix string
			column int
		}
		found := false
		for _, c := range gnmiCounterLeaves {
			if c.leaf == counterName {
				col.prefix = c.prefix
				col.column = c.column
				found = true
				break
			}
		}
		if !found {
			return resolvedUpdate{}, false
		}
		oid := col.prefix + strconv.Itoa(col.column) + "." + strconv.Itoa(ifIndex)
		raw := ic.GetDynamicAt(oid, tSec)
		if raw == "" {
			return resolvedUpdate{}, false
		}
		v, err := strconv.ParseUint(raw, 10, 64)
		if err != nil {
			return resolvedUpdate{}, false
		}
		path = buildCounterLeafPath(ifName, counterName)
		value = v
	}

	return resolvedUpdate{Path: path, Value: value}, true
}

// buildStateLeafPath constructs a fully-keyed path
// `/interfaces/interface[name=<ifName>]/state/<leaf>`.
func buildStateLeafPath(ifName, leaf string) *gnmipb.Path {
	return &gnmipb.Path{
		Elem: []*gnmipb.PathElem{
			{Name: "interfaces"},
			{Name: "interface", Key: map[string]string{"name": ifName}},
			{Name: "state"},
			{Name: leaf},
		},
	}
}

// buildCounterLeafPath constructs a fully-keyed path
// `/interfaces/interface[name=<ifName>]/state/counters/<leaf>`.
func buildCounterLeafPath(ifName, leaf string) *gnmipb.Path {
	return &gnmipb.Path{
		Elem: []*gnmipb.PathElem{
			{Name: "interfaces"},
			{Name: "interface", Key: map[string]string{"name": ifName}},
			{Name: "state"},
			{Name: "counters"},
			{Name: leaf},
		},
	}
}

// pathToString renders a gNMI Path back into the canonical
// `/foo/bar[k=v]/baz` form for error messages. Keys within a single
// PathElem are emitted in sorted order so error messages are stable
// regardless of map iteration order (P18) — gNMI paths are usually
// keyed by `name` only, but multi-key list keys exist in OpenConfig
// and stability matters for log diffing.
func pathToString(p *gnmipb.Path) string {
	if p == nil {
		return ""
	}
	out := ""
	for _, e := range p.GetElem() {
		out += "/" + e.GetName()
		keys := e.GetKey()
		if len(keys) == 0 {
			continue
		}
		sortedKeys := make([]string, 0, len(keys))
		for k := range keys {
			sortedKeys = append(sortedKeys, k)
		}
		sort.Strings(sortedKeys)
		for _, k := range sortedKeys {
			out += fmt.Sprintf("[%s=%s]", k, keys[k])
		}
	}
	if out == "" {
		return "/"
	}
	return out
}
