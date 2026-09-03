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
	"strings"
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
		// Seed the reverse lookup from BOTH real ifDescr (when present)
		// AND the synth name fallback. Without the synth seeding, devices
		// whose JSON lacks `ifDescr.<N>` for some interfaces emit ON_CHANGE
		// events whose path's `name` key resolves only via synthIfName at
		// emit time, but `ifIndexFromPath` lookups miss → events silently
		// dropped. Real ifDescr takes precedence over synth (same ifDescr
		// → first wins; synth is appended after).
		descr := lookupIfDescr(d, ifIndex)
		if descr != "" {
			if prev, ok := r.descrToIndex[descr]; ok {
				log.Printf("gNMI: duplicate ifDescr %q on device %s shadowing ifIndex %d→%d", descr, devIP, prev, ifIndex)
			} else {
				r.descrToIndex[descr] = ifIndex
			}
		}
		// Synth-name fallback: gnmi_paths.go's resolveLeaf uses
		// synthIfName(ifIndex) when lookupIfDescr returns "". Seed the
		// reverse lookup with the same form so ifIndexFromPath finds it.
		synth := synthIfName(ifIndex)
		if synth != "" && synth != descr {
			if _, ok := r.descrToIndex[synth]; !ok {
				r.descrToIndex[synth] = ifIndex
			}
		}
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
	leaf   string
	prefix string // ifTablePrefix or ifXTablePrefix
	column int
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

// gnmiStateLeaves enumerates the 5 non-counter leaves under
// `/interfaces/interface[name=*]/state/`. Counter leaves are listed
// separately in gnmiCounterLeaves. `last-change` was added by the
// add-interface-state change (§D6); ON_CHANGE subscriptions on this
// leaf fire whenever any state mutation updates the slot's
// lastChangeNs.
var gnmiStateLeaves = []string{"name", "ifindex", "oper-status", "admin-status", "last-change"}

// operStatusOpenConfig maps the IF-MIB / state-engine integer enum to
// the OpenConfig identityref string. Explicit `OperUnknown` case avoids
// relying on the default branch coincidentally returning "UNKNOWN".
// Values outside the IF-MIB range return "UNKNOWN".
func operStatusOpenConfig(v uint8) string {
	switch v {
	case OperUp:
		return "openconfig-interfaces:UP"
	case OperDown:
		return "openconfig-interfaces:DOWN"
	case OperTesting:
		return "openconfig-interfaces:TESTING"
	case OperUnknown:
		return "openconfig-interfaces:UNKNOWN"
	case OperDormant:
		return "openconfig-interfaces:DORMANT"
	case OperNotPresent:
		return "openconfig-interfaces:NOT_PRESENT"
	case OperLowerLayerDn:
		return "openconfig-interfaces:LOWER_LAYER_DOWN"
	default:
		return "openconfig-interfaces:UNKNOWN"
	}
}

// adminStatusOpenConfig maps ifAdminStatus integer enum (UP=1, DOWN=2,
// TESTING=3) to the OpenConfig identityref string. **Asymmetric vs
// `operStatusOpenConfig`:** IF-MIB has no `adminUnknown` enum value, so
// the default branch returns UP rather than UNKNOWN. The state-engine
// mutators reject out-of-range values, so this fallback is reachable
// only from a future contributor's bug; the UP default keeps the
// system in a safer mode than a phantom "UNKNOWN" admin state would.
func adminStatusOpenConfig(v uint8) string {
	switch v {
	case AdminUp:
		return "openconfig-interfaces:UP"
	case AdminDown:
		return "openconfig-interfaces:DOWN"
	case AdminTesting:
		return "openconfig-interfaces:TESTING"
	default:
		return "openconfig-interfaces:UP"
	}
}

// isStateOnlyLeaf returns true when leaf is one of the 5 static-or-state
// leaves that may be ON_CHANGE subscribed (§D5). Counter leaves return
// false. Used by the ON_CHANGE Subscribe handler to gate per-sub paths
// — counter-touching paths are rejected with InvalidArgument.
func isStateOnlyLeaf(leaf string) bool {
	for _, l := range gnmiStateLeaves {
		if l == leaf {
			return true
		}
	}
	return false
}

// opticalLeafKind classifies a served optical leaf by its container shape
// in the pinned model, which is what decides how a path expands.
type opticalLeafKind uint8

const (
	// opticalLeafScalar lives in BOTH `config/` and `state/` and has no
	// statistics container (frequency, operational-mode, line-port,
	// target-output-power).
	opticalLeafScalar opticalLeafKind = iota
	// opticalLeafStats lives under `state/<leaf>/` with an
	// {instant,avg,min,max} container.
	opticalLeafStats
	// opticalLeafCounter lives directly under `state/` as a bare counter
	// leaf — fec-uncorrectable-blocks is the only one, and it explicitly
	// has NO statistics container in the pinned revision.
	opticalLeafCounter
)

// gnmiOpticalLeaves is the served optical surface, taken verbatim from the
// pinned OpenConfig revisions (openconfig-terminal-device 2026-01-14 +
// openconfig-platform-transceiver 2026-03-25, whose `optical-power-state`
// grouping supplies input/output power and laser bias). Every entry is
// reachable under the single prefix
// `/components/component[name=$och]/optical-channel/`, because
// `optical-channel` augments `/components/component`.
//
// This table IS the served contract: gnmiOpticalPathManifest derives the
// full path list from it, and TestOpticalPathManifest pins that list, so a
// leaf invented here fails CI rather than a collector's schema validation.
// Leaf names must never be invented — the epic's fidelity rule is that a
// path whose existence cannot be confirmed is omitted, not guessed.
//
// `post-fec-ber` is deliberately ABSENT despite existing in OpenConfig:
// Ciena removed it from their model, so a collector rule keyed on it would
// never fire against real hardware. That is a faithfulness choice, not an
// omission — see design.md.
var gnmiOpticalLeaves = []struct {
	leaf string
	kind opticalLeafKind
}{
	// config/ + state/ scalars.
	{OpticalLeafFrequency, opticalLeafScalar},
	{OpticalLeafTargetOutputPower, opticalLeafScalar},
	{OpticalLeafOperationalMode, opticalLeafScalar},
	{OpticalLeafLinePort, opticalLeafScalar},
	// state/<leaf>/{instant,avg,min,max}. Receive-side spine first, then
	// the off-spine leaves that stay flat under a receive fault.
	{OpticalLeafInputPower, opticalLeafStats},
	{OpticalLeafOSNR, opticalLeafStats},
	{OpticalLeafESNR, opticalLeafStats},
	{OpticalLeafQValue, opticalLeafStats},
	{OpticalLeafPreFECBER, opticalLeafStats},
	{OpticalLeafOutputPower, opticalLeafStats},
	{OpticalLeafLaserBias, opticalLeafStats},
	{OpticalLeafChromaticDisp, opticalLeafStats},
	{OpticalLeafPMD, opticalLeafStats},
	{OpticalLeafPDL, opticalLeafStats},
	// Bare counter, no statistics container.
	{OpticalLeafUncorrBlock, opticalLeafCounter},
}

// opticalStats is the statistics-container selector set, in emission order.
var opticalStats = []string{OpticalStatInstant, OpticalStatAvg, OpticalStatMin, OpticalStatMax}

// opticalLeafKindOf returns the leaf's container shape, and whether it is
// served at all. An unserved name (including `post-fec-ber`) returns false
// so callers can surface NotFound.
func opticalLeafKindOf(leaf string) (opticalLeafKind, bool) {
	for _, l := range gnmiOpticalLeaves {
		if l.leaf == leaf {
			return l.kind, true
		}
	}
	return 0, false
}

// isOpticalLeafSelector reports whether a ClassifyLeaves result came from
// the optical branch. Selectors carry their container prefix (`state/…` or
// `config/…`), which the interface branch never produces, so the ON_CHANGE
// validator can branch its rejection message on leaf CLASS instead of
// calling every rejected leaf a counter.
func isOpticalLeafSelector(sel string) bool {
	return strings.HasPrefix(sel, "state/") || strings.HasPrefix(sel, "config/")
}

// resolvedUpdate is the resolver's intermediate value type. It carries
// a fully-formed gNMI Path plus a typed Go value. The handler converts
// the value into a TypedValue per the requested encoding.
type resolvedUpdate struct {
	Path *gnmipb.Path
	// Value is one of: string, uint32, uint64, gnmiDecimal. The gNMI
	// encoder branches on the dynamic type.
	Value interface{}
}

// gnmiDecimal is a fixed-precision decimal, carrying the value together
// with the `fraction-digits` its YANG type declares.
//
// It exists as a distinct type rather than a pre-formatted string
// because the two advertised encodings need different renderings of the
// same value: RFC 7951 §6.1 requires decimal64 be a JSON *string* under
// JSON_IETF, while PROTO needs `double_val`. Handing the encoder a Go
// string would silently take the `string_val` branch and quietly
// corrupt an advertised encoding — the value would look right in
// JSON_IETF and be wrong in PROTO.
//
// Precision caveat: optical bit error rates carry 18 fraction digits,
// which exceeds a float64 significand, so `double_val` is lossy for
// them. That is inherent to representing decimal64 in gNMI's PROTO
// scalar set; JSON_IETF preserves the digits.
type gnmiDecimal struct {
	val    float64
	digits int
}

// String renders the value with exactly `digits` fraction digits, which
// is the RFC 7951 decimal64 lexical form.
func (d gnmiDecimal) String() string {
	return strconv.FormatFloat(d.val, 'f', d.digits, 64)
}

// ClassifyLeaves returns the leaf-name list a path covers, without
// performing any state-engine or counter reads. Used by the ON_CHANGE
// handler to validate that every sub's path touches only static leaves
// BEFORE registering listeners or doing real Resolve work — avoiding
// the cost of wildcard expansion and counter computation when the
// validator only needs the path's SHAPE.
//
// Returns codes.NotFound for out-of-scope paths and the same codes
// Resolve would return for shape errors; never returns Unavailable
// (it doesn't depend on the counter engine being initialised).
//
// Leaf names are the trailing identifier (`oper-status`, `in-octets`,
// etc.). Counter leaves are returned as bare names (`in-octets`, not
// `counters/in-octets`) so the caller can detect them via the
// gnmiCounterLeaves table or by checking `isStateOnlyLeaf` returning
// false.
func (r *pathResolver) ClassifyLeaves(p *gnmipb.Path) ([]string, error) {
	if p == nil {
		return nil, status.Error(codes.NotFound, "empty gNMI path")
	}
	if origin := p.GetOrigin(); origin != "" && origin != "openconfig" {
		return nil, status.Errorf(codes.NotFound, "origin %q not supported (only openconfig)", origin)
	}
	elems := p.GetElem()
	if len(elems) == 0 {
		return nil, status.Errorf(codes.NotFound, "path %q is not under /interfaces/interface or /components/component", pathToString(p))
	}
	
	// Altiplano dynamic schema interception
	if elems[0].GetName() == "access-node" {
		return []string{}, nil
	}

	// Optical branch: shape-only, so it deliberately does NOT consult the
	// value engine — not even to check whether one exists. A device without
	// optical channels still gets a shape answer here, and the ON_CHANGE
	// validator rejects the path on leaf class; the NotFound for "no optical
	// channels" belongs to Resolve, which is where a value is actually asked
	// for. Keeping the split means ON_CHANGE validation can never return
	// Unavailable, which is its whole reason for existing.
	if elems[0].GetName() == "components" {
		if len(elems) >= 2 && elems[1].GetName() != "component" {
			return nil, status.Errorf(codes.NotFound, "only /components/component is supported, got %q", elems[1].GetName())
		}
		return expandOpticalLeafSelector(componentRest(elems))
	}
	if len(elems) < 2 || elems[0].GetName() != "interfaces" || elems[1].GetName() != "interface" {
		return nil, status.Errorf(codes.NotFound, "path %q is not under /interfaces/interface or /components/component", pathToString(p))
	}
	leafSelector, err := r.expandLeafSelector(elems[2:])
	if err != nil {
		return nil, err
	}
	// expandLeafSelector returns counter leaves prefixed with "counters/".
	// Strip that prefix so callers can use isStateOnlyLeaf directly.
	out := make([]string, len(leafSelector))
	for i, l := range leafSelector {
		if strings.HasPrefix(l, "counters/") {
			out[i] = l[len("counters/"):]
		} else {
			out[i] = l
		}
	}
	return out, nil
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

	elems := p.GetElem()
	if len(elems) == 0 {
		return nil, status.Errorf(codes.NotFound, "path %q is not under /interfaces/interface or /components/component", pathToString(p))
	}

	// Altiplano dynamic schema interception
	if r.device != nil && r.device.AltiplanoData != nil {
		if elems[0].GetName() == "interfaces" || elems[0].GetName() == "access-node" {
			return r.resolveAltiplano(p)
		}
	}

	// Two served branches, dispatched on the first element. `/components`
	// carries the optical surface; `/interfaces` the packet surface.
	if elems[0].GetName() == "components" {
		return r.resolveComponents(p, elems, t)
	}

	// Path must start `/interfaces/interface[...]`.
	if len(elems) < 2 || elems[0].GetName() != "interfaces" || elems[1].GetName() != "interface" {
		return nil, status.Errorf(codes.NotFound, "path %q is not under /interfaces/interface or /components/component", pathToString(p))
	}

	// P5: capture the IfCounterCycler once per Resolve so every value in the
	// response is read from the same cycler instance. This preserves the
	// SNMP/sFlow byte-identity invariant (a swap of the underlying cycler
	// mid-call would otherwise interleave samples).
	//
	// The capture lives HERE, inside the interfaces branch, not at the top of
	// Resolve: hoisted, it asserted the *interface* engine for every path, so
	// an optical Get against a device with no HC counters failed with
	// `Unavailable: interface counters not initialized` — a misleading code on
	// a path that never touches that engine.
	if r.device == nil || r.device.metricsCycler == nil {
		return nil, status.Error(codes.Unavailable, "interface counters not initialized")
	}
	ic := r.device.metricsCycler.ifCounters.Load()
	if ic == nil {
		return nil, status.Error(codes.Unavailable, "interface counters not initialized")
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

// opticalCycler returns the device's optical engine, distinguishing the two
// reasons it can be missing — a distinction the gRPC code must preserve:
//
//   - a PACKET device has no optical channels and never will, so an optical
//     path is permanently absent → NotFound. Returning Unavailable there
//     would be retryable, wrongly inviting a client to poll forever for a
//     surface the device cannot have.
//   - an OPTICAL device mid-initialisation has channels but no published
//     engine yet → Unavailable, which correctly says "try again".
func (r *pathResolver) opticalCycler() (*OpticalCycler, error) {
	if r.device == nil {
		return nil, status.Error(codes.NotFound, "device serves no optical channels")
	}
	if r.device.metricsCycler != nil {
		if oc := r.device.metricsCycler.OpticalCyclerOf(); oc != nil {
			return oc, nil
		}
	}
	// The device-type check comes BEFORE the nil-metricsCycler case, so a
	// missing cycler on an optical type reports the retryable code. Both
	// creation paths assign metricsCycler before the gNMI server starts, so
	// this ordering is unobservable today — but getting it backwards would
	// make a future lazy-init report a permanent absence for a device that is
	// merely still starting.
	if r.opticalCapable() {
		return nil, status.Error(codes.Unavailable, "optical engine not initialized yet")
	}
	return nil, status.Error(codes.NotFound, "device serves no optical channels")
}

// opticalCapable reports whether this device's TYPE has optical channels,
// independent of whether the engine is published yet.
func (r *pathResolver) opticalCapable() bool {
	return r.device != nil && IsOpticalDeviceType(r.device.resourceFile)
}

// resolveComponents handles `/components/component[name=…]/optical-channel/…`.
// Shapes, mirroring the interface branch:
//
//	/components                                              -> every channel, every leaf
//	/components/component[name=*]                            -> every channel, every leaf
//	/components/component[name=OCH-1-1]                      -> one channel, every leaf
//	…/optical-channel                                        -> every leaf
//	…/optical-channel/config                                 -> the 4 config scalars
//	…/optical-channel/config/frequency                       -> one scalar
//	…/optical-channel/state                                  -> every state leaf
//	…/optical-channel/state/osnr                             -> that stats container (4)
//	…/optical-channel/state/osnr/avg                          -> one statistic
//	…/optical-channel/state/fec-uncorrectable-blocks         -> the bare counter
func (r *pathResolver) resolveComponents(p *gnmipb.Path, elems []*gnmipb.PathElem, t time.Time) ([]resolvedUpdate, error) {
	oc, err := r.opticalCycler()
	if err != nil {
		return nil, err
	}
	names, err := r.expandComponentKey(oc, elems)
	if err != nil {
		return nil, err
	}
	selectors, err := expandOpticalLeafSelector(componentRest(elems))
	if err != nil {
		return nil, err
	}

	// One elapsed offset for the whole response, from the optical engine's
	// own startTime — the same contract the interface branch has, so every
	// value in a response is coherent and gNMI agrees with the cycler (and
	// therefore with any other surface) at the same instant.
	tSec := t.Sub(oc.StartTime()).Seconds()
	out := make([]resolvedUpdate, 0, len(names)*len(selectors))
	for _, name := range names {
		for _, sel := range selectors {
			container, leafPath, _ := strings.Cut(sel, "/")
			value, ok := oc.GetDynamicAt(name, opticalEngineLeaf(sel), tSec)
			if !ok {
				continue
			}
			out = append(out, resolvedUpdate{
				Path:  buildOpticalPath(name, container, leafPath),
				Value: value,
			})
		}
	}
	return out, nil
}

// opticalEngineLeaf maps a served selector onto the leaf name the value
// engine expects. The engine is container-agnostic — `config/frequency` and
// `state/frequency` are the same quantity, because a simulator's configured
// intent and operational state cannot diverge — so the container prefix is
// stripped and statistics selectors keep their `<leaf>/<stat>` shape.
func opticalEngineLeaf(selector string) string {
	_, rest, found := strings.Cut(selector, "/")
	if !found {
		return selector
	}
	return rest
}

// expandComponentKey resolves the `component[name=…]` key to a channel set.
// `*`, a missing key map, and a bare `/components` all wildcard over the
// engine's sorted channel list, so expansion is deterministic.
func (r *pathResolver) expandComponentKey(oc *OpticalCycler, elems []*gnmipb.PathElem) ([]string, error) {
	all := oc.Components()
	if len(elems) < 2 {
		// Bare `/components` — every channel.
		dst := make([]string, len(all))
		copy(dst, all)
		return dst, nil
	}
	if elems[1].GetName() != "component" {
		return nil, status.Errorf(codes.NotFound, "only /components/component is supported, got %q", elems[1].GetName())
	}
	keys := elems[1].GetKey()
	name := "*"
	if keys != nil {
		v, ok := keys["name"]
		switch {
		case !ok:
			name = "*"
		case v == "":
			// Same contract as the interface branch: wildcard intent must be
			// explicit, so an empty key is a client bug rather than "all".
			return nil, status.Error(codes.InvalidArgument, "component name key must not be empty (use name=* for wildcard)")
		default:
			name = v
		}
	}
	if name == "*" {
		dst := make([]string, len(all))
		copy(dst, all)
		return dst, nil
	}
	for _, n := range all {
		if n == name {
			return []string{name}, nil
		}
	}
	return nil, status.Errorf(codes.NotFound, "unknown component name %q", name)
}

// componentRest returns the path segments after `component[name=…]`.
func componentRest(elems []*gnmipb.PathElem) []*gnmipb.PathElem {
	if len(elems) < 2 {
		return nil
	}
	return elems[2:]
}

// expandOpticalLeafSelector translates the segments after
// `component[name=…]` into fully-qualified selectors of the form
// `config/<leaf>`, `state/<leaf>` or `state/<leaf>/<stat>`.
//
// It reads no values, so ClassifyLeaves can share it and keep its
// shape-only contract (which is what keeps ON_CHANGE rejection cheap and
// unable to return Unavailable).
func expandOpticalLeafSelector(rest []*gnmipb.PathElem) ([]string, error) {
	// `/components/component[name=…]` with nothing further, or an explicit
	// `optical-channel` with nothing further → the whole subtree.
	if len(rest) == 0 {
		return allOpticalSelectors(), nil
	}
	if rest[0].GetName() != "optical-channel" {
		return nil, status.Errorf(codes.NotFound,
			"only /components/component[]/optical-channel is supported, got %q", rest[0].GetName())
	}
	rest = rest[1:]
	if len(rest) == 0 {
		return allOpticalSelectors(), nil
	}

	container := rest[0].GetName()
	if container != "config" && container != "state" {
		return nil, status.Errorf(codes.NotFound,
			"only optical-channel/config and optical-channel/state are supported, got %q", container)
	}
	rest = rest[1:]
	// A whole container.
	if len(rest) == 0 {
		return opticalSelectorsFor(container), nil
	}

	leaf := rest[0].GetName()
	kind, served := opticalLeafKindOf(leaf)
	if !served {
		return nil, status.Errorf(codes.NotFound, "unknown or unserved optical leaf %q", leaf)
	}
	// `config/` holds only the scalars; the measured leaves are state-only.
	if container == "config" && kind != opticalLeafScalar {
		return nil, status.Errorf(codes.NotFound, "optical leaf %q exists only under state/", leaf)
	}
	rest = rest[1:]

	switch kind {
	case opticalLeafScalar, opticalLeafCounter:
		if len(rest) > 0 {
			// fec-uncorrectable-blocks is a BARE counter in the pinned model.
			// Asking for `/instant` on it is exactly the mistake a collector
			// author makes by analogy with the other leaves, so the error says
			// why rather than just "not found".
			if kind == opticalLeafCounter {
				return nil, status.Errorf(codes.NotFound,
					"optical leaf %q is a bare counter with no statistics container; drop the %q selector",
					leaf, rest[0].GetName())
			}
			return nil, status.Errorf(codes.NotFound, "unexpected path depth under %s/%s", container, leaf)
		}
		return []string{container + "/" + leaf}, nil
	default: // opticalLeafStats
		if len(rest) == 0 {
			out := make([]string, 0, len(opticalStats))
			for _, s := range opticalStats {
				out = append(out, container+"/"+leaf+"/"+s)
			}
			return out, nil
		}
		if len(rest) > 1 {
			return nil, status.Errorf(codes.NotFound, "unexpected path depth under %s/%s", container, leaf)
		}
		stat := rest[0].GetName()
		for _, s := range opticalStats {
			if s == stat {
				return []string{container + "/" + leaf + "/" + stat}, nil
			}
		}
		return nil, status.Errorf(codes.NotFound, "unknown statistic %q on optical leaf %q", stat, leaf)
	}
}

// opticalSelectorsFor returns every selector in one container.
func opticalSelectorsFor(container string) []string {
	out := make([]string, 0, len(gnmiOpticalLeaves)*len(opticalStats))
	for _, l := range gnmiOpticalLeaves {
		switch l.kind {
		case opticalLeafScalar:
			out = append(out, container+"/"+l.leaf)
		case opticalLeafCounter:
			if container == "state" {
				out = append(out, container+"/"+l.leaf)
			}
		default:
			if container == "state" {
				for _, s := range opticalStats {
					out = append(out, container+"/"+l.leaf+"/"+s)
				}
			}
		}
	}
	return out
}

// allOpticalSelectors returns every served selector, config before state.
func allOpticalSelectors() []string {
	return append(opticalSelectorsFor("config"), opticalSelectorsFor("state")...)
}

// buildOpticalPath constructs a fully-keyed path
// `/components/component[name=<och>]/optical-channel/<container>/<leaf>[/<stat>]`.
func buildOpticalPath(component, container, leafPath string) *gnmipb.Path {
	elems := []*gnmipb.PathElem{
		{Name: "components"},
		{Name: "component", Key: map[string]string{"name": component}},
		{Name: "optical-channel"},
		{Name: container},
	}
	for _, seg := range strings.Split(leafPath, "/") {
		if seg != "" {
			elems = append(elems, &gnmipb.PathElem{Name: seg})
		}
	}
	return &gnmipb.Path{Elem: elems}
}

// gnmiOpticalPathManifest returns every path this resolver serves for one
// component, in canonical string form. Derived from gnmiOpticalLeaves so it
// cannot drift from what Resolve emits; pinned by TestOpticalPathManifest
// against the table traced from the pinned OpenConfig revisions, so an
// invented or dropped path fails in CI rather than at a collector.
func gnmiOpticalPathManifest(component string) []string {
	sels := allOpticalSelectors()
	out := make([]string, 0, len(sels))
	for _, sel := range sels {
		container, leafPath, _ := strings.Cut(sel, "/")
		out = append(out, pathToString(buildOpticalPath(component, container, leafPath)))
	}
	return out
}

// Capabilities returns the static CapabilityResponse advertised by the
// gNMI server. Encodings: JSON_IETF + PROTO.
//
// Models: openconfig-interfaces for the packet surface, plus the three the
// optical surface is drawn from. `openconfig-platform-transceiver` is not
// optional decoration — `optical-channel/state` reuses its
// `optical-power-state` grouping for input-power, output-power and
// laser-bias-current, so a client validating against the advertised model
// set would fail to find those leaves if it were omitted.
//
// Versions are the pinned revisions the served paths were traced against
// (design.md); they and gnmiOpticalLeaves move together.
//
// The optical models are advertised ONLY by optically-capable devices. A
// collector that generates subscriptions from Capabilities would otherwise
// subscribe optical paths against a packet device and get a stream that
// sends sync_response and then nothing forever — every tick resolves
// NotFound, which the SAMPLE path logs and skips, so the client sees no
// error at all. Advertising a model is a claim the device can serve it.
func (r *pathResolver) Capabilities() *gnmipb.CapabilityResponse {
	models := []*gnmipb.ModelData{
		{
			Name:         "openconfig-interfaces",
			Organization: "OpenConfig working group",
			Version:      "3.0.0",
		},
	}
	if r.opticalCapable() {
		models = append(models,
			&gnmipb.ModelData{
				Name:         "openconfig-terminal-device",
				Organization: "OpenConfig working group",
				Version:      "2026-01-14",
			},
			&gnmipb.ModelData{
				Name:         "openconfig-platform",
				Organization: "OpenConfig working group",
				Version:      "2025-07-15",
			},
			&gnmipb.ModelData{
				Name:         "openconfig-platform-transceiver",
				Organization: "OpenConfig working group",
				Version:      "2026-03-25",
			},
		)
	}
	return &gnmipb.CapabilityResponse{
		SupportedModels: models,
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
		// Read from the interface state engine (post add-interface-state).
		// nil-state defensive path returns the OpenConfig UP default —
		// matches behavior pre-state-engine for backward-compat.
		v := OperUp
		if state := ic.State(); state != nil {
			v = state.OperStatus(ifIndex)
		}
		value = operStatusOpenConfig(v)
	case "admin-status":
		path = buildStateLeafPath(ifName, "admin-status")
		v := AdminUp
		if state := ic.State(); state != nil {
			v = state.AdminStatus(ifIndex)
		}
		value = adminStatusOpenConfig(v)
	case "last-change":
		// OpenConfig last-change is uint64 nanoseconds since Unix epoch.
		// The state engine returns absolute Unix nanos directly. When the
		// state engine is nil (test harness only — production paths
		// always have a state engine via InitIfCountersWithScenario), skip
		// the leaf entirely (ok=false) rather than emitting `0` which a
		// collector would parse as "1970-01-01" timestamp.
		state := ic.State()
		if state == nil {
			return resolvedUpdate{}, false
		}
		path = buildStateLeafPath(ifName, "last-change")
		value = state.LastChangeNs(ifIndex)
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
