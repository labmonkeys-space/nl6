/*
 * Copyright 2026 Ronny Trommer <ronny@no42.org>
 * SPDX-License-Identifier: Apache-2.0
 */

package main

import (
	"reflect"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// Counter roll-up: children bounded by their parent, aggregates equal to the
// sum of their members. Every test reads through GetDynamicAt at explicit
// instants and drives holds through the test seam, as the hold tests do.

// newRollupCycler builds: 1 eth0, 2 eth1, 3 eth0.100, 4 eth0.200, 5 be1
// (aggregate of 1 and 2, via ifStackTable), 6 be1.300, 7 eth7 standalone.
func newRollupCycler(t *testing.T) *IfCounterCycler {
	t.Helper()
	res := buildTestResources(t, []uint64{1e9, 1e9, 1e9, 1e9, 2e9, 2e9, 1e9})
	names := map[int]string{1: "eth0", 2: "eth1", 3: "eth0.100", 4: "eth0.200", 5: "be1", 6: "be1.300", 7: "eth7"}
	for i, n := range names {
		res.oidIndex.Store(ifTablePrefix+"2."+strconv.Itoa(i), n)
		res.oidIndex.Store(oidIfAdminStatus+"."+strconv.Itoa(i), "1")
		res.oidIndex.Store(oidIfOperStatus+"."+strconv.Itoa(i), "1")
	}
	res.SNMP = append(res.SNMP,
		SNMPResource{OID: "1.3.6.1.2.1.31.1.2.1.3.5.1", Response: "1"},
		SNMPResource{OID: "1.3.6.1.2.1.31.1.2.1.3.5.2", Response: "1"},
	)
	mc := NewMetricsCycler(0, GetDeviceProfile(""))
	mc.InitIfCountersWithScenario(res, 1, IfErrorTypical)
	ic := mc.ifCounters.Load()
	if ic == nil {
		t.Fatal("no cycler")
	}
	return ic
}

// counter32Shadow reports the Counter32 columns that are the low 32 bits of a
// Counter64 column. They wrap independently of the column they shadow, so no
// sum or bound is meaningful on them; the bound is pinned on the HC column.
func counter32Shadow(prefix string) bool {
	for _, s := range []string{ifTablePrefix + "10.", ifTablePrefix + "11.", ifTablePrefix + "16.", ifTablePrefix + "17.", ifXTablePrefix + "2.", ifXTablePrefix + "3.", ifXTablePrefix + "4.", ifXTablePrefix + "5."} {
		if prefix == s {
			return true
		}
	}
	return false
}

func col(t *testing.T, ic *IfCounterCycler, prefix string, ifIndex int, at float64) uint64 {
	t.Helper()
	return ctr(t, ic.GetDynamicAt(prefix+strconv.Itoa(ifIndex), at))
}

func TestRollup_HierarchyIsBuilt(t *testing.T) {
	ic := newRollupCycler(t)
	if got := ic.members[4]; !reflect.DeepEqual(got, []int{1, 2}) {
		t.Errorf("members of be1 = %v, want [1 2]", got)
	}
	if ic.counterParent[2] != 1 || ic.counterParent[3] != 1 || ic.counterParent[5] != 5 {
		t.Errorf("parents = %v", ic.counterParent)
	}
	if s := ic.share[2] + ic.share[3]; s >= 1 || s <= 0 {
		t.Errorf("sibling shares sum to %v, want in (0, 1)", s)
	}
	if ic.State().Parent(5) != 0 {
		t.Error("the aggregate has a parent in the state engine")
	}
}

func TestRollup_ChildrenBoundedByParentOnEveryColumn(t *testing.T) {
	ic := newRollupCycler(t)
	for _, c := range heldColumns() {
		if counter32Shadow(c) {
			continue
		}
		for _, at := range []float64{0, 600, 3600, 7200} {
			p := col(t, ic, c, 1, at)
			if s := col(t, ic, c, 3, at) + col(t, ic, c, 4, at); s > p {
				t.Errorf("%s at t=%g: children %d > parent %d", c, at, s, p)
			}
			if col(t, ic, c, 3, at) == 0 && c == ifXTablePrefix+"6." {
				t.Errorf("%s at t=%g: child reads 0", c, at)
			}
			// The bound on growth, not only on the pre-seeded total: a child
			// that took its parent's whole delta would still pass the total
			// for hours against a 24 h base.
			pg := p - col(t, ic, c, 1, 0)
			if cg := col(t, ic, c, 3, at) + col(t, ic, c, 4, at) - col(t, ic, c, 3, 0) - col(t, ic, c, 4, 0); cg > pg {
				t.Errorf("%s at t=%g: children grew %d, parent %d", c, at, cg, pg)
			}
		}
	}
}

func TestRollup_AggregateEqualsMembersOnEveryColumn(t *testing.T) {
	ic := newRollupCycler(t)
	for _, c := range heldColumns() {
		if counter32Shadow(c) {
			continue
		}
		octets := c == ifXTablePrefix+"6." || c == ifXTablePrefix+"10."
		for _, at := range []float64{0, 600, 3600, 7200} {
			agg := col(t, ic, c, 5, at)
			sum := col(t, ic, c, 1, at) + col(t, ic, c, 2, at)
			// Packet, error and discard columns floor a sum against a sum of
			// floors, so the aggregate reads at or above the member sum by
			// at most (members - 1).
			switch {
			case octets && agg != sum:
				t.Errorf("%s at t=%g: aggregate %d != member sum %d", c, at, agg, sum)
			case !octets && (agg < sum || agg-sum > 1):
				t.Errorf("%s at t=%g: aggregate %d, member sum %d, want sum..sum+1", c, at, agg, sum)
			}
		}
	}
	// And the bundle subinterface is bounded by the bundle.
	for _, at := range []float64{0, 600, 3600} {
		if b, s := col(t, ic, ifXTablePrefix+"6.", 5, at), col(t, ic, ifXTablePrefix+"6.", 6, at); s > b || s == 0 {
			t.Errorf("t=%g: be1.300 %d, be1 %d", at, s, b)
		}
	}
}

func TestRollup_BoundSurvivesAParentFlap(t *testing.T) {
	ic := newRollupCycler(t)
	const in = ifXTablePrefix + "6."
	moveLink(t, ic.State(), 1, OperDown)
	ic.reconcileHold(1, 100)
	ic.reconcileHold(3, 100)
	ic.reconcileHold(4, 100)
	if ic.State().OperStatus(3) != OperLowerLayerDn {
		t.Fatal("child did not follow its parent down")
	}
	for _, at := range []float64{100, 120, 130} {
		p, s := col(t, ic, in, 1, at), col(t, ic, in, 3, at)+col(t, ic, in, 4, at)
		if s > p {
			t.Errorf("held t=%g: children %d > parent %d", at, s, p)
		}
		if p != col(t, ic, in, 1, 100) || s != col(t, ic, in, 3, 100)+col(t, ic, in, 4, 100) {
			t.Errorf("t=%g: parent or children moved while held", at)
		}
	}
	moveLink(t, ic.State(), 1, OperUp)
	ic.reconcileHold(1, 130)
	ic.reconcileHold(3, 130)
	ic.reconcileHold(4, 130)
	for _, at := range []float64{130, 140, 1000} {
		if p, s := col(t, ic, in, 1, at), col(t, ic, in, 3, at)+col(t, ic, in, 4, at); s > p {
			t.Errorf("after recovery t=%g: children %d > parent %d", at, s, p)
		}
	}
	if a, b := col(t, ic, in, 3, 130), col(t, ic, in, 3, 1000); b <= a {
		t.Errorf("child did not resume: %d -> %d", a, b)
	}
}

func TestRollup_ChildAloneAdminDownIsHeldWhileParentGrows(t *testing.T) {
	ic := newRollupCycler(t)
	const in = ifXTablePrefix + "6."
	ic.State().ApplyAdminStatus(3, AdminDown)
	ic.reconcileHold(3, 100)
	held := col(t, ic, in, 3, 100)
	if got := col(t, ic, in, 3, 700); got != held {
		t.Errorf("admin-down child moved: %d -> %d", held, got)
	}
	if a, b := col(t, ic, in, 1, 100), col(t, ic, in, 1, 700); b <= a {
		t.Errorf("parent did not grow: %d -> %d", a, b)
	}
	if p, s := col(t, ic, in, 1, 700), col(t, ic, in, 3, 700)+col(t, ic, in, 4, 700); s > p {
		t.Errorf("bound broken: children %d > parent %d", s, p)
	}
}

func TestRollup_MemberDownLowersTheAggregate(t *testing.T) {
	ic := newRollupCycler(t)
	const in = ifXTablePrefix + "6."
	moveLink(t, ic.State(), 1, OperDown)
	ic.reconcileHold(1, 100)
	b0, m2 := col(t, ic, in, 5, 100), col(t, ic, in, 2, 100)
	b1, m2b := col(t, ic, in, 5, 110), col(t, ic, in, 2, 110)
	if b1-b0 != m2b-m2 {
		t.Errorf("aggregate grew %d, the up member grew %d", b1-b0, m2b-m2)
	}
	if b1-b0 == 0 {
		t.Error("aggregate stopped although one member is up")
	}
}

func TestRollup_AggregateOwnHold(t *testing.T) {
	ic := newRollupCycler(t)
	const in = ifXTablePrefix + "6."
	ic.State().ApplyAdminStatus(5, AdminDown)
	ic.reconcileHold(5, 100)
	if a, b := col(t, ic, in, 5, 100), col(t, ic, in, 5, 900); a != b {
		t.Errorf("admin-down aggregate moved: %d -> %d", a, b)
	}
	if a, b := col(t, ic, in, 1, 100), col(t, ic, in, 1, 900); b <= a {
		t.Error("member stopped with the aggregate; members keep their own state")
	}
}

func TestRollup_MemberThatIsAChildIsNotSummed(t *testing.T) {
	res := buildTestResources(t, []uint64{1e9, 1e9, 1e9, 2e9})
	for i, n := range map[int]string{1: "eth0", 2: "eth1", 3: "eth0.100", 4: "be1"} {
		res.oidIndex.Store(ifTablePrefix+"2."+strconv.Itoa(i), n)
	}
	res.SNMP = append(res.SNMP,
		SNMPResource{OID: "1.3.6.1.2.1.31.1.2.1.3.4.2", Response: "1"},
		SNMPResource{OID: "1.3.6.1.2.1.31.1.2.1.3.4.3", Response: "1"},
	)
	mc := NewMetricsCycler(0, GetDeviceProfile(""))
	mc.InitIfCountersWithScenario(res, 1, IfErrorClean)
	ic := mc.ifCounters.Load()
	if ic.members[3] != nil {
		t.Errorf("be1 with one legal member is an aggregate: %v", ic.members[3])
	}
}

func TestReadStackLayersSplitsParentsAndAggregates(t *testing.T) {
	known := map[int]bool{1: true, 2: true, 3: true, 4: true, 5: true}
	got := readStackLayers([]SNMPResource{
		{OID: "1.3.6.1.2.1.31.1.2.1.3.3.1", Response: "1"},
		{OID: "1.3.6.1.2.1.31.1.2.1.3.4.1", Response: "1"},
		{OID: "1.3.6.1.2.1.31.1.2.1.3.4.2", Response: "1"},
		{OID: "1.3.6.1.2.1.31.1.2.1.3.4.2", Response: "1"}, // repeated row
		{OID: "1.3.6.1.2.1.31.1.2.1.3.5.9", Response: "1"}, // unknown lower
	}, known)
	if want := map[int]int{3: 1}; !reflect.DeepEqual(got.parents, want) {
		t.Errorf("parents = %v, want %v", got.parents, want)
	}
	if want := map[int][]int{4: {1, 2}}; !reflect.DeepEqual(got.members, want) {
		t.Errorf("members = %v, want %v", got.members, want)
	}
}

// Concurrent parent and child flaps with a continuous reader of both: the
// bound and monotonicity hold at every read.
func TestRollup_MonotonicAndBoundedUnderConcurrentFlaps(t *testing.T) {
	ic := newRollupCycler(t)
	state := ic.State()
	const in = ifXTablePrefix + "6."
	var stop atomic.Bool
	var wg sync.WaitGroup
	for _, ifIndex := range []int{1, 3, 1, 4} {
		wg.Add(1)
		go func(ifIndex int) {
			defer wg.Done()
			for i := 0; !stop.Load(); i++ {
				target := OperDown
				if i%2 == 0 {
					target = OperUp
				}
				if res, evts := state.SetLinkState(ifIndex, target); res == LinkMovedVisible {
					for _, e := range evts {
						state.Broadcast(e)
					}
				}
			}
		}(ifIndex)
	}
	var prevP, prevC uint64
	backwards, broken := 0, 0
	deadline := time.Now().Add(200 * time.Millisecond)
	for time.Now().Before(deadline) {
		at := time.Since(ic.startTime).Seconds()
		p := col(t, ic, in, 1, at)
		c := col(t, ic, in, 3, at) + col(t, ic, in, 4, at)
		if p < prevP || c < prevC {
			backwards++
		}
		if c > p {
			broken++
		}
		prevP, prevC = p, c
	}
	stop.Store(true)
	wg.Wait()
	if backwards != 0 || broken != 0 {
		t.Errorf("%d backwards reads, %d bound violations under concurrent flaps", backwards, broken)
	}
}

// Every child of every shipped profile is bounded by its parent and every
// aggregate equals the sum of its members, at fixed instants.
func TestShippedHierarchyCountersRollUp(t *testing.T) {
	withIfScenario(t, IfScenarioAllNormal, 0)
	sm := &SimulatorManager{resourcesCache: make(map[string]*DeviceResources)}
	children, aggregates := map[string][]int{}, map[string][]int{}
	for _, profile := range shippedProfileNames(t) {
		res, err := sm.LoadSpecificResources(profile)
		if err != nil {
			t.Fatal(err)
		}
		mc := NewMetricsCycler(0, GetDeviceProfile(""))
		mc.InitIfCountersWithScenario(res, 1, IfErrorClean)
		ic := mc.ifCounters.Load()
		if ic == nil {
			continue
		}
		byParent := map[int][]int{}
		for i := range ic.knownIfIndexes {
			if p := ic.counterParent[i-1]; p != 0 {
				byParent[p] = append(byParent[p], i)
				children[profile] = append(children[profile], i)
			}
			if ic.members[i-1] != nil {
				aggregates[profile] = append(aggregates[profile], i)
			}
		}
		for _, at := range []float64{0, 600, 3600} {
			for p, cs := range byParent {
				for _, c := range []string{ifXTablePrefix + "6.", ifXTablePrefix + "10."} {
					var sum uint64
					for _, ch := range cs {
						sum += col(t, ic, c, ch, at)
					}
					if pv := col(t, ic, c, p, at); sum > pv {
						t.Errorf("%s %s%d at t=%g: children %d > parent %d", profile, c, p, at, sum, pv)
					}
				}
			}
			for _, agg := range aggregates[profile] {
				for _, c := range []string{ifXTablePrefix + "6.", ifXTablePrefix + "10."} {
					var sum uint64
					for _, m := range ic.members[agg-1] {
						sum += col(t, ic, c, m, at)
					}
					if av := col(t, ic, c, agg, at); av != sum {
						t.Errorf("%s %s%d at t=%g: aggregate %d != members %d", profile, c, agg, at, av, sum)
					}
				}
			}
		}
	}
	for _, m := range []map[string][]int{children, aggregates} {
		for p := range m {
			sort.Ints(m[p])
		}
	}
	wantChildren := map[string][]int{
		"cisco_asr9902.json":   {55, 56, 57},
		"juniper_mx10004.json": {73, 74, 75, 76},
		"juniper_mx240.json":   {25, 26, 27, 28},
		"juniper_mx960.json":   {81, 82, 83, 84, 85},
		"nokia_7750_sr12.json": {73},
	}
	if !reflect.DeepEqual(children, wantChildren) {
		t.Errorf("children = %v, want %v", children, wantChildren)
	}
	if want := map[string][]int{"cisco_asr9902.json": {51}}; !reflect.DeepEqual(aggregates, want) {
		t.Errorf("aggregates = %v, want %v", aggregates, want)
	}
	_ = strings.TrimSpace
}

// Edge rows in the stack table: a bundle with an unresolvable member row is
// not demoted to a child of the other member, a port claimed by two
// aggregates is counted once, an aggregate that is also a child sums
// nothing, and a zero-speed child keeps its zero dial.
func TestRollup_StackTableEdges(t *testing.T) {
	known := map[int]bool{1: true, 2: true, 3: true, 4: true, 5: true}
	got := readStackLayers([]SNMPResource{
		{OID: "1.3.6.1.2.1.31.1.2.1.3.3.1", Response: "1"},
		{OID: "1.3.6.1.2.1.31.1.2.1.3.3.99", Response: "1"}, // unknown member
		{OID: "1.3.6.1.2.1.31.1.2.1.3.4.1", Response: "1"},
		{OID: "1.3.6.1.2.1.31.1.2.1.3.4.2", Response: "1"},
		{OID: "1.3.6.1.2.1.31.1.2.1.3.5.1", Response: "1"},
		{OID: "1.3.6.1.2.1.31.1.2.1.3.5.2", Response: "1"},
	}, known)
	if _, isChild := got.parents[3]; isChild {
		t.Error("a bundle with one unresolvable member row became a child of the other member")
	}
	if len(got.members) != 2 {
		t.Errorf("members = %v, want 4 and 5", got.members)
	}

	// 1 eth0, 2 eth1, 3 eth2, 4 be1 over 1+2, 5 be2 over 1+3 (port 1 claimed
	// twice), 6 eth0.100 with speed 0, 7 be3.0 stacked on 1+2 AND a child of 8 be3.
	res := buildTestResources(t, []uint64{1e9, 1e9, 1e9, 2e9, 2e9, 0, 2e9, 2e9})
	for i, n := range map[int]string{1: "eth0", 2: "eth1", 3: "eth2", 4: "be1", 5: "be2", 6: "eth0.100", 7: "be3.0", 8: "be3"} {
		res.oidIndex.Store(ifTablePrefix+"2."+strconv.Itoa(i), n)
	}
	for _, r := range []string{"4.1", "4.2", "5.1", "5.3", "7.1", "7.2"} {
		res.SNMP = append(res.SNMP, SNMPResource{OID: "1.3.6.1.2.1.31.1.2.1.3." + r, Response: "1"})
	}
	mc := NewMetricsCycler(0, GetDeviceProfile(""))
	mc.InitIfCountersWithScenario(res, 1, IfErrorClean)
	ic := mc.ifCounters.Load()
	if !reflect.DeepEqual(ic.members[3], []int{1, 2}) {
		t.Errorf("be1 members = %v, want [1 2]", ic.members[3])
	}
	if ic.members[4] != nil {
		t.Errorf("be2 kept port 1 that be1 already claims: %v", ic.members[4])
	}
	if ic.members[6] != nil || ic.counterParent[6] != 8 {
		t.Errorf("be3.0: members %v parent %d, want no members and parent 8", ic.members[6], ic.counterParent[6])
	}
	if ic.counterParent[5] != 0 || ic.share[5] != 0 {
		t.Errorf("zero-speed child composed: parent %d share %v", ic.counterParent[5], ic.share[5])
	}
	if v := col(t, ic, ifXTablePrefix+"6.", 6, 3600); v != 0 {
		t.Errorf("zero-speed child serves %d, want 0", v)
	}
}
