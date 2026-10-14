/*
 * Copyright 2026 Ronny Trommer <ronny@no42.org>
 * SPDX-License-Identifier: Apache-2.0
 */

package main

import (
	"net"
	"reflect"
	"slices"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	gnmipb "github.com/openconfig/gnmi/proto/gnmi"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// shippedDevice builds a device of the shipped profile with a live interface
// state engine, the way InitIfCountersWithScenario builds it in production.
func shippedDevice(t *testing.T, profile string) *DeviceSimulator {
	t.Helper()
	sm := &SimulatorManager{resourcesCache: make(map[string]*DeviceResources)}
	res, err := sm.LoadSpecificResources(profile)
	if err != nil {
		t.Fatalf("LoadSpecificResources(%s): %v", profile, err)
	}
	mc := &MetricsCycler{}
	mc.InitIfCounters(res, 1)
	return &DeviceSimulator{ID: profile, IP: net.IPv4(10, 42, 0, 10), resourceFile: profile, resources: res, metricsCycler: mc}
}

func operOID(idx int) string { return ifTablePrefix + "8." + strconv.Itoa(idx) }

func TestSplitSubinterfaceName(t *testing.T) {
	for _, tc := range []struct {
		in, parent, unit string
		ok               bool
	}{
		{"xe-0/0/0.0", "xe-0/0/0", "0", true},
		{"HundredGigE0/0/0/8.100", "HundredGigE0/0/0/8", "100", true},
		{"Bundle-Ether1.4294967295", "Bundle-Ether1", "4294967295", true},
		{"Bundle-Ether1.4294967296", "", "", false},
		{"xe-0/0/0.01", "", "", false},
		{"xe-0/0/0.+1", "", "", false},
		{"xe-0/0/0.", "", "", false},
		{".0", "", "", false},
		{"xe-0/0/0", "", "", false},
	} {
		p, u, ok := splitSubinterfaceName(tc.in)
		if p != tc.parent || u != tc.unit || ok != tc.ok {
			t.Errorf("splitSubinterfaceName(%q) = (%q, %q, %v), want (%q, %q, %v)", tc.in, p, u, ok, tc.parent, tc.unit, tc.ok)
		}
	}
}

func TestSubinterfaceParentsNeedsAnExistingParentAndOneLevel(t *testing.T) {
	got := subinterfaceParents(map[int]string{
		1: "eth0", 2: "eth0.100", 3: "eth9.5", 4: "eth0.100.7", 5: "lo0.0",
	})
	want := map[int]int{2: 1}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("parents = %v, want %v (eth9 and lo0 do not exist; a unit of a unit is top-level)", got, want)
	}
}

// TestMx10004UnitGoesDownWithItsPort pins the reported defect through the SNMP
// read path: the port's link going down took the port down and left the unit up.
func TestMx10004UnitGoesDownWithItsPort(t *testing.T) {
	dev := shippedDevice(t, "juniper_mx10004.json")
	srv := &SNMPServer{device: dev}
	st := dev.metricsCycler.ifCounters.Load().State()
	if p := st.Parent(73); p != 1 {
		t.Fatalf("Parent(73) = %d, want 1 (xe-0/0/0.0 under xe-0/0/0)", p)
	}

	res, evts := st.SetLinkState(1, OperDown)
	if res != LinkMovedVisible {
		t.Fatalf("SetLinkState = %v", res)
	}
	if len(evts) != 2 || evts[0].IfIndex != 1 || evts[1].IfIndex != 73 || evts[1].Oper != OperLowerLayerDn {
		t.Fatalf("events = %+v, want the port then the unit at lowerLayerDown", evts)
	}
	if got := srv.findResponse(operOID(1)); got != "2" {
		t.Errorf("ifOperStatus.1 = %q, want 2", got)
	}
	if got := srv.findResponse(operOID(73)); got != "7" {
		t.Errorf("ifOperStatus.73 = %q, want 7 (lowerLayerDown)", got)
	}
	if a, b := st.LastChangeNs(1), st.LastChangeNs(73); a != b || a != evts[0].LastChangeNs {
		t.Errorf("lastChange port = %d, unit = %d, event = %d: the unit must change with its port", a, b, evts[0].LastChangeNs)
	}

	res, evts = st.SetLinkState(1, OperUp)
	if res != LinkMovedVisible || len(evts) != 2 || evts[1].IfIndex != 73 || evts[1].Oper != OperUp {
		t.Fatalf("link up: %v %+v, want the unit to come back with its port", res, evts)
	}
	if got := srv.findResponse(operOID(73)); got != "1" {
		t.Errorf("ifOperStatus.73 after the port came back = %q, want 1", got)
	}
}

func TestPortAdminDownTakesTheUnitDown(t *testing.T) {
	st := shippedDevice(t, "juniper_mx10004.json").metricsCycler.ifCounters.Load().State()
	evts := st.ApplyAdminStatus(1, AdminDown)
	var got []string
	for _, e := range evts {
		got = append(got, strconv.Itoa(e.IfIndex)+":"+strconv.Itoa(int(e.Changed))+":"+strconv.Itoa(int(e.Oper)))
	}
	want := []string{"1:2:2", "1:1:2", "73:1:7"}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("events (ifIndex:changed:oper) = %v, want %v", got, want)
	}
}

func TestUnitOwnStateWinsOverItsParent(t *testing.T) {
	st := shippedDevice(t, "juniper_mx10004.json").metricsCycler.ifCounters.Load().State()
	st.ApplyAdminStatus(73, AdminDown)
	before := st.Snapshot(73)

	res, evts := st.SetLinkState(1, OperDown)
	if res != LinkMovedVisible || len(evts) != 1 {
		t.Fatalf("port down over a shut unit: %v %+v, want only the port's event", res, evts)
	}
	after := st.Snapshot(73)
	if after.Oper != OperDown {
		t.Errorf("shut unit oper = %d, want down(2): its own admin wins", after.Oper)
	}
	if after.LastChangeNs != before.LastChangeNs {
		t.Errorf("shut unit lastChange moved on its port's transition")
	}

	// Unshut under a down port: the unit reads lowerLayerDown. Its own link
	// going down then wins again, down(2), as a visible move.
	st.ApplyAdminStatus(73, AdminUp)
	if got := st.OperStatus(73); got != OperLowerLayerDn {
		t.Errorf("unshut unit under a down port = %d, want lowerLayerDown(7)", got)
	}
	if res, evts := st.SetLinkState(73, OperDown); res != LinkMovedVisible || len(evts) != 1 || evts[0].Oper != OperDown {
		t.Errorf("unit link down under a down port = %v %+v, want one visible move to down(2)", res, evts)
	}
}

// TestUnitBouncesWithItsPortFireNoLinkTrap: RFC 2863 sends linkDown on
// entering down(2) and linkUp on leaving it. The unit moves between up(1) and
// lowerLayerDown(7), so neither fires; a linkUp on recovery alone was unpaired.
// The port's own transitions keep their roles.
func TestUnitBouncesWithItsPortFireNoLinkTrap(t *testing.T) {
	st := shippedDevice(t, "juniper_mx10004.json").metricsCycler.ifCounters.Load().State()
	var got []string
	for _, target := range []uint8{OperDown, OperUp} {
		_, evts := st.SetLinkState(1, target)
		for _, e := range evts {
			if role, ok := linkRoleFor(e); ok {
				got = append(got, strconv.Itoa(e.IfIndex)+":"+role)
			}
		}
	}
	want := []string{"1:" + roleLinkDown, "1:" + roleLinkUp}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("link roles fired = %v, want %v (none for the unit)", got, want)
	}
}

// TestFamilyTransitionsAreSerialised races two writers on the port's link
// and one on the unit's admin. Each mutation and its cascade must be one step:
// with a strictly increasing clock, the newest event per interface (by
// LastChangeNs) must name the state the engine ends in, and the unit's
// lastChange must never go backwards. Without the family lock a cascade from
// an older parent transition overwrote a newer one, and a unit move derived
// from a parent value that changed before its CAS.
func TestFamilyTransitionsAreSerialised(t *testing.T) {
	var tick atomic.Int64
	clock := func() time.Time { return time.Unix(0, 1_000_000_000+tick.Add(1)) }
	st := newInterfaceStateWithClock(2, nil, nil, clock)
	st.setParents(map[int]int{2: 1})
	st.Seed(1, OperUp, AdminUp)
	st.Seed(2, OperUp, AdminUp)

	const n = 20000
	var mu sync.Mutex
	var all []StateChange
	record := func(evts []StateChange) {
		mu.Lock()
		all = append(all, evts...)
		mu.Unlock()
	}
	var backwards atomic.Int64
	stop := make(chan struct{})
	var watch sync.WaitGroup
	watch.Add(1)
	go func() {
		defer watch.Done()
		var last uint64
		for {
			select {
			case <-stop:
				return
			default:
			}
			if lc := st.LastChangeNs(2); lc < last {
				backwards.Add(1)
			} else {
				last = lc
			}
		}
	}()
	var wg sync.WaitGroup
	for _, target := range []uint8{OperDown, OperUp} {
		wg.Add(1)
		go func(target uint8) {
			defer wg.Done()
			for i := 0; i < n; i++ {
				_, evts := st.SetLinkState(1, target)
				record(evts)
			}
		}(target)
	}
	wg.Add(1)
	go func() {
		defer wg.Done()
		for i := 0; i < n; i++ {
			record(st.ApplyAdminStatus(2, []uint8{AdminDown, AdminUp}[i%2]))
		}
	}()
	wg.Wait()
	close(stop)
	watch.Wait()

	if b := backwards.Load(); b != 0 {
		t.Errorf("the unit's lastChange went backwards %d times", b)
	}
	newest := map[int]StateChange{}
	for _, e := range all {
		if e.Changed&LeafOperStatus != 0 && e.LastChangeNs >= newest[e.IfIndex].LastChangeNs {
			newest[e.IfIndex] = e
		}
	}
	for _, idx := range []int{1, 2} {
		if got := st.OperStatus(idx); newest[idx].Oper != got {
			t.Errorf("ifIndex %d ends at oper %d but its newest event says %d", idx, got, newest[idx].Oper)
		}
		if got := st.LastChangeNs(idx); newest[idx].LastChangeNs != got {
			t.Errorf("ifIndex %d ends at lastChange %d but its newest event says %d", idx, got, newest[idx].LastChangeNs)
		}
	}
}

func TestUnitTransitionFiresTheNotifyHook(t *testing.T) {
	st := shippedDevice(t, "juniper_mx10004.json").metricsCycler.ifCounters.Load().State()
	var fired []int
	st.SetNotify(func(e StateChange) { fired = append(fired, e.IfIndex) })
	defer st.SetNotify(nil)
	_, evts := st.SetLinkState(1, OperDown)
	for _, e := range evts {
		st.Broadcast(e)
	}
	if !reflect.DeepEqual(fired, []int{1, 73}) {
		t.Errorf("notify fired for %v, want [1 73]: the unit's link trap must follow its port", fired)
	}
}

func TestAsr9902SubinterfacesFollowTheirParents(t *testing.T) {
	dev := shippedDevice(t, "cisco_asr9902.json")
	srv := &SNMPServer{device: dev}
	ic := dev.metricsCycler.ifCounters.Load()
	st := ic.State()
	children := map[int][]int{}
	for _, idx := range ic.IfIndices() {
		if p := st.Parent(idx); p != 0 {
			children[p] = append(children[p], idx)
		}
	}
	n := 0
	for p, kids := range children {
		n += len(kids)
		st.SetLinkState(p, OperDown)
		for _, c := range kids {
			if got := srv.findResponse(operOID(c)); got != "7" {
				t.Errorf("ifOperStatus.%d = %q with parent %d down, want 7", c, got, p)
			}
		}
	}
	if n != 3 {
		t.Errorf("%d subinterfaces, want the 3 VLAN subinterfaces", n)
	}
}

func TestFlapSchedulerSkipsSubinterfaces(t *testing.T) {
	ic := shippedDevice(t, "juniper_mx10004.json").metricsCycler.ifCounters.Load()
	s := NewFlapScheduler(FlapSchedulerOptions{})
	s.Register(net.IPv4(10, 42, 0, 10), ic.IfIndices(), IfFlapTypical, ic.State())
	if got := s.pendingCountForTest(); got != 72 {
		t.Errorf("%d scheduled interfaces, want the 72 ports and not the unit", got)
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	for k := range s.byKey {
		if k.ifIndex == 73 {
			t.Errorf("the logical unit is scheduled to flap on its own")
		}
	}
}

// TestDialoutListsNoSubinterface pins the reported defect through the dial-out
// exporter's own resolver: it listed xe-0/0/0.0 as a 73rd interface.
func TestDialoutListsNoSubinterface(t *testing.T) {
	dev := shippedDevice(t, "juniper_mx10004.json")
	e := NewGnmiDialoutExporter(dev, "127.0.0.1:1", "gnmireverse", nil, gnmipb.Encoding_JSON_IETF, "sample", nil, time.Second, nil)
	ups, err := e.resolver.Resolve(pathFromString(t, "/interfaces/interface[name=*]/state/name"), time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if len(ups) != 72 {
		t.Errorf("%d interfaces, want 72", len(ups))
	}
	for _, u := range ups {
		if strings.Contains(pathToString(u.Path), "xe-0/0/0.0") {
			t.Errorf("dial-out serves the unit as an interface: %s", pathToString(u.Path))
		}
	}
	// Built by hand: the string helper splits a key value at its slashes.
	named := func(name string) *gnmipb.Path {
		return &gnmipb.Path{Elem: []*gnmipb.PathElem{
			{Name: "interfaces"}, {Name: "interface", Key: map[string]string{"name": name}},
			{Name: "state"}, {Name: "oper-status"},
		}}
	}
	if ups, err := e.resolver.Resolve(named("xe-0/0/0"), time.Now()); err != nil || len(ups) != 1 {
		t.Fatalf("control: the port by name = %v, %v; want one update", ups, err)
	}
	if _, err := e.resolver.Resolve(named("xe-0/0/0.0"), time.Now()); status.Code(err) != codes.NotFound {
		t.Errorf("the unit by name = %v; want NotFound", err)
	}

	// ON_CHANGE: the port's event is served, the unit's is not.
	ic := dev.metricsCycler.ifCounters.Load()
	_, evts := ic.State().SetLinkState(1, OperDown)
	p := pathFromString(t, "/interfaces/interface[name=*]/state/oper-status")
	for _, evt := range evts {
		got, err := changedUpdatesForPath(e.resolver, ic, p, evt, 1)
		if err != nil {
			t.Fatal(err)
		}
		if want := map[int]int{1: 1, 73: 0}[evt.IfIndex]; len(got) != want {
			t.Errorf("ifIndex %d ON_CHANGE produced %d updates, want %d", evt.IfIndex, len(got), want)
		}
	}
}

// TestRestOperPostOnAUnitUnderADownPortIsMasked: the POST is applied to the
// unit's link but collectors keep reading lowerLayerDown, so the caller must be
// told it is masked, as for an admin-down interface.
func TestRestOperPostOnAUnitUnderADownPortIsMasked(t *testing.T) {
	dev := shippedDevice(t, "juniper_mx10004.json")
	sm := &SimulatorManager{}
	sm.mu.Lock()
	sm.indexDeviceByIP(dev)
	sm.mu.Unlock()
	ip := dev.IP.String()

	if out, err := sm.mutateInterfaceState(ip, 73, true, OperUp, 0); err != nil || out.Masked {
		t.Fatalf("control: unit POST UP with its port up = %+v, %v; want unmasked", out, err)
	}
	if _, err := sm.mutateInterfaceState(ip, 1, true, OperDown, 0); err != nil {
		t.Fatal(err)
	}
	out, err := sm.mutateInterfaceState(ip, 73, true, OperUp, 0)
	if err != nil {
		t.Fatal(err)
	}
	if !out.Masked || out.OperStatus != ifStatusName(OperLowerLayerDn) {
		t.Errorf("unit POST UP under a down port = %+v; want masked, reading lowerLayerDown", out)
	}
	if out, _ := sm.mutateInterfaceState(ip, 73, true, OperDown, 0); out.Masked {
		t.Errorf("unit POST DOWN under a down port = %+v; its own fault is visible, want unmasked", out)
	}
}

func TestStackedParentsReadsActiveRowsOnly(t *testing.T) {
	known := map[int]bool{1: true, 2: true, 3: true, 4: true}
	got := stackedParents([]SNMPResource{
		{OID: "1.3.6.1.2.1.31.1.2.1.3.3.1", Response: "1"},  // active: 3 on 1
		{OID: ".1.3.6.1.2.1.31.1.2.1.3.2.1", Response: "2"}, // notInService
		{OID: "1.3.6.1.2.1.31.1.2.1.3.4.1", Response: "1"},  // 4 on two lower layers
		{OID: "1.3.6.1.2.1.31.1.2.1.3.4.2", Response: "1"},
		{OID: "1.3.6.1.2.1.31.1.2.1.3.9.1", Response: "1"}, // unknown ifIndex
		{OID: "1.3.6.1.2.1.31.1.2.1.3.0.1", Response: "1"}, // the table's 0 marker
	}, known)
	if want := map[int]int{3: 1}; !reflect.DeepEqual(got, want) {
		t.Errorf("stackedParents = %v, want %v", got, want)
	}
	// The same row twice, as two resource parts can carry it, is one row.
	dup := stackedParents([]SNMPResource{
		{OID: "1.3.6.1.2.1.31.1.2.1.3.3.1", Response: "1"},
		{OID: "1.3.6.1.2.1.31.1.2.1.3.3.1", Response: "1"},
	}, known)
	if want := map[int]int{3: 1}; !reflect.DeepEqual(dup, want) {
		t.Errorf("a repeated row = %v, want %v", dup, want)
	}
	// The name rule decides first; a stack row cannot re-parent its child.
	if got := interfaceParents(map[int]string{1: "a", 2: "b", 3: "a.0"}, map[int]int{3: 2}); got[3] != 1 {
		t.Errorf("a stack row overrode the name rule: parents = %v", got)
	}
}

// TestNokiaRouterInterfaceFollowsItsPort: toWAN is stacked on port 1/1/1, so it
// goes down with the port although its name says nothing about the port.
func TestNokiaRouterInterfaceFollowsItsPort(t *testing.T) {
	dev := shippedDevice(t, "nokia_7750_sr12.json")
	srv := &SNMPServer{device: dev}
	st := dev.metricsCycler.ifCounters.Load().State()
	if p := st.Parent(73); p != 1 {
		t.Fatalf("Parent(toWAN) = %d, want 1 (port 1/1/1)", p)
	}
	if st.Parent(74) != 0 || !st.Linkless(74) {
		t.Errorf("system: Parent = %d, Linkless = %v; want a top-level loopback", st.Parent(74), st.Linkless(74))
	}
	st.SetLinkState(1, OperDown)
	if got := srv.findResponse(operOID(73)); got != "7" {
		t.Errorf("ifOperStatus of toWAN with its port down = %q, want 7", got)
	}
	if got := srv.findResponse(operOID(74)); got != "1" {
		t.Errorf("ifOperStatus of system with port 1/1/1 down = %q, want 1", got)
	}
	// A stacked router interface is still an interface to gNMI: only a
	// <port>.<unit> name is served under its port's subinterfaces instead.
	if st.NamedSubinterface(73) {
		t.Errorf("toWAN counts as a named subinterface")
	}
	r := newPathResolver(dev)
	byName := &gnmipb.Path{Elem: []*gnmipb.PathElem{
		{Name: "interfaces"}, {Name: "interface", Key: map[string]string{"name": "toWAN"}},
		{Name: "state"}, {Name: "oper-status"},
	}}
	if ups, err := r.Resolve(byName, time.Now()); err != nil || len(ups) != 1 {
		t.Errorf("gNMI interface[name=toWAN] = %v, %v; want one update", ups, err)
	}
	// RFC 2863 ifStackTable describes every interface: each appears once as a
	// higher layer and once as a lower layer, with 0 where nothing is there.
	higher, lower := map[int]int{}, map[int]int{}
	for _, e := range dev.resources.SNMP {
		rest, ok := strings.CutPrefix(strings.TrimPrefix(e.OID, "."), ifStackStatusPrefix)
		if !ok {
			continue
		}
		hs, ls, _ := strings.Cut(rest, ".")
		h, _ := strconv.Atoi(hs)
		l, _ := strconv.Atoi(ls)
		higher[h]++
		lower[l]++
	}
	for _, idx := range dev.metricsCycler.ifCounters.Load().IfIndices() {
		if higher[idx] != 1 || lower[idx] != 1 {
			t.Errorf("ifStackTable: ifIndex %d is a higher layer %d times and a lower layer %d times, want 1 and 1", idx, higher[idx], lower[idx])
		}
	}
	all, err := r.Resolve(pathFromString(t, "/interfaces/interface[name=*]/state/ifindex"), time.Now())
	if err != nil || len(all) != 74 {
		t.Errorf("gNMI lists %d interfaces (%v), want all 74 including toWAN and system", len(all), err)
	}
}

// TestFlapSchedulerSkipsLinklessInterfaces: a loopback does not go down and a
// stacked router interface moves only with its port.
func TestFlapSchedulerSkipsLinklessInterfaces(t *testing.T) {
	for profile, skipped := range map[string][]int{
		"nokia_7750_sr12.json": {73, 74},
		"linux_server.json":    {1},
	} {
		ic := shippedDevice(t, profile).metricsCycler.ifCounters.Load()
		s := NewFlapScheduler(FlapSchedulerOptions{})
		s.Register(net.IPv4(10, 42, 0, 10), ic.IfIndices(), IfFlapTypical, ic.State())
		if got, want := s.pendingCountForTest(), len(ic.IfIndices())-len(skipped); got != want {
			t.Errorf("%s: %d scheduled interfaces, want %d", profile, got, want)
		}
		s.mu.Lock()
		for k := range s.byKey {
			if slices.Contains(skipped, k.ifIndex) {
				t.Errorf("%s: ifIndex %d has no physical link and is scheduled to flap", profile, k.ifIndex)
			}
		}
		s.mu.Unlock()
	}
}
