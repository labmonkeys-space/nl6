/*
 * Copyright 2026 Ronny Trommer <ronny@no42.org>
 * SPDX-License-Identifier: Apache-2.0
 */

package main

import (
	"context"
	"encoding/binary"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	gnmipb "github.com/openconfig/gnmi/proto/gnmi"
)

// Counter hold while the derived oper-status is not up(1).
//
// The dial is a pure function of elapsed time, so every test below drives the
// ledger with an EXPLICIT instant through reconcileHold and reads through
// GetDynamicAt at explicit instants. No test here sleeps to make a counter
// move. The mutator-driven tests use the production hook, which samples the
// cycler's clock, and then assert the hold at instants far enough past the
// transition that the sampled instant cannot matter.

// newHoldCycler builds a cycler with nIf 1 Gbps interfaces seeded admin-up,
// link-up, through the production init so the hook and the seed pass run.
func newHoldCycler(t *testing.T, nIf int) *IfCounterCycler {
	t.Helper()
	speeds := make([]uint64, nIf)
	for i := range speeds {
		speeds[i] = 1_000_000_000
	}
	res := buildTestResources(t, speeds)
	for i := 1; i <= nIf; i++ {
		res.oidIndex.Store(fmt.Sprintf("%s.%d", oidIfAdminStatus, i), "1")
		res.oidIndex.Store(fmt.Sprintf("%s.%d", oidIfOperStatus, i), "1")
	}
	mc := NewMetricsCycler(0, GetDeviceProfile(""))
	mc.InitIfCountersWithScenario(res, 1, IfErrorClean)
	ic := mc.ifCounters.Load()
	if ic == nil || ic.State() == nil {
		t.Fatal("fixture has no cycler or no state engine")
	}
	return ic
}

func ctr(t *testing.T, s string) uint64 {
	t.Helper()
	v, err := strconv.ParseUint(s, 10, 64)
	if err != nil {
		t.Fatalf("not a counter: %q", s)
	}
	return v
}

// heldColumns is every dial-derived column the hold must cover. The state
// columns are excluded because they are not counters.
func heldColumns() []string {
	var cols []string
	for _, c := range ifCyclerColumns {
		if isStateCol(c.col, c.prefix) {
			continue
		}
		cols = append(cols, c.prefix+strconv.Itoa(c.col)+".")
	}
	return cols
}

// moveLink moves the link WITHOUT broadcasting, so the production hook does
// not run and the test chooses the ledger instant itself through
// reconcileHold. linkDown / linkUp broadcast, which is what every production
// source does, so the hook samples the cycler's clock.
func moveLink(t *testing.T, s *InterfaceState, ifIndex int, v uint8) {
	t.Helper()
	if res, _ := s.SetLinkState(ifIndex, v); res != LinkMovedVisible {
		t.Fatalf("SetLinkState(%d, %d) = %v, want LinkMovedVisible", ifIndex, v, res)
	}
}

func linkDown(t *testing.T, s *InterfaceState, ifIndex int) {
	t.Helper()
	res, evts := s.SetLinkState(ifIndex, OperDown)
	if res != LinkMovedVisible {
		t.Fatalf("SetLinkState(%d, down) = %v, want LinkMovedVisible", ifIndex, res)
	}
	for _, e := range evts {
		s.Broadcast(e)
	}
}

func linkUp(t *testing.T, s *InterfaceState, ifIndex int) {
	t.Helper()
	res, evts := s.SetLinkState(ifIndex, OperUp)
	if res != LinkMovedVisible {
		t.Fatalf("SetLinkState(%d, up) = %v, want LinkMovedVisible", ifIndex, res)
	}
	for _, e := range evts {
		s.Broadcast(e)
	}
}

func TestCounterHold_HoldsEveryColumnWhileDown(t *testing.T) {
	ic := newHoldCycler(t, 2)
	moveLink(t, ic.State(), 1, OperDown)
	ic.reconcileHold(1, 100)

	for _, col := range heldColumns() {
		held := ic.GetDynamicAt(col+"1", 100)
		for _, at := range []float64{100, 110, 1000, 7200} {
			if got := ic.GetDynamicAt(col+"1", at); got != held {
				t.Errorf("%s1 at t=%g = %s, want held %s", col, at, got, held)
			}
		}
		// Interface 2 stayed up and keeps growing on the octet columns.
		if strings.HasSuffix(col, ".6.") || strings.HasSuffix(col, ".10.") {
			if a, b := ctr(t, ic.GetDynamicAt(col+"2", 100)), ctr(t, ic.GetDynamicAt(col+"2", 110)); b <= a {
				t.Errorf("%s2 did not grow while up: %d -> %d", col, a, b)
			}
		}
	}
}

func TestCounterHold_RecoveryResumesFromHeldValueWithoutJump(t *testing.T) {
	ic := newHoldCycler(t, 1)
	const in = ifXTablePrefix + "6.1"
	moveLink(t, ic.State(), 1, OperDown)
	ic.reconcileHold(1, 100)
	held := ctr(t, ic.GetDynamicAt(in, 160))

	moveLink(t, ic.State(), 1, OperUp)
	ic.reconcileHold(1, 160)
	h := ic.hold[0].Load()
	if h == nil || h.down {
		t.Fatalf("ledger after up: %+v, want closed", h)
	}

	atUp := ctr(t, ic.GetDynamicAt(in, 160))
	if atUp != held {
		t.Fatalf("value at the up instant = %d, want the held value %d", atUp, held)
	}
	later := ctr(t, ic.GetDynamicAt(in, 170))
	// 1 Gbps is 125e6 B/s; the dial runs between 60 and 100 % of it.
	if later <= atUp || later-atUp > 10*125_000_000 {
		t.Errorf("10 s after recovery grew by %d, want (0, 1.25e9]", later-atUp)
	}
	// The skipped interval equals what the dial would have produced.
	if want := ic.deltaOctetsAt(0, 160, true) - ic.deltaOctetsAt(0, 100, true); h.skippedIn != want {
		t.Errorf("skippedIn = %d, want %d", h.skippedIn, want)
	}
}

func TestCounterHold_TwoCyclesAccumulateAndStayMonotonic(t *testing.T) {
	ic := newHoldCycler(t, 1)
	const in = ifXTablePrefix + "6.1"
	s := ic.State()
	var prev uint64
	check := func(at float64) {
		t.Helper()
		v := ctr(t, ic.GetDynamicAt(in, at))
		if v < prev {
			t.Errorf("t=%g: %d < previous %d", at, v, prev)
		}
		prev = v
	}
	check(0)
	moveLink(t, s, 1, OperDown)
	ic.reconcileHold(1, 10)
	check(20)
	moveLink(t, s, 1, OperUp)
	ic.reconcileHold(1, 30)
	check(40)
	moveLink(t, s, 1, OperDown)
	ic.reconcileHold(1, 50)
	check(60)
	moveLink(t, s, 1, OperUp)
	ic.reconcileHold(1, 70)
	check(80)
	h := ic.hold[0].Load()
	want := (ic.deltaOctetsAt(0, 30, true) - ic.deltaOctetsAt(0, 10, true)) + (ic.deltaOctetsAt(0, 70, true) - ic.deltaOctetsAt(0, 50, true))
	if h.skippedIn != want {
		t.Errorf("skippedIn after two cycles = %d, want %d", h.skippedIn, want)
	}
	if got, want := ctr(t, ic.GetDynamicAt(in, 80)), ic.baseInOctets[0]+ic.deltaOctetsAt(0, 80, true)-h.skippedIn; got != want {
		t.Errorf("value at 80 = %d, want base + delta - skipped = %d", got, want)
	}
}

// Out-of-order hooks: the ledger follows the engine's CURRENT state, not the
// event, so whichever order two hooks run in, the end state is the engine's.
func TestCounterHold_ReconcileFollowsEngineNotEvent(t *testing.T) {
	ic := newHoldCycler(t, 1)
	s := ic.State()
	// Engine is up; a stale "down" hook must not open a hold.
	ic.reconcileHold(1, 10)
	if h := ic.hold[0].Load(); h != nil {
		t.Fatalf("reconcile on an up engine opened %+v", h)
	}
	// Engine goes down; the hook that observes it opens once, and a repeat
	// keeps the first instant.
	if _, evts := s.SetLinkState(1, OperDown); len(evts) == 0 {
		t.Fatal("no event")
	}
	ic.reconcileHold(1, 20)
	ic.reconcileHold(1, 25)
	if h := ic.hold[0].Load(); h == nil || !h.down || h.downAt != 20 {
		t.Fatalf("after two down reconciles: %+v, want down at 20", h)
	}
	// Engine goes up; a close at an instant before the open is clamped.
	if _, evts := s.SetLinkState(1, OperUp); len(evts) == 0 {
		t.Fatal("no event")
	}
	ic.reconcileHold(1, 15)
	if h := ic.hold[0].Load(); h == nil || h.down || h.skippedIn != 0 {
		t.Fatalf("close before open: %+v, want closed with nothing skipped", h)
	}
}

func TestCounterHold_SeededDownInterfaceHoldsAtBase(t *testing.T) {
	res := buildTestResources(t, []uint64{1_000_000_000, 1_000_000_000, 1_000_000_000})
	res.oidIndex.Store(oidIfAdminStatus+".1", "1")
	res.oidIndex.Store(oidIfOperStatus+".1", "2")  // link down
	res.oidIndex.Store(oidIfAdminStatus+".2", "2") // admin down, link up
	res.oidIndex.Store(oidIfOperStatus+".2", "1")
	res.oidIndex.Store(oidIfAdminStatus+".3", "1")
	res.oidIndex.Store(oidIfOperStatus+".3", "1")
	mc := NewMetricsCycler(0, GetDeviceProfile(""))
	mc.InitIfCountersWithScenario(res, 1, IfErrorClean)
	ic := mc.ifCounters.Load()
	for _, i := range []int{1, 2} {
		for _, col := range heldColumns() {
			oid := col + strconv.Itoa(i)
			if a, b := ic.GetDynamicAt(oid, 0), ic.GetDynamicAt(oid, 3600); a != b {
				t.Errorf("seeded-down %s: %s at t=0, %s at t=3600", oid, a, b)
			}
		}
		if got := ctr(t, ic.GetDynamicAt(ifXTablePrefix+"6."+strconv.Itoa(i), 3600)); got != ic.baseInOctets[i-1] {
			t.Errorf("seeded-down ifHCInOctets.%d = %d, want base %d", i, got, ic.baseInOctets[i-1])
		}
	}
	if a, b := ctr(t, ic.GetDynamicAt(ifXTablePrefix+"6.3", 0)), ctr(t, ic.GetDynamicAt(ifXTablePrefix+"6.3", 3600)); b <= a {
		t.Errorf("seeded-up interface 3 did not grow: %d -> %d", a, b)
	}
}

// --- every mutation source reaches the ledger through the funnel ----------

// holdState reports whether the ledger for ifIndex is open.
func holdState(ic *IfCounterCycler, ifIndex int) bool {
	h := ic.hold[ifIndex-1].Load()
	return h != nil && h.down
}

func TestCounterHold_RESTOperAndAdminAndAutoRevert(t *testing.T) {
	f := newStateAPIFixture(t)
	ic := f.device.metricsCycler.ifCounters.Load()
	post := func(path, body string) {
		t.Helper()
		req := httptest.NewRequest("POST", path, strings.NewReader(body))
		rr := httptest.NewRecorder()
		f.router.ServeHTTP(rr, req)
		if rr.Code != http.StatusAccepted {
			t.Fatalf("%s %s: %d %s", path, body, rr.Code, rr.Body.String())
		}
	}
	post("/api/v1/devices/10.42.0.1/interfaces/1/oper-status", `{"status":"DOWN"}`)
	if !holdState(ic, 1) {
		t.Fatal("REST oper-down did not open the hold")
	}
	post("/api/v1/devices/10.42.0.1/interfaces/1/oper-status", `{"status":"UP"}`)
	if holdState(ic, 1) {
		t.Fatal("REST oper-up did not close the hold")
	}
	post("/api/v1/devices/10.42.0.1/interfaces/2/admin-status", `{"status":"DOWN"}`)
	if !holdState(ic, 2) {
		t.Fatal("REST admin-down did not open the hold (derived oper is down)")
	}
	// A masked link move under admin-down broadcasts nothing and must leave
	// the open ledger as it is.
	before := ic.hold[1].Load()
	if res, _ := ic.State().SetLinkState(2, OperDown); res != LinkMovedMasked {
		t.Fatalf("link move under admin-down = %v, want LinkMovedMasked", res)
	}
	if ic.hold[1].Load() != before {
		t.Fatal("a masked link move touched the ledger")
	}
	post("/api/v1/devices/10.42.0.1/interfaces/2/admin-status", `{"status":"UP"}`)
	// Admin up releases oper to the link, which is now down: still held.
	if !holdState(ic, 2) {
		t.Fatal("admin-up over a down link closed the hold")
	}
	linkUp(t, ic.State(), 2)
	if holdState(ic, 2) {
		t.Fatal("link up after admin up did not close the hold")
	}

	// Auto-revert: the revert goroutine broadcasts through the same funnel.
	ch := make(chan StateChange, 16)
	ic.State().AddListener(ch)
	defer ic.State().RemoveListener(ch)
	post("/api/v1/devices/10.42.0.1/interfaces/1/oper-status", `{"status":"DOWN","duration":"50ms"}`)
	if !holdState(ic, 1) {
		t.Fatal("duration POST did not open the hold")
	}
	for _, want := range []uint8{OperDown, OperUp} {
		select {
		case ev := <-ch:
			if ev.Oper != want {
				t.Fatalf("event Oper = %d, want %d", ev.Oper, want)
			}
		case <-time.After(5 * time.Second):
			t.Fatalf("no Oper=%d event", want)
		}
	}
	waitRevertsDone(t, f.mgr, "10.42.0.1")
	if holdState(ic, 1) {
		t.Fatal("auto-revert did not close the hold")
	}
}

func TestCounterHold_SNMPSetAdminStatus(t *testing.T) {
	s, _ := newSetTestServer(t, 2)
	ic := s.device.metricsCycler.ifCounters.Load()
	if status, _ := setVia(t, s, snmpVersion2c, []testBind{intBind(oidIfAdminStatus+".2", 2)}); status != snmpErrNoError {
		t.Fatalf("SET down: status %d", status)
	}
	if !holdState(ic, 2) {
		t.Fatal("SNMP SET admin-down did not open the hold")
	}
	if status, _ := setVia(t, s, snmpVersion2c, []testBind{intBind(oidIfAdminStatus+".2", 1)}); status != snmpErrNoError {
		t.Fatalf("SET up: status %d", status)
	}
	if holdState(ic, 2) {
		t.Fatal("SNMP SET admin-up did not close the hold")
	}
	if holdState(ic, 1) {
		t.Fatal("interface 1 was never named and is held")
	}
}

func TestCounterHold_ParentCascadeHoldsTheSubinterface(t *testing.T) {
	dev := shippedDevice(t, "juniper_mx10004.json")
	ic := dev.metricsCycler.ifCounters.Load()
	st := ic.State()
	const port, unit = 1, 73
	if st.Parent(unit) != port {
		t.Fatalf("Parent(%d) = %d, want %d", unit, st.Parent(unit), port)
	}
	linkDown(t, st, port)
	if st.OperStatus(unit) != OperLowerLayerDn {
		t.Fatalf("unit oper = %d, want lowerLayerDown", st.OperStatus(unit))
	}
	if !holdState(ic, unit) || !holdState(ic, port) {
		t.Fatalf("hold port=%v unit=%v, want both open", holdState(ic, port), holdState(ic, unit))
	}
	linkUp(t, st, port)
	if holdState(ic, unit) || holdState(ic, port) {
		t.Fatalf("hold port=%v unit=%v after up, want both closed", holdState(ic, port), holdState(ic, unit))
	}
}

func TestCounterHold_FlapSchedulerMovesTheLedger(t *testing.T) {
	ic := newHoldCycler(t, 1)
	state := ic.State()
	ch := make(chan StateChange, 64)
	state.AddListener(ch)
	s := NewFlapScheduler(FlapSchedulerOptions{Seed: 42})
	s.Register(net.IPv4(10, 0, 0, 1), []int{1}, IfFlapAggressive, state)
	accelerateFlapEntries(s)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan struct{})
	go func() { s.Run(ctx); close(done) }()
	// Observe the down event and then the ledger. The hook runs inside
	// Broadcast after the listener send, so wait for the up event to order
	// the final assertion.
	events := drainEvents(ch, 2, 7*time.Second)
	s.Stop()
	<-done
	if len(events) < 2 || events[0].Oper != OperDown || events[1].Oper != OperUp {
		t.Fatalf("events = %+v, want down then up", events)
	}
	if holdState(ic, 1) {
		t.Fatal("ledger still open after the scheduler's up event")
	}
	if h := ic.hold[0].Load(); h == nil || h.skippedIn == 0 {
		t.Fatalf("ledger after a flap = %+v, want a closed entry with skipped octets", h)
	}
}

// Concurrent writers and a continuous reader: no read may go backwards. The
// reader is serialised against the ledger by reading at instants the writers
// have already passed, which is the only ordering the design promises.
func TestCounterHold_MonotonicUnderConcurrentFlaps(t *testing.T) {
	ic := newHoldCycler(t, 1)
	state := ic.State()
	const in = ifXTablePrefix + "6.1"
	var stop atomic.Bool
	var wg sync.WaitGroup
	for w := 0; w < 4; w++ {
		wg.Add(1)
		go func(w int) {
			defer wg.Done()
			for i := 0; !stop.Load(); i++ {
				target := OperDown
				if (i+w)%2 == 0 {
					target = OperUp
				}
				if res, evts := state.SetLinkState(1, target); res == LinkMovedVisible {
					for _, e := range evts {
						state.Broadcast(e)
					}
				}
			}
		}(w)
	}
	var prev uint64
	deadline := time.Now().Add(200 * time.Millisecond)
	backwards := 0
	for time.Now().Before(deadline) {
		v := ctr(t, ic.GetDynamic(in))
		if v < prev {
			backwards++
		}
		prev = v
	}
	stop.Store(true)
	wg.Wait()
	if backwards != 0 {
		t.Errorf("%d backwards reads under concurrent flaps", backwards)
	}
}

// --- every surface reads the held value at one instant --------------------

func TestCounterHold_SNMPGnmiAndSflowAgree(t *testing.T) {
	dev := newTestGnmiDevice(t, 2)
	ic := dev.metricsCycler.ifCounters.Load()
	linkDown(t, ic.State(), 1)
	at := ic.startTime.Add(300 * time.Second)
	tSec := at.Sub(ic.startTime).Seconds()

	// The cycler, which findResponse delegates to.
	want := ic.GetDynamicAt(ifXTablePrefix+"6.1", tSec)
	if later := ic.GetDynamicAt(ifXTablePrefix+"6.1", tSec+600); later != want {
		t.Fatalf("interface 1 is not held: %s then %s", want, later)
	}

	// Legacy gNMI resolver.
	legacy := newPathResolver(dev)
	ups, err := legacy.Resolve(pathFromString(t, "/interfaces/interface[name=TestIf1]/state/counters/in-octets"), at)
	if err != nil || len(ups) != 1 {
		t.Fatalf("legacy resolve: %v, %d updates", err, len(ups))
	}
	if got := fmt.Sprint(ups[0].Value); got != want {
		t.Errorf("legacy gNMI in-octets = %s, want %s", got, want)
	}

	// Catalogue resolver.
	cat, err := parseGnmiCatalog(readTestCatalog(t), "min")
	if err != nil {
		t.Fatal(err)
	}
	notes, err := newCatalogResolver(dev, cat).Resolve(pathFromString(t, "/interfaces/interface[name=TestIf1]/state/counters/in-octets"), at)
	if err != nil {
		t.Fatalf("catalogue resolve: %v", err)
	}
	var catGot string
	for _, n := range notes {
		for _, u := range n.Updates {
			if strings.HasSuffix(pathToString(u.Path), "in-octets") {
				catGot = fmt.Sprint(u.Value)
			}
		}
	}
	if catGot != want {
		t.Errorf("catalogue gNMI in-octets = %q, want %s", catGot, want)
	}

	// sFlow counter source.
	var sflowGot string
	for _, rec := range NewInterfaceCounterSource(ic).Snapshot(at) {
		if rec.SourceID == 1 {
			sflowGot = strconv.FormatUint(binary.BigEndian.Uint64(rec.Body[sflowIfCountersInOctets:]), 10)
			// ifStatus sits before the octets: bit 0 admin up, bit 1 oper up.
			if st := binary.BigEndian.Uint32(rec.Body[sflowIfCountersInOctets-4:]); st != 1 {
				t.Errorf("sFlow ifStatus = %d, want 1 (admin up, oper down) beside the held counters", st)
			}
		}
	}
	if sflowGot != want {
		t.Errorf("sFlow in-octets = %s, want %s", sflowGot, want)
	}
}

func TestCounterHold_SampleKeepsSendingTheHeldValue(t *testing.T) {
	srv, _, _, _ := newTestGnmiServer(t, 1)
	ic := srv.device.metricsCycler.ifCounters.Load()
	linkDown(t, ic.State(), 1)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	stream := newFakeSubscribeStream(ctx)
	stream.recvQueue <- &gnmipb.SubscribeRequest{Request: &gnmipb.SubscribeRequest_Subscribe{Subscribe: &gnmipb.SubscriptionList{
		Mode: gnmipb.SubscriptionList_STREAM,
		Subscription: []*gnmipb.Subscription{{
			Path:           pathFromString(t, "/interfaces/interface[name=TestIf1]/state/counters/in-octets"),
			Mode:           gnmipb.SubscriptionMode_SAMPLE,
			SampleInterval: uint64(time.Second),
		}},
	}}}
	subscribeErr := make(chan error, 1)
	go func() { subscribeErr <- srv.Subscribe(stream) }()
	var values []string
	for len(values) < 3 {
		r := drainOne(t, stream, 3*time.Second)
		for _, u := range r.GetUpdate().GetUpdate() {
			values = append(values, string(u.GetVal().GetJsonIetfVal()))
		}
	}
	cancel()
	<-subscribeErr
	for i := 1; i < len(values); i++ {
		if values[i] != values[0] {
			t.Errorf("SAMPLE update %d = %s, want the held value %s", i, values[i], values[0])
		}
	}
}

// reconcileHold is the test seam: the production hook with a fixed instant
// in place of the cycler's clock. It lives here so no production caller can
// sample a clock outside the write bracket.
func (ic *IfCounterCycler) reconcileHold(ifIndex int, t float64) {
	ic.reconcileHoldAt(ifIndex, func() float64 { return t })
}
