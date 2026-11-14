/*
 * Copyright 2026 Ronny Trommer <ronny@no42.org>
 * SPDX-License-Identifier: Apache-2.0
 */

package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"log"
	"net"
	"net/http"
	"strings"
	"sync"
	"testing"
	"time"
)

// Link-state propagation across the topology graph (nl6#1023). The engine half
// (the peerDown cause) is tested against InterfaceState directly; the manager
// half through the surfaces a collector or a harness uses: SNMP ifOperStatus,
// the REST POST and its body, the topology graph, and the Tier C notify hook
// that fires link traps and syslog.

// propagationFixture links alpha if1 to bravo if2 with propagation on.
func propagationFixture(t *testing.T) (*lldpFixture, *DeviceSimulator, *DeviceSimulator) {
	t.Helper()
	f := newLLDPFixture(t)
	f.mgr.SetLinkPropagation(true)
	a := f.addDevice(t, 1, 4, "alpha")
	b := f.addDevice(t, 2, 4, "bravo")
	must(t, f.mgr.AddTopologyLinks([]LinkJSON{{A: ep(a.IP.String(), 1), B: ep(b.IP.String(), 2)}}))
	return f, a, b
}

// servedOper is ifOperStatus.<ifIndex> as SNMP serves it.
func servedOper(d *DeviceSimulator, ifIndex int) string {
	return d.snmpServer.findResponse(fmt.Sprintf(".1.3.6.1.2.1.2.2.1.8.%d", ifIndex))
}

// postStatus drives the REST oper-status or admin-status POST and decodes the
// 202 body.
func postStatus(t *testing.T, d *DeviceSimulator, ifIndex int, leaf, status string) stateChangeOutcome {
	t.Helper()
	path := fmt.Sprintf("/api/v1/devices/%s/interfaces/%d/%s", d.IP, ifIndex, leaf)
	w := doReq(t, setupRoutes(), http.MethodPost, path, fmt.Sprintf(`{"status":%q}`, status))
	if w.Code != http.StatusAccepted {
		t.Fatalf("POST %s %s = %d %s, want 202", path, status, w.Code, w.Body.String())
	}
	var out stateChangeOutcome
	if err := json.Unmarshal(w.Body.Bytes(), &out); err != nil {
		t.Fatalf("decode %s: %v", w.Body.String(), err)
	}
	return out
}

// wantOper asserts the SNMP-served ifOperStatus of each (device, ifIndex).
func wantOper(t *testing.T, step string, d *DeviceSimulator, ifIndex int, want string) {
	t.Helper()
	if got := servedOper(d, ifIndex); got != want {
		t.Errorf("%s: %s ifOperStatus.%d = %q, want %q", step, d.sysName, ifIndex, got, want)
	}
}

// notifyRecorder captures the Tier C hook's events, which is what fires the
// link trap and syslog message of a transition.
type notifyRecorder struct {
	mu   sync.Mutex
	evts []StateChange
}

func recordNotify(d *DeviceSimulator) *notifyRecorder {
	r := &notifyRecorder{}
	deviceInterfaceState(d).SetNotify(func(evt StateChange) {
		r.mu.Lock()
		r.evts = append(r.evts, evt)
		r.mu.Unlock()
	})
	return r
}

func (r *notifyRecorder) opers(ifIndex int) []uint8 {
	r.mu.Lock()
	defer r.mu.Unlock()
	var out []uint8
	for _, e := range r.evts {
		if e.IfIndex == ifIndex {
			out = append(out, e.Oper)
		}
	}
	return out
}

func TestDeriveOper_PeerDownIsAFaultUnderAdminUpOnly(t *testing.T) {
	cases := []struct {
		admin, link uint8
		want        uint8
	}{
		{AdminUp, OperUp, OperDown},         // the propagated outage
		{AdminUp, OperDown, OperDown},       // two faults read as one
		{AdminUp, OperTesting, OperTesting}, // the port's own reading is more specific
		{AdminUp, OperDormant, OperDormant}, // likewise
		{AdminDown, OperUp, OperDown},       // admin forces, as without the bit
		{AdminTesting, OperUp, OperTesting}, // likewise
		{AdminUp, OperLowerLayerDn, OperLowerLayerDn},
	}
	for _, c := range cases {
		if got := deriveOper(c.admin, c.link, true); got != c.want {
			t.Errorf("deriveOper(admin=%d, link=%d, peerDown) = %d, want %d", c.admin, c.link, got, c.want)
		}
	}
	// Without the bit the rule is exactly the nl6#694 one: admin forces,
	// admin up releases oper to the link.
	for admin := AdminUp; admin <= AdminTesting; admin++ {
		for link := OperUp; link <= OperLowerLayerDn; link++ {
			want := link
			switch admin {
			case AdminDown:
				want = OperDown
			case AdminTesting:
				want = OperTesting
			}
			if got := deriveOper(admin, link, false); got != want {
				t.Errorf("deriveOper(admin=%d, link=%d, no peerDown) = %d, want %d", admin, link, got, want)
			}
		}
	}
}

func TestSetPeerDown_VisibleTransitionStampsAndIsIdempotent(t *testing.T) {
	clock := time.Unix(1_800_000_000, 0)
	s := newInterfaceStateWithClock(2, nil, nil, func() time.Time { return clock })
	s.Seed(1, OperUp, AdminUp)

	clock = clock.Add(5 * time.Second)
	evts := s.SetPeerDown(1, true)
	if len(evts) != 1 || evts[0].Oper != OperDown || evts[0].PrevOper != OperUp || evts[0].Changed != LeafOperStatus {
		t.Fatalf("SetPeerDown(true) events = %+v, want one oper event up -> down", evts)
	}
	if got, want := s.LastChangeNs(1), uint64(clock.UnixNano()); got != want {
		t.Errorf("lastChange = %d, want %d: the far end entered a new operational state", got, want)
	}
	if snap := s.Snapshot(1); !snap.PeerDown || snap.Link != OperUp || snap.Oper != OperDown {
		t.Errorf("snapshot = %+v, want peerDown with the own link untouched (up) and oper down", snap)
	}
	if again := s.SetPeerDown(1, true); again != nil {
		t.Errorf("SetPeerDown(true) twice returned %+v, want nil: the resync must be idempotent", again)
	}
	evts = s.SetPeerDown(1, false)
	if len(evts) != 1 || evts[0].Oper != OperUp {
		t.Fatalf("SetPeerDown(false) events = %+v, want one oper event down -> up", evts)
	}
}

func TestSetPeerDown_MaskedBeneathAdminDownStillComposes(t *testing.T) {
	s := NewInterfaceState(1, nil, nil)
	s.Seed(1, OperUp, AdminDown)
	before := s.LastChangeNs(1)

	if evts := s.SetPeerDown(1, true); evts != nil {
		t.Fatalf("SetPeerDown under admin down returned %+v, want nil (masked)", evts)
	}
	if s.LastChangeNs(1) != before {
		t.Errorf("a masked peerDown stamped lastChange")
	}
	// The bit was stored: unshutting the port releases it to the far end's
	// fault, not to its own good link.
	evts := s.ApplyAdminStatus(1, AdminUp)
	if len(evts) != 1 || evts[0].Changed != LeafAdminStatus {
		t.Fatalf("admin up under peerDown returned %+v, want the admin event only", evts)
	}
	if got := s.OperStatus(1); got != OperDown {
		t.Errorf("oper after admin up = %d, want down(2): the far end is still silent", got)
	}
}

func TestPeerDownAndOwnLinkComposeAsTwoCauses(t *testing.T) {
	s := NewInterfaceState(1, nil, nil)
	s.Seed(1, OperUp, AdminUp)
	s.SetPeerDown(1, true)

	// The port's own link goes down and comes back while the far end is
	// silent: both moves are masked and the port never comes up.
	if res, _ := s.SetLinkState(1, OperDown); res != LinkMovedMasked {
		t.Errorf("own link down under peerDown = %v, want LinkMovedMasked", res)
	}
	if res, _ := s.SetLinkState(1, OperUp); res != LinkMovedMasked {
		t.Errorf("own link up under peerDown = %v, want LinkMovedMasked", res)
	}
	if got := s.OperStatus(1); got != OperDown {
		t.Fatalf("oper = %d, want down while the far end is silent", got)
	}
	// Own link down again, then the far end recovers: still down.
	s.SetLinkState(1, OperDown)
	if evts := s.SetPeerDown(1, false); evts != nil {
		t.Errorf("peer recovery over an own fault returned %+v, want nil", evts)
	}
	if got := s.OperStatus(1); got != OperDown {
		t.Errorf("oper = %d, want down: the port's own fault still holds", got)
	}
}

func TestSetPeerDown_CascadesToSubinterfaces(t *testing.T) {
	s := NewInterfaceState(2, nil, nil)
	s.setParents(map[int]int{2: 1})
	s.Seed(1, OperUp, AdminUp)
	s.Seed(2, OperUp, AdminUp)

	evts := s.SetPeerDown(1, true)
	if len(evts) != 2 || evts[1].IfIndex != 2 || evts[1].Oper != OperLowerLayerDn {
		t.Fatalf("events = %+v, want the port's down then the unit's lowerLayerDown", evts)
	}
}

func TestSeedPeerDown_StoresTheCauseWithoutATransition(t *testing.T) {
	clock := time.Unix(1_800_000_000, 0)
	s := newInterfaceStateWithClock(1, nil, nil, func() time.Time { return clock })
	s.Seed(1, OperUp, AdminUp)
	before := s.LastChangeNs(1)
	var hooked []int
	s.setOperHook(func(ifIndex int) { hooked = append(hooked, ifIndex) })

	clock = clock.Add(5 * time.Second)
	if moved := s.SeedPeerDown(1, true); len(moved) != 1 || moved[0] != 1 {
		t.Fatalf("SeedPeerDown(true) moved %v, want [1]", moved)
	}
	if snap := s.Snapshot(1); !snap.PeerDown || snap.Link != OperUp || snap.Oper != OperDown {
		t.Errorf("snapshot = %+v, want peerDown, own link up, oper down", snap)
	}
	if got := s.LastChangeNs(1); got != before {
		t.Errorf("lastChange = %d, want %d unchanged: a seed is not a transition", got, before)
	}
	if len(hooked) != 1 || hooked[0] != 1 {
		t.Errorf("hold hook calls = %v, want [1]", hooked)
	}
	if again := s.SeedPeerDown(1, true); again != nil {
		t.Errorf("SeedPeerDown(true) twice moved %v, want nil", again)
	}
	// Release after boot is a real transition.
	evts := s.SetPeerDown(1, false)
	if len(evts) != 1 || evts[0].Oper != OperUp || evts[0].PrevOper != OperDown {
		t.Fatalf("SetPeerDown(false) after a seed = %+v, want one oper event down -> up", evts)
	}
	if got, want := s.LastChangeNs(1), uint64(clock.UnixNano()); got != want {
		t.Errorf("lastChange after release = %d, want %d", got, want)
	}
}

func TestSeedPeerDown_CascadesToSubinterfacesWithoutStamping(t *testing.T) {
	s := NewInterfaceState(2, nil, nil)
	s.setParents(map[int]int{2: 1})
	s.Seed(1, OperUp, AdminUp)
	s.Seed(2, OperUp, AdminUp)
	before := s.LastChangeNs(2)
	var hooked []int
	s.setOperHook(func(ifIndex int) { hooked = append(hooked, ifIndex) })

	if moved := s.SeedPeerDown(1, true); len(moved) != 2 || moved[0] != 1 || moved[1] != 2 {
		t.Fatalf("moved = %v, want [1 2]", moved)
	}
	if got := s.OperStatus(2); got != OperLowerLayerDn {
		t.Errorf("unit oper = %d, want lowerLayerDown(7)", got)
	}
	if got := s.LastChangeNs(2); got != before {
		t.Errorf("unit lastChange = %d, want %d unchanged", got, before)
	}
	if len(hooked) != 2 || hooked[0] != 1 || hooked[1] != 2 {
		t.Errorf("hold hook calls = %v, want [1 2]", hooked)
	}
}

func TestSeedPeerDown_MaskedBeneathAdminDownStoresTheBit(t *testing.T) {
	s := NewInterfaceState(1, nil, nil)
	s.Seed(1, OperUp, AdminDown)
	hooked := 0
	s.setOperHook(func(int) { hooked++ })

	if moved := s.SeedPeerDown(1, true); moved != nil {
		t.Fatalf("SeedPeerDown under admin down moved %v, want nil", moved)
	}
	if hooked != 0 {
		t.Errorf("hold hook called %d times under admin down, want 0", hooked)
	}
	if !s.Snapshot(1).PeerDown {
		t.Fatal("the bit was not stored")
	}
	s.ApplyAdminStatus(1, AdminUp)
	if got := s.OperStatus(1); got != OperDown {
		t.Errorf("oper after admin up = %d, want down(2): the far end is still silent", got)
	}
}

func TestStateSnapshotTransmitsIgnoresPeerDown(t *testing.T) {
	s := NewInterfaceState(3, nil, nil)
	s.Seed(1, OperUp, AdminUp)
	s.Seed(2, OperUp, AdminDown)
	s.Seed(3, OperDown, AdminUp)
	for i := 1; i <= 3; i++ {
		s.SetPeerDown(i, true)
	}
	if !s.Snapshot(1).Transmits() {
		t.Errorf("admin up, link up, held by its partner: must still transmit, or the outage latches")
	}
	if s.Snapshot(2).Transmits() {
		t.Errorf("admin down must not transmit")
	}
	if s.Snapshot(3).Transmits() {
		t.Errorf("link down must not transmit")
	}
}

func TestLinkPropagation_LinkDownTakesTheFarEndDownWithItsOwnNotification(t *testing.T) {
	_, a, b := propagationFixture(t)
	rec := recordNotify(b)
	wantOper(t, "baseline", b, 2, "1")

	postStatus(t, a, 1, "oper-status", "DOWN")
	wantOper(t, "near link down", a, 1, "2")
	wantOper(t, "near link down", b, 2, "2")
	if got := rec.opers(2); len(got) != 1 || got[0] != OperDown {
		t.Errorf("far end notify events = %v, want one down(2): the far end raises its own link trap", got)
	}
	// Only the linked port moved.
	wantOper(t, "near link down", b, 1, "1")

	postStatus(t, a, 1, "oper-status", "UP")
	wantOper(t, "near link up", b, 2, "1")
	if got := rec.opers(2); len(got) != 2 || got[1] != OperUp {
		t.Errorf("far end notify events = %v, want down then up", got)
	}
}

// The latch the issue reproduced by hand: with propagation counting the
// shut port's own peerDown, both ends stayed down after `no shutdown`.
func TestLinkPropagation_AdminDownPropagatesAndNoShutdownRestoresBothEnds(t *testing.T) {
	_, a, b := propagationFixture(t)

	postStatus(t, a, 1, "admin-status", "DOWN")
	wantOper(t, "near shut", a, 1, "2")
	wantOper(t, "near shut", b, 2, "2")

	postStatus(t, a, 1, "admin-status", "UP")
	wantOper(t, "no shutdown", a, 1, "1")
	wantOper(t, "no shutdown", b, 2, "1")
}

func TestLinkPropagation_OverlappingFaultsOnBothEndsCompose(t *testing.T) {
	_, a, b := propagationFixture(t)

	postStatus(t, a, 1, "oper-status", "DOWN") // A's fault
	postStatus(t, b, 2, "oper-status", "DOWN") // B's fault, masked by A's
	postStatus(t, b, 2, "oper-status", "UP")   // B's fault clears first
	wantOper(t, "B recovered while A is down", b, 2, "2")
	wantOper(t, "B recovered while A is down", a, 1, "2")

	postStatus(t, a, 1, "oper-status", "UP")
	wantOper(t, "both faults cleared", a, 1, "1")
	wantOper(t, "both faults cleared", b, 2, "1")

	// The other order: A's fault clears first and A stays down on B's.
	postStatus(t, a, 1, "oper-status", "DOWN")
	postStatus(t, b, 2, "oper-status", "DOWN")
	postStatus(t, a, 1, "oper-status", "UP")
	wantOper(t, "A recovered while B is down", a, 1, "2")
	postStatus(t, b, 2, "oper-status", "UP")
	wantOper(t, "both faults cleared again", a, 1, "1")
	wantOper(t, "both faults cleared again", b, 2, "1")
}

func TestLinkPropagation_OffByDefault(t *testing.T) {
	f := newLLDPFixture(t)
	a := f.addDevice(t, 1, 4, "alpha")
	b := f.addDevice(t, 2, 4, "bravo")
	must(t, f.mgr.AddTopologyLinks([]LinkJSON{{A: ep(a.IP.String(), 1), B: ep(b.IP.String(), 2)}}))

	out := postStatus(t, a, 1, "oper-status", "DOWN")
	wantOper(t, "propagation off", b, 2, "1")
	if out.PeerDown {
		t.Errorf("peer_down = true without -topology-link-propagation")
	}
	if deviceInterfaceState(b).Snapshot(2).PeerDown {
		t.Errorf("the far end carries peerDown without -topology-link-propagation")
	}
}

func TestLinkPropagation_RESTBodyReportsTheFarEndAsHeld(t *testing.T) {
	_, a, b := propagationFixture(t)
	postStatus(t, a, 1, "oper-status", "DOWN")

	out := postStatus(t, b, 2, "oper-status", "UP")
	if !out.PeerDown || !out.Masked || out.OperStatus != "DOWN" || out.Link != "UP" {
		t.Errorf("far end POST UP while held = %+v, want link UP, oper DOWN, masked, peer_down", out)
	}
	out = postStatus(t, a, 1, "oper-status", "UP")
	if out.PeerDown || out.Masked {
		t.Errorf("near end POST UP = %+v, want neither masked nor peer_down", out)
	}
}

func TestLinkPropagation_AddLinkWithTheNearEndAlreadyDownHoldsTheFarEnd(t *testing.T) {
	f := newLLDPFixture(t)
	f.mgr.SetLinkPropagation(true)
	a := f.addDevice(t, 1, 4, "alpha")
	b := f.addDevice(t, 2, 4, "bravo")
	postStatus(t, a, 1, "oper-status", "DOWN")
	rb := recordNotify(b)

	must(t, f.mgr.AddTopologyLinks([]LinkJSON{{A: ep(a.IP.String(), 1), B: ep(b.IP.String(), 2)}}))
	wantOper(t, "link added to a down port", b, 2, "2")
	// A runtime link add is an operator action: the far end's transition is
	// visible, unlike a seed at device publication.
	if got := rb.opers(2); len(got) != 1 || got[0] != OperDown {
		t.Errorf("bravo notify events on a runtime link add = %v, want exactly [down]", got)
	}
}

func TestLinkPropagation_RESTTopologyPostAndDeleteResyncAndRelease(t *testing.T) {
	f := newLLDPFixture(t)
	f.mgr.SetLinkPropagation(true)
	a := f.addDevice(t, 1, 4, "alpha")
	b := f.addDevice(t, 2, 4, "bravo")
	postStatus(t, a, 1, "oper-status", "DOWN")

	link := fmt.Sprintf(`{"a":{"ip":%q,"ifindex":1},"b":{"ip":%q,"ifindex":2}}`, a.IP, b.IP)
	if w := doReq(t, setupRoutes(), http.MethodPost, "/api/v1/topology", `{"links":[`+link+`]}`); w.Code != http.StatusCreated {
		t.Fatalf("POST /topology = %d %s", w.Code, w.Body.String())
	}
	wantOper(t, "POST /topology", b, 2, "2")

	if w := doReq(t, setupRoutes(), http.MethodDelete, "/api/v1/topology", link); w.Code != http.StatusNoContent {
		t.Fatalf("DELETE /topology = %d %s", w.Code, w.Body.String())
	}
	wantOper(t, "DELETE /topology", b, 2, "1")
	wantOper(t, "DELETE /topology", a, 1, "2") // its own fault is untouched
}

func TestLinkPropagation_DeleteDeviceReleasesTheSurvivor(t *testing.T) {
	f, a, b := propagationFixture(t)
	postStatus(t, a, 1, "oper-status", "DOWN")
	wantOper(t, "before delete", b, 2, "2")

	if err := f.mgr.DeleteDevice(a.ID); err != nil {
		t.Fatalf("DeleteDevice: %v", err)
	}
	wantOper(t, "partner deleted", b, 2, "1")
}

func TestLinkPropagation_ClearReleasesEveryEnd(t *testing.T) {
	f, a, b := propagationFixture(t)
	postStatus(t, a, 1, "oper-status", "DOWN")

	f.mgr.releaseLinks(f.mgr.topology.Clear())
	wantOper(t, "graph cleared", b, 2, "1")
}

func TestLinkPropagation_DevicePublishedNextToADownPartnerIsHeldSilently(t *testing.T) {
	f := newLLDPFixture(t)
	f.mgr.SetLinkPropagation(true)
	a := f.addDevice(t, 1, 4, "alpha")
	postStatus(t, a, 1, "oper-status", "DOWN")
	// The link names a device that does not exist yet (-topology-config at
	// startup, before the auto-start batch).
	must(t, f.mgr.AddTopologyLinks([]LinkJSON{{A: ep(a.IP.String(), 1), B: ep("10.42.0.2", 2)}}))

	// Publication runs the tail shared by createSingleDevice and the batch
	// loop, not the resync helper on its own: deleting the resync from that
	// tail is what this test must catch.
	b := f.buildDevice(t, 2, 4, "bravo")
	rb := recordNotify(b)
	lastBefore := deviceInterfaceState(b).LastChangeNs(2)
	f.mgr.publishDevice(b)

	wantOper(t, "published", b, 2, "2")
	if got := rb.opers(2); got != nil {
		t.Errorf("bravo notify events at publication = %v, want none", got)
	}
	if got := deviceInterfaceState(b).LastChangeNs(2); got != lastBefore {
		t.Errorf("bravo lastChange.2 = %d, want %d unchanged: held from boot", got, lastBefore)
	}
	ic := b.metricsCycler.ifCounters.Load()
	for _, col := range heldColumns() {
		if x, y := ic.GetDynamicAt(col+"2", 10), ic.GetDynamicAt(col+"2", 3600); x != y {
			t.Errorf("held %s2 moved: %s at t=10, %s at t=3600", col, x, y)
		}
	}

	postStatus(t, a, 1, "oper-status", "UP")
	wantOper(t, "partner recovered", b, 2, "1")
	if got := rb.opers(2); len(got) != 1 || got[0] != OperUp {
		t.Errorf("bravo notify events after release = %v, want exactly [up]", got)
	}
	// Release closes the counter hold: the octet counters advance again.
	// (The discard and error columns stay zero under the clean scenario, so
	// they cannot show a release.)
	for _, col := range []string{".1.3.6.1.2.1.2.2.1.10.", ".1.3.6.1.2.1.2.2.1.16."} {
		if x, y := ic.GetDynamicAt(col+"2", 10), ic.GetDynamicAt(col+"2", 3600); x == y {
			t.Errorf("released %s2 still held: %s at t=10 and t=3600", col, x)
		}
	}
}

func TestLinkPropagation_PartnerOfASeededDownPortIsHeldSilently(t *testing.T) {
	f := newLLDPFixture(t)
	f.mgr.SetLinkPropagation(true)
	a := f.addDevice(t, 1, 4, "alpha")
	ra := recordNotify(a)
	must(t, f.mgr.AddTopologyLinks([]LinkJSON{{A: ep(a.IP.String(), 1), B: ep("10.42.0.2", 2)}}))
	lastBefore := deviceInterfaceState(a).LastChangeNs(1)

	b := f.buildDeviceWithLinkDown(t, 2, 4, "bravo", 2)
	f.mgr.publishDevice(b)

	wantOper(t, "partner published with its port seeded down", a, 1, "2")
	if got := ra.opers(1); got != nil {
		t.Errorf("alpha notify events at partner publication = %v, want none", got)
	}
	if got := deviceInterfaceState(a).LastChangeNs(1); got != lastBefore {
		t.Errorf("alpha lastChange.1 = %d, want %d unchanged", got, lastBefore)
	}
	if out := postStatus(t, a, 1, "oper-status", "UP"); !out.PeerDown || !out.Masked {
		t.Errorf("alpha POST UP while held = %+v, want masked and peer_down", out)
	}
}

func TestLinkPropagation_FlapSchedulerFiresReachTheFarEndIncludingMaskedOnes(t *testing.T) {
	f, a, b := propagationFixture(t)
	if err := f.mgr.StartFlapSubsystem(FlapSubsystemConfig{}); err != nil {
		t.Fatalf("StartFlapSubsystem: %v", err)
	}
	t.Cleanup(f.mgr.StopFlapSubsystem)
	sched := f.mgr.flapScheduler.Load()

	sched.fireWithRecover(deviceInterfaceState(a), 1, OperDown, a.IP)
	wantOper(t, "scheduler fire on A", b, 2, "2")

	// B's own fire is masked (A holds B down) yet changes what B transmits:
	// A must stay down after its own fault clears.
	sched.fireWithRecover(deviceInterfaceState(b), 2, OperDown, b.IP)
	sched.fireWithRecover(deviceInterfaceState(a), 1, OperUp, a.IP)
	wantOper(t, "A's fault cleared, B's masked fault holds", a, 1, "2")

	sched.fireWithRecover(deviceInterfaceState(b), 2, OperUp, b.IP)
	wantOper(t, "both cleared", a, 1, "1")
	wantOper(t, "both cleared", b, 2, "1")
}

func TestLinkPropagation_SNMPSetShutdownTakesTheFarEndDown(t *testing.T) {
	_, a, b := propagationFixture(t)
	if v := a.snmpServer.applySetActions([]setAction{{column: ifAdminStatusColumn, ifIndex: 1, value: int(AdminDown)}}); v.errStatus != snmpErrNoError {
		t.Fatalf("SET ifAdminStatus.1 = down: %+v", v)
	}
	wantOper(t, "SNMP SET shutdown", b, 2, "2")
	a.snmpServer.applySetActions([]setAction{{column: ifAdminStatusColumn, ifIndex: 1, value: int(AdminUp)}})
	wantOper(t, "SNMP SET no shutdown", b, 2, "1")
}

// Both auto-revert branches restore the far end: the oper-status one restores
// the near end's link, the admin-status one its admin.
func TestLinkPropagation_AutoRevertRestoresTheFarEnd(t *testing.T) {
	for _, leaf := range []string{"oper-status", "admin-status"} {
		t.Run(leaf, func(t *testing.T) {
			_, a, b := propagationFixture(t)
			path := fmt.Sprintf("/api/v1/devices/%s/interfaces/1/%s", a.IP, leaf)
			if w := doReq(t, setupRoutes(), http.MethodPost, path, `{"status":"DOWN","duration":"400ms"}`); w.Code != http.StatusAccepted {
				t.Fatalf("POST with duration = %d %s", w.Code, w.Body.String())
			}
			t.Cleanup(func() { manager.awaitAutoRevertsForDevice(a.IP.String()) })
			wantOper(t, "before the revert", b, 2, "2")

			deadline := time.Now().Add(5 * time.Second)
			for servedOper(b, 2) != "1" && time.Now().Before(deadline) {
				time.Sleep(5 * time.Millisecond)
			}
			wantOper(t, "after the revert", b, 2, "1")
		})
	}
}

func TestTopologyGraph_DownEndNamesTheCauseNotTheHeldEnd(t *testing.T) {
	_, a, b := propagationFixture(t)
	postStatus(t, a, 1, "oper-status", "DOWN")

	g := getGraph(t, setupRoutes())
	e, _ := edgeFor(g, a.IP.String(), 1)
	want := "a"
	if e.A.IP != a.IP.String() {
		want = "b"
	}
	if e.Active || e.DownEnd != want {
		t.Errorf("edge = %+v, want inactive with downEnd %q (alpha caused it; bravo is held)", e, want)
	}

	// A second, independent fault on bravo makes it "both".
	postStatus(t, b, 2, "admin-status", "DOWN")
	g = getGraph(t, setupRoutes())
	if e, _ = edgeFor(g, a.IP.String(), 1); e.DownEnd != "both" {
		t.Errorf("two independent faults: downEnd = %q, want both", e.DownEnd)
	}

	// The mirror case, so each side's rule is exercised: bravo alone causes
	// it and alpha is the held end.
	postStatus(t, a, 1, "oper-status", "UP")
	g = getGraph(t, setupRoutes())
	e, _ = edgeFor(g, a.IP.String(), 1)
	want = "b"
	if e.A.IP != a.IP.String() {
		want = "a"
	}
	if e.Active || e.DownEnd != want {
		t.Errorf("edge = %+v, want inactive with downEnd %q (bravo caused it; alpha is held)", e, want)
	}
}

// Concurrent mutations of one near end must leave the far end matching the
// near end's final state. Each resync reads the state when it runs, under
// linkPropMu, so whichever runs last sees the last mutation.
func TestLinkPropagation_ConcurrentNearEndMutationsConverge(t *testing.T) {
	f, a, b := propagationFixture(t)
	st := deviceInterfaceState(a)
	ip := a.IP.String()

	var wg sync.WaitGroup
	for g := 0; g < 8; g++ {
		wg.Add(1)
		go func(g int) {
			defer wg.Done()
			for i := 0; i < 200; i++ {
				link := OperUp
				if (g+i)%2 == 0 {
					link = OperDown
				}
				if res, evts := st.SetLinkState(1, link); res != LinkUnchanged {
					f.mgr.publishStateChanges(ip, st, 1, evts)
				}
			}
		}(g)
	}
	wg.Wait()

	want := !st.Snapshot(1).Transmits()
	if got := deviceInterfaceState(b).Snapshot(2).PeerDown; got != want {
		t.Errorf("far end peerDown = %t after the race, want %t (the near end's final state)", got, want)
	}
}

// A link end naming an interface its device does not have is inert, like an
// end whose device does not exist yet: a typo in -topology-config must not
// take a real port down or fire a trap for an interface nobody has.
func TestLinkPropagation_AnEndOnAnUnknownIfIndexIsInert(t *testing.T) {
	f := newLLDPFixture(t)
	f.mgr.SetLinkPropagation(true)
	a := f.addDevice(t, 1, 4, "alpha")
	b := f.addDevice(t, 2, 4, "bravo")
	rec := recordNotify(b)
	must(t, f.mgr.AddTopologyLinks([]LinkJSON{
		{A: ep(a.IP.String(), 99), B: ep(b.IP.String(), 2)},
		{A: ep(a.IP.String(), 1), B: ep(b.IP.String(), 98)},
	}))
	wantOper(t, "linked to alpha/99", b, 2, "1")

	postStatus(t, a, 1, "oper-status", "DOWN")
	if got := rec.opers(98); len(got) != 0 {
		t.Errorf("bravo fired %v for ifIndex 98, which it does not have", got)
	}
	if got := rec.opers(2); len(got) != 0 {
		t.Errorf("bravo/2 fired %v, want nothing: its partner alpha/99 does not exist", got)
	}
}

// A device type with no interface-state engine counts as transmitting, as
// operUp treats it as up, and takes no peerDown.
func TestLinkPropagation_ADeviceWithoutAnEngineTransmitsAndTakesNothing(t *testing.T) {
	f := newLLDPFixture(t)
	f.mgr.SetLinkPropagation(true)
	a := f.addDevice(t, 1, 4, "alpha")
	bare := &DeviceSimulator{ID: "dev-bare", IP: net.ParseIP("10.42.0.9"), sysName: "bare"}
	f.mgr.mu.Lock()
	f.mgr.devices[bare.ID] = bare
	f.mgr.deviceIPs[bare.IP.String()] = struct{}{}
	f.mgr.indexDeviceByIP(bare)
	f.mgr.mu.Unlock()

	must(t, f.mgr.AddTopologyLinks([]LinkJSON{{A: ep(a.IP.String(), 1), B: ep(bare.IP.String(), 1)}}))
	wantOper(t, "linked to an engine-less device", a, 1, "1")
	postStatus(t, a, 1, "oper-status", "DOWN")
	postStatus(t, a, 1, "oper-status", "UP")
	wantOper(t, "after a flap towards it", a, 1, "1")
}

func TestStateChange_MaskedByNamesTheFirstEngineCause(t *testing.T) {
	f, a, b := propagationFixture(t)

	// Peer hold: the link the caller set is up, the partner is silent.
	postStatus(t, a, 1, "oper-status", "DOWN")
	if out := postStatus(t, b, 2, "oper-status", "UP"); !out.Masked || !out.PeerDown || out.MaskedBy != "peer" {
		t.Errorf("held far end POST UP = %+v, want masked by peer", out)
	}

	// Admin down with no link and no partner.
	postStatus(t, a, 3, "admin-status", "DOWN")
	if out := postStatus(t, a, 3, "oper-status", "UP"); !out.Masked || out.PeerDown || out.MaskedBy != "admin" {
		t.Errorf("shut port POST UP = %+v, want masked by admin", out)
	}
	// Admin testing is the other admin != up state; it names admin too.
	postStatus(t, a, 3, "admin-status", "TESTING")
	if out := postStatus(t, a, 3, "oper-status", "UP"); !out.Masked || out.PeerDown || out.MaskedBy != "admin" {
		t.Errorf("testing port POST UP = %+v, want masked by admin", out)
	}

	// A subinterface under that shut parent: lowerLayerDown, named parent.
	deviceInterfaceState(a).setParents(map[int]int{4: 3})
	if out := postStatus(t, a, 4, "oper-status", "UP"); !out.Masked || out.MaskedBy != "parent" || out.OperStatus != "LOWER_LAYER_DOWN" {
		t.Errorf("unit under a shut parent POST UP = %+v, want masked by parent", out)
	}

	// Precedence: admin down on the held port names admin, not peer. The
	// engine's derivation returns on admin before it looks at the peer.
	postStatus(t, b, 2, "admin-status", "DOWN")
	if out := postStatus(t, b, 2, "oper-status", "UP"); !out.Masked || !out.PeerDown || out.MaskedBy != "admin" {
		t.Errorf("shut and held port POST UP = %+v, want masked by admin ahead of peer", out)
	}

	// Partner silent AND parent shut: the engine returns down(2) on the peer
	// clause before it reaches the parent clause, so the cause is peer. A
	// REST-side order with parent first would name a cause whose outcome
	// (lowerLayerDown) the body does not report.
	postStatus(t, b, 2, "admin-status", "UP")
	deviceInterfaceState(b).setParents(map[int]int{4: 3})
	must(t, f.mgr.AddTopologyLinks([]LinkJSON{{A: ep(a.IP.String(), 2), B: ep(b.IP.String(), 4)}}))
	postStatus(t, b, 3, "admin-status", "DOWN")
	postStatus(t, a, 2, "oper-status", "DOWN")
	if out := postStatus(t, b, 4, "oper-status", "UP"); !out.Masked || !out.PeerDown || out.MaskedBy != "peer" || out.OperStatus != "DOWN" {
		t.Errorf("unit under a shut parent with a silent partner POST UP = %+v, want oper DOWN masked by peer", out)
	}

	// Not masked: an unlinked, admin-up, top-level port carries no field.
	postStatus(t, a, 2, "oper-status", "UP")
	if !f.mgr.RemoveTopologyLink(ep(a.IP.String(), 2), ep(b.IP.String(), 4)) {
		t.Fatal("remove the second link")
	}
	// The raw body is read so a dropped omitempty shows as a present key.
	path := fmt.Sprintf("/api/v1/devices/%s/interfaces/2/oper-status", a.IP)
	w := doReq(t, setupRoutes(), http.MethodPost, path, `{"status":"UP"}`)
	if w.Code != http.StatusAccepted {
		t.Fatalf("plain POST UP = %d %s, want 202", w.Code, w.Body.String())
	}
	var out stateChangeOutcome
	if err := json.Unmarshal(w.Body.Bytes(), &out); err != nil {
		t.Fatal(err)
	}
	if out.Masked || out.MaskedBy != "" || strings.Contains(w.Body.String(), "masked_by") {
		t.Errorf("plain POST UP = %s, want no masked_by key", w.Body.String())
	}
}

func TestLinkPropagation_SubinterfaceEndWarnsOnceAndPropagatesItsOwnShutdown(t *testing.T) {
	var logs bytes.Buffer
	prev := log.Writer()
	log.SetOutput(&logs)
	t.Cleanup(func() { log.SetOutput(prev) })

	f := newLLDPFixture(t)
	f.mgr.SetLinkPropagation(true)
	a := f.addDevice(t, 1, 4, "alpha")
	b := f.addDevice(t, 2, 4, "bravo")
	// A ifIndex 4 is a unit of A ifIndex 3. Linking it is a modelling
	// mistake the docs explain; the engine still honours the unit's own
	// state and says so once.
	deviceInterfaceState(a).setParents(map[int]int{4: 3})
	must(t, f.mgr.AddTopologyLinks([]LinkJSON{{A: ep(a.IP.String(), 4), B: ep(b.IP.String(), 2)}}))

	postStatus(t, a, 4, "oper-status", "DOWN")
	wantOper(t, "unit's own shutdown", b, 2, "2")
	postStatus(t, a, 4, "oper-status", "UP")
	wantOper(t, "unit's own restore", b, 2, "1")

	// The parent's shutdown does not travel through the unit's link: a
	// physical outage is modelled by linking the physical ports.
	postStatus(t, a, 3, "admin-status", "DOWN")
	wantOper(t, "parent shut", a, 4, "7")
	wantOper(t, "far end of a unit under a shut parent", b, 2, "1")

	if got := strings.Count(logs.String(), "subinterface"); got != 1 {
		t.Errorf("subinterface link-end warning logged %d times, want exactly once:\n%s", got, logs.String())
	}
}

func TestTopologyStatus_ReportsLinkPropagation(t *testing.T) {
	f := newLLDPFixture(t)
	router := setupRoutes()
	read := func(step string, want bool) {
		t.Helper()
		w := doReq(t, router, http.MethodGet, "/api/v1/topology/status", "")
		if w.Code != http.StatusOK {
			t.Fatalf("%s: status = %d %s", step, w.Code, w.Body.String())
		}
		var st topologyStatus
		if err := json.Unmarshal(w.Body.Bytes(), &st); err != nil {
			t.Fatal(err)
		}
		if st.LinkPropagation != want || !strings.Contains(w.Body.String(), `"link_propagation":`) {
			t.Errorf("%s: body %s, want link_propagation=%v", step, w.Body.String(), want)
		}
	}
	read("flag off", false)
	f.mgr.SetLinkPropagation(true)
	read("flag on", true)
}
