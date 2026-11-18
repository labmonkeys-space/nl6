/*
 * Copyright 2026 Ronny Trommer <ronny@no42.org>
 * SPDX-License-Identifier: Apache-2.0
 */

package main

import (
	"encoding/binary"
	"encoding/json"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"
)

// ypFakeClock drives the exporter's clock and timers by hand.
type ypFakeClock struct {
	mu     sync.Mutex
	now    time.Time
	timers []*ypFakeTimer
}

type ypFakeTimer struct {
	c     *ypFakeClock
	ch    chan time.Time
	at    time.Time
	armed bool
}

func (c *ypFakeClock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.now
}

func (c *ypFakeClock) NewTimer() ypTimer {
	c.mu.Lock()
	defer c.mu.Unlock()
	t := &ypFakeTimer{c: c, ch: make(chan time.Time, 1)}
	c.timers = append(c.timers, t)
	return t
}

// Advance moves the clock and fires every armed timer that is due.
func (c *ypFakeClock) Advance(d time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.now = c.now.Add(d)
	for _, t := range c.timers {
		t.fireLocked()
	}
}

// armedCount reports how many timers wait for a deadline.
func (c *ypFakeClock) armedCount() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	n := 0
	for _, t := range c.timers {
		if t.armed {
			n++
		}
	}
	return n
}

func (t *ypFakeTimer) fireLocked() {
	if t.armed && !t.at.After(t.c.now) {
		t.armed = false
		select {
		case t.ch <- t.c.now:
		default:
		}
	}
}

func (t *ypFakeTimer) C() <-chan time.Time { return t.ch }

func (t *ypFakeTimer) ResetAt(at time.Time) {
	t.c.mu.Lock()
	defer t.c.mu.Unlock()
	t.at, t.armed = at, true
	t.fireLocked()
}

func (t *ypFakeTimer) Stop() {
	t.c.mu.Lock()
	defer t.c.mu.Unlock()
	t.armed = false
}

// ypTestStart is a fake-clock instant 10 s past a period boundary, near the
// real time so the counter cycler evaluates sane values.
func ypTestStart() time.Time {
	k := time.Since(ypAnchor) / time.Minute
	return ypAnchor.Add(k*time.Minute + 10*time.Second)
}

func newYangPushTestDevice(t *testing.T) (*DeviceSimulator, *InterfaceState) {
	t.Helper()
	sm := &SimulatorManager{resourcesCache: make(map[string]*DeviceResources)}
	res, err := sm.LoadSpecificResources("huawei_ne8000.json")
	if err != nil {
		t.Fatalf("load profile: %v", err)
	}
	mc := &MetricsCycler{}
	mc.InitIfCountersWithScenario(res, 1, IfErrorClean)
	ic := mc.ifCounters.Load()
	if ic == nil || ic.State() == nil || len(ic.IfIndices()) == 0 {
		t.Fatal("huawei_ne8000 has no interface state engine")
	}
	dev := &DeviceSimulator{ID: "ne8000-test", IP: net.IPv4(127, 0, 0, 1), resources: res,
		metricsCycler: mc, resourceFile: "huawei_ne8000.json"}
	dev.cachedSysName.Store("ne8000-sim")
	return dev, ic.State()
}

// ypCollector is a loopback UDP-notif receiver that reassembles segments.
type ypCollector struct {
	conn *net.UDPConn
}

type ypRecv struct {
	MsgID, PubID uint32
	Src          *net.UDPAddr
	Seq          uint64
	Kind         string
	SubID        uint32
	Obs          string
	Contents     map[string]any
	Raw          []byte
}

func newYPCollector(t *testing.T) *ypCollector {
	t.Helper()
	conn, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatalf("collector listen: %v", err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	return &ypCollector{conn: conn}
}

func (c *ypCollector) addr() string { return c.conn.LocalAddr().String() }

// next returns the next reassembled message, or false after timeout.
func (c *ypCollector) next(t *testing.T, timeout time.Duration) (ypRecv, bool) {
	t.Helper()
	var payload []byte
	buf := make([]byte, 65536)
	_ = c.conn.SetReadDeadline(time.Now().Add(timeout))
	for {
		n, src, err := c.conn.ReadFromUDP(buf)
		if err != nil {
			var ne net.Error
			if errors.As(err, &ne) && ne.Timeout() {
				return ypRecv{}, false
			}
			t.Fatalf("collector read: %v", err)
		}
		d := buf[:n]
		hl := int(d[1])
		payload = append(payload, d[hl:]...)
		if hl == udpNotifSegHeader && binary.BigEndian.Uint16(d[14:16])&1 == 0 {
			continue // more segments follow
		}
		r := ypRecv{
			PubID: binary.BigEndian.Uint32(d[4:8]),
			MsgID: binary.BigEndian.Uint32(d[8:12]),
			Src:   src,
			Raw:   payload,
		}
		var env struct {
			Envelope struct {
				Seq      uint64                     `json:"sequence-number"`
				Contents map[string]json.RawMessage `json:"contents"`
			} `json:"ietf-yp-notification:envelope"`
		}
		if err := json.Unmarshal(payload, &env); err != nil {
			t.Fatalf("payload is not JSON: %v\n%s", err, payload)
		}
		r.Seq = env.Envelope.Seq
		for k, v := range env.Envelope.Contents {
			r.Kind = k
			_ = json.Unmarshal(v, &r.Contents)
		}
		if id, ok := r.Contents["id"].(float64); ok {
			r.SubID = uint32(id)
		}
		r.Obs, _ = r.Contents["ietf-yp-observation:timestamp"].(string)
		return r, true
	}
}

func (c *ypCollector) mustNext(t *testing.T) ypRecv {
	t.Helper()
	r, ok := c.next(t, 3*time.Second)
	if !ok {
		t.Fatal("collector: no message within 3s")
	}
	return r
}

func startYangPushTest(t *testing.T, dev *DeviceSimulator, collector string) (*YangPushExporter, *ypFakeClock) {
	t.Helper()
	fc := &ypFakeClock{now: ypTestStart()}
	e, err := NewYangPushExporter(dev, &DeviceYangPushConfig{Collector: collector, SegmentSize: defaultYangPushSegmentSize}, fc.Now)
	if err != nil {
		t.Fatalf("NewYangPushExporter: %v", err)
	}
	e.newTimer = fc.NewTimer
	t.Cleanup(func() { _ = e.Close() })
	e.Start()
	return e, fc
}

// waitArmed waits until the run loop has armed both periodic timers, so an
// Advance cannot slip in before a deadline is set.
func waitArmed(t *testing.T, fc *ypFakeClock) {
	t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	for fc.armedCount() < 2 {
		if time.Now().After(deadline) {
			t.Fatalf("periodic timers not armed (armed=%d)", fc.armedCount())
		}
		time.Sleep(time.Millisecond)
	}
}

func readStart(t *testing.T, c *ypCollector) []ypRecv {
	t.Helper()
	var out []ypRecv
	for range 4 { // three subscription-started, then the sub-10 sync
		out = append(out, c.mustNext(t))
	}
	return out
}

func TestYangPushStartSendsSubscriptionStarted(t *testing.T) {
	dev, _ := newYangPushTestDevice(t)
	c := newYPCollector(t)
	startYangPushTest(t, dev, c.addr())
	msgs := readStart(t, c)
	for i, want := range []uint32{8, 9, 10} {
		m := msgs[i]
		if m.Kind != "ietf-subscribed-notifications:subscription-started" || m.SubID != want {
			t.Fatalf("message %d = %s id %d, want subscription-started id %d", i, m.Kind, m.SubID, want)
		}
		// One counter per device over all subscriptions, from 1 (IETF 127).
		if m.MsgID != uint32(i+1) || m.Seq != uint64(i+1) {
			t.Errorf("sub %d: message id %d seq %d, want %d", want, m.MsgID, m.Seq, i+1)
		}
		if m.PubID != 0x7F000001 {
			t.Errorf("publisher id %#x, want 127.0.0.1 as uint32", m.PubID)
		}
		if !m.Src.IP.Equal(dev.IP) {
			t.Errorf("source %v, want device IP %v", m.Src, dev.IP)
		}
		if !strings.Contains(string(m.Raw), `"hostname":"ne8000-sim"`) {
			t.Errorf("hostname missing: %s", m.Raw)
		}
	}
}

func TestYangPushPeriodicAlignment(t *testing.T) {
	dev, _ := newYangPushTestDevice(t)
	c := newYPCollector(t)
	_, fc := startYangPushTest(t, dev, c.addr())
	readStart(t, c)
	waitArmed(t, fc)
	boundary := fc.Now().Add(50 * time.Second) // ypTestStart is 10 s past a boundary
	for k := range 3 {
		at8 := boundary.Add(time.Duration(k) * time.Minute)
		fc.Advance(at8.Sub(fc.Now()))
		m := c.mustNext(t)
		if m.Kind != "ietf-yang-push:push-update" || m.SubID != 8 {
			t.Fatalf("tick %d: got %s id %d, want push-update 8", k, m.Kind, m.SubID)
		}
		// Messages 1 to 4 are the three subscription-started and the sync.
		if want := 5 + 2*k; m.MsgID != uint32(want) || m.Seq != uint64(want) {
			t.Errorf("sub 8 tick %d: message id %d seq %d, want %d", k, m.MsgID, m.Seq, want)
		}
		if m.Obs != ypMillis(at8) {
			t.Errorf("sub 8 observation %s, want %s", m.Obs, ypMillis(at8))
		}
		if _, ok := c.next(t, 50*time.Millisecond); ok {
			t.Fatal("sub 9 fired together with sub 8")
		}
		fc.Advance(3 * time.Second)
		m = c.mustNext(t)
		if m.Kind != "ietf-yang-push:push-update" || m.SubID != 9 {
			t.Fatalf("tick %d: got %s id %d, want push-update 9", k, m.Kind, m.SubID)
		}
		if want := 6 + 2*k; m.MsgID != uint32(want) || m.Seq != uint64(want) {
			t.Errorf("sub 9 tick %d: message id %d seq %d, want %d", k, m.MsgID, m.Seq, want)
		}
		if want := ypMillis(at8.Add(3 * time.Second)); m.Obs != want {
			t.Errorf("sub 9 observation %s, want %s", m.Obs, want)
		}
		waitArmed(t, fc)
	}
}

func TestYangPushOnChangeSyncThenChange(t *testing.T) {
	dev, st := newYangPushTestDevice(t)
	c := newYPCollector(t)
	startYangPushTest(t, dev, c.addr())
	msgs := readStart(t, c)
	sync := msgs[3]
	if sync.Kind != "ietf-yang-push:push-update" || sync.SubID != 10 || sync.MsgID != 4 || sync.Seq != 4 {
		t.Fatalf("sync = %s id %d msg %d seq %d, want push-update 10 msg 4 seq 4", sync.Kind, sync.SubID, sync.MsgID, sync.Seq)
	}
	ic := dev.metricsCycler.ifCounters.Load()
	ifs := sync.Contents["datastore-contents"].(map[string]any)["ietf-interfaces:interfaces"].(map[string]any)["interface"].([]any)
	if len(ifs) != len(ic.IfIndices()) {
		t.Errorf("sync carries %d interfaces, want %d", len(ifs), len(ic.IfIndices()))
	}
	target := 0
	for _, idx := range ic.IfIndices() {
		if st.OperStatus(idx) == OperUp {
			target = idx
			break
		}
	}
	if target == 0 {
		t.Fatal("no interface is up")
	}
	_, evts := st.SetLinkState(target, OperDown)
	for _, ev := range evts {
		st.Broadcast(ev)
	}
	m := c.mustNext(t)
	if m.Kind != "ietf-yang-push:push-change-update" || m.SubID != 10 || m.MsgID != 5 || m.Seq != 5 {
		t.Fatalf("got %s id %d msg %d seq %d, want push-change-update 10 msg 5", m.Kind, m.SubID, m.MsgID, m.Seq)
	}
	// The change must agree with what a periodic subscription-9 read reports
	// for the same interface now, as a whole entry in the captured patch shape.
	want := ypIfaceFrom(buildIosxeRow(dev, ic, target, time.Now()), lookupIfType(dev, target), 0, "")
	if want.Oper != "down" {
		t.Fatalf("engine reports %s oper %q, want down", want.Name, want.Oper)
	}
	id, edits := ypEdits(t, m.Raw)
	if id != "0" || len(edits) != 1 || edits[0].EditID != "edit1" {
		t.Fatalf("patch-id %q edits %+v, want patch 0 with edit1", id, edits)
	}
	if wantTarget := "/ietf-interfaces:interfaces/interface[name=" + want.Name + "]"; edits[0].Target != wantTarget {
		t.Errorf("target = %q, want %q", edits[0].Target, wantTarget)
	}
	var value struct {
		Interface []map[string]any `json:"interface"`
	}
	if err := json.Unmarshal(edits[0].Value, &value); err != nil || len(value.Interface) != 1 {
		t.Fatalf("value is not one unprefixed interface entry: %s", edits[0].Value)
	}
	got := value.Interface[0]
	if got["name"] != want.Name || got["oper-status"] != "down" || got["type"] != want.Type || got["last-change"] == nil {
		t.Errorf("entry = %v, want name %s, oper-status down, type %s and a last-change", got, want.Name, want.Type)
	}
}

// description is the ifAlias SNMP serves: the topology link label, else the
// value the device profile holds.
func TestYangPushDescriptionIsServedIfAlias(t *testing.T) {
	dev, _ := newYangPushTestDevice(t)
	e := &YangPushExporter{dev: dev}
	static := lookupIfColumn(dev, ifAliasPrefix, 1)
	if static == "" {
		t.Fatal("the huawei_ne8000 profile has no ifAlias for ifIndex 1")
	}
	if got := e.entry(e.row(1, time.Now())).Description; got != static {
		t.Fatalf("description = %q, want the static ifAlias %q", got, static)
	}
	// A topology link on the port overrides the static profile value with
	// to_<peer.sysName>_<peerIfDescr>, matching SNMP.
	f := newLLDPFixture(t)
	peer := f.addDevice(t, 2, 2, "spine1")
	f.mgr.mu.Lock()
	f.mgr.devices[dev.ID] = dev
	f.mgr.deviceIPs[dev.IP.String()] = struct{}{}
	f.mgr.indexDeviceByIP(dev)
	f.mgr.mu.Unlock()
	if err := f.mgr.topology.AddLink(ep(dev.IP.String(), 1), ep(peer.IP.String(), 2)); err != nil {
		t.Fatal(err)
	}
	want := "to_spine1_" + devIfDescr(peer, 2)
	if got := e.entry(e.row(1, time.Now())).Description; got != want {
		t.Errorf("description with topology link = %q, want %q", got, want)
	}
}

// waitArmedN waits until n timers are armed: the two periodic ones plus the
// dampening timer while a window is open.
func waitArmedN(t *testing.T, fc *ypFakeClock, n int) {
	t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	for fc.armedCount() != n {
		if time.Now().After(deadline) {
			t.Fatalf("armed timers = %d, want %d", fc.armedCount(), n)
		}
		time.Sleep(time.Millisecond)
	}
}

// ypOnChangeSetup starts an exporter, reads the start messages and returns two
// interfaces that are up, in ifIndex order.
func ypOnChangeSetup(t *testing.T) (*YangPushExporter, *ypFakeClock, *ypCollector, *InterfaceState, *DeviceSimulator, [2]int) {
	t.Helper()
	dev, st := newYangPushTestDevice(t)
	c := newYPCollector(t)
	e, fc := startYangPushTest(t, dev, c.addr())
	readStart(t, c)
	waitArmed(t, fc)
	var up [2]int
	n := 0
	for _, idx := range dev.metricsCycler.ifCounters.Load().IfIndices() {
		if st.OperStatus(idx) == OperUp && n < 2 {
			up[n] = idx
			n++
		}
	}
	if n < 2 {
		t.Fatal("fewer than two interfaces are up")
	}
	// IfIndices is not sorted, and a collected update orders its edits by
	// ifIndex.
	if up[0] > up[1] {
		up[0], up[1] = up[1], up[0]
	}
	return e, fc, c, st, dev, up
}

func ypSetLink(st *InterfaceState, idx int, oper uint8) {
	_, evts := st.SetLinkState(idx, oper)
	for _, ev := range evts {
		st.Broadcast(ev)
	}
}

// ypEditEntries returns the patch id and, per edit, the interface entry.
func ypEditEntries(t *testing.T, raw []byte) (string, []map[string]any) {
	t.Helper()
	id, edits := ypEdits(t, raw)
	var out []map[string]any
	for _, ed := range edits {
		var v struct {
			Interface []map[string]any `json:"interface"`
		}
		if err := json.Unmarshal(ed.Value, &v); err != nil || len(v.Interface) != 1 {
			t.Fatalf("edit %s value is not one interface entry: %s", ed.EditID, ed.Value)
		}
		out = append(out, v.Interface[0])
	}
	return id, out
}

// The first change goes out at once. Changes in the following dampening
// period are collected into one update with an edit per interface.
func TestYangPushOnChangeDampeningCollects(t *testing.T) {
	_, fc, c, st, dev, up := ypOnChangeSetup(t)
	ypSetLink(st, up[0], OperDown)
	id, entries := ypEditEntries(t, c.mustNext(t).Raw)
	if id != "0" || len(entries) != 1 || entries[0]["oper-status"] != "down" {
		t.Fatalf("first change: patch %q entries %v, want patch 0 with one entry down", id, entries)
	}
	waitArmedN(t, fc, 3)
	ypSetLink(st, up[0], OperUp)
	ypSetLink(st, up[1], OperDown)
	if m, ok := c.next(t, 300*time.Millisecond); ok {
		t.Fatalf("a change went out inside the dampening period: %s", m.Raw)
	}
	fc.Advance(ypDampening)
	id, entries = ypEditEntries(t, c.mustNext(t).Raw)
	if id != "1" || len(entries) != 2 {
		t.Fatalf("collected change: patch %q with %d entries, want patch 1 with 2", id, len(entries))
	}
	if entries[0]["name"] != devIfDescr(dev, up[0]) || entries[0]["oper-status"] != "up" ||
		entries[1]["name"] != devIfDescr(dev, up[1]) || entries[1]["oper-status"] != "down" {
		t.Errorf("entries = %v, want %s up then %s down", entries, devIfDescr(dev, up[0]), devIfDescr(dev, up[1]))
	}
}

// A link that goes down and up inside one period is reported once, with the
// state it has when the period ends.
func TestYangPushOnChangeFlapInsideWindow(t *testing.T) {
	_, fc, c, st, dev, up := ypOnChangeSetup(t)
	ypSetLink(st, up[0], OperDown)
	c.mustNext(t)
	waitArmedN(t, fc, 3)
	ypSetLink(st, up[1], OperDown)
	ypSetLink(st, up[1], OperUp)
	fc.Advance(ypDampening)
	_, entries := ypEditEntries(t, c.mustNext(t).Raw)
	if len(entries) != 1 || entries[0]["name"] != devIfDescr(dev, up[1]) || entries[0]["oper-status"] != "up" {
		t.Fatalf("entries = %v, want one entry for %s with oper-status up", entries, devIfDescr(dev, up[1]))
	}
}

// A period that ends with nothing collected sends nothing, and the next
// change goes out without waiting.
func TestYangPushOnChangeQuietWindow(t *testing.T) {
	_, fc, c, st, _, up := ypOnChangeSetup(t)
	ypSetLink(st, up[0], OperDown)
	c.mustNext(t)
	waitArmedN(t, fc, 3)
	fc.Advance(ypDampening)
	if m, ok := c.next(t, 300*time.Millisecond); ok {
		t.Fatalf("a quiet period sent %s", m.Raw)
	}
	fc.Advance(time.Second)
	ypSetLink(st, up[1], OperDown)
	_, entries := ypEditEntries(t, c.mustNext(t).Raw)
	if len(entries) != 1 || entries[0]["oper-status"] != "down" {
		t.Fatalf("entries = %v, want one entry down", entries)
	}
}

// A device that fidelity mutes during a period drops what it collected,
// counts it and closes the period. Transitions that arrive while muted do not
// enter pending either, even if fidelity is lifted before the period ends.
func TestYangPushOnChangeMutedWindow(t *testing.T) {
	e, fc, c, st, _, up := ypOnChangeSetup(t)
	ypSetLink(st, up[0], OperDown)
	c.mustNext(t)
	waitArmedN(t, fc, 3)
	withFidelity(t, true)
	before := e.fidelitySuppressed.Load()
	ypSetLink(st, up[1], OperDown)
	deadline := time.Now().Add(3 * time.Second)
	for e.fidelitySuppressed.Load() == before {
		if time.Now().After(deadline) {
			t.Fatal("fidelity_suppressed did not grow for the muted transition")
		}
		time.Sleep(time.Millisecond)
	}
	// Lifting fidelity before the period ends must not send the transition
	// that happened while muted.
	withFidelity(t, false)
	fc.Advance(ypDampening)
	if m, ok := c.next(t, 300*time.Millisecond); ok {
		t.Fatalf("transition while muted was sent after unmuting: %s", m.Raw)
	}
	waitArmedN(t, fc, 2)
}

// An admin-status transition that also moves oper-status broadcasts both
// LeafAdminStatus and LeafOperStatus at the same instant. Subscription 10
// sends the whole entry on the first and must not send a duplicate 5 seconds
// later for the twin oper event.
func TestYangPushOnChangeAdminSkipsTwinOper(t *testing.T) {
	_, fc, c, st, dev, up := ypOnChangeSetup(t)
	for _, ev := range st.setAdminLeaf(up[0], AdminDown) {
		st.Broadcast(ev)
	}
	id, entries := ypEditEntries(t, c.mustNext(t).Raw)
	if id != "0" || len(entries) != 1 || entries[0]["name"] != devIfDescr(dev, up[0]) ||
		entries[0]["admin-status"] != "down" || entries[0]["oper-status"] != "down" {
		t.Fatalf("admin down: patch %q entries %v, want patch 0 with admin and oper down", id, entries)
	}
	waitArmedN(t, fc, 3)
	fc.Advance(ypDampening)
	if m, ok := c.next(t, 300*time.Millisecond); ok {
		t.Fatalf("twin oper event caused a second update after the dampening period: %s", m.Raw)
	}
}

// A transition stamped with LastChangeRewindSentinel omits last-change even
// when a later transition has already written a valid timestamp into the live
// engine slot.
func TestYangPushChangeUpdateRewindOmitsLastChange(t *testing.T) {
	dev, st := newYangPushTestDevice(t)
	e := &YangPushExporter{dev: dev, subs: vrpSubs, pubID: 0x7F000001}
	idx := dev.metricsCycler.ifCounters.Load().IfIndices()[0]
	// Stamp a valid transition into the live engine slot first.
	st.SetLinkState(idx, OperDown)
	raw := encodeEnvelope(ypTestStart(), "ne8000-sim", 1, e.changeUpdate(StateChange{
		IfIndex:      idx,
		Admin:        AdminUp,
		Oper:         OperDown,
		LastChangeNs: LastChangeRewindSentinel,
		Changed:      LeafOperStatus,
		At:           ypTestStart(),
	}))
	_, entries := ypEditEntries(t, raw)
	if len(entries) != 1 || entries[0]["last-change"] != nil {
		t.Fatalf("entry after clock rewind still carries last-change: %v", entries)
	}
}

func TestYangPushCollectorUnreachable(t *testing.T) {
	dev, _ := newYangPushTestDevice(t)
	dead, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	addr := dead.LocalAddr().String()
	_ = dead.Close()
	e, fc := startYangPushTest(t, dev, addr)
	waitArmed(t, fc)
	// The kernel reports ICMP port-unreachable on a later send, and macOS
	// rate-limits those ICMPs, so not every message fails and ticks need some
	// real time between them. Over many ticks the count must keep rising, which also
	// proves the loop survives the errors and re-arms its timers.
	tick := func(n int) uint64 {
		for range n {
			fc.Advance(time.Minute)
			waitArmed(t, fc)
			time.Sleep(20 * time.Millisecond)
		}
		t.Logf("failures %d segments %d messages %d", e.sendFailures.Load(), e.segmentsSent.Load(), e.messagesSent.Load())
		return e.sendFailures.Load()
	}
	first := tick(5)
	second := tick(10)
	if first == 0 || second <= first {
		t.Fatalf("send_failures after 5 ticks %d, after 15 ticks %d; want >0 and growing", first, second)
	}
}

func TestYangPushStateBurstDoesNotBlock(t *testing.T) {
	dev, st := newYangPushTestDevice(t)
	c := newYPCollector(t)
	e, fc := startYangPushTest(t, dev, c.addr())
	readStart(t, c) // the listener is registered before the sync goes out
	waitArmed(t, fc)
	idxs := dev.metricsCycler.ifCounters.Load().IfIndices()
	idx := idxs[0]
	lastIdx := idxs[1]
	// Stall the exporter: its next send blocks on the clock. It takes at most
	// one event, the listener holds onChangeBufferDepth, and the rest must be
	// dropped and counted without blocking InterfaceState. The 1000th event
	// transitions a second interface (lastIdx) so only a drop-oldest queue
	// retains lastIdx in the collected update.
	fc.mu.Lock()
	done := make(chan struct{})
	go func() {
		defer close(done)
		for n := range 999 {
			_, evts := st.SetLinkState(idx, ypFlap(n))
			for _, ev := range evts {
				st.Broadcast(ev)
			}
		}
		_, evts := st.SetLinkState(lastIdx, OperDown)
		for _, ev := range evts {
			st.Broadcast(ev)
		}
	}()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		fc.mu.Unlock()
		t.Fatal("InterfaceState blocked during the flap burst")
	}
	dropped := e.stateEventsDropped.Load()
	fc.mu.Unlock()
	if want := uint64(1000 - onChangeBufferDepth - 1); dropped < want {
		t.Fatalf("state_events_dropped = %d after 1000 flaps against a stalled exporter, want >= %d", dropped, want)
	}
	// Drop-oldest: the final transition on lastIdx is retained in the tail of
	// the queue and goes out when the dampening period ends.
	waitArmedN(t, fc, 3)
	fc.Advance(ypDampening)
	var last ypRecv
	for {
		m, ok := c.next(t, 500*time.Millisecond)
		if !ok {
			break
		}
		if m.Kind == "ietf-yang-push:push-change-update" {
			last = m
		}
	}
	wantLast := `"name":` + jsonString(devIfDescr(dev, lastIdx))
	if !strings.Contains(string(last.Raw), wantLast) || !strings.Contains(string(last.Raw), `"oper-status":"down"`) {
		t.Fatalf("last change does not carry the final transition on %s: %s", devIfDescr(dev, lastIdx), last.Raw)
	}
}

func TestYangPushStopIdempotentNoLeak(t *testing.T) {
	dev, st := newYangPushTestDevice(t)
	c := newYPCollector(t)
	baseline := runtime.NumGoroutine()
	fc := &ypFakeClock{now: ypTestStart()}
	e, err := NewYangPushExporter(dev, &DeviceYangPushConfig{Collector: c.addr(), SegmentSize: defaultYangPushSegmentSize}, fc.Now)
	if err != nil {
		t.Fatal(err)
	}
	e.newTimer = fc.NewTimer
	e.Start()
	readStart(t, c)
	waitArmed(t, fc)
	idx := dev.metricsCycler.ifCounters.Load().IfIndices()[0]
	fc.Advance(time.Minute) // a periodic send in flight
	for n := range 20 {
		_, evts := st.SetLinkState(idx, ypFlap(n))
		for _, ev := range evts {
			st.Broadcast(ev)
		}
	}
	var wg sync.WaitGroup
	for range 2 {
		wg.Add(1)
		go func() { defer wg.Done(); _ = e.Close() }()
	}
	wg.Wait()
	if err := e.Close(); err != nil {
		t.Errorf("third Close: %v", err)
	}
	deadline := time.Now().Add(3 * time.Second)
	for runtime.NumGoroutine() > baseline && time.Now().Before(deadline) {
		time.Sleep(5 * time.Millisecond)
	}
	if n := runtime.NumGoroutine(); n > baseline {
		t.Fatalf("goroutines %d > baseline %d after Close", n, baseline)
	}
	// The listener is gone: a further transition must not panic or deliver.
	_, evts := st.SetLinkState(idx, OperDown)
	for _, ev := range evts {
		st.Broadcast(ev)
	}
}

func TestYangPushFidelityMutes(t *testing.T) {
	withFidelity(t, true)
	dev, st := newYangPushTestDevice(t)
	c := newYPCollector(t)
	e, fc := startYangPushTest(t, dev, c.addr())
	waitArmed(t, fc)
	fc.Advance(time.Minute)
	waitArmed(t, fc)
	idx := dev.metricsCycler.ifCounters.Load().IfIndices()[0]
	_, evts := st.SetLinkState(idx, OperDown)
	for _, ev := range evts {
		st.Broadcast(ev)
	}
	if m, ok := c.next(t, 300*time.Millisecond); ok {
		t.Fatalf("fidelity on, yet received %s id %d", m.Kind, m.SubID)
	}
	if e.fidelitySuppressed.Load() == 0 {
		t.Fatal("fidelity_suppressed = 0")
	}
	if e.messagesSent.Load() != 0 {
		t.Fatalf("messages_sent = %d with fidelity on", e.messagesSent.Load())
	}
}

func TestYangPushStatusEndpoint(t *testing.T) {
	dev, _ := newYangPushTestDevice(t)
	c := newYPCollector(t)
	// The exporter's run goroutine reads the global manager for ifAlias, so
	// swap it before the exporter starts. Its cleanup then runs after the
	// exporter's Close, which waits for that goroutine.
	sm := &SimulatorManager{devices: map[string]*DeviceSimulator{"d": dev}}
	sm.yangPushSubsystemActive.Store(true)
	prev := manager
	manager = sm
	t.Cleanup(func() { manager = prev })
	e, _ := startYangPushTest(t, dev, c.addr())
	readStart(t, c)
	dev.yangPushExporter = e

	gone := &YangPushExporter{collector: c.addr()}
	gone.messagesSent.Store(5)
	gone.sendFailures.Store(2)
	sm.persistYangPushCounters(gone)
	sm.persistYangPushCounters(gone) // single-shot

	w := httptest.NewRecorder()
	yangPushStatusHandler(w, httptest.NewRequest(http.MethodGet, "/api/v1/yangpush/status", nil))
	if w.Code != http.StatusOK {
		t.Fatalf("status %d", w.Code)
	}
	var st YangPushStatus
	if err := json.Unmarshal(w.Body.Bytes(), &st); err != nil {
		t.Fatal(err)
	}
	if !st.SubsystemActive || st.DevicesExporting != 1 || len(st.Collectors) != 1 {
		t.Fatalf("status = %+v", st)
	}
	row := st.Collectors[0]
	if row.Collector != c.addr() || row.Devices != 1 || row.MessagesSent != 4+5 || row.SegmentsSent < 4 || row.SendFailures != 2 {
		t.Errorf("row = %+v", row)
	}
	for _, key := range []string{"messages_sent", "segments_sent", "send_failures", "state_events_dropped", "fidelity_suppressed"} {
		if !strings.Contains(w.Body.String(), `"`+key+`"`) {
			t.Errorf("status JSON lacks %s: %s", key, w.Body.String())
		}
	}
}

// ypFlap alternates the link down and up.
func ypFlap(n int) uint8 {
	if n%2 == 0 {
		return OperDown
	}
	return OperUp
}

// TestYangPushBindFailureFailsOptIn: a device IP the host cannot bind fails
// construction; there is no unbound fallback.
func TestYangPushBindFailureFailsOptIn(t *testing.T) {
	dev, _ := newYangPushTestDevice(t)
	dev.IP = net.IPv4(192, 0, 2, 1) // TEST-NET-1, not a local address
	c := newYPCollector(t)
	e, err := NewYangPushExporter(dev, &DeviceYangPushConfig{Collector: c.addr(), SegmentSize: defaultYangPushSegmentSize}, time.Now)
	if err == nil {
		_ = e.Close()
		t.Fatal("bind to a non-local device IP succeeded; want an error")
	}
}
