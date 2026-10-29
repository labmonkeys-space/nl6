/*
 * Copyright 2026 Ronny Trommer <ronny@no42.org>
 * SPDX-License-Identifier: Apache-2.0
 */

package main

import (
	"context"
	"fmt"
	"net"
	"regexp"
	"runtime"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

// newNetconfTestDevice builds a cisco_catalyst_9500 device with a live
// interface state engine and no protocol listeners.
func newNetconfTestDevice(t *testing.T) (*DeviceSimulator, *InterfaceState) {
	t.Helper()
	sm := &SimulatorManager{resourcesCache: make(map[string]*DeviceResources)}
	res, err := sm.LoadSpecificResources("cisco_catalyst_9500.json")
	if err != nil {
		t.Fatalf("load profile: %v", err)
	}
	mc := &MetricsCycler{}
	mc.InitIfCountersWithScenario(res, 1, IfErrorClean)
	ic := mc.ifCounters.Load()
	if ic == nil || ic.State() == nil {
		t.Fatal("profile has no interface state engine")
	}
	return &DeviceSimulator{resources: res, metricsCycler: mc}, ic.State()
}

// iosxeTestClient drives a session built by newIOSXENetconfSession.
type iosxeTestClient struct {
	*netconfTestClient
	sess *netconfSession
}

func startIOSXETestClient(t *testing.T, dev *DeviceSimulator) *iosxeTestClient {
	t.Helper()
	srv, cli := net.Pipe()
	sess := newIOSXENetconfSession(1, dev, srv, newNetconfSessionRegistry())
	done := make(chan error, 1)
	finished := make(chan struct{})
	go func() { done <- sess.Serve(context.Background()); close(finished) }()
	t.Cleanup(func() { _ = cli.Close(); sess.close(); <-finished })

	c := &netconfTestClient{t: t, conn: cli, f: newNetconfFramer(cli, cli), done: done}
	_ = cli.SetDeadline(time.Now().Add(10 * time.Second))
	if _, err := c.f.ReadMessage(); err != nil {
		t.Fatalf("read server hello: %v", err)
	}
	hello := `<hello xmlns="urn:ietf:params:xml:ns:netconf:base:1.0"><capabilities><capability>urn:ietf:params:netconf:base:1.0</capability></capabilities></hello>`
	if err := c.f.WriteMessage([]byte(hello)); err != nil {
		t.Fatalf("write client hello: %v", err)
	}
	return &iosxeTestClient{netconfTestClient: c, sess: sess}
}

var ncSubIDRe = regexp.MustCompile(`<subscription-id[^>]*>(\d+)<`)

// subscribe establishes a subscription and returns its id. The sync-on-start
// pushes are left for the caller to read.
func (c *iosxeTestClient) subscribe(xpath string) uint32 {
	c.t.Helper()
	r := c.rpc(netconfTestSub(xpath))
	m := ncSubIDRe.FindStringSubmatch(r)
	if m == nil {
		c.t.Fatalf("subscription refused: %s", r)
	}
	n, _ := strconv.ParseUint(m[1], 10, 32)
	return uint32(n)
}

type ncNotif struct {
	kind, target, name, admin, oper string
	sub                             uint32
	raw                             string
}

var (
	ncKindRe   = regexp.MustCompile(`<(push-update|push-change-update) `)
	ncTargetRe = regexp.MustCompile(`<target>([^<]*)<`)
	ncNameRe   = regexp.MustCompile(`<name>([^<]*)<`)
	ncAdminRe  = regexp.MustCompile(`<admin-status>([^<]*)<`)
	ncOperRe   = regexp.MustCompile(`<oper-status>([^<]*)<`)
)

func ncGroup(re *regexp.Regexp, s string) string {
	if m := re.FindStringSubmatch(s); m != nil {
		return m[1]
	}
	return ""
}

func (c *iosxeTestClient) next() ncNotif {
	c.t.Helper()
	raw, err := c.f.ReadMessage()
	if err != nil {
		c.t.Fatalf("read notification: %v", err)
	}
	s := string(raw)
	n := ncNotif{
		kind: ncGroup(ncKindRe, s), target: ncGroup(ncTargetRe, s), name: ncGroup(ncNameRe, s),
		admin: ncGroup(ncAdminRe, s), oper: ncGroup(ncOperRe, s), raw: s,
	}
	id, _ := strconv.ParseUint(ncGroup(ncSubIDRe, s), 10, 32)
	n.sub = uint32(id)
	if n.kind == "" {
		c.t.Fatalf("not a push: %s", s)
	}
	return n
}

// sub establishes a keyed subscription and reads its one sync push. Each
// sync push must be read before the next request: net.Pipe has no buffer.
func (c *iosxeTestClient) sub(xpath string) uint32 {
	c.t.Helper()
	id := c.subscribe(xpath)
	c.drain(1)
	return id
}

func (c *iosxeTestClient) drain(n int) {
	c.t.Helper()
	for i := 0; i < n; i++ {
		c.next()
	}
}

func ncXPath(name, leaf string) string {
	x := iosxeTestIfaceNm + "[name='" + name + "']"
	if leaf != "" {
		x += "/" + leaf
	}
	return x
}

func ncBroadcast(st *InterfaceState, evts []StateChange) {
	for _, e := range evts {
		st.Broadcast(e)
	}
}

func ncLink(st *InterfaceState, ifIndex int, link uint8) {
	_, evts := st.SetLinkState(ifIndex, link)
	ncBroadcast(st, evts)
}

func ncAdmin(st *InterfaceState, ifIndex int, admin uint8) {
	ncBroadcast(st, st.ApplyAdminStatus(ifIndex, admin))
}

// ncSentinel subscribes to GigabitEthernet1/0/6 oper-status. Flapping it and
// reading its push proves nothing else was queued in between, because the
// listener handles events in order.
type ncSentinel struct {
	c    *iosxeTestClient
	st   *InterfaceState
	id   uint32
	down bool
}

func newNcSentinel(c *iosxeTestClient, st *InterfaceState) *ncSentinel {
	return &ncSentinel{c: c, st: st, id: c.sub(ncXPath("GigabitEthernet1/0/6", "oper-status"))}
}

func (s *ncSentinel) expectNext() {
	s.c.t.Helper()
	s.down = !s.down
	link := OperUp
	if s.down {
		link = OperDown
	}
	ncLink(s.st, 6, link)
	if n := s.c.next(); n.sub != s.id {
		s.c.t.Fatalf("unexpected push before the sentinel: %s", n.raw)
	}
}

func TestNetconfLinkDownPushesLowerLayerDown(t *testing.T) {
	dev, st := newNetconfTestDevice(t)
	c := startIOSXETestClient(t, dev)
	const ifn = "GigabitEthernet1/0/24"
	oper := c.sub(ncXPath(ifn, "oper-status"))
	admin := c.sub(ncXPath(ifn, "admin-status"))
	row := c.sub(ncXPath(ifn, ""))

	ncLink(st, 24, OperDown)
	want := []ncNotif{
		{sub: row, admin: "if-state-up", oper: "if-oper-state-lower-layer-down"},
		{sub: admin, admin: "if-state-up"},
		{sub: oper, oper: "if-oper-state-lower-layer-down"},
	}
	for _, w := range want {
		n := c.next()
		if n.kind != "push-change-update" || n.target != "/interfaces/interface=GigabitEthernet1%2F0%2F24" {
			t.Fatalf("push shape: %s", n.raw)
		}
		if n.sub != w.sub || n.admin != w.admin || n.oper != w.oper {
			t.Fatalf("got sub %d admin %q oper %q, want %+v", n.sub, n.admin, n.oper, w)
		}
	}
}

func TestNetconfShutdownOnUpLinkPushesNoPass(t *testing.T) {
	dev, st := newNetconfTestDevice(t)
	c := startIOSXETestClient(t, dev)
	sentinel := newNcSentinel(c, st)
	oper := c.sub(ncXPath("GigabitEthernet1/0/5", "oper-status"))
	admin := c.sub(ncXPath("GigabitEthernet1/0/5", "admin-status"))

	ncAdmin(st, 5, AdminDown)
	if n := c.next(); n.sub != admin || n.admin != "if-state-down" {
		t.Fatalf("admin leaf push: %s", n.raw)
	}
	if n := c.next(); n.sub != oper || n.oper != "if-oper-state-no-pass" {
		t.Fatalf("oper leaf push: %s", n.raw)
	}
	// One push per subscription: the oper event of the pair adds nothing.
	sentinel.expectNext()
}

func TestNetconfNoShutdownSequence(t *testing.T) {
	dev, st := newNetconfTestDevice(t)
	c := startIOSXETestClient(t, dev)
	sentinel := newNcSentinel(c, st)
	c.sub(ncXPath("GigabitEthernet1/0/5", "oper-status"))

	ncAdmin(st, 5, AdminDown)
	if n := c.next(); n.oper != "if-oper-state-no-pass" {
		t.Fatalf("shutdown push: %s", n.raw)
	}
	ncAdmin(st, 5, AdminUp)
	for _, want := range []string{iosxeOperInvalid, "if-oper-state-lower-layer-down", "if-oper-state-ready"} {
		if n := c.next(); n.oper != want {
			t.Fatalf("no-shutdown step: got %q, want %q", n.oper, want)
		}
	}
	sentinel.expectNext()
}

func TestNetconfShutdownOnLinkDownIsSilent(t *testing.T) {
	dev, st := newNetconfTestDevice(t)
	c := startIOSXETestClient(t, dev)
	sentinel := newNcSentinel(c, st)
	c.sub(ncXPath("GigabitEthernet1/0/24", "oper-status"))
	c.sub(ncXPath("GigabitEthernet1/0/24", "admin-status"))
	c.sub(ncXPath("GigabitEthernet1/0/24", ""))

	ncLink(st, 24, OperDown)
	c.drain(3)

	ncAdmin(st, 24, AdminDown)
	if s := st.Snapshot(24); s.Admin != AdminDown {
		t.Fatalf("admin did not change: %+v", s)
	}
	ncAdmin(st, 24, AdminUp)
	if s := st.Snapshot(24); s.Admin != AdminUp {
		t.Fatalf("admin did not change back: %+v", s)
	}
	sentinel.expectNext()
}

func TestNetconfReverseSubscriptionOrder(t *testing.T) {
	dev, st := newNetconfTestDevice(t)
	c := startIOSXETestClient(t, dev)
	const ifn = "GigabitEthernet1/0/7"
	ids := []uint32{
		c.sub(ncXPath(ifn, "")),
		c.sub(ncXPath(ifn, "admin-status")),
		c.sub(ncXPath(ifn, "oper-status")),
		c.sub(ncXPath(ifn, "admin-status")),
	}

	ncAdmin(st, 7, AdminDown)
	for i := len(ids) - 1; i >= 0; i-- {
		if n := c.next(); n.sub != ids[i] {
			t.Fatalf("push %d went to sub %d, want %d", len(ids)-1-i, n.sub, ids[i])
		}
	}
}

func TestNetconfSyncOnStartFirstIsPushUpdate(t *testing.T) {
	dev, _ := newNetconfTestDevice(t)
	c := startIOSXETestClient(t, dev)
	id := c.subscribe(iosxeTestIfaceNm + "/oper-status")
	first := c.next()
	if first.kind != "push-update" || first.name != "GigabitEthernet1/0/1" || first.sub != id ||
		first.oper != "if-oper-state-ready" {
		t.Fatalf("first push: %s", first.raw)
	}
	for i := 2; i <= 48; i++ {
		n := c.next()
		want := "/interfaces/interface=GigabitEthernet1%2F0%2F" + strconv.Itoa(i)
		if n.kind != "push-change-update" || n.target != want {
			t.Fatalf("push %d: got %s %s, want push-change-update %s", i, n.kind, n.target, want)
		}
	}

	// A keyed subscription on a later interface gets push-change-update too.
	c.subscribe(ncXPath("GigabitEthernet1/0/24", ""))
	if n := c.next(); n.kind != "push-change-update" || n.admin != "if-state-up" {
		t.Fatalf("keyed sync: %s", n.raw)
	}
	// The first interface keeps push-update when keyed.
	c.subscribe(ncXPath("GigabitEthernet1/0/1", "admin-status"))
	if n := c.next(); n.kind != "push-update" || n.name != "GigabitEthernet1/0/1" || n.admin != "if-state-up" {
		t.Fatalf("keyed sync on the first interface: %s", n.raw)
	}
}

func TestNetconfSyncOnStartUnknownInterfaceEmpty(t *testing.T) {
	dev, st := newNetconfTestDevice(t)
	c := startIOSXETestClient(t, dev)
	sentinel := newNcSentinel(c, st)
	id := c.subscribe(ncXPath("GigabitEthernet9/9/9", "oper-status"))
	n := c.next()
	if n.kind != "push-update" || n.sub != id {
		t.Fatalf("unknown interface sync: %s", n.raw)
	}
	if want := "<datastore-contents-xml/>"; !regexp.MustCompile(regexp.QuoteMeta(want)).MatchString(n.raw) {
		t.Fatalf("push is not empty: %s", n.raw)
	}
	sentinel.expectNext()
}

func TestNetconfSlowReaderDropsOldestAndCounts(t *testing.T) {
	dev, st := newNetconfTestDevice(t)
	c := startIOSXETestClient(t, dev)
	c.sub(ncXPath("GigabitEthernet1/0/24", ""))
	ev := c.sess.ev
	dropped0 := atomic.LoadUint64(ev.dropped)
	handled := func() uint64 { return uint64(ev.out.len()) + atomic.LoadUint64(ev.dropped) - dropped0 }

	// The client reads nothing from here on. A first push parks the writer
	// on the pipe, so every later push stays in the queue or is dropped.
	c.sess.enqueue([]byte("<parked/>"))
	for deadline := time.Now().Add(time.Second); ev.out.len() != 0; time.Sleep(time.Millisecond) {
		if time.Now().After(deadline) {
			t.Fatal("writer did not take the parked push")
		}
	}
	// Each flap waits until the listener has queued its push, so no event is
	// lost before the queue and every overflow lands in the counter.
	const flaps = 500
	var inEngine time.Duration
	for i := 0; i < flaps; i++ {
		link := OperDown
		if i%2 == 1 {
			link = OperUp
		}
		want := handled() + 1
		start := time.Now()
		ncLink(st, 24, link)
		inEngine += time.Since(start)
		deadline := time.Now().Add(time.Second)
		for handled() < want {
			if time.Now().After(deadline) {
				t.Fatalf("flap %d: push not queued within 1s (queue %d, dropped %d): the listener is blocked",
					i, ev.out.len(), atomic.LoadUint64(ev.dropped)-dropped0)
			}
			time.Sleep(50 * time.Microsecond)
		}
	}
	if inEngine > time.Second {
		t.Fatalf("500 flaps spent %v in the engine: Broadcast blocked on a NETCONF reader", inEngine)
	}
	if n := ev.out.len(); n != netconfSendQueueDepth {
		t.Fatalf("queue holds %d pushes, want exactly the cap %d", n, netconfSendQueueDepth)
	}
	// The queue holds the newest 100. Every other push was dropped and counted.
	if d := atomic.LoadUint64(ev.dropped) - dropped0; d != flaps-netconfSendQueueDepth {
		t.Fatalf("dropped %d, want %d", d, flaps-netconfSendQueueDepth)
	}
	// Oldest-drop: the newest push, carrying the final last-change, survived.
	var last []byte
	for msg, ok := ev.out.pop(); ok; msg, ok = ev.out.pop() {
		last = msg
	}
	want := "<last-change>" + iosxeTimestamp(time.Unix(0, int64(st.Snapshot(24).LastChangeNs))) + "</last-change>"
	if !strings.Contains(string(last), want) {
		t.Fatalf("newest queued push lacks %s: the queue dropped new pushes, not old ones", want)
	}
}

func ncListenerCount(st *InterfaceState) int {
	n := 0
	st.listeners.Range(func(_, _ any) bool { n++; return true })
	return n
}

func TestNetconfClientDisconnectRemovesListener(t *testing.T) {
	dev, st := newNetconfTestDevice(t)
	baseline := runtime.NumGoroutine()
	c := startIOSXETestClient(t, dev)
	c.sub(ncXPath("GigabitEthernet1/0/24", "oper-status"))
	if n := ncListenerCount(st); n != 1 {
		t.Fatalf("listeners while subscribed: %d, want 1", n)
	}
	_ = c.conn.Close()
	c.waitDone()

	deadline := time.Now().Add(2 * time.Second)
	for ncListenerCount(st) != 0 || runtime.NumGoroutine() > baseline {
		if time.Now().After(deadline) {
			t.Fatalf("after disconnect: %d listeners, %d goroutines (baseline %d)",
				ncListenerCount(st), runtime.NumGoroutine(), baseline)
		}
		time.Sleep(10 * time.Millisecond)
	}
}

func TestNetconfOtherConsumersUnchanged(t *testing.T) {
	dev, st := newNetconfTestDevice(t)
	var got []string
	// Observing the Tier C hook the way the other state-engine tests do.
	st.SetNotify(func(e StateChange) {
		got = append(got, fmt.Sprintf("%d %d>%d a%d c%d", e.IfIndex, e.PrevOper, e.Oper, e.Admin, e.Changed))
	})
	defer st.SetNotify(nil)
	cycle := func() []string {
		got = nil
		ncLink(st, 24, OperDown)
		ncAdmin(st, 24, AdminDown)
		ncAdmin(st, 24, AdminUp)
		ncLink(st, 24, OperUp)
		ncAdmin(st, 24, AdminDown)
		ncAdmin(st, 24, AdminUp)
		return append([]string(nil), got...)
	}
	without := cycle()

	c := startIOSXETestClient(t, dev)
	c.sub(ncXPath("GigabitEthernet1/0/24", ""))
	c.subscribe(iosxeTestIfaceNm + "/oper-status")
	c.drain(48)
	with := cycle()

	if fmt.Sprint(with) != fmt.Sprint(without) {
		t.Fatalf("notify calls changed with a NETCONF subscriber:\nwithout %v\nwith    %v", without, with)
	}
	if len(without) == 0 {
		t.Fatal("the cycle fired no notify call, so the comparison proves nothing")
	}
}
