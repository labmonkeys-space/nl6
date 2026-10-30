/*
 * Copyright 2026 Ronny Trommer <ronny@no42.org>
 * SPDX-License-Identifier: Apache-2.0
 */

package main

import (
	"context"
	"io"
	"slices"
	"strconv"
	"sync"
	"sync/atomic"
	"time"
)

const (
	// netconfEventBufferDepth is the state-engine listener channel depth,
	// the same as gNMI ON_CHANGE.
	netconfEventBufferDepth = 16
	// netconfSendQueueDepth bounds the pushes waiting for a slow client.
	// A full queue drops its oldest push and counts it.
	netconfSendQueueDepth = 100
)

// netconfEvents is the per-session push state. The subscription set is kept
// here through the session hooks, so the listener never reads session.subs.
type netconfEvents struct {
	mu   sync.Mutex
	subs []*netconfSub // creation order

	out           netconfOutbox
	sent, dropped *uint64

	// writing is true while a writer goroutine drains out. The writer starts
	// on the first push and exits once out is empty, so an idle session
	// holds no writer.
	writing atomic.Bool

	// wg counts the writer, so the server can wait for it after the session
	// ended.
	wg sync.WaitGroup

	// ready is closed once the session is registered with the device's
	// dispatcher, or once registration was given up. disp is that
	// dispatcher, set by startEvents and cleared by onEnd.
	ready chan struct{}
	disp  atomic.Pointer[netconfDispatcher]

	// onEvent renders one state change for the session. It is installed by
	// the dialect constructor and may be nil.
	onEvent func(s *netconfSession, e *netconfStateEvent)

	// skip names the oper event that follows an admin event which moved
	// oper too. The admin event already pushed the row, so its twin is
	// dropped. Only the dispatcher goroutine touches it.
	skip struct {
		ifIndex int
		at      time.Time
		set     bool
	}
}

// netconfPush is one rendered push and the subscription it belongs to.
type netconfPush struct {
	sub *netconfSub
	msg []byte
}

// netconfOutbox is a bounded oldest-drop ring of rendered pushes. push never
// blocks. At most one writer goroutine drains it.
type netconfOutbox struct {
	mu   sync.Mutex
	buf  [netconfSendQueueDepth]netconfPush
	head int
	n    int
}

// push queues msg and reports whether it displaced the oldest push.
func (o *netconfOutbox) push(p netconfPush) (dropped bool) {
	o.mu.Lock()
	if o.n == netconfSendQueueDepth {
		o.buf[o.head] = netconfPush{}
		o.head = (o.head + 1) % netconfSendQueueDepth
		o.n--
		dropped = true
	}
	o.buf[(o.head+o.n)%netconfSendQueueDepth] = p
	o.n++
	o.mu.Unlock()
	return dropped
}

func (o *netconfOutbox) pop() (netconfPush, bool) {
	o.mu.Lock()
	defer o.mu.Unlock()
	if o.n == 0 {
		return netconfPush{}, false
	}
	p := o.buf[o.head]
	o.buf[o.head] = netconfPush{}
	o.head = (o.head + 1) % netconfSendQueueDepth
	o.n--
	return p, true
}

func (o *netconfOutbox) len() int {
	o.mu.Lock()
	defer o.mu.Unlock()
	return o.n
}

// newIOSXENetconfSession builds a session that pushes interface state changes
// the way an IOS XE switch does.
func newIOSXENetconfSession(id uint32, dev *DeviceSimulator, rw io.ReadWriter, reg *netconfSessionRegistry) *netconfSession {
	s := newNetconfSession(id, dev, rw, reg)
	ev := &netconfEvents{ready: make(chan struct{})}
	if manager != nil {
		ev.sent, ev.dropped = &manager.netconfNotificationsSent, &manager.netconfNotificationsDropped
	} else {
		ev.sent, ev.dropped = new(uint64), new(uint64)
	}
	s.ev = ev
	ev.onEvent = (*netconfSession).iosxeStateEvent
	s.onStart = s.startEvents
	s.onEnd = func() {
		if d := ev.disp.Swap(nil); d != nil {
			d.unregister(s)
			reg.releaseDispatcher(d)
		}
	}
	s.onSubscribe = s.syncOnStart
	s.onUnsubscribe = func(sub *netconfSub) {
		sub.deleted.Store(true)
		ev.mu.Lock()
		if i := slices.Index(ev.subs, sub); i >= 0 {
			ev.subs = slices.Delete(ev.subs, i, i+1)
		}
		ev.mu.Unlock()
	}
	return s
}

// netconfIfCounters returns the device's counter cycler, or nil.
func netconfIfCounters(dev *DeviceSimulator) *IfCounterCycler {
	if dev == nil || dev.metricsCycler == nil {
		return nil
	}
	return dev.metricsCycler.ifCounters.Load()
}

// startEvents registers the session with the device's dispatcher and returns
// once it is in, so every change from then on reaches it. A change in the
// window between the hello and the registration goes to the sessions already
// present, as it did when each session registered its own listener. The
// writer starts on demand, in enqueue.
func (s *netconfSession) startEvents(ctx context.Context) {
	state := netconfIfCounters(s.dev).State()
	if state == nil || s.reg == nil {
		return
	}
	d := s.reg.acquireDispatcher(state)
	s.ev.disp.Store(d)
	d.register(ctx, s)
}

// runWriter drains the send queue and exits when it is empty. It writes
// under wmu, the mutex RPC replies use, and discards a push whose
// subscription was deleted. onUnsubscribe sets that flag before the delete
// reply is written, so no push for the subscription follows the reply.
//
// A write error closes the session, so Serve ends and the listener
// deregisters. Once the session is closed it returns with writing still
// set, so no writer starts again and nothing more is written.
func (s *netconfSession) runWriter() {
	ev := s.ev
	defer ev.wg.Done()
	for {
		if s.isClosed() {
			return
		}
		p, ok := ev.out.pop()
		if !ok {
			// A push that lands between the empty pop and the Store sees
			// writing set and starts nothing, so look again after the Store.
			ev.writing.Store(false)
			if ev.out.len() == 0 || !ev.writing.CompareAndSwap(false, true) {
				return
			}
			continue
		}
		s.wmu.Lock()
		// A session closed while this push waited for wmu writes nothing
		// more, so nothing follows a Junos session-end trailer.
		if s.isClosed() {
			s.wmu.Unlock()
			return
		}
		if p.sub.deleted.Load() {
			s.wmu.Unlock()
			continue
		}
		err := s.framer.WriteMessage(p.msg)
		s.wmu.Unlock()
		if err != nil {
			s.close()
			return
		}
		atomic.AddUint64(ev.sent, 1)
	}
}

// waitEvents waits for the writer. Call it after Serve returned, so the
// session has left the dispatcher and no push can be queued any more.
func (s *netconfSession) waitEvents() {
	if s.ev != nil {
		s.ev.wg.Wait()
	}
}

// enqueue queues a push without blocking and starts the writer if none runs.
func (s *netconfSession) enqueue(sub *netconfSub, msg []byte) {
	if s.ev.out.push(netconfPush{sub: sub, msg: msg}) {
		atomic.AddUint64(s.ev.dropped, 1)
	}
	if s.ev.writing.CompareAndSwap(false, true) {
		// The dispatcher is the only caller, and teardown leaves it before
		// Serve returns, so this Add never races the Wait in waitEvents.
		s.ev.wg.Add(1)
		go s.runWriter()
	}
}

// netconfDispatcher is the one state-change listener of a device. It fans
// every event out to the sessions registered on it, so an idle session costs
// no listener goroutine of its own. Membership changes go through the run
// loop, which is the only goroutine that touches sessions, so handleStateChange
// runs under no lock and a session that has left never sees another event.
//
// The registry refcounts it: the first session starts it and the last one
// stops it, so a device with no NETCONF client has no listener and no
// goroutine. The channel is never closed: a Broadcast may still hold it from
// its Range.
type netconfDispatcher struct {
	state *InterfaceState
	ch    chan StateChange
	join  chan netconfDispatchCmd
	leave chan netconfDispatchCmd
	stop  chan struct{}
	wg    sync.WaitGroup

	sessions []*netconfSession // owned by run
}

// netconfDispatchCmd is a join or leave request; ack is closed once applied.
type netconfDispatchCmd struct {
	sess *netconfSession
	ack  chan struct{}
}

func newNetconfDispatcher(state *InterfaceState) *netconfDispatcher {
	d := initNetconfDispatcher(state)
	d.start()
	return d
}

// initNetconfDispatcher builds a dispatcher without starting it, so a test
// can seed its channel and session set first.
func initNetconfDispatcher(state *InterfaceState) *netconfDispatcher {
	return &netconfDispatcher{
		state: state,
		ch:    make(chan StateChange, netconfEventBufferDepth),
		join:  make(chan netconfDispatchCmd),
		leave: make(chan netconfDispatchCmd),
		stop:  make(chan struct{}),
	}
}

func (d *netconfDispatcher) start() {
	d.wg.Add(1)
	go d.run()
}

// register adds s and closes s.ev.ready once it is in. It returns without
// registering when ctx ends first, and closes ready then too.
func (d *netconfDispatcher) register(ctx context.Context, s *netconfSession) {
	cmd := netconfDispatchCmd{sess: s, ack: make(chan struct{})}
	select {
	case d.join <- cmd:
		<-cmd.ack
	case <-ctx.Done():
		close(s.ev.ready)
	}
}

// unregister removes s. When it returns, no further event reaches s. A
// stopped dispatcher dispatches nothing, so it returns at once then.
func (d *netconfDispatcher) unregister(s *netconfSession) {
	cmd := netconfDispatchCmd{sess: s, ack: make(chan struct{})}
	select {
	case d.leave <- cmd:
		<-cmd.ack
	case <-d.stop:
	}
}

// close stops the run loop and waits for it.
func (d *netconfDispatcher) close() {
	close(d.stop)
	d.wg.Wait()
}

func (d *netconfDispatcher) run() {
	defer d.wg.Done()
	d.state.AddListener(d.ch)
	defer d.state.RemoveListener(d.ch)
	for {
		select {
		case <-d.stop:
			return
		case evt := <-d.ch:
			d.dispatch(evt)
		case cmd := <-d.join:
			// Events broadcast before this session's hello go to the
			// sessions that were there, never to the new one.
			d.drain()
			d.sessions = append(d.sessions, cmd.sess)
			close(cmd.sess.ev.ready)
			close(cmd.ack)
		case cmd := <-d.leave:
			if i := slices.Index(d.sessions, cmd.sess); i >= 0 {
				d.sessions = slices.Delete(d.sessions, i, i+1)
			}
			close(cmd.ack)
		}
	}
}

// drain dispatches every event already queued, without blocking.
func (d *netconfDispatcher) drain() {
	for {
		select {
		case evt := <-d.ch:
			d.dispatch(evt)
		default:
			return
		}
	}
}

// dispatch hands one event to every session. The interface name and the
// row are built at most once per event, not once per session: every
// session on a device reads the same engine at the same instant.
func (d *netconfDispatcher) dispatch(evt StateChange) {
	if len(d.sessions) == 0 {
		return
	}
	e := &netconfStateEvent{evt: evt, dev: d.sessions[0].dev}
	for _, s := range d.sessions {
		s.handleStateEvent(e)
	}
}

// netconfStateEvent is one state change with the per-device derivations
// shared across the sessions that render it. Only the dispatcher goroutine
// touches it.
type netconfStateEvent struct {
	evt  StateChange
	dev  *DeviceSimulator
	name string
	row  *iosxeRow // the whole row, built on first request
}

func (e *netconfStateEvent) ifName() string {
	if e.name == "" {
		e.name = devIfDescr(e.dev, e.evt.IfIndex)
	}
	return e.name
}

func (e *netconfStateEvent) fullRow() iosxeRow {
	if e.row == nil {
		row := buildIosxeRow(e.dev, netconfIfCounters(e.dev), e.evt.IfIndex, e.evt.At)
		e.row = &row
	}
	return *e.row
}

// twinOperEvent reports whether evt is the oper event that follows an admin
// event which already moved oper. An admin change broadcasts both, with the
// same ifIndex and instant, and only the first is rendered. Every dialect
// calls it once per event, in order.
func (ev *netconfEvents) twinOperEvent(evt StateChange) bool {
	if evt.Changed == LeafOperStatus && ev.skip.set && ev.skip.ifIndex == evt.IfIndex && ev.skip.at.Equal(evt.At) {
		ev.skip.set = false
		return true
	}
	if evt.Changed&LeafAdminStatus != 0 && evt.PrevOper != evt.Oper {
		ev.skip.ifIndex, ev.skip.at, ev.skip.set = evt.IfIndex, evt.At, true
	}
	return false
}

// handleStateChange renders one event for this session alone.
func (s *netconfSession) handleStateChange(evt StateChange) {
	s.handleStateEvent(&netconfStateEvent{evt: evt, dev: s.dev})
}

// handleStateEvent renders one event through the dialect hook. A session
// without one renders nothing.
func (s *netconfSession) handleStateEvent(e *netconfStateEvent) {
	if s.ev != nil && s.ev.onEvent != nil {
		s.ev.onEvent(s, e)
	}
}

// iosxeStateEvent is the IOS XE rendering of one state change.
func (s *netconfSession) iosxeStateEvent(e *netconfStateEvent) {
	evt := e.evt
	// A session closed after a write error renders nothing more.
	if s.isClosed() {
		return
	}
	ev := s.ev
	if ev.twinOperEvent(evt) {
		return
	}
	// The event carries the link as it was when the change happened. The
	// link read now may already have moved past a queued event.
	if iosxeSuppress(evt) {
		return
	}

	name := e.ifName()
	ev.mu.Lock()
	var subs []*netconfSub
	wholeRow := false
	// Every subscription on the interface gets the push, whatever leaf it
	// selects. An admin-status leaf subscription is re-sent on a link-only
	// move: the c8000v capture shows the admin-status leaf re-sent on
	// carrier loss.
	for _, sub := range ev.subs {
		if sub.sel.IfName == "" || sub.sel.IfName == name {
			subs = append(subs, sub)
			wholeRow = wholeRow || sub.sel.Leaves == iosxeLeafRow
		}
	}
	ev.mu.Unlock()
	if len(subs) == 0 {
		return
	}

	// A leaf subscription renders only name, admin and oper, which the event
	// carries. The counters are read only when a subscription shows the row.
	row := iosxeRow{Name: name}
	if wholeRow {
		row = e.fullRow()
	}
	row.Admin = iosxeAdminStatus(evt.Admin)
	row.LastChange = "" // unknown after a clock rewind: the leaf is omitted
	if evt.LastChangeNs != LastChangeRewindSentinel {
		row.LastChange = iosxeTimestamp(time.Unix(0, int64(evt.LastChangeNs)))
	}
	// Newest subscription first, as both captured devices do. A multi-step
	// sequence goes out like the c8000v sent it: every step but the last,
	// subscription by subscription, then the last step across all of them.
	// A leaf subscription that does not show oper re-sends once per step.
	push := func(sub *netconfSub, oper string) {
		row.Oper = oper
		s.enqueue(sub, renderPushChangeUpdate(sub.id, evt.At, sub.sel.Leaves, row))
	}
	seq := iosxeOperSequence(evt)
	for i := len(subs) - 1; i >= 0; i-- {
		for _, oper := range seq[:len(seq)-1] {
			push(subs[i], oper)
		}
	}
	for i := len(subs) - 1; i >= 0; i-- {
		push(subs[i], seq[len(seq)-1])
	}
}

// iosxeSuppress reports whether a change goes unreported. On a port whose
// link is not up, the switch sends nothing when only admin moves, or when
// oper moves only between no-pass and lower-layer-down. Link moves are
// always reported.
func iosxeSuppress(evt StateChange) bool {
	if evt.Link == OperUp || evt.Changed&LeafAdminStatus == 0 {
		return false
	}
	if evt.PrevOper == evt.Oper {
		return true
	}
	// A previous oper of down reads as no-pass (admin was down) or as
	// lower-layer-down (the link was down). Both are in the silent pair.
	prevIn := evt.PrevOper == OperDown || evt.PrevOper == OperLowerLayerDn
	now := iosxeOperStatus(evt.Admin, evt.Oper)
	nowIn := now == "if-oper-state-no-pass" || now == "if-oper-state-lower-layer-down"
	return prevIn && nowIn
}

// iosxeOperSequence returns the oper-status values one change pushes. Admin
// up over an up link steps through invalid and lower-layer-down to ready,
// with no delay. Every other change pushes one value.
func iosxeOperSequence(evt StateChange) []string {
	if evt.Changed&LeafAdminStatus != 0 && evt.Admin == AdminUp && evt.PrevOper == OperDown && evt.Oper == OperUp {
		return []string{iosxeOperInvalid, "if-oper-state-lower-layer-down", "if-oper-state-ready"}
	}
	return []string{iosxeOperStatus(evt.Admin, evt.Oper)}
}

// syncOnStart publishes sub to the listener and sends the current state of
// every interface it selects, in ascending ifIndex. The device's first
// interface goes as push-update, every other one as push-change-update. A name
// the device does not have gets one empty push-update.
//
// It runs on the RPC goroutine and writes directly, like a reply, so a large
// sync is never lost to the send queue. It holds wmu from before the sub is
// published until the last sync push is written. A change push queued for
// the sub meanwhile waits for wmu in the writer, so it can never overtake the
// sync. A change before publication is already in the state the sync reads.
func (s *netconfSession) syncOnStart(sub *netconfSub) {
	s.wmu.Lock()
	defer s.wmu.Unlock()
	s.ev.mu.Lock()
	s.ev.subs = append(s.ev.subs, sub)
	s.ev.mu.Unlock()

	ic := netconfIfCounters(s.dev)
	indices := slices.Clone(ic.IfIndices())
	slices.Sort(indices)
	now := time.Now()

	targets := indices
	if sub.sel.IfName != "" {
		targets = nil
		for _, i := range indices {
			if devIfDescr(s.dev, i) == sub.sel.IfName {
				targets = []int{i}
				break
			}
		}
		if targets == nil {
			_ = s.writePush(renderPushUpdate(sub.id, now, sub.sel.Leaves, nil))
			return
		}
	}
	for _, i := range targets {
		row := buildIosxeRow(s.dev, ic, i, now)
		var msg []byte
		if i == indices[0] {
			msg = renderPushUpdate(sub.id, now, sub.sel.Leaves, &row)
		} else {
			msg = renderPushChangeUpdate(sub.id, now, sub.sel.Leaves, row)
		}
		if !s.writePush(msg) {
			return
		}
	}
}

// writePush writes one sync push and reports whether it went out. A write
// error closes the session, as in the writer. The caller holds wmu.
func (s *netconfSession) writePush(msg []byte) bool {
	if err := s.framer.WriteMessage(msg); err != nil {
		s.close()
		return false
	}
	atomic.AddUint64(s.ev.sent, 1)
	return true
}

// iosxeIfTypes maps the IANA ifType numbers nl6 profiles carry to the
// Cisco-IOS-XE-interfaces-oper enum names.
var iosxeIfTypes = map[int]string{
	6:   "iana-iftype-ethernet-csmacd",
	24:  "iana-iftype-sw-loopback",
	53:  "iana-iftype-propvirtual",
	131: "iana-iftype-tunnel",
	135: "iana-iftype-l2vlan",
	136: "iana-iftype-l3ipvlan",
	161: "iana-iftype-ieee8023-adlag",
}

// buildIosxeRow reads the row leaves nl6 serves for ifIndex at now.
func buildIosxeRow(dev *DeviceSimulator, ic *IfCounterCycler, ifIndex int, now time.Time) iosxeRow {
	row := iosxeRow{
		Name:          devIfDescr(dev, ifIndex),
		IfIndex:       ifIndex,
		InterfaceType: "iana-iftype-other",
		PhysAddress:   lookupIfColumn(dev, ifTablePrefix+"6.", ifIndex),
		Admin:         iosxeAdminStatus(AdminUp),
		Oper:          iosxeOperInvalid,
	}
	if name, ok := iosxeIfTypes[lookupIfType(dev, ifIndex)]; ok {
		row.InterfaceType = name
	}
	if mbps, err := strconv.ParseUint(lookupIfColumn(dev, ifXTablePrefix+"15.", ifIndex), 10, 64); err == nil && mbps > 0 {
		row.Speed = mbps * 1000000
	} else if bps, err := strconv.ParseUint(lookupIfColumn(dev, ifTablePrefix+"5.", ifIndex), 10, 64); err == nil {
		row.Speed = bps
	}
	if ic == nil {
		return row
	}
	if state := ic.State(); state != nil {
		if snap := state.Snapshot(ifIndex); snap.Found {
			row.Admin = iosxeAdminStatus(snap.Admin)
			row.Oper = iosxeOperStatus(snap.Admin, snap.Oper)
			if snap.LastChangeNs != LastChangeRewindSentinel {
				row.LastChange = iosxeTimestamp(time.Unix(0, int64(snap.LastChangeNs)))
			}
		}
	}
	t := now.Sub(ic.startTime).Seconds()
	read := func(prefix string, col int) uint64 {
		v, _ := strconv.ParseUint(ic.GetDynamicAt(prefix+strconv.Itoa(col)+"."+strconv.Itoa(ifIndex), t), 10, 64)
		return v
	}
	row.Stats = iosxeStats{
		DiscontinuityTime: iosxeTimestamp(ic.startTime),
		InOctets:          read(ifXTablePrefix, colIfHCInOctets),
		InUnicastPkts:     read(ifXTablePrefix, colIfHCInUcastPkts),
		InBroadcastPkts:   read(ifXTablePrefix, colIfHCInBroadcastPkts),
		InMulticastPkts:   read(ifXTablePrefix, colIfHCInMulticastPkts),
		InDiscards:        read(ifTablePrefix, colIfInDiscards),
		InErrors:          read(ifTablePrefix, colIfInErrors),
		OutOctets:         read(ifXTablePrefix, colIfHCOutOctets),
		OutUnicastPkts:    read(ifXTablePrefix, colIfHCOutUcastPkts),
		OutBroadcastPkts:  read(ifXTablePrefix, colIfHCOutBroadcastPkts),
		OutMulticastPkts:  read(ifXTablePrefix, colIfHCOutMulticastPkts),
		OutDiscards:       read(ifTablePrefix, colIfOutDiscards),
		OutErrors:         read(ifTablePrefix, colIfOutErrors),
	}
	return row
}
