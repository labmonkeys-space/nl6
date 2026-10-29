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

	// ready is closed once the state listener is registered.
	ready chan struct{}

	// skip names the oper event that follows an admin event which moved
	// oper too. The admin event already pushed the row, so its twin is
	// dropped. Only the listener goroutine touches it.
	skip struct {
		ifIndex int
		at      time.Time
		set     bool
	}
}

// netconfOutbox is a bounded oldest-drop ring of rendered pushes. push never
// blocks. One writer goroutine drains it.
type netconfOutbox struct {
	mu   sync.Mutex
	buf  [netconfSendQueueDepth][]byte
	head int
	n    int
	wake chan struct{}
}

// push queues msg and reports whether it displaced the oldest push.
func (o *netconfOutbox) push(msg []byte) (dropped bool) {
	o.mu.Lock()
	if o.n == netconfSendQueueDepth {
		o.buf[o.head] = nil
		o.head = (o.head + 1) % netconfSendQueueDepth
		o.n--
		dropped = true
	}
	o.buf[(o.head+o.n)%netconfSendQueueDepth] = msg
	o.n++
	o.mu.Unlock()
	select {
	case o.wake <- struct{}{}:
	default:
	}
	return dropped
}

func (o *netconfOutbox) pop() ([]byte, bool) {
	o.mu.Lock()
	defer o.mu.Unlock()
	if o.n == 0 {
		return nil, false
	}
	msg := o.buf[o.head]
	o.buf[o.head] = nil
	o.head = (o.head + 1) % netconfSendQueueDepth
	o.n--
	return msg, true
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
	ev.out.wake = make(chan struct{}, 1)
	if manager != nil {
		ev.sent, ev.dropped = &manager.netconfNotificationsSent, &manager.netconfNotificationsDropped
	} else {
		ev.sent, ev.dropped = new(uint64), new(uint64)
	}
	s.ev = ev
	s.onStart = s.startEvents
	s.onSubscribe = func(sub *netconfSub) {
		ev.mu.Lock()
		ev.subs = append(ev.subs, sub)
		ev.mu.Unlock()
		s.syncOnStart(sub)
	}
	s.onUnsubscribe = func(sub *netconfSub) {
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

// startEvents starts the writer and the state listener. It returns once the
// listener is registered, so no change after the hello is missed.
func (s *netconfSession) startEvents(ctx context.Context) {
	go s.runWriter(ctx)
	state := netconfIfCounters(s.dev).State()
	if state == nil {
		return
	}
	go s.runStateListener(ctx, state)
	select {
	case <-s.ev.ready:
	case <-ctx.Done():
	}
}

// runWriter drains the send queue. It shares writeMessage, and so the write
// mutex, with RPC replies.
func (s *netconfSession) runWriter(ctx context.Context) {
	ev := s.ev
	for {
		select {
		case <-ctx.Done():
			return
		case <-ev.out.wake:
		}
		for {
			msg, ok := ev.out.pop()
			if !ok {
				break
			}
			if err := s.writeMessage(msg); err != nil {
				return
			}
			atomic.AddUint64(ev.sent, 1)
		}
	}
}

// enqueue queues a push without blocking.
func (s *netconfSession) enqueue(msg []byte) {
	if s.ev.out.push(msg) {
		atomic.AddUint64(s.ev.dropped, 1)
	}
}

// runStateListener turns state-engine events into pushes until ctx ends.
func (s *netconfSession) runStateListener(ctx context.Context, state *InterfaceState) {
	ch := make(chan StateChange, netconfEventBufferDepth)
	state.AddListener(ch)
	defer state.RemoveListener(ch)
	close(s.ev.ready)
	for {
		select {
		case <-ctx.Done():
			return
		case evt := <-ch:
			s.handleStateChange(state, evt)
		}
	}
}

func (s *netconfSession) handleStateChange(state *InterfaceState, evt StateChange) {
	ev := s.ev
	if evt.Changed == LeafOperStatus && ev.skip.set && ev.skip.ifIndex == evt.IfIndex && ev.skip.at.Equal(evt.At) {
		ev.skip.set = false
		return
	}
	if evt.Changed&LeafAdminStatus != 0 && evt.PrevOper != evt.Oper {
		ev.skip.ifIndex, ev.skip.at, ev.skip.set = evt.IfIndex, evt.At, true
	}
	if iosxeSuppress(evt, state.LinkState(evt.IfIndex)) {
		return
	}

	name := devIfDescr(s.dev, evt.IfIndex)
	ev.mu.Lock()
	var subs []*netconfSub
	for _, sub := range ev.subs {
		if sub.sel.IfName == "" || sub.sel.IfName == name {
			subs = append(subs, sub)
		}
	}
	ev.mu.Unlock()
	if len(subs) == 0 {
		return
	}

	row := buildIosxeRow(s.dev, netconfIfCounters(s.dev), evt.IfIndex, evt.At)
	row.Admin = iosxeAdminStatus(evt.Admin)
	if evt.LastChangeNs != LastChangeRewindSentinel {
		row.LastChange = iosxeTimestamp(time.Unix(0, int64(evt.LastChangeNs)))
	}
	for _, oper := range iosxeOperSequence(evt) {
		row.Oper = oper
		// Newest subscription first, as both captured devices do.
		for i := len(subs) - 1; i >= 0; i-- {
			s.enqueue(renderPushChangeUpdate(subs[i].id, evt.At, subs[i].sel.Leaves, row))
		}
	}
}

// iosxeSuppress reports whether a change goes unreported. On a port whose
// link is not up, the switch sends nothing when only admin moves, or when
// oper moves only between no-pass and lower-layer-down. Link moves are
// always reported.
func iosxeSuppress(evt StateChange, link uint8) bool {
	if link == OperUp || evt.Changed&LeafAdminStatus == 0 {
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

// syncOnStart sends the current state of every interface sub selects, in
// ascending ifIndex. The device's first interface goes as push-update, every
// other one as push-change-update. A name the device does not have gets one
// empty push-update. It runs on the RPC goroutine and writes directly, like a
// reply, so a large sync is never lost to the send queue.
func (s *netconfSession) syncOnStart(sub *netconfSub) {
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
			s.writePush(renderPushUpdate(sub.id, now, sub.sel.Leaves, nil))
			return
		}
	}
	for _, i := range targets {
		row := buildIosxeRow(s.dev, ic, i, now)
		if i == indices[0] {
			s.writePush(renderPushUpdate(sub.id, now, sub.sel.Leaves, &row))
		} else {
			s.writePush(renderPushChangeUpdate(sub.id, now, sub.sel.Leaves, row))
		}
	}
}

func (s *netconfSession) writePush(msg []byte) {
	if s.writeMessage(msg) == nil {
		atomic.AddUint64(s.ev.sent, 1)
	}
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
