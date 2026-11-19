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
	"sort"
	"strconv"
	"sync"
	"sync/atomic"
	"time"
)

// ypTimer is the part of a timer the run loop uses. Tests substitute a fake
// driven by a manual clock.
type ypTimer interface {
	C() <-chan time.Time
	ResetAt(at time.Time)
	Stop()
}

type ypRealTimer struct {
	t     *time.Timer
	clock func() time.Time
}

func (r *ypRealTimer) C() <-chan time.Time  { return r.t.C }
func (r *ypRealTimer) ResetAt(at time.Time) { r.t.Reset(at.Sub(r.clock())) }
func (r *ypRealTimer) Stop()                { r.t.Stop() }

// YangPushExporter streams the three VRP subscriptions (vrpSubs) of one
// huawei_ne8000 device to a collector over UDP-notif. One goroutine per device
// owns the socket, both periodic timers and the state listener, so the
// message id needs no locking.
//
// The device keeps its own schedule inside a load-test scenario. A scenario
// that claims the device installs scenPart, and gate then decides per message
// whether it is sent and how it is counted. No scenario emitter exists for
// this protocol.
type YangPushExporter struct {
	dev       *DeviceSimulator
	collector string
	segSize   int
	pubID     uint32
	clock     func() time.Time
	newTimer  func() ypTimer
	subs      [3]ypSub
	conn      net.Conn

	// Run-loop state, touched only by the run goroutine.
	msgID   uint32 // messages sent so far, over all subscriptions
	patchID uint64 // change-updates sent so far; run goroutine only
	started bool
	twins   operTwins // admin events whose oper twin is still to come

	stop      chan struct{}
	stopOnce  sync.Once
	startOnce sync.Once
	wg        sync.WaitGroup

	messagesSent       atomic.Uint64
	segmentsSent       atomic.Uint64
	sendFailures       atomic.Uint64
	stateEventsDropped atomic.Uint64
	fidelitySuppressed atomic.Uint64
	countersPersisted  sync.Once

	// scenPart is the scenario participation handle, nil unless a yang-push
	// scenario claimed this device. The controller stores it, the run
	// goroutine loads it once per gate call.
	scenPart atomic.Pointer[scenarioPart]
}

// NewYangPushExporter opens the device's UDP-notif socket: bound to the device
// IP inside its netns and connected to the collector, so the source address is
// the one NetGauze later dials for NETCONF and ICMP port-unreachable surfaces as
// a send failure. A bind failure is an error; there is no shared-socket fallback.
func NewYangPushExporter(dev *DeviceSimulator, cfg *DeviceYangPushConfig, clock func() time.Time) (*YangPushExporter, error) {
	ip4 := dev.IP.To4()
	if ip4 == nil {
		return nil, fmt.Errorf("yang_push: device IP %v is not IPv4", dev.IP)
	}
	segSize := cfg.SegmentSize
	if segSize == 0 {
		segSize = defaultYangPushSegmentSize
	}
	conn, err := dialYangPush(dev, cfg.Collector)
	if err != nil {
		return nil, fmt.Errorf("yang_push: socket for %s to %s: %w", dev.IP, cfg.Collector, err)
	}
	e := &YangPushExporter{
		dev:       dev,
		collector: cfg.Collector,
		segSize:   segSize,
		pubID:     binary.BigEndian.Uint32(ip4),
		clock:     clock,
		subs:      vrpSubs,
		conn:      conn,
		twins:     operTwins{},
		stop:      make(chan struct{}),
	}
	e.newTimer = func() ypTimer {
		t := time.NewTimer(time.Hour)
		t.Stop()
		return &ypRealTimer{t: t, clock: clock}
	}
	return e, nil
}

// dialYangPush opens the connected UDP socket bound to the device IP, inside
// the device's netns when it has one (without: tests, -no-namespace). The
// source address is what NetGauze dials for NETCONF, so a failed bind is an
// error and there is no unbound fallback.
func dialYangPush(dev *DeviceSimulator, collector string) (net.Conn, error) {
	local := &net.UDPAddr{IP: dev.IP}
	if dev.netNamespace != nil {
		ctx, cancel := context.WithTimeout(context.Background(), deviceDialTimeout)
		defer cancel()
		return dev.netNamespace.DialContextInNamespace(ctx, "udp4", collector, local)
	}
	raddr, err := net.ResolveUDPAddr("udp4", collector)
	if err != nil {
		return nil, err
	}
	return net.DialUDP("udp4", local, raddr)
}

// Subscriptions lists the subscriptions this device serves, for the NETCONF
// subscriptions answer.
func (e *YangPushExporter) Subscriptions() []ypSub {
	out := make([]ypSub, len(e.subs))
	copy(out, e.subs[:])
	return out
}

// Start launches the run goroutine. Calling it twice is a no-op.
func (e *YangPushExporter) Start() {
	e.startOnce.Do(func() {
		e.wg.Add(1)
		go e.run()
	})
}

// Close stops the run goroutine, waits for an in-flight send to finish and
// closes the socket. Idempotent and safe for concurrent callers.
func (e *YangPushExporter) Close() error {
	if e == nil {
		return nil
	}
	var err error
	e.stopOnce.Do(func() {
		e.startOnce.Do(func() {}) // a later Start must not launch the loop
		close(e.stop)
		e.wg.Wait()
		if e.conn != nil {
			err = e.conn.Close()
		}
	})
	return err
}

func (e *YangPushExporter) cycler() *IfCounterCycler {
	if e.dev.metricsCycler == nil {
		return nil
	}
	return e.dev.metricsCycler.ifCounters.Load()
}

func (e *YangPushExporter) run() {
	defer e.wg.Done()
	// Register before the sync-on-start snapshot, as gNMI ON_CHANGE does, so a
	// transition racing the snapshot is not lost.
	var sc chan StateChange
	if st := e.cycler().State(); st != nil {
		sc = make(chan StateChange, onChangeBufferDepth)
		// A full listener drops its oldest event, counted here, so the latest
		// transition always goes out.
		st.AddListenerCounting(sc, &e.stateEventsDropped)
		defer st.RemoveListener(sc)
	}
	e.ensureStarted()

	// One timer per periodic subscription. Subscription 9 fires 3 s after 8.
	offsets := [2]time.Duration{0, 3 * time.Second}
	var next [2]time.Time
	var timers [2]ypTimer
	for i := range timers {
		timers[i] = e.newTimer()
		defer timers[i].Stop()
		next[i] = ypNextFire(e.subs[i], offsets[i], e.clock())
		timers[i].ResetAt(next[i])
	}
	periodic := func(i int) {
		obs := next[i]
		e.ensureStarted()
		e.emit(i, e.clock(), func() []byte { return encodePushUpdate(e.subs[i], obs, e.pubID, e.interfaces(obs)) })
		next[i] = ypNextFire(e.subs[i], offsets[i], later(obs, e.clock()))
		timers[i].ResetAt(next[i])
	}

	// On-change dampening (RFC 8641): after a change-update, further changes
	// are collected for ypDampening and go out as one update when it ends.
	damp := e.newTimer()
	defer damp.Stop()
	inWindow := false
	pending := map[int]struct{}{}
	openWindow := func() {
		inWindow = true
		damp.ResetAt(e.clock().Add(ypDampening))
	}

	for {
		select {
		case <-e.stop:
			return
		case <-timers[0].C():
			periodic(0)
		case <-timers[1].C():
			periodic(1)
		case evt := <-sc:
			if e.twins.twin(evt) {
				continue
			}
			e.ensureStarted()
			if inWindow {
				if !e.gateEvent(e.clock()) {
					continue
				}
				pending[evt.IfIndex] = struct{}{}
				continue
			}
			if e.emit(2, e.clock(), func() []byte { return e.changeUpdate(evt) }) {
				openWindow()
			}
		case <-damp.C():
			// Take what is already queued, so a change that raced the timer
			// belongs to this period and not to the next.
			for n := len(sc); n > 0; n-- {
				select {
				case evt := <-sc:
					if e.twins.twin(evt) {
						continue
					}
					if !e.gateEvent(e.clock()) {
						continue
					}
					pending[evt.IfIndex] = struct{}{}
				default:
				}
			}
			inWindow = false
			if len(pending) == 0 {
				continue
			}
			idxs := make([]int, 0, len(pending))
			for idx := range pending {
				idxs = append(idxs, idx)
			}
			sort.Ints(idxs)
			clear(pending)
			obs := e.clock()
			if e.emit(2, obs, func() []byte { return e.collectedUpdate(idxs, obs) }) {
				openWindow()
			}
		}
	}
}

// ypInWindow reports whether a claimed device may send at now. It is the
// scenario gate, closed one step earlier at the end: the report states T1 in
// milliseconds and the envelope event-time has milliseconds too, so a message
// in the last partial millisecond before T1 would carry an event-time equal to
// the reported T1. A receiver that selects [T0,T1) by event-time would not
// count it, and the run would show a loss that did not happen.
func ypInWindow(part *scenarioPart, now time.Time) bool {
	if part.decide(sourceScenario, now) != gateProceed {
		return false
	}
	gs := part.gate.Load()
	return gs != nil && now.Truncate(time.Millisecond).Before(gs.t1.Truncate(time.Millisecond))
}

// speaks reports whether the device may send at now, without counting. A
// device no scenario claimed speaks unless fidelity mutes it. A claimed device
// speaks inside the scenario window only.
func (e *YangPushExporter) speaks(now time.Time) bool {
	if part := e.scenPart.Load(); part != nil {
		return ypInWindow(part, now)
	}
	return !fidelityMutesBackground(sourceBackground)
}

// gate decides whether one message goes out at now, and counts it. When ok,
// the caller sends the message and reports the result through done. A refused
// message must not be built or sent, so it consumes no message id.
//
// For a claimed device it follows the gNMI dial-out gate for the decision and
// syslog for the write: the drain admit is held across all segments, and the
// ledger bucket is chosen when the last write returned.
func (e *YangPushExporter) gate(now time.Time) (ok bool, done func(sent bool)) {
	part := e.scenPart.Load()
	if part == nil {
		if fidelityMutesBackground(sourceBackground) {
			e.fidelitySuppressed.Add(1)
			return false, nil
		}
		return true, func(bool) {}
	}
	if !ypInWindow(part, now) {
		part.ledger.backgroundSuppressed.Add(1)
		return false, nil
	}
	part.ledger.emitted.Add(1)
	if !part.drain.admit() {
		part.ledger.dropped.Add(1)
		return false, nil
	}
	return true, func(sent bool) {
		if sent {
			part.bucketFor(part.now()).Add(1)
		} else {
			part.ledger.sendFailures.Add(1)
		}
		part.drain.leave()
	}
}

// gateEvent decides whether a state change is collected for the dampening
// period. A change that arrives while the device is silent is dropped, so it
// cannot go out later with an old state.
func (e *YangPushExporter) gateEvent(now time.Time) bool {
	part := e.scenPart.Load()
	if part == nil {
		if fidelityMutesBackground(sourceBackground) {
			e.fidelitySuppressed.Add(1)
			return false
		}
		return true
	}
	if !ypInWindow(part, now) {
		part.ledger.backgroundSuppressed.Add(1)
		return false
	}
	return true
}

// ensureStarted sends the three subscription-started notifications and the
// subscription-10 sync-on-start push-update, once, at the first moment the
// device may speak: fidelity off, or inside the window of the scenario that
// claimed it. Each of the four messages is gated and counted on its own. If
// the first one is refused, the device has not announced and tries again at
// its next activity.
func (e *YangPushExporter) ensureStarted() {
	now := e.clock()
	if e.started || !e.speaks(now) {
		return
	}
	for i := range e.subs {
		ok, done := e.gate(now)
		if !ok {
			if i == 0 {
				return
			}
			continue
		}
		e.started = true
		done(e.send(i, now, encodeSubscriptionStarted(e.subs[i], e.pubID)))
	}
	// Subscription 10's sync push-update carries every interface entry and
	// point-in-time initial-state.
	if ok, done := e.gate(now); ok {
		done(e.send(2, now, encodePushUpdate(e.subs[2], now, e.pubID, e.interfaces(now))))
	}
}

// emit sends one push for subscription i if the gate lets it out, and reports
// whether it was let out. The contents are built only then.
func (e *YangPushExporter) emit(i int, eventTime time.Time, contents func() []byte) bool {
	ok, done := e.gate(eventTime)
	if !ok {
		return false
	}
	done(e.send(i, eventTime, contents()))
	return true
}

// send frames one message for subscription i and reports whether every
// segment was written. Message id and envelope sequence-number are the same
// counter. It is one counter per device over all its subscriptions and starts
// at 1, as in the IETF 127 capture. The IETF 125 capture counted per
// subscription from 0. A failed segment aborts the rest of the message; the id
// stays consumed.
func (e *YangPushExporter) send(i int, eventTime time.Time, contents []byte) bool {
	e.msgID++
	id := e.msgID
	payload := encodeEnvelope(eventTime, gnmiDeviceSysName(e.dev), uint64(id), contents)
	for _, seg := range udpNotifFrame(e.pubID, id, payload, e.segSize) {
		if _, err := e.conn.Write(seg); err != nil {
			e.sendFailures.Add(1)
			return false
		}
		e.segmentsSent.Add(1)
	}
	e.messagesSent.Add(1)
	return true
}

// row reads the ietf-interfaces source values of one interface at obs.
func (e *YangPushExporter) row(idx int, obs time.Time) iosxeRow {
	return buildIosxeRow(e.dev, e.cycler(), idx, obs)
}

// entry converts a row into the leaves nl6 serves for that interface.
func (e *YangPushExporter) entry(row iosxeRow) ypIface {
	unknown, _ := strconv.ParseUint(lookupIfColumn(e.dev, ifTablePrefix+"15.", row.IfIndex), 10, 32)
	// The ifAlias as SNMP serves it: the topology link label, else the value
	// in the device profile.
	alias := e.linkAlias(row.IfIndex)
	if alias == "" {
		alias = lookupIfColumn(e.dev, ifAliasPrefix, row.IfIndex)
	}
	return ypIfaceFrom(row, lookupIfType(e.dev, row.IfIndex), uint32(unknown), alias)
}

// linkAlias is devIfAlias for the run goroutine. DeleteDevice holds the
// manager write lock while Close waits for this goroutine, so the peer lookup
// must not block on that lock. It polls for the lock and gives up when the
// exporter stops.
func (e *YangPushExporter) linkAlias(ifIndex int) string {
	mgr := lldpManager()
	if mgr == nil {
		return ""
	}
	return devIfAliasVia(mgr, e.dev, ifIndex, func(ip string) *DeviceSimulator {
		for !mgr.mu.TryRLock() {
			select {
			case <-e.stop:
				return nil
			default:
				time.Sleep(time.Millisecond)
			}
		}
		defer mgr.mu.RUnlock()
		return mgr.devicesByIP[ip]
	})
}

// interfaces reads every interface at obs.
func (e *YangPushExporter) interfaces(obs time.Time) []ypIface {
	idxs := e.cycler().IfIndices()
	out := make([]ypIface, 0, len(idxs))
	for _, idx := range idxs {
		out = append(out, e.entry(e.row(idx, obs)))
	}
	return out
}

// changeUpdate renders the push-change-update for one transition. The entry
// is the interface as read at the event time, with the status leaves and
// last-change taken from the event rather than the engine's current state.
// Later events inside the dampening period go out through collectedUpdate.
func (e *YangPushExporter) changeUpdate(evt StateChange) []byte {
	row := e.row(evt.IfIndex, evt.At)
	row.Admin = iosxeAdminStatus(evt.Admin)
	row.Oper = iosxeOperStatus(evt.Admin, evt.Oper)
	row.LastChange = iosxeTimestamp(time.Unix(0, int64(evt.LastChangeNs)))
	return encodePushChangeUpdate(e.subs[2], evt.At, e.pubID, e.nextPatchID(), []ypIface{e.entry(row)})
}

// collectedUpdate renders the push-change-update that ends a dampening
// period: one edit per interface in idxs, each as it is at now.
func (e *YangPushExporter) collectedUpdate(idxs []int, now time.Time) []byte {
	ifcs := make([]ypIface, 0, len(idxs))
	for _, idx := range idxs {
		ifcs = append(ifcs, e.entry(e.row(idx, now)))
	}
	return encodePushChangeUpdate(e.subs[2], now, e.pubID, e.nextPatchID(), ifcs)
}

// nextPatchID numbers the change-updates of this device from 0. Only the run
// goroutine calls it.
func (e *YangPushExporter) nextPatchID() uint64 {
	id := e.patchID
	e.patchID++
	return id
}

// ypNextFire is the first instant strictly after t on subscription s's grid
// (anchor + offset + k*period).
func ypNextFire(s ypSub, offset time.Duration, t time.Time) time.Time {
	base := s.Anchor.Add(offset)
	period := time.Duration(s.PeriodCs) * 10 * time.Millisecond
	if t.Before(base) {
		return base
	}
	return base.Add((t.Sub(base)/period + 1) * period)
}

func later(a, b time.Time) time.Time {
	if b.After(a) {
		return b
	}
	return a
}
