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
// per-subscription message ids need no locking.
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
	msgID   [3]uint32
	started bool
	work    chan StateChange

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
		work:      make(chan StateChange, onChangeBufferDepth),
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
		return dev.netNamespace.DialContextInNamespace(ctx, "udp", collector, local)
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
		st.AddListener(sc)
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
		e.emit(i, func() []byte { return encodePushUpdate(e.subs[i], obs, e.pubID, e.interfaces(obs)) })
		next[i] = ypNextFire(e.subs[i], offsets[i], later(obs, e.clock()))
		timers[i].ResetAt(next[i])
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
			e.forward(evt)
		case evt := <-e.work:
			e.drain(sc)
			e.ensureStarted()
			e.emit(2, func() []byte { return e.changeUpdate(evt) })
		}
	}
}

// forward moves a state event into the exporter's queue without blocking.
// A full queue drops its oldest event, counted, so the latest transition
// always goes out. Only the run goroutine touches the queue.
func (e *YangPushExporter) forward(evt StateChange) {
	select {
	case e.work <- evt:
		return
	default:
	}
	<-e.work
	e.stateEventsDropped.Add(1)
	e.work <- evt
}

// drain forwards everything the listener holds, so InterfaceState finds room
// while this goroutine sends.
func (e *YangPushExporter) drain(sc chan StateChange) {
	for {
		select {
		case evt := <-sc:
			e.forward(evt)
		default:
			return
		}
	}
}

// ensureStarted sends the three subscription-started notifications and the
// subscription-10 sync-on-start push-update, once, at the first moment
// fidelity lets the device speak.
func (e *YangPushExporter) ensureStarted() {
	if e.started || fidelityMutesBackground(sourceBackground) {
		return
	}
	e.started = true
	now := e.clock()
	for i := range e.subs {
		e.send(i, now, encodeSubscriptionStarted(e.subs[i], e.pubID))
	}
	// Subscription 10's sync push-update carries only the two status leaves
	// and point-in-time initial-state.
	e.send(2, now, encodePushUpdate(e.subs[2], now, e.pubID, e.interfaces(now)))
}

// emit sends one push for subscription i unless fidelity mutes it.
func (e *YangPushExporter) emit(i int, contents func() []byte) {
	if fidelityMutesBackground(sourceBackground) {
		e.fidelitySuppressed.Add(1)
		return
	}
	e.send(i, e.clock(), contents())
}

// send frames one message for subscription i. Message id and envelope
// sequence-number are the same per-subscription counter. A failed segment
// aborts the rest of the message; the id stays consumed.
func (e *YangPushExporter) send(i int, eventTime time.Time, contents []byte) {
	id := e.msgID[i]
	e.msgID[i]++
	payload := encodeEnvelope(eventTime, gnmiDeviceSysName(e.dev), uint64(id), contents)
	for _, seg := range udpNotifFrame(e.pubID, id, payload, e.segSize) {
		if _, err := e.conn.Write(seg); err != nil {
			e.sendFailures.Add(1)
			return
		}
		e.segmentsSent.Add(1)
	}
	e.messagesSent.Add(1)
}

// interfaces reads every interface at obs.
func (e *YangPushExporter) interfaces(obs time.Time) []ypIface {
	ic := e.cycler()
	idxs := ic.IfIndices()
	out := make([]ypIface, 0, len(idxs))
	for _, idx := range idxs {
		row := buildIosxeRow(e.dev, ic, idx, obs)
		unknown, _ := strconv.ParseUint(lookupIfColumn(e.dev, ifTablePrefix+"15.", idx), 10, 32)
		out = append(out, ypIfaceFrom(row, lookupIfType(e.dev, idx), uint32(unknown)))
	}
	return out
}

// changeUpdate renders the push-change-update for one transition, from the
// values the event carries rather than the engine's current state, so a burst
// reports each step.
func (e *YangPushExporter) changeUpdate(evt StateChange) []byte {
	row := iosxeRow{
		Name:    devIfDescr(e.dev, evt.IfIndex),
		IfIndex: evt.IfIndex,
		Admin:   iosxeAdminStatus(evt.Admin),
		Oper:    iosxeOperStatus(evt.Admin, evt.Oper),
	}
	return encodePushChangeUpdate(e.subs[2], evt.At, e.pubID, "edit1", ypIfaceFrom(row, 0, 0), evt.Changed)
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
