/*
 * Copyright 2026 Ronny Trommer <ronny@no42.org>
 * SPDX-License-Identifier: Apache-2.0
 */

package main

import (
	"context"
	"io"
	"net"
	"testing"
	"time"
)

// Two sessions on one device share one dispatcher and one engine listener,
// and each gets exactly one push for one change.
func TestNetconfDispatcherSharedAcrossSessions(t *testing.T) {
	dev, st := newNetconfTestDevice(t)
	reg := newNetconfSessionRegistry()
	a := startIOSXETestClientReg(t, dev, reg)
	b := startIOSXETestClientReg(t, dev, reg)
	a.sub(ncXPath("GigabitEthernet1/0/24", "oper-status"))
	b.sub(ncXPath("GigabitEthernet1/0/24", "oper-status"))
	if n := ncListenerCount(st); n != 1 {
		t.Fatalf("listeners with two sessions: %d, want 1", n)
	}
	if a.sess.ev.disp.Load() != b.sess.ev.disp.Load() {
		t.Fatal("the two sessions hold different dispatchers")
	}

	ncLink(st, 24, OperDown)
	for name, c := range map[string]*iosxeTestClient{"a": a, "b": b} {
		if n := c.next(); n.oper != "if-oper-state-lower-layer-down" {
			t.Fatalf("%s: push oper %q, want lower-layer-down", name, n.oper)
		}
		ncExpectNone(t, c, 300*time.Millisecond)
	}

	// The first session to leave keeps the dispatcher alive for the other.
	_ = a.conn.Close()
	a.waitDone()
	if n := ncListenerCount(st); n != 1 {
		t.Fatalf("listeners after one session left: %d, want 1", n)
	}
	ncLink(st, 24, OperUp)
	if n := b.next(); n.oper != "if-oper-state-ready" {
		t.Fatalf("b after a left: push oper %q, want ready", n.oper)
	}
	_ = b.conn.Close()
	b.waitDone()
	if n := ncListenerCount(st); n != 0 {
		t.Fatalf("listeners after both sessions left: %d, want 0", n)
	}
	reg.mu.Lock()
	disp, refs := reg.disp, reg.dispRefs
	reg.mu.Unlock()
	if disp != nil || refs != 0 {
		t.Fatalf("registry keeps dispatcher %v with %d refs", disp != nil, refs)
	}
}

// An event queued on the dispatcher before a session joins goes to the
// sessions that were there and never to the new one. The run loop picks
// between a queued event and a join at random, so the join must drain first;
// without that, a few of these rounds deliver the event to the newcomer.
func TestNetconfDispatcherEventBeforeJoinNotDelivered(t *testing.T) {
	dev, st := newNetconfTestDevice(t)
	a := startIOSXETestClientReg(t, dev, nil)
	b := startIOSXETestClientReg(t, dev, nil)
	a.sub(ncXPath("GigabitEthernet1/0/24", "oper-status"))
	b.sub(ncXPath("GigabitEthernet1/0/24", "oper-status"))

	link := uint8(OperDown)
	for round := 0; round < 20; round++ {
		d := initNetconfDispatcher(st)
		d.sessions = []*netconfSession{a.sess}
		_, evts := st.SetLinkState(24, link)
		if len(evts) != 1 {
			t.Fatalf("round %d: %d events, want 1", round, len(evts))
		}
		d.ch <- evts[0]
		d.start()
		b.sess.ev.ready = make(chan struct{})
		d.register(context.Background(), b.sess)

		want := "if-oper-state-lower-layer-down"
		if link == OperUp {
			want = "if-oper-state-ready"
		}
		if n := a.next(); n.oper != want {
			t.Fatalf("round %d: a got oper %q, want %q", round, n.oper, want)
		}
		ncExpectNone(t, b, 40*time.Millisecond)
		d.unregister(b.sess)
		d.close()
		if link == OperDown {
			link = OperUp
		} else {
			link = OperDown
		}
	}
}

// A session whose ctx ends while it registers returns without registering.
func TestNetconfDispatcherRegisterCancelled(t *testing.T) {
	dev, _ := newNetconfTestDevice(t)
	// No run loop, so the join can never be accepted and only ctx can
	// release register.
	d := &netconfDispatcher{join: make(chan netconfDispatchCmd)}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	s := newIOSXENetconfSession(9, dev, struct{ io.ReadWriter }{nil}, nil)
	finished := make(chan struct{})
	go func() { d.register(ctx, s); close(finished) }()
	select {
	case <-finished:
	case <-time.After(5 * time.Second):
		t.Fatal("register did not return on a cancelled ctx")
	}
}

// startIOSXETestClientReg is startIOSXETestClient on a shared registry. A nil
// registry gives a session that joins no dispatcher.
func startIOSXETestClientReg(t *testing.T, dev *DeviceSimulator, reg *netconfSessionRegistry) *iosxeTestClient {
	t.Helper()
	srv, cli := net.Pipe()
	var id uint32 = 1
	if reg != nil {
		id = reg.subSeq.Load() + 1
	}
	sess := newIOSXENetconfSession(id, dev, srv, reg)
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

// ncExpectNone fails when a message arrives within d.
func ncExpectNone(t *testing.T, c *iosxeTestClient, d time.Duration) {
	t.Helper()
	_ = c.conn.SetReadDeadline(time.Now().Add(d))
	defer c.conn.SetReadDeadline(time.Now().Add(10 * time.Second))
	if raw, err := c.f.ReadMessage(); err == nil {
		t.Fatalf("unexpected push: %s", raw)
	} else if ne, ok := err.(net.Error); !ok || !ne.Timeout() {
		t.Fatalf("read: %v", err)
	}
}
