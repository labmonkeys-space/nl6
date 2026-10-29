/*
 * Copyright 2026 Ronny Trommer <ronny@no42.org>
 * SPDX-License-Identifier: Apache-2.0
 */

package main

import (
	"context"
	"strings"
	"testing"
	"time"

	gnmipb "github.com/openconfig/gnmi/proto/gnmi"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// onChangeClient is an ON_CHANGE STREAM subscription with one reader
// goroutine, so a timed wait that gives up never leaves a Recv behind to
// swallow the next response.
type onChangeClient struct {
	resps chan *gnmipb.SubscribeResponse
	errs  chan error
	close func()
}

// openOnChange opens an ON_CHANGE STREAM subscription over gRPC.
func openOnChange(t *testing.T, addr string, enc gnmipb.Encoding, paths ...string) *onChangeClient {
	t.Helper()
	conn := dialTestGnmi(t, addr)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	stream, err := gnmipb.NewGNMIClient(conn).Subscribe(ctx)
	if err != nil {
		t.Fatal(err)
	}
	subs := make([]*gnmipb.Subscription, 0, len(paths))
	for _, p := range paths {
		subs = append(subs, &gnmipb.Subscription{Path: pathFromString(t, p), Mode: gnmipb.SubscriptionMode_ON_CHANGE})
	}
	if err := stream.Send(&gnmipb.SubscribeRequest{Request: &gnmipb.SubscribeRequest_Subscribe{Subscribe: &gnmipb.SubscriptionList{
		Mode: gnmipb.SubscriptionList_STREAM, Encoding: enc, Subscription: subs,
	}}}); err != nil {
		t.Fatal(err)
	}
	c := &onChangeClient{resps: make(chan *gnmipb.SubscribeResponse, 64), errs: make(chan error, 1)}
	c.close = func() { cancel(); _ = conn.Close() }
	go func() {
		for {
			resp, err := stream.Recv()
			if err != nil {
				c.errs <- err
				return
			}
			c.resps <- resp
		}
	}()
	return c
}

// untilSync reads responses up to and including sync_response and
// returns the update responses before it.
func (c *onChangeClient) untilSync(t *testing.T) []*gnmipb.SubscribeResponse {
	t.Helper()
	var out []*gnmipb.SubscribeResponse
	for {
		select {
		case resp := <-c.resps:
			if resp.GetSyncResponse() {
				return out
			}
			out = append(out, resp)
		case err := <-c.errs:
			t.Fatalf("before sync_response: %v", err)
		case <-time.After(5 * time.Second):
			t.Fatal("no sync_response within 5s")
		}
	}
}

// within returns the next response, or nil when none arrives in d.
func (c *onChangeClient) within(t *testing.T, d time.Duration) *gnmipb.SubscribeResponse {
	t.Helper()
	select {
	case resp := <-c.resps:
		return resp
	case err := <-c.errs:
		t.Fatalf("recv: %v", err)
		return nil
	case <-time.After(d):
		return nil
	}
}

// err returns the stream's terminal error, waiting up to 5s for it.
func (c *onChangeClient) err(t *testing.T) error {
	t.Helper()
	select {
	case err := <-c.errs:
		return err
	case <-time.After(5 * time.Second):
		t.Fatal("stream did not end within 5s")
		return nil
	}
}

func leafValues(resp *gnmipb.SubscribeResponse) map[string]string {
	out := map[string]string{}
	for _, u := range resp.GetUpdate().GetUpdate() {
		out[pathToString(u.GetPath())] = u.GetVal().GetStringVal()
	}
	return out
}

// TestCatalogServer_OnChangeDeliversStateChange: a catalogue ON_CHANGE
// subscription sends its snapshot and sync, then exactly one notification
// for the entry whose link moved, carrying the moved leaf alone, and
// nothing while the state is stable or when another interface moves.
func TestCatalogServer_OnChangeDeliversStateChange(t *testing.T) {
	dev, addr, cleanup := startTestCatalogServer(t)
	defer cleanup()
	c := openOnChange(t, addr, gnmipb.Encoding_PROTO, "/interfaces/interface[name=TestIf2]/state/oper-status")
	defer c.close()

	snap := c.untilSync(t)
	if len(snap) != 1 || len(snap[0].GetUpdate().GetUpdate()) != 1 {
		t.Fatalf("snapshot: %v", snap)
	}
	if got := leafValues(snap[0])["/state/oper-status"]; got != "UP" {
		t.Fatalf("snapshot oper-status %q, want UP", got)
	}

	state := dev.metricsCycler.ifCounters.Load().State()
	// Another interface moving is not this subscription's business.
	if ok, evt := setLinkVisible(state, 1, OperDown); ok {
		state.Broadcast(evt)
	}
	if resp := c.within(t, 300*time.Millisecond); resp != nil {
		t.Fatalf("update for an interface the path does not name: %v", resp)
	}

	ok, evt := setLinkVisible(state, 2, OperDown)
	if !ok {
		t.Fatal("link did not move")
	}
	state.Broadcast(evt)
	resp := c.within(t, time.Second)
	if resp == nil {
		t.Fatal("no update within 1s of the link moving")
	}
	if p := pathToString(resp.GetUpdate().GetPrefix()); !strings.Contains(p, "interface[name=TestIf2]") {
		t.Fatalf("update prefix %q, want the TestIf2 entry", p)
	}
	vals := leafValues(resp)
	if len(vals) != 1 || vals["/state/oper-status"] != "DOWN" {
		t.Fatalf("update leaves %v, want oper-status DOWN alone", vals)
	}
	if extra := c.within(t, 500*time.Millisecond); extra != nil {
		t.Fatalf("a second update while the state is stable: %v", extra)
	}

	// Admin down on a link that is already down moves admin alone; an
	// oper-status subscription has nothing to say about it.
	for _, e := range state.ApplyAdminStatus(2, AdminDown) {
		state.Broadcast(e)
	}
	if extra := c.within(t, 300*time.Millisecond); extra != nil {
		t.Fatalf("oper-status subscription fired on an admin-only change: %v", extra)
	}

	// A wildcard subscription fires once, for the entry that moved.
	w := openOnChange(t, addr, gnmipb.Encoding_PROTO, "/interfaces/interface[name=*]/state/oper-status")
	defer w.close()
	if snap := w.untilSync(t); len(snap) != 2 {
		t.Fatalf("wildcard snapshot responses %d, want one per interface", len(snap))
	}
	ok, evt = setLinkVisible(state, 1, OperUp)
	if !ok {
		t.Fatal("link 1 did not move")
	}
	state.Broadcast(evt)
	resp = w.within(t, time.Second)
	if resp == nil {
		t.Fatal("wildcard: no update within 1s")
	}
	if p := pathToString(resp.GetUpdate().GetPrefix()); !strings.Contains(p, "interface[name=TestIf1]") {
		t.Fatalf("wildcard update prefix %q, want the TestIf1 entry", p)
	}
	if extra := w.within(t, 300*time.Millisecond); extra != nil {
		t.Fatalf("wildcard: a second entry fired for one interface's change: %v", extra)
	}
}

// TestCatalogServer_OnChangeRefusals: a catalogue ON_CHANGE subscription
// covering a counter or a sensor leaf is refused with InvalidArgument and
// the message the legacy resolver sends for the same class.
func TestCatalogServer_OnChangeRefusals(t *testing.T) {
	_, addr, cleanup := startTestCatalogServer(t)
	defer cleanup()
	for _, c := range []struct{ path, want string }{
		{"/interfaces/interface/state", `counter leaf "state/counters/in-octets"; counters are continuously varying`},
		{"/interfaces/interface/state/counters", `counter leaf "state/counters/in-octets"`},
		{"/components", `sensor leaf "instant", a reading that changes continuously`},
	} {
		cl := openOnChange(t, addr, gnmipb.Encoding_PROTO, c.path)
		err := cl.err(t)
		cl.close()
		if status.Code(err) != codes.InvalidArgument || !strings.Contains(err.Error(), c.want) {
			t.Errorf("%s: %v, want InvalidArgument containing %q", c.path, err, c.want)
		}
	}
}

// TestCatalogServer_OnChangeStaticLeavesSnapshotOnly: a path covering
// only inventory leaves gets its snapshot and sync and never an update.
func TestCatalogServer_OnChangeStaticLeavesSnapshotOnly(t *testing.T) {
	dev, addr, cleanup := startTestCatalogServer(t)
	defer cleanup()
	c := openOnChange(t, addr, gnmipb.Encoding_PROTO, "/components/component[name=*]/state/serial-no")
	defer c.close()
	if snap := c.untilSync(t); len(snap) == 0 {
		t.Fatal("no snapshot for inventory leaves")
	}
	state := dev.metricsCycler.ifCounters.Load().State()
	if ok, evt := setLinkVisible(state, 2, OperDown); ok {
		state.Broadcast(evt)
	}
	if resp := c.within(t, 300*time.Millisecond); resp != nil {
		t.Fatalf("inventory leaf updated on a link change: %v", resp)
	}
}

// TestCatalogServer_OnChangeMixedWithLegacy: one stream carries a
// catalogue subscription and a legacy one on the same device; both get
// their snapshot and both fire on the change.
func TestCatalogServer_OnChangeMixedWithLegacy(t *testing.T) {
	dev, addr, cleanup := startTestCatalogServer(t)
	defer cleanup()
	// The minimal catalogue serves oper-status but not admin-status, so
	// the second path falls to the legacy resolver.
	c := openOnChange(t, addr, gnmipb.Encoding_PROTO,
		"/interfaces/interface[name=TestIf2]/state/oper-status",
		"/interfaces/interface[name=TestIf2]/state/admin-status")
	defer c.close()
	if snap := c.untilSync(t); len(snap) != 2 {
		t.Fatalf("snapshot responses %d, want 2", len(snap))
	}
	state := dev.metricsCycler.ifCounters.Load().State()
	evts := state.ApplyAdminStatus(2, AdminDown)
	for _, e := range evts {
		state.Broadcast(e)
	}
	got := 0
	for i := 0; i < 2; i++ {
		if resp := c.within(t, time.Second); resp != nil {
			got++
		}
	}
	if got != 2 {
		t.Fatalf("%d updates after admin down, want one catalogue (oper) and one legacy (admin)", got)
	}
}

// TestMX10004OnChangeCarriesCatalogueShape: on the shipped MX10004
// catalogue an ON_CHANGE update is one notification per entry with the
// Juniper header extension, the moved leaf and the entry's always leaves,
// as a SAMPLE tick is shaped.
func TestMX10004OnChangeCarriesCatalogueShape(t *testing.T) {
	cats, err := loadEmbeddedGnmiCatalogs()
	if err != nil {
		t.Fatal(err)
	}
	_, dev, addr, cleanup := startTestGnmiServerWithDevice(t, cats["juniper_mx10004"], newMX10004TestDevice(t, 2))
	defer cleanup()
	c := openOnChange(t, addr, gnmipb.Encoding_PROTO, "/interfaces/interface[name=TestIf1]/state/oper-status")
	defer c.close()
	c.untilSync(t)
	state := dev.metricsCycler.ifCounters.Load().State()
	ok, evt := setLinkVisible(state, 1, OperDown)
	if !ok {
		t.Fatal("link did not move")
	}
	state.Broadcast(evt)
	resp := c.within(t, time.Second)
	if resp == nil {
		t.Fatal("no update within 1s")
	}
	if len(resp.GetExtension()) == 0 {
		t.Fatalf("catalogue update without the vendor extension: %v", resp)
	}
	// The moved leaf, plus the entry's always leaves (name, init-time and
	// the like), which ride along as they do on a SAMPLE tick; no other
	// state leaf and no counter.
	vals := leafValues(resp)
	if vals["/state/oper-status"] != "DOWN" {
		t.Fatalf("update leaves %v, want oper-status DOWN", vals)
	}
	for p := range vals {
		if strings.Contains(p, "counters") || p == "/state/admin-status" || p == "/state/last-change" {
			t.Fatalf("update carries %s, which did not move: %v", p, vals)
		}
	}
}
