/*
 * Copyright 2026 Ronny Trommer <ronny@no42.org>
 * SPDX-License-Identifier: Apache-2.0
 */

package main

import (
	"context"
	"fmt"
	"net"
	"os"
	"strings"
	"testing"
	"time"
)

// netconfTestClient is a minimal NETCONF client over net.Pipe.
type netconfTestClient struct {
	t      *testing.T
	conn   net.Conn
	f      *netconfFramer
	hello  string
	done   chan error
	msgSeq int
}

func startNetconfTestClient(t *testing.T, id uint32, reg *netconfSessionRegistry, clientBase11 bool, cfg ...func(*netconfSession)) (*netconfTestClient, *netconfSession) {
	t.Helper()
	srv, cli := net.Pipe()
	sess := newNetconfSession(id, nil, srv, reg)
	for _, f := range cfg {
		f(sess)
	}
	done := make(chan error, 1)
	go func() { done <- sess.Serve(context.Background()) }()
	t.Cleanup(func() { _ = cli.Close(); sess.close() })

	c := &netconfTestClient{t: t, conn: cli, f: newNetconfFramer(cli, cli), done: done}
	_ = cli.SetDeadline(time.Now().Add(10 * time.Second))
	h, err := c.f.ReadMessage()
	if err != nil {
		t.Fatalf("read server hello: %v", err)
	}
	c.hello = string(h)
	caps := `<capability>urn:ietf:params:netconf:base:1.0</capability>`
	if clientBase11 {
		caps += `<capability>urn:ietf:params:netconf:base:1.1</capability>`
	}
	ch := `<hello xmlns="urn:ietf:params:xml:ns:netconf:base:1.0"><capabilities>` + caps + `</capabilities></hello>`
	if err := c.f.WriteMessage([]byte(ch)); err != nil {
		t.Fatalf("write client hello: %v", err)
	}
	if clientBase11 && strings.Contains(c.hello, netconfBase11) {
		c.f.chunked = true
	}
	return c, sess
}

// rpc sends one request with a fresh message-id and returns the reply.
func (c *netconfTestClient) rpc(op string) string {
	c.t.Helper()
	c.msgSeq++
	return c.rawRPC(fmt.Sprintf(`<rpc xmlns="urn:ietf:params:xml:ns:netconf:base:1.0" message-id="m%d">%s</rpc>`, c.msgSeq, op))
}

func (c *netconfTestClient) rawRPC(msg string) string {
	c.t.Helper()
	if err := c.f.WriteMessage([]byte(msg)); err != nil {
		c.t.Fatalf("write rpc: %v", err)
	}
	r, err := c.f.ReadMessage()
	if err != nil {
		c.t.Fatalf("read reply: %v", err)
	}
	return string(r)
}

func (c *netconfTestClient) waitDone() {
	c.t.Helper()
	select {
	case err := <-c.done:
		if err != nil {
			c.t.Fatalf("Serve returned %v", err)
		}
	case <-time.After(10 * time.Second):
		c.t.Fatal("session did not end")
	}
}

func netconfTestSub(xpath string) string {
	return string(iosxeSubReq("yp:yang-push", xpath, iosxeTestDamp0))
}

const netconfTestOperXPath = iosxeTestIfaceNm + "[name='GigabitEthernet1/0/1']/oper-status"

func TestNetconfHelloAdvertisesCat9300Capabilities(t *testing.T) {
	raw, err := os.ReadFile("testdata/netconf/cat9300-hello-caps.txt")
	if err != nil {
		t.Fatal(err)
	}
	have := map[string]bool{}
	for _, l := range strings.Split(string(raw), "\n") {
		have[strings.TrimSpace(l)] = true
	}
	hello := string(netconfServerHello(7))
	for _, c := range netconfHelloCapabilities {
		if !have[c] {
			t.Errorf("capability not in the capture: %s", c)
		}
		if !strings.Contains(hello, "<capability>"+strings.ReplaceAll(c, "&", "&amp;")+"</capability>") {
			t.Errorf("capability missing from hello: %s", c)
		}
	}
	if len(netconfHelloCapabilities) != 9 {
		t.Errorf("hello advertises %d capabilities, want 9", len(netconfHelloCapabilities))
	}
	for _, never := range []string{"interfaces-oper", "yang-library"} {
		if strings.Contains(hello, never) {
			t.Errorf("hello must not mention %s", never)
		}
	}
	for _, want := range []string{
		"urn:ietf:params:netconf:base:1.0", "urn:ietf:params:netconf:base:1.1",
		"urn:ietf:params:netconf:capability:notification:1.0", "urn:ietf:params:netconf:capability:interleave:1.0",
		"<session-id>7</session-id>",
	} {
		if !strings.Contains(hello, want) {
			t.Errorf("hello lacks %s", want)
		}
	}
}

func TestNetconfChunkedAfterBase11(t *testing.T) {
	for _, base11 := range []bool{true, false} {
		c, sess := startNetconfTestClient(t, 1, newNetconfSessionRegistry(), base11)
		reply := c.rpc(`<close-session/>`)
		if !strings.Contains(reply, "<ok/>") {
			t.Fatalf("base11=%v reply %q", base11, reply)
		}
		if sess.framer.chunked != base11 {
			t.Errorf("base11=%v: session chunked=%v", base11, sess.framer.chunked)
		}
		c.waitDone()
	}
}

func TestNetconfRFC8639NamespaceUnknown(t *testing.T) {
	c, _ := startNetconfTestClient(t, 1, newNetconfSessionRegistry(), true)
	r := c.rpc(`<establish-subscription xmlns="urn:ietf:params:xml:ns:yang:ietf-subscribed-notifications"/>`)
	for _, want := range []string{`message-id="m1"`, "<error-type>protocol</error-type>", "<error-tag>unknown-namespace</error-tag>", "<bad-element>establish-subscription</bad-element>",
		"<error-path>\n    /rpc\n  </error-path>", "<bad-namespace>urn:ietf:params:xml:ns:yang:ietf-subscribed-notifications</bad-namespace>"} {
		if !strings.Contains(r, want) {
			t.Errorf("reply lacks %s: %s", want, r)
		}
	}
}

func TestNetconfDeleteSubscription(t *testing.T) {
	c, sess := startNetconfTestClient(t, 1, newNetconfSessionRegistry(), true)
	r := c.rpc(netconfTestSub(netconfTestOperXPath))
	if !strings.Contains(r, "notif-bis:ok</subscription-result>") || !strings.Contains(r, ">2147483648</subscription-id>") {
		t.Fatalf("establish reply: %s", r)
	}
	// The sub is appended just after the reply is written.
	for i := 0; i < 500 && len(sess.Subs()) != 1; i++ {
		time.Sleep(10 * time.Millisecond)
	}
	if len(sess.Subs()) != 1 {
		t.Fatalf("subs = %d", len(sess.Subs()))
	}
	del := func(id string) string {
		return c.rpc(`<delete-subscription xmlns="urn:ietf:params:xml:ns:yang:ietf-event-notifications"><subscription-id>` + id + `</subscription-id></delete-subscription>`)
	}
	if r := del("2147483648"); !strings.Contains(r, "notif-bis:ok</subscription-result>") {
		t.Errorf("delete known: %s", r)
	}
	if len(sess.Subs()) != 0 {
		t.Errorf("sub not removed")
	}
	for _, id := range []string{"2147483648", "5"} {
		if r := del(id); !strings.Contains(r, "notif-bis:error-no-such-subscription</subscription-result>") {
			t.Errorf("delete %s: %s", id, r)
		}
	}
}

func TestNetconfCloseSession(t *testing.T) {
	reg := newNetconfSessionRegistry()
	c, _ := startNetconfTestClient(t, 1, reg, true)
	r := c.rpc(`<close-session/>`)
	if !strings.Contains(r, `message-id="m1"`) || !strings.Contains(r, "<ok/>") {
		t.Fatalf("reply: %s", r)
	}
	c.waitDone()
	if _, err := c.f.ReadMessage(); err == nil {
		t.Error("connection still open after close-session")
	}
	if reg.kill(1) {
		t.Error("session still registered")
	}
}

func TestNetconfKillSession(t *testing.T) {
	reg := newNetconfSessionRegistry()
	victim, _ := startNetconfTestClient(t, 1, reg, true)
	killer, _ := startNetconfTestClient(t, 2, reg, true)
	// Registration happens in Serve, which races the helper return. A
	// completed RPC on each session proves both are registered.
	victim.rpc(netconfTestSub(netconfTestOperXPath))

	r := killer.rpc(`<kill-session><session-id>1</session-id></kill-session>`)
	if !strings.Contains(r, "<ok/>") {
		t.Fatalf("kill other: %s", r)
	}
	victim.waitDone()
	r = killer.rpc(`<kill-session><session-id>2</session-id></kill-session>`)
	for _, want := range []string{"<error-type>protocol</error-type>", "<error-tag>invalid-value</error-tag>", "<bad-element>session-id</bad-element>\n</error-info>",
		`<error-info xmlns="urn:ietf:params:xml:ns:netconf:base:1.0" xmlns:nc="urn:ietf:params:xml:ns:netconf:base:1.0">`} {
		if !strings.Contains(r, want) {
			t.Errorf("kill own lacks %s: %s", want, r)
		}
	}
	r = killer.rpc(`<kill-session><session-id>99</session-id></kill-session>`)
	if !strings.Contains(r, "<error-tag>invalid-value</error-tag>") {
		t.Errorf("kill unknown: %s", r)
	}
	reg.closeAll()
	killer.waitDone()
}

func TestNetconfSubscriptionCapPerSession(t *testing.T) {
	c, sess := startNetconfTestClient(t, 1, newNetconfSessionRegistry(), true)
	sub := netconfTestSub(netconfTestOperXPath)
	for i := 0; i < netconfMaxSubsPerSession; i++ {
		if r := c.rpc(sub); !strings.Contains(r, "notif-bis:ok</subscription-result>") {
			t.Fatalf("subscription %d: %s", i+1, r)
		}
	}
	r := c.rpc(sub)
	if !strings.Contains(r, "notif-bis:error-other</subscription-result>") || strings.Contains(r, "<subscription-id") {
		t.Errorf("subscription 257: %s", r)
	}
	if n := len(sess.Subs()); n != netconfMaxSubsPerSession {
		t.Errorf("subs = %d", n)
	}
}

func TestNetconfUnsupportedOperation(t *testing.T) {
	c, _ := startNetconfTestClient(t, 1, newNetconfSessionRegistry(), true)
	for _, op := range []string{
		`<get/>`,
		`<create-subscription xmlns="urn:ietf:params:xml:ns:netconf:notification:1.0"/>`,
		`<edit-config/>`,
	} {
		r := c.rpc(op)
		if !strings.Contains(r, "<error-type>protocol</error-type>") || !strings.Contains(r, "<error-tag>operation-not-supported</error-tag>") {
			t.Errorf("%s: %s", op, r)
		}
	}
}

func TestNetconfMissingMessageID(t *testing.T) {
	c, _ := startNetconfTestClient(t, 1, newNetconfSessionRegistry(), true)
	r := c.rawRPC(`<rpc xmlns="urn:ietf:params:xml:ns:netconf:base:1.0"><get/></rpc>`)
	for _, want := range []string{"<error-type>rpc</error-type>", "<error-tag>missing-attribute</error-tag>", "<bad-attribute>message-id</bad-attribute>"} {
		if !strings.Contains(r, want) {
			t.Errorf("reply lacks %s: %s", want, r)
		}
	}
	// The session stays usable.
	if r := c.rpc(`<get/>`); !strings.Contains(r, "operation-not-supported") {
		t.Errorf("session unusable after missing message-id: %s", r)
	}
}

func TestNetconfSubscriptionIDsStartAt2147483648(t *testing.T) {
	reg := newNetconfSessionRegistry()
	if got := reg.nextSubID(); got != 2147483648 {
		t.Fatalf("first id = %d", got)
	}
	c, sess := startNetconfTestClient(t, 1, reg, true)
	hooked := make(chan uint32, 4)
	sess.onSubscribe = func(sub *netconfSub) { hooked <- sub.id }
	r := c.rpc(netconfTestSub(netconfTestOperXPath))
	if !strings.Contains(r, ">2147483649</subscription-id>") {
		t.Errorf("second id: %s", r)
	}
	r = c.rpc(netconfTestSub(netconfTestOperXPath))
	if !strings.Contains(r, ">2147483650</subscription-id>") {
		t.Errorf("third id: %s", r)
	}
	for _, want := range []uint32{2147483649, 2147483650} {
		select {
		case got := <-hooked:
			if got != want {
				t.Errorf("onSubscribe saw %d, want %d", got, want)
			}
		case <-time.After(5 * time.Second):
			t.Fatal("onSubscribe not called")
		}
	}
}

func TestNetconfOnUnsubscribeOnDelete(t *testing.T) {
	got := make(chan uint32, 4)
	c, _ := startNetconfTestClient(t, 1, newNetconfSessionRegistry(), true, func(s *netconfSession) {
		s.onUnsubscribe = func(sub *netconfSub) { got <- sub.id }
	})
	c.rpc(netconfTestSub(netconfTestOperXPath))
	c.rpc(`<delete-subscription xmlns="urn:ietf:params:xml:ns:yang:ietf-event-notifications"><subscription-id>2147483648</subscription-id></delete-subscription>`)
	select {
	case id := <-got:
		if id != 2147483648 {
			t.Errorf("unsubscribed %d", id)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("onUnsubscribe not called after delete")
	}
	// A failed delete must not call the hook.
	c.rpc(`<delete-subscription xmlns="urn:ietf:params:xml:ns:yang:ietf-event-notifications"><subscription-id>9</subscription-id></delete-subscription>`)
	select {
	case id := <-got:
		t.Errorf("unexpected unsubscribe %d", id)
	case <-time.After(50 * time.Millisecond):
	}
}

func TestNetconfOnUnsubscribeOnExit(t *testing.T) {
	for _, how := range []string{"close-session", "kill-session", "eof"} {
		t.Run(how, func(t *testing.T) {
			reg := newNetconfSessionRegistry()
			got := make(chan uint32, 4)
			c, _ := startNetconfTestClient(t, 1, reg, true, func(s *netconfSession) {
				s.onUnsubscribe = func(sub *netconfSub) { got <- sub.id }
			})
			c.rpc(netconfTestSub(netconfTestOperXPath))
			c.rpc(netconfTestSub(netconfTestOperXPath))
			switch how {
			case "close-session":
				c.rpc(`<close-session/>`)
			case "kill-session":
				k, _ := startNetconfTestClient(t, 2, reg, true)
				k.rpc(`<get/>`)
				if r := k.rpc(`<kill-session><session-id>1</session-id></kill-session>`); !strings.Contains(r, "<ok/>") {
					t.Fatalf("kill: %s", r)
				}
			case "eof":
				_ = c.conn.Close()
			}
			c.waitDone()
			for _, want := range []uint32{2147483648, 2147483649} {
				select {
				case id := <-got:
					if id != want {
						t.Errorf("unsubscribed %d, want %d", id, want)
					}
				case <-time.After(5 * time.Second):
					t.Fatalf("onUnsubscribe missing for %d", want)
				}
			}
		})
	}
}

func TestNetconfOnStartContextEnds(t *testing.T) {
	for _, how := range []string{"close-session", "kill-session"} {
		t.Run(how, func(t *testing.T) {
			reg := newNetconfSessionRegistry()
			ctxCh := make(chan context.Context, 1)
			c, _ := startNetconfTestClient(t, 1, reg, true, func(s *netconfSession) {
				s.onStart = func(ctx context.Context) { ctxCh <- ctx }
			})
			c.rpc(`<get/>`) // the hook has run before the first RPC is handled
			ctx := <-ctxCh
			if ctx.Err() != nil {
				t.Fatal("ctx done too early")
			}
			if how == "close-session" {
				c.rpc(`<close-session/>`)
			} else {
				k, _ := startNetconfTestClient(t, 2, reg, true)
				k.rpc(`<kill-session><session-id>1</session-id></kill-session>`)
			}
			c.waitDone()
			select {
			case <-ctx.Done():
			case <-time.After(5 * time.Second):
				t.Fatal("onStart ctx not done after session end")
			}
		})
	}
}

func TestNetconfSubscriptionVisibleAfterReply(t *testing.T) {
	seen := make(chan int, 1)
	var sess *netconfSession
	c, s := startNetconfTestClient(t, 1, newNetconfSessionRegistry(), true, func(s *netconfSession) {
		s.onSubscribe = func(*netconfSub) { seen <- len(sess.Subs()) }
	})
	sess = s
	req := `<rpc xmlns="urn:ietf:params:xml:ns:netconf:base:1.0" message-id="v1">` + netconfTestSub(netconfTestOperXPath) + `</rpc>`
	if err := c.f.WriteMessage([]byte(req)); err != nil {
		t.Fatal(err)
	}
	// net.Pipe blocks the server's reply write until we read it, so the
	// subscription must not be visible yet.
	time.Sleep(100 * time.Millisecond)
	if n := len(sess.Subs()); n != 0 {
		t.Fatalf("subscription visible before its reply was written (%d)", n)
	}
	if _, err := c.f.ReadMessage(); err != nil {
		t.Fatal(err)
	}
	select {
	case n := <-seen:
		if n != 1 {
			t.Errorf("onSubscribe saw %d subs, want 1", n)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("onSubscribe not called")
	}
}
