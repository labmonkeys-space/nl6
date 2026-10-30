/*
 * Copyright 2026 Ronny Trommer <ronny@no42.org>
 * SPDX-License-Identifier: Apache-2.0
 */

package main

import (
	"bufio"
	"context"
	"io"
	"net"
	"regexp"
	"strings"
	"testing"
	"time"
)

const junosTestVersion = "24.2R1.17"

// junosTestClient drives a session built by newJunosNetconfSession and reads
// its raw bytes, framing included.
type junosTestClient struct {
	t     *testing.T
	conn  net.Conn
	br    *bufio.Reader
	sess  *netconfSession
	done  chan struct{}
	hello string
}

func startJunosTestClient(t *testing.T, dev *DeviceSimulator, id uint32, reg *netconfSessionRegistry, clientHello string) *junosTestClient {
	t.Helper()
	srv, cli := net.Pipe()
	sess := newJunosNetconfSession(id, dev, srv, reg, "admin")
	c := &junosTestClient{t: t, conn: cli, br: bufio.NewReader(cli), sess: sess, done: make(chan struct{})}
	go func() { _ = sess.Serve(context.Background()); close(c.done) }()
	t.Cleanup(func() { _ = cli.Close(); sess.close(); <-c.done })
	_ = cli.SetDeadline(time.Now().Add(10 * time.Second))
	c.hello = c.readFramed()
	c.send(clientHello)
	return c
}

const junosClientHello10 = `<hello xmlns="urn:ietf:params:xml:ns:netconf:base:1.0"><capabilities><capability>urn:ietf:params:netconf:base:1.0</capability></capabilities></hello>`

func (c *junosTestClient) send(msg string) {
	c.t.Helper()
	if _, err := io.WriteString(c.conn, msg+netconfEOM); err != nil {
		c.t.Fatalf("write: %v", err)
	}
}

// readFramed returns the next message with its trailing end-of-message marker.
func (c *junosTestClient) readFramed() string {
	c.t.Helper()
	var sb strings.Builder
	for !strings.HasSuffix(sb.String(), netconfEOM) {
		b, err := c.br.ReadByte()
		if err != nil {
			c.t.Fatalf("read: %v (got %q)", err, sb.String())
		}
		sb.WriteByte(b)
	}
	return sb.String()
}

func junosRPCXML(id, body string) string {
	return `<rpc message-id="` + id + `" xmlns="urn:ietf:params:xml:ns:netconf:base:1.0">` + body + `</rpc>`
}

func TestJunosSessionHelloAndClose(t *testing.T) {
	dev := newJunosTestDevice(t)
	c := startJunosTestClient(t, dev, 7, newNetconfSessionRegistry(), junosClientHello10)
	if want := string(junosServerHello(7, "admin")) + netconfEOM; c.hello != want {
		t.Fatalf("hello\n got: %q\nwant: %q", c.hello, want)
	}
	if strings.HasPrefix(c.hello, "\n") {
		t.Fatal("hello must not start with a newline")
	}
	c.send(junosRPCXML("101", "<close-session/>"))
	if got, want := c.readFramed(), string(junosOKReply(junosTestVersion, "101"))+netconfEOM; got != want {
		t.Fatalf("close-session reply\n got: %q\nwant: %q", got, want)
	}
	rest, err := io.ReadAll(c.br)
	if err != nil {
		t.Fatalf("read to EOF: %v", err)
	}
	if !regexp.MustCompile(`^\n<!-- session end at \d{4}-\d\d-\d\d \d\d:\d\d:\d\d UTC -->\n$`).Match(rest) {
		t.Fatalf("trailer = %q", rest)
	}
}

func TestJunosSessionIgnoresBase11(t *testing.T) {
	dev := newJunosTestDevice(t)
	h := `<hello xmlns="urn:ietf:params:xml:ns:netconf:base:1.0"><capabilities><capability>urn:ietf:params:netconf:base:1.0</capability><capability>urn:ietf:params:netconf:base:1.1</capability></capabilities></hello>`
	c := startJunosTestClient(t, dev, 1, newNetconfSessionRegistry(), h)
	c.send(junosRPCXML("101", "<get-configuration/>"))
	got := c.readFramed()
	if !strings.HasSuffix(got, "</rpc-reply>\n"+netconfEOM) || strings.Contains(got, "\n#") {
		t.Fatalf("reply is not EOM framed: %q", got)
	}
	if c.sess.framer.chunked {
		t.Fatal("framer switched to chunked")
	}
}

func TestJunosSessionRPCTable(t *testing.T) {
	dev := newJunosTestDevice(t)
	const (
		streamsGet = `<get><filter type="subtree"><netconf xmlns="urn:ietf:params:xml:ns:netmod:notification"><streams><stream/></streams></netconf></filter></get>`
		stateGet   = `<get><filter type="subtree"><netconf-state xmlns="urn:ietf:params:xml:ns:yang:ietf-netconf-monitoring"><capabilities/></netconf-state></filter></get>`
		ifStateGet = `<get><filter type="subtree"><interfaces-state xmlns="urn:ietf:params:xml:ns:yang:ietf-interfaces"/></filter></get>`
	)
	sub := func(stream string) string {
		return `<create-subscription xmlns="urn:ietf:params:xml:ns:netconf:notification:1.0">` + stream + `</create-subscription>`
	}
	c := startJunosTestClient(t, dev, 1, newNetconfSessionRegistry(), junosClientHello10)
	at := c.sess.startedAt
	v := junosTestVersion
	rows := []struct {
		name, body string
		want       []byte
		id         string
	}{
		{"create-subscription no stream", sub(""), junosOKReply(v, "101"), ""},
		{"create-subscription NETCONF", sub("<stream>NETCONF</stream>"), junosOKReply(v, "101"), ""},
		{name: "create-subscription startTime", body: sub("<startTime>2026-01-01T00:00:00Z</startTime>"), want: junosSyntaxError(v, "101", "startTime", 1)},
		{name: "create-subscription filter", body: sub(`<filter type="subtree"/>`), want: junosSyntaxError(v, "101", "filter", 1)},
		{name: "message-id escaped", body: "<bogus-rpc/>", id: "a&amp;b", want: junosSyntaxError(v, "a&b", "bogus-rpc", 1)},
		{"get streams", streamsGet, junosStreamsReply(v, "101"), ""},
		{"get netconf-state", stateGet, junosNetconfStateReply(v, "101"), ""},
		{"get no filter", "<get/>", junosGetReply(dev, v, "101", at), ""},
		{"get-configuration", "<get-configuration/>", junosGetConfigurationReply(dev, v, "101", at), ""},
		{"establish-subscription draft", `<establish-subscription xmlns="urn:ietf:params:xml:ns:yang:ietf-event-notifications"/>`, junosSyntaxError(v, "101", "establish-subscription", 2), ""},
		{"establish-subscription 8639", `<establish-subscription xmlns="urn:ietf:params:xml:ns:yang:ietf-subscribed-notifications"/>`, junosSyntaxError(v, "101", "establish-subscription", 2), ""},
		{"get interfaces-state", ifStateGet, []byte(strings.ReplaceAll(junosFixture(t, "syntax-error-ietfif.xml"), junosCaptureVersion, v)), ""},
		{"unknown op", "<bogus-rpc/>", junosSyntaxError(v, "101", "bogus-rpc", 1), ""},
	}
	for _, row := range rows {
		t.Run(row.name, func(t *testing.T) {
			id := row.id
			if id == "" {
				id = "101"
			}
			c.send(junosRPCXML(id, row.body))
			if got, want := c.readFramed(), string(row.want)+netconfEOM; got != want {
				t.Fatalf("reply\n got: %q\nwant: %q", got, want)
			}
		})
	}
	if n := len(c.sess.Subs()); n != 1 {
		t.Fatalf("subscriptions held = %d, want 1 after two create-subscription", n)
	}
	c.sess.ev.mu.Lock()
	n := len(c.sess.ev.subs)
	c.sess.ev.mu.Unlock()
	if n != 1 {
		t.Fatalf("event subscriptions = %d, want 1", n)
	}
}

func TestJunosSessionKillSession(t *testing.T) {
	dev := newJunosTestDevice(t)
	reg := newNetconfSessionRegistry()
	victim := startJunosTestClient(t, dev, 1, reg, junosClientHello10)
	killer := startJunosTestClient(t, dev, 2, reg, junosClientHello10)
	// Commit time is per device: two sessions on one registry agree.
	commitRe := regexp.MustCompile(`junos:commit-seconds="\d+"`)
	victim.send(junosRPCXML("100", "<get/>"))
	killer.send(junosRPCXML("100", "<get/>"))
	vc, kc := commitRe.FindString(victim.readFramed()), commitRe.FindString(killer.readFramed())
	if vc == "" || vc != kc {
		t.Fatalf("commit-seconds differ between sessions: %q vs %q", vc, kc)
	}
	if !victim.sess.startedAt.Equal(killer.sess.startedAt) {
		t.Fatal("sessions on one registry report different commit times")
	}
	// The victim's Serve registers before it reads the client hello, which
	// the helper already sent, so the registry holds both.
	killer.send(junosRPCXML("101", "<kill-session><session-id>1</session-id></kill-session>"))
	if got, want := killer.readFramed(), string(junosOKReply(junosTestVersion, "101"))+netconfEOM; got != want {
		t.Fatalf("kill reply\n got: %q\nwant: %q", got, want)
	}
	select {
	case <-victim.done:
	case <-time.After(5 * time.Second):
		t.Fatal("killed session still running")
	}
	killer.send(junosRPCXML("102", "<kill-session><session-id>99</session-id></kill-session>"))
	if got, want := killer.readFramed(), string(junosSyntaxError(junosTestVersion, "102", "session-id", 1))+netconfEOM; got != want {
		t.Fatalf("bad id reply\n got: %q\nwant: %q", got, want)
	}
}

func TestJunosSessionCloseHasNoGapBeforeTrailer(t *testing.T) {
	dev := newJunosTestDevice(t)
	reply := string(junosOKReply(junosTestVersion, "101")) + netconfEOM
	endRe := regexp.MustCompile(`^\n<!-- session end at \d{4}-\d\d-\d\d \d\d:\d\d:\d\d UTC -->\n$`)
	for i := 0; i < 50; i++ {
		c := startJunosTestClient(t, dev, 1, newNetconfSessionRegistry(), junosClientHello10)
		c.send(junosRPCXML("100", "<create-subscription xmlns=\"urn:ietf:params:xml:ns:netconf:notification:1.0\"/>"))
		_ = c.readFramed()
		sub := c.sess.Subs()[0]
		push := "<notification>push</notification>"
		go func() {
			c.sess.enqueue(sub, []byte(push))
		}()
		c.send(junosRPCXML("101", "<close-session/>"))
		rest, err := io.ReadAll(c.br)
		if err != nil {
			t.Fatalf("read to EOF: %v", err)
		}
		got := string(rest)
		// The push may precede the reply or be dropped on close, never sit
		// between the reply and the trailer.
		k := strings.Index(got, reply)
		if k < 0 {
			t.Fatalf("iteration %d: no close-session reply in %q", i, got)
		}
		if pre := got[:k]; pre != "" && pre != push+netconfEOM {
			t.Fatalf("iteration %d: unexpected bytes before the reply: %q", i, pre)
		}
		if !endRe.MatchString(got[k+len(reply):]) {
			t.Fatalf("iteration %d: bytes after the reply are not exactly the trailer: %q", i, got[k+len(reply):])
		}
	}
}

func TestIOSXESessionUnchanged(t *testing.T) {
	dev, _ := newNetconfTestDevice(t)
	srv, cli := net.Pipe()
	sess := newIOSXENetconfSession(1, dev, srv, newNetconfSessionRegistry())
	finished := make(chan struct{})
	go func() { _ = sess.Serve(context.Background()); close(finished) }()
	t.Cleanup(func() { _ = cli.Close(); sess.close(); <-finished })
	_ = cli.SetDeadline(time.Now().Add(10 * time.Second))
	got, err := newNetconfFramer(cli, cli).ReadMessage()
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != string(netconfServerHello(1)) {
		t.Fatalf("hello changed:\n%q", got)
	}
	if sess.base10Only || sess.rpc != nil || sess.hello != nil {
		t.Fatal("IOS XE session installed a Junos hook")
	}
}
