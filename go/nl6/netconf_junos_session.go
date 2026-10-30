/*
 * Copyright 2026 Ronny Trommer <ronny@no42.org>
 * SPDX-License-Identifier: Apache-2.0
 */

package main

import (
	"bytes"
	"encoding/xml"
	"fmt"
	"io"
	"slices"
	"time"
)

const (
	junosNotificationNS = "urn:ietf:params:xml:ns:netconf:notification:1.0"
	junosNetmodNS       = "urn:ietf:params:xml:ns:netmod:notification"
	junosMonitoringNS   = "urn:ietf:params:xml:ns:yang:ietf-netconf-monitoring"
	junosRFC8639NS      = "urn:ietf:params:xml:ns:yang:ietf-subscribed-notifications"
)

// newJunosNetconfSession builds a session that speaks the Junos dialect:
// the Junos hello, base:1.0 framing only, and the Junos replies. Its single
// notification stream is fed by the same dispatcher as the IOS XE session.
// onEvent stays nil until the Junos notification renderer is installed.
func newJunosNetconfSession(id uint32, dev *DeviceSimulator, rw io.ReadWriter, reg *netconfSessionRegistry, user string) *netconfSession {
	s := newNetconfSession(id, dev, rw, reg)
	s.startedAt = time.Now()
	ev := &netconfEvents{ready: make(chan struct{})}
	if manager != nil {
		ev.sent, ev.dropped = &manager.netconfNotificationsSent, &manager.netconfNotificationsDropped
	} else {
		ev.sent, ev.dropped = new(uint64), new(uint64)
	}
	s.ev = ev
	s.onStart = s.startEvents
	s.onEnd = func() {
		if d := ev.disp.Swap(nil); d != nil {
			d.unregister(s)
			reg.releaseDispatcher(d)
		}
	}
	s.onUnsubscribe = func(sub *netconfSub) {
		sub.deleted.Store(true)
		ev.mu.Lock()
		if i := slices.Index(ev.subs, sub); i >= 0 {
			ev.subs = slices.Delete(ev.subs, i, i+1)
		}
		ev.mu.Unlock()
	}
	s.base10Only = true
	s.hello = func(sessionID uint32) []byte { return junosServerHello(sessionID, user) }
	s.trailer = func() []byte {
		return []byte(fmt.Sprintf(junosSessionEndFormat, time.Now().UTC().Format(junosTimeFormat)))
	}
	s.rpc = s.junosRPC
	return s
}

// junosRPC answers one request in the Junos dialect.
func (s *netconfSession) junosRPC(r netconfRPC) (done bool) {
	version := junosVersion(s.dev)
	id := r.messageID
	reply := func(b []byte) bool { return s.writeMessage(b) != nil }

	switch {
	case r.op == "close-session" && r.ns == netconfBaseNS:
		_ = s.writeMessage(junosOKReply(version, id))
		return true
	case r.op == "kill-session" && r.ns == netconfBaseNS:
		if !s.killTarget(r) {
			return reply(junosSyntaxError(version, id, "session-id", 1))
		}
		return reply(junosOKReply(version, id))
	case r.op == "create-subscription" && r.ns == junosNotificationNS:
		if stream, ok := netconfChildText(r.opXML, "stream"); ok && stream != "NETCONF" {
			return reply(junosSyntaxError(version, id, r.op, 1))
		}
		s.junosSubscribe()
		return reply(junosOKReply(version, id))
	case r.op == "get" && r.ns == netconfBaseNS:
		switch {
		case junosHasElementNS(r.opXML, junosNetmodNS):
			return reply(junosStreamsReply(version, id))
		case junosHasElementNS(r.opXML, junosMonitoringNS):
			return reply(junosNetconfStateReply(version, id))
		}
		return reply(junosGetReply(s.dev, version, id, s.startedAt))
	case r.op == "get-configuration":
		return reply(junosGetConfigurationReply(s.dev, version, id, s.startedAt))
	case r.op == "establish-subscription" && (r.ns == netconfDraftNS || r.ns == junosRFC8639NS):
		return reply(junosSyntaxError(version, id, r.op, 2))
	}
	return reply(junosSyntaxError(version, id, r.op, 1))
}

// junosSubscribe adds the session's one subscription. A second
// create-subscription adds nothing: one subscription serves the single stream.
func (s *netconfSession) junosSubscribe() {
	s.mu.Lock()
	defer s.mu.Unlock()
	if len(s.subs) > 0 {
		return
	}
	sub := &netconfSub{}
	s.subs = append(s.subs, sub)
	s.ev.mu.Lock()
	s.ev.subs = append(s.ev.subs, sub)
	s.ev.mu.Unlock()
}

// junosHasElementNS reports whether any element below the root of op is in
// the namespace ns.
func junosHasElementNS(op []byte, ns string) bool {
	dec := xml.NewDecoder(bytes.NewReader(op))
	first := true
	for {
		tok, err := dec.Token()
		if err != nil {
			return false
		}
		if se, ok := tok.(xml.StartElement); ok {
			if !first && se.Name.Space == ns {
				return true
			}
			first = false
		}
	}
}
