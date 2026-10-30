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
func newJunosNetconfSession(id uint32, dev *DeviceSimulator, rw io.ReadWriter, reg *netconfSessionRegistry, user string) *netconfSession {
	s := newNetconfSession(id, dev, rw, reg)
	s.startedAt = time.Now()
	ev := &netconfEvents{ready: make(chan struct{})}
	if manager != nil {
		ev.sent, ev.dropped = &manager.netconfNotificationsSent, &manager.netconfNotificationsDropped
	} else {
		ev.sent, ev.dropped = new(uint64), new(uint64)
	}
	ev.onEvent = (*netconfSession).junosStateEvent
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
		// The reply and the session-end trailer go out under one hold of wmu,
		// so no push can land between them. The trailer follows only a
		// reply that was written.
		s.wmu.Lock()
		defer s.wmu.Unlock()
		// Closed under the lock, so a push waiting for wmu is dropped.
		defer s.close()
		if s.framer.WriteMessage(junosOKReply(version, id)) == nil {
			_, _ = fmt.Fprintf(s.framer.w, junosSessionEndFormat, time.Now().UTC().Format(junosTimeFormat))
		}
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
		child, ok := junosFilterChild(r.opXML)
		switch {
		case !ok:
			return reply(junosGetReply(s.dev, version, id, s.startedAt))
		case child.Space == junosNetmodNS && child.Local == "netconf":
			return reply(junosStreamsReply(version, id))
		case child.Space == junosMonitoringNS && child.Local == "netconf-state":
			return reply(junosNetconfStateReply(version, id))
		}
		// Any other filtered subtree, such as ietf-interfaces
		// interfaces-state, is refused naming that subtree.
		return reply(junosSyntaxError(version, id, child.Local, 1))
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

// junosFilterChild returns the first element inside the filter of a get.
// ok is false for a get without a filter or with an empty one.
func junosFilterChild(op []byte) (xml.Name, bool) {
	dec := xml.NewDecoder(bytes.NewReader(op))
	depth, inFilter := 0, false
	for {
		tok, err := dec.Token()
		if err != nil {
			return xml.Name{}, false
		}
		switch se := tok.(type) {
		case xml.StartElement:
			depth++
			if inFilter {
				return se.Name, true
			}
			if depth == 2 && se.Name.Local == "filter" {
				inFilter = true
			}
		case xml.EndElement:
			depth--
			if inFilter && depth < 2 {
				return xml.Name{}, false
			}
		}
	}
}
