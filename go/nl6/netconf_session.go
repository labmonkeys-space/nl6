/*
 * Copyright 2026 Ronny Trommer <ronny@no42.org>
 * SPDX-License-Identifier: Apache-2.0
 */

package main

import (
	"bytes"
	"context"
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
)

// netconfMaxSubsPerSession caps establish-subscription per session. The
// device accepted at least 150. nl6 stops at 256.
const netconfMaxSubsPerSession = 256

// netconfFirstSubID is where subscription ids start, as on the device.
const netconfFirstSubID = 2147483648

// netconfSub is one accepted subscription.
type netconfSub struct {
	id  uint32
	sel iosxeSelection
	// deleted is set when the subscription ends. A push still queued for it
	// is discarded, checked under wmu right before the write.
	deleted atomic.Bool
}

// netconfSession serves one NETCONF client. Replies and notifications share
// wmu so a notification never splits a reply.
type netconfSession struct {
	id  uint32
	dev *DeviceSimulator
	rw  io.ReadWriter
	reg *netconfSessionRegistry

	framer *netconfFramer
	wmu    sync.Mutex

	mu   sync.Mutex
	subs []*netconfSub // creation order

	closed    chan struct{}
	closeOnce sync.Once

	// onStart runs once after the hello exchange. onSubscribe runs right
	// after an ok establish-subscription reply was written. Both may be nil.
	// onUnsubscribe runs after a successful delete-subscription and once for
	// every subscription still held when Serve exits, on any path.
	onStart       func(ctx context.Context)
	onSubscribe   func(sub *netconfSub)
	onUnsubscribe func(sub *netconfSub)

	// ev carries the state-change push machinery. Nil unless the session
	// was built by newIOSXENetconfSession.
	ev *netconfEvents
}

func newNetconfSession(id uint32, dev *DeviceSimulator, rw io.ReadWriter, reg *netconfSessionRegistry) *netconfSession {
	return &netconfSession{
		id:     id,
		dev:    dev,
		rw:     rw,
		reg:    reg,
		framer: newNetconfFramer(rw, rw),
		closed: make(chan struct{}),
	}
}

// close ends the session and unblocks a pending read.
func (s *netconfSession) close() {
	s.closeOnce.Do(func() {
		close(s.closed)
		if c, ok := s.rw.(io.Closer); ok {
			_ = c.Close()
		}
	})
}

func (s *netconfSession) isClosed() bool {
	select {
	case <-s.closed:
		return true
	default:
		return false
	}
}

// writeMessage writes one framed message under the write mutex.
func (s *netconfSession) writeMessage(msg []byte) error {
	s.wmu.Lock()
	defer s.wmu.Unlock()
	return s.framer.WriteMessage(msg)
}

// Subs returns a copy of the subscriptions in creation order.
func (s *netconfSession) Subs() []*netconfSub {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]*netconfSub(nil), s.subs...)
}

// Serve runs the session until close-session, kill-session, EOF or ctx end.
func (s *netconfSession) Serve(ctx context.Context) error {
	if s.reg != nil {
		s.reg.add(s)
		defer s.reg.remove(s)
	}
	defer s.close()
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	defer s.teardown()

	// Closing the session unblocks the pending read when ctx ends.
	stop := context.AfterFunc(ctx, s.close)
	defer stop()

	if err := s.writeMessage(netconfServerHello(s.id)); err != nil {
		return err
	}
	hello, err := s.framer.ReadMessage()
	if err != nil {
		return s.endErr(err)
	}
	if !bytes.Contains(hello, []byte("<hello")) {
		return errors.New("netconf: first message is not a hello")
	}
	if bytes.Contains(hello, []byte(netconfBase11)) {
		// Both peers advertise base:1.1. The reader side needs no lock here
		// because only this goroutine reads, and no notification writer
		// exists before onStart.
		s.wmu.Lock()
		s.framer.chunked = true
		s.wmu.Unlock()
	}
	if s.onStart != nil {
		s.onStart(ctx)
	}

	for {
		msg, err := s.framer.ReadMessage()
		if err != nil {
			return s.endErr(err)
		}
		if done := s.handleRPC(msg); done {
			return nil
		}
	}
}

// teardown reports every remaining subscription as removed.
func (s *netconfSession) teardown() {
	s.mu.Lock()
	subs := s.subs
	s.subs = nil
	s.mu.Unlock()
	if s.onUnsubscribe == nil {
		return
	}
	for _, sub := range subs {
		s.onUnsubscribe(sub)
	}
}

// endErr maps the end of the stream to nil. Any EOF, even a truncated message,
// is the end of the session and never a clean close-session.
func (s *netconfSession) endErr(err error) error {
	if errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF) ||
		errors.Is(err, io.ErrClosedPipe) || s.isClosed() {
		return nil
	}
	return err
}

type netconfRPC struct {
	messageID string
	hasMsgID  bool
	op        string
	ns        string
	opXML     []byte
}

// parseNetconfRPC extracts the rpc envelope and the operation element.
func parseNetconfRPC(data []byte) (netconfRPC, error) {
	var r netconfRPC
	dec := xml.NewDecoder(bytes.NewReader(data))
	for {
		tok, err := dec.Token()
		if err != nil {
			return r, errors.New("netconf: malformed rpc")
		}
		se, ok := tok.(xml.StartElement)
		if !ok {
			continue
		}
		if se.Name.Local != "rpc" {
			return r, errors.New("netconf: not an rpc")
		}
		for _, a := range se.Attr {
			if a.Name.Local == "message-id" && a.Name.Space == "" {
				r.messageID, r.hasMsgID = a.Value, true
			}
		}
		break
	}
	for {
		start := dec.InputOffset()
		tok, err := dec.Token()
		if err != nil {
			return r, errors.New("netconf: rpc has no operation")
		}
		se, ok := tok.(xml.StartElement)
		if !ok {
			continue
		}
		r.op, r.ns = se.Name.Local, se.Name.Space
		if err := dec.Skip(); err != nil {
			return r, errors.New("netconf: malformed rpc")
		}
		r.opXML = data[start:dec.InputOffset()]
		return r, nil
	}
}

// netconfChildText returns the text of the first child element with the given
// local name.
func netconfChildText(op []byte, name string) (string, bool) {
	dec := xml.NewDecoder(bytes.NewReader(op))
	depth := 0
	for {
		tok, err := dec.Token()
		if err != nil {
			return "", false
		}
		switch t := tok.(type) {
		case xml.StartElement:
			depth++
			if depth == 2 && t.Name.Local == name {
				var sb strings.Builder
				for {
					inner, err := dec.Token()
					if err != nil {
						return "", false
					}
					switch it := inner.(type) {
					case xml.CharData:
						sb.Write(it)
					case xml.EndElement:
						return strings.TrimSpace(sb.String()), true
					}
				}
			}
		case xml.EndElement:
			depth--
		}
	}
}

func netconfReplyOpen(messageID string) string {
	return fmt.Sprintf(`<rpc-reply xmlns="%s" message-id="%s" xmlns:nc="%s">`,
		netconfBaseNS, netconfXMLEscaper.Replace(messageID), netconfBaseNS)
}

func netconfOKReply(messageID string) []byte {
	return []byte(netconfReplyOpen(messageID) + "<ok/></rpc-reply>")
}

func netconfSubResultReply(messageID string, result iosxeSubResult, subID uint32, withID bool) []byte {
	var b strings.Builder
	b.WriteString(netconfReplyOpen(messageID))
	fmt.Fprintf(&b, `<subscription-result xmlns='%s' xmlns:notif-bis="%s">%s</subscription-result> `,
		netconfDraftNS, netconfDraftNS, result)
	if withID {
		fmt.Fprintf(&b, `<subscription-id xmlns='%s'>%d</subscription-id> `, netconfDraftNS, subID)
	}
	b.WriteString("</rpc-reply>")
	return []byte(b.String())
}

// netconfTextEscaper escapes the three characters element text needs.
var netconfTextEscaper = strings.NewReplacer("&", "&amp;", "<", "&lt;", ">", "&gt;")

// netconfErrorReply renders an rpc-error. An empty messageID omits the
// attribute, as for a request that carried none.
func netconfErrorReply(messageID string, hasMsgID bool, e iosxeRPCError, badAttr string) []byte {
	var b strings.Builder
	if hasMsgID {
		b.WriteString(netconfReplyOpen(messageID))
	} else {
		fmt.Fprintf(&b, `<rpc-reply xmlns="%s">`, netconfBaseNS)
	}
	fmt.Fprintf(&b, "<rpc-error><error-type>%s</error-type><error-tag>%s</error-tag><error-severity>error</error-severity>", e.Type, e.Tag)
	if e.Path != "" {
		fmt.Fprintf(&b, "<error-path%s>\n    %s\n  </error-path>", e.PathNS, e.Path)
	}
	if e.Message != "" {
		// Quotes stay literal, matching the decoded captures (no raw wire
		// bytes of this element were kept). &#34; would be equivalent XML;
		// literal quotes keep the text readable.
		b.WriteString(`<error-message xml:lang="en">` + netconfTextEscaper.Replace(e.Message) + "</error-message>")
	}
	if e.BadElement != "" || badAttr != "" {
		fmt.Fprintf(&b, `<error-info xmlns="%s" xmlns:nc="%s">`, netconfBaseNS, netconfBaseNS)
		if badAttr != "" {
			fmt.Fprintf(&b, "<bad-attribute>%s</bad-attribute>", badAttr)
		}
		if e.BadElement != "" {
			fmt.Fprintf(&b, "<bad-element>%s</bad-element>", e.BadElement)
		}
		if e.BadNamespace != "" {
			fmt.Fprintf(&b, "\n<bad-namespace>%s</bad-namespace>", e.BadNamespace)
		}
		b.WriteString("\n</error-info>")
	}
	b.WriteString("</rpc-error></rpc-reply>")
	return []byte(b.String())
}

// handleRPC answers one request and reports whether the session is over.
func (s *netconfSession) handleRPC(data []byte) (done bool) {
	r, err := parseNetconfRPC(data)
	if err != nil {
		_ = s.writeMessage(netconfErrorReply("", false, iosxeRPCError{Type: "rpc", Tag: "malformed-message"}, ""))
		return false
	}
	if !r.hasMsgID {
		_ = s.writeMessage(netconfErrorReply("", false, iosxeRPCError{Type: "rpc", Tag: "missing-attribute", BadElement: "rpc"}, "message-id"))
		return false
	}
	id := r.messageID
	reply := func(b []byte) bool { return s.writeMessage(b) != nil }

	switch {
	case r.op == "establish-subscription" && r.ns == netconfDraftNS:
		return s.handleEstablish(r)
	case r.op == "establish-subscription" && r.ns == netconfRFC8639:
		return reply(netconfErrorReply(id, true, iosxeRPCError{Type: "protocol", Tag: "unknown-namespace", BadElement: "establish-subscription", Path: "/rpc", BadNamespace: netconfRFC8639}, ""))
	case r.op == "delete-subscription" && r.ns == netconfDraftNS:
		return reply(s.handleDelete(r))
	case r.op == "close-session" && r.ns == netconfBaseNS:
		_ = s.writeMessage(netconfOKReply(id))
		return true
	case r.op == "kill-session" && r.ns == netconfBaseNS:
		return reply(s.handleKill(r))
	}
	return reply(netconfErrorReply(id, true, iosxeRPCError{Type: "protocol", Tag: "operation-not-supported"}, ""))
}

func (s *netconfSession) handleEstablish(r netconfRPC) bool {
	sel, result, rpcErr := parseEstablishSubscription(r.opXML)
	if rpcErr != nil {
		return s.writeMessage(netconfErrorReply(r.messageID, true, *rpcErr, "")) != nil
	}
	if result != iosxeSubOK {
		return s.writeMessage(netconfSubResultReply(r.messageID, result, 0, false)) != nil
	}
	s.mu.Lock()
	if len(s.subs) >= netconfMaxSubsPerSession {
		s.mu.Unlock()
		return s.writeMessage(netconfSubResultReply(r.messageID, iosxeSubErrorOther, 0, false)) != nil
	}
	subID := uint32(netconfFirstSubID)
	if s.reg != nil {
		subID = s.reg.nextSubID()
	}
	s.mu.Unlock()

	// The subscription becomes visible only after its reply is on the wire.
	// RPCs are handled by one goroutine, so the cap check cannot be raced.
	if err := s.writeMessage(netconfSubResultReply(r.messageID, iosxeSubOK, subID, true)); err != nil {
		return true
	}
	sub := &netconfSub{id: subID, sel: sel}
	s.mu.Lock()
	s.subs = append(s.subs, sub)
	s.mu.Unlock()
	if s.onSubscribe != nil {
		s.onSubscribe(sub)
	}
	return false
}

func (s *netconfSession) handleDelete(r netconfRPC) []byte {
	txt, _ := netconfChildText(r.opXML, "subscription-id")
	n, err := strconv.ParseUint(txt, 10, 32)
	if err == nil {
		s.mu.Lock()
		for i, sub := range s.subs {
			if sub.id == uint32(n) {
				s.subs = append(s.subs[:i], s.subs[i+1:]...)
				s.mu.Unlock()
				if s.onUnsubscribe != nil {
					s.onUnsubscribe(sub)
				}
				return netconfSubResultReply(r.messageID, iosxeSubOK, 0, false)
			}
		}
		s.mu.Unlock()
	}
	return netconfSubResultReply(r.messageID, "notif-bis:error-no-such-subscription", 0, false)
}

func (s *netconfSession) handleKill(r netconfRPC) []byte {
	bad := netconfErrorReply(r.messageID, true, iosxeRPCError{Type: "protocol", Tag: "invalid-value", BadElement: "session-id"}, "")
	txt, _ := netconfChildText(r.opXML, "session-id")
	n, err := strconv.ParseUint(txt, 10, 32)
	if err != nil || uint32(n) == s.id || s.reg == nil || !s.reg.kill(uint32(n)) {
		return bad
	}
	return netconfOKReply(r.messageID)
}

// netconfSessionRegistry tracks the sessions of one device so kill-session can
// reach another session, and hands out subscription ids.
type netconfSessionRegistry struct {
	mu       sync.Mutex
	sessions map[uint32]*netconfSession
	subSeq   atomic.Uint32
}

func newNetconfSessionRegistry() *netconfSessionRegistry {
	return &netconfSessionRegistry{sessions: make(map[uint32]*netconfSession)}
}

func (g *netconfSessionRegistry) add(s *netconfSession) {
	g.mu.Lock()
	g.sessions[s.id] = s
	g.mu.Unlock()
}

func (g *netconfSessionRegistry) remove(s *netconfSession) {
	g.mu.Lock()
	if g.sessions[s.id] == s {
		delete(g.sessions, s.id)
	}
	g.mu.Unlock()
}

// kill closes the session with the given id. It reports whether one existed.
func (g *netconfSessionRegistry) kill(id uint32) bool {
	g.mu.Lock()
	s := g.sessions[id]
	g.mu.Unlock()
	if s == nil {
		return false
	}
	s.close()
	return true
}

// closeAll closes every session.
func (g *netconfSessionRegistry) closeAll() {
	g.mu.Lock()
	all := make([]*netconfSession, 0, len(g.sessions))
	for _, s := range g.sessions {
		all = append(all, s)
	}
	g.mu.Unlock()
	for _, s := range all {
		s.close()
	}
}

// nextSubID returns the next subscription id, starting at 2147483648.
func (g *netconfSessionRegistry) nextSubID() uint32 {
	return netconfFirstSubID - 1 + g.subSeq.Add(1)
}
