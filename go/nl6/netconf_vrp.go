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
	"net"
	"strconv"
	"strings"
	"time"
)

// The VRP dialect serves what a YANG-Push collector (NetGauze) reads over
// NETCONF from a huawei_ne8000: the YANG library, every module through
// get-schema, and the configured subscriptions and their filters. It sends
// no notifications; the subscriptions stream over UDP-notif.

const (
	vrpMonitoringNS  = "urn:ietf:params:xml:ns:yang:ietf-netconf-monitoring"
	vrpYangPushNS    = "urn:ietf:params:xml:ns:yang:ietf-yang-push"
	vrpDatastoresNS  = "urn:ietf:params:xml:ns:yang:ietf-datastores"
	vrpUDPNotifNS    = "urn:ietf:params:xml:ns:yang:ietf-udp-notif-transport"
	vrpReceiversNS   = "urn:ietf:params:xml:ns:yang:ietf-subscribed-notif-receivers"
	vrpInterfacesNS  = "urn:ietf:params:xml:ns:yang:ietf-interfaces"
	vrpReceiverName  = "COLLECTOR"
	vrpMonitoringCap = vrpMonitoringNS + "?module=ietf-netconf-monitoring&revision=2010-10-04"
)

// vrpTextEscaper escapes module source for element text. Quotes and
// whitespace stay literal so the text decodes back to the source byte for
// byte.
var vrpTextEscaper = strings.NewReplacer("&", "&amp;", "<", "&lt;", ">", "&gt;")

// newVrpNetconfSession builds a session that speaks the VRP dialect over
// base:1.1 chunked framing when the client offers it.
func newVrpNetconfSession(id uint32, dev *DeviceSimulator, rw io.ReadWriter, reg *netconfSessionRegistry, _ string) *netconfSession {
	s := newNetconfSession(id, dev, rw, reg)
	s.hello = vrpServerHello
	s.rpc = s.vrpRPC
	return s
}

// vrpServerHello lists only what the dialect serves.
func vrpServerHello(sessionID uint32) []byte {
	return netconfHelloWithCaps(sessionID, []string{
		netconfBase10,
		netconfBase11,
		"urn:ietf:params:netconf:capability:yang-library:1.1?revision=2019-01-04&content-id=" + vrpContentID(),
		vrpMonitoringCap,
	})
}

// vrpRPC answers one request in the VRP dialect.
func (s *netconfSession) vrpRPC(r netconfRPC) (done bool) {
	id := r.messageID
	reply := func(b []byte) bool { return s.writeMessage(b) != nil }
	switch {
	case r.op == "get" && r.ns == netconfBaseNS:
		return reply(vrpDataReply(id, s.vrpGetData(r.opXML)))
	case r.op == "get-schema" && r.ns == vrpMonitoringNS:
		src, ok := vrpGetSchema(r.opXML)
		if !ok {
			return reply(netconfErrorReply(id, true, iosxeRPCError{Type: "application", Tag: "invalid-value"}, ""))
		}
		var b strings.Builder
		b.WriteString(netconfReplyOpen(id))
		fmt.Fprintf(&b, `<data xmlns="%s">`, vrpMonitoringNS)
		_, _ = vrpTextEscaper.WriteString(&b, string(src))
		b.WriteString("</data></rpc-reply>")
		return reply([]byte(b.String()))
	case r.op == "close-session" && r.ns == netconfBaseNS:
		_ = s.writeMessage(netconfOKReply(id))
		return true
	case r.op == "kill-session" && r.ns == netconfBaseNS:
		return reply(s.handleKill(r))
	}
	return reply(netconfErrorReply(id, true, iosxeRPCError{Type: "protocol", Tag: "operation-not-supported"}, ""))
}

// vrpDataReply wraps data in <data>, or sends <data/> when it is empty.
func vrpDataReply(id string, data []byte) []byte {
	if len(data) == 0 {
		return []byte(netconfReplyOpen(id) + "<data/></rpc-reply>")
	}
	return []byte(netconfReplyOpen(id) + "<data>" + string(data) + "</data></rpc-reply>")
}

// vrpGetSchema returns the source a get-schema names. The format, when
// given, must be yang; no version means the served revision.
func vrpGetSchema(op []byte) ([]byte, bool) {
	name, _ := netconfChildText(op, "identifier")
	version, _ := netconfChildText(op, "version")
	if f, ok := netconfChildText(op, "format"); ok && f[strings.LastIndex(f, ":")+1:] != "yang" {
		return nil, false
	}
	m, ok := vrpYangModule(name, version)
	return m.Source, ok && name != ""
}

// vrpFilterNode is one top-level element of a subtree filter.
type vrpFilterNode struct {
	name xml.Name
	xml  []byte
}

// vrpFilterNodes returns the top-level elements of the get's filter. ok is
// false when the get has no filter.
func vrpFilterNodes(op []byte) (nodes []vrpFilterNode, ok bool) {
	dec := xml.NewDecoder(bytes.NewReader(op))
	depth := 0
	for {
		start := dec.InputOffset()
		tok, err := dec.Token()
		if err != nil {
			return nodes, ok
		}
		switch t := tok.(type) {
		case xml.StartElement:
			depth++
			if depth == 2 && t.Name.Local == "filter" {
				ok = true
			}
			if depth == 3 && ok {
				if dec.Skip() != nil {
					return nodes, ok
				}
				depth--
				nodes = append(nodes, vrpFilterNode{name: t.Name, xml: op[start:dec.InputOffset()]})
			}
		case xml.EndElement:
			depth--
		}
	}
}

// vrpGetData answers a get. Each top-level filter element selects one
// subtree; an unknown one selects nothing. No filter returns everything.
func (s *netconfSession) vrpGetData(op []byte) []byte {
	nodes, filtered := vrpFilterNodes(op)
	lib := vrpYangLibraryXML()
	split := bytes.Index(lib, []byte("<modules-state "))
	e := s.vrpExporter()
	if !filtered {
		out := append([]byte(nil), lib...)
		out = append(out, vrpFiltersXML(e)...)
		return append(out, vrpSubscriptionsXML(s.dev, e, 0)...)
	}
	var out []byte
	for _, n := range nodes {
		switch {
		case n.name.Space == yangLibNS && n.name.Local == "yang-library":
			out = append(out, lib[:split]...)
		case n.name.Space == yangLibNS && n.name.Local == "modules-state":
			out = append(out, lib[split:]...)
		case n.name.Space == netconfRFC8639 && n.name.Local == "filters":
			out = append(out, vrpFiltersXML(e)...)
		case n.name.Space == netconfRFC8639 && n.name.Local == "subscriptions":
			var id uint64
			if txt, ok := vrpSubscriptionIDFilter(n.xml); ok {
				var err error
				if id, err = strconv.ParseUint(txt, 10, 32); err != nil || id == 0 {
					continue
				}
			}
			out = append(out, vrpSubscriptionsXML(s.dev, e, uint32(id))...)
		}
	}
	return out
}

// vrpSubscriptionIDFilter returns the <id> under <subscription> in a
// subscriptions filter.
func vrpSubscriptionIDFilter(node []byte) (string, bool) {
	dec := xml.NewDecoder(bytes.NewReader(node))
	var path []string
	for {
		tok, err := dec.Token()
		if err != nil {
			return "", false
		}
		switch t := tok.(type) {
		case xml.StartElement:
			path = append(path, t.Name.Local)
			if strings.Join(path, "/") == "subscriptions/subscription/id" {
				var v string
				if dec.DecodeElement(&v, &t) != nil {
					return "", false
				}
				return strings.TrimSpace(v), true
			}
		case xml.EndElement:
			path = path[:len(path)-1]
		}
	}
}

// vrpExporter returns the device's YANG-Push exporter, or nil when it has
// none. stopNetconfServer holds d.mu while it waits for the sessions, so a
// session must never block on d.mu: it retries the read lock until it gets
// it or the session is closed.
func (s *netconfSession) vrpExporter() *YangPushExporter {
	if s.dev == nil {
		return nil
	}
	for !s.dev.mu.TryRLock() {
		if s.isClosed() {
			return nil
		}
		time.Sleep(time.Millisecond)
	}
	defer s.dev.mu.RUnlock()
	return s.dev.yangPushExporter
}

// vrpXPathXML rewrites a JSON-style ietf-interfaces XPath
// (/ietf-interfaces:interfaces/interface) with the if: prefix on every step,
// as the device's XML filter carries it.
func vrpXPathXML(p string) string {
	parts := strings.Split(p, " | ")
	for i, part := range parts {
		steps := strings.Split(strings.TrimPrefix(part, "/"), "/")
		for j, st := range steps {
			steps[j] = "if:" + strings.TrimPrefix(st, "ietf-interfaces:")
		}
		parts[i] = "/" + strings.Join(steps, "/")
	}
	return strings.Join(parts, " | ")
}

// vrpFiltersXML renders the selection filters of e's subscriptions. The if:
// prefix is declared on the element that uses it, because NetGauze parses
// the copied <filters> subtree on its own.
func vrpFiltersXML(e *YangPushExporter) []byte {
	if e == nil {
		return nil
	}
	var b strings.Builder
	fmt.Fprintf(&b, `<filters xmlns="%s">`, netconfRFC8639)
	for _, sub := range e.Subscriptions() {
		fmt.Fprintf(&b, `<selection-filter xmlns="%s"><filter-id>%s</filter-id><datastore-xpath-filter xmlns:if="%s">%s</datastore-xpath-filter></selection-filter>`,
			vrpYangPushNS, netconfEscape(sub.FilterRef), vrpInterfacesNS, netconfEscape(vrpXPathXML(sub.XPath)))
	}
	b.WriteString("</filters>")
	return []byte(b.String())
}

// vrpSubscriptionsXML renders e's subscriptions, only the one with id when
// id is not 0, in the shape of the captured VRP configuration, then the
// receiver instance naming the collector. Nil when nothing matches.
func vrpSubscriptionsXML(dev *DeviceSimulator, e *YangPushExporter, id uint32) []byte {
	if e == nil {
		return nil
	}
	var b strings.Builder
	matched := false
	for _, sub := range e.Subscriptions() {
		if id != 0 && sub.ID != id {
			continue
		}
		if !matched {
			fmt.Fprintf(&b, `<subscriptions xmlns="%s">`, netconfRFC8639)
			matched = true
		}
		fmt.Fprintf(&b, `<subscription><id>%d</id>`, sub.ID)
		fmt.Fprintf(&b, `<datastore xmlns="%s" xmlns:ds="%s">ds:operational</datastore>`, vrpYangPushNS, vrpDatastoresNS)
		fmt.Fprintf(&b, `<selection-filter-ref xmlns="%s">%s</selection-filter-ref>`, vrpYangPushNS, netconfEscape(sub.FilterRef))
		b.WriteString(`<dscp>0</dscp>`)
		fmt.Fprintf(&b, `<transport xmlns:unt="%s">unt:udp-notif</transport>`, vrpUDPNotifNS)
		b.WriteString(`<encoding>encode-json</encoding>`)
		if dev != nil && dev.IP != nil {
			fmt.Fprintf(&b, `<source-address>%s</source-address>`, dev.IP)
		}
		fmt.Fprintf(&b, `<receivers><receiver><name>%s</name><receiver-instance-ref xmlns="%s">%s</receiver-instance-ref></receiver></receivers>`,
			vrpReceiverName, vrpReceiversNS, vrpReceiverName)
		if sub.Periodic {
			fmt.Fprintf(&b, `<periodic xmlns="%s"><period>%d</period><anchor-time>%s</anchor-time></periodic>`,
				vrpYangPushNS, sub.PeriodCs, sub.Anchor.UTC().Format("2006-01-02T15:04:05Z"))
		} else {
			fmt.Fprintf(&b, `<on-change xmlns="%s"><dampening-period>0</dampening-period><sync-on-start>true</sync-on-start></on-change>`, vrpYangPushNS)
		}
		b.WriteString(`</subscription>`)
	}
	if !matched {
		return nil
	}
	host, port, err := net.SplitHostPort(e.collector)
	if err != nil {
		host, port = e.collector, ""
	}
	fmt.Fprintf(&b, `<receiver-instances xmlns="%s"><receiver-instance><name>%s</name><udp-notif-receiver xmlns="%s"><remote-address>%s</remote-address><remote-port>%s</remote-port><enable-segmentation>true</enable-segmentation><max-segment-size>%d</max-segment-size></udp-notif-receiver></receiver-instance></receiver-instances>`,
		vrpReceiversNS, vrpReceiverName, vrpUDPNotifNS, netconfEscape(host), netconfEscape(port), e.segSize)
	b.WriteString(`</subscriptions>`)
	return []byte(b.String())
}
