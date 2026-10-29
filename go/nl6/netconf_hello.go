/*
 * Copyright 2026 Ronny Trommer <ronny@no42.org>
 * SPDX-License-Identifier: Apache-2.0
 */

package main

import (
	"fmt"
	"strings"
)

const (
	netconfBaseNS   = "urn:ietf:params:xml:ns:netconf:base:1.0"
	netconfBase10   = "urn:ietf:params:netconf:base:1.0"
	netconfBase11   = "urn:ietf:params:netconf:base:1.1"
	netconfDraftNS  = "urn:ietf:params:xml:ns:yang:ietf-event-notifications"
	netconfRFC8639  = "urn:ietf:params:xml:ns:yang:ietf-subscribed-notifications"
	netconfNotifNS  = "urn:ietf:params:xml:ns:netconf:notification:1.0"
	netconfYangPush = "urn:ietf:params:xml:ns:yang:ietf-yang-push"
)

// netconfHelloCapabilities is what the simulated switch advertises. The
// module lines for the ietf-* and deviation modules are copied from a Catalyst
// 9300 hello. The interfaces-oper line follows the same shape with the module
// revision shipped in the YANG file.
var netconfHelloCapabilities = []string{
	netconfBase10,
	netconfBase11,
	"urn:ietf:params:netconf:capability:notification:1.0",
	"urn:ietf:params:netconf:capability:interleave:1.0",
	"urn:ietf:params:xml:ns:yang:ietf-event-notifications?module=ietf-event-notifications&revision=2016-10-27&features=json,configured-subscriptions&deviations=cisco-xe-ietf-event-notifications-deviation,cisco-xe-ietf-yang-push-deviation",
	"urn:ietf:params:xml:ns:yang:ietf-yang-push?module=ietf-yang-push&revision=2021-03-01&features=on-change&deviations=cisco-xe-ietf-yang-push-deviation",
	"http://cisco.com/ns/yang/cisco-xe-ietf-event-notifications-deviation?module=cisco-xe-ietf-event-notifications-deviation&revision=2018-12-03",
	"http://cisco.com/ns/yang/cisco-xe-ietf-yang-push-deviation?module=cisco-xe-ietf-yang-push-deviation&revision=2018-12-03",
	"http://cisco.com/ns/yang/Cisco-IOS-XE-interfaces-oper?module=Cisco-IOS-XE-interfaces-oper&revision=2026-08-01",
	"urn:ietf:params:xml:ns:yang:ietf-interfaces?module=ietf-interfaces&revision=2014-05-08&features=pre-provisioning,if-mib,arbitrary-names&deviations=cisco-xe-ietf-ip-deviation",
}

var netconfXMLEscaper = strings.NewReplacer("&", "&amp;", "<", "&lt;", ">", "&gt;", `"`, "&quot;")

// netconfServerHello renders the server hello for a session.
func netconfServerHello(sessionID uint32) []byte {
	var b strings.Builder
	b.WriteString(`<?xml version="1.0" encoding="UTF-8"?>`)
	fmt.Fprintf(&b, `<hello xmlns="%s"><capabilities>`, netconfBaseNS)
	for _, c := range netconfHelloCapabilities {
		fmt.Fprintf(&b, "<capability>%s</capability>", netconfXMLEscaper.Replace(c))
	}
	fmt.Fprintf(&b, "</capabilities><session-id>%d</session-id></hello>", sessionID)
	return []byte(b.String())
}
