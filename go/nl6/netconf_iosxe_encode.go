/*
 * Copyright 2026 Ronny Trommer <ronny@no42.org>
 * SPDX-License-Identifier: Apache-2.0
 */

package main

import (
	"bytes"
	"encoding/xml"
	"net/url"
	"strconv"
	"time"
)

// IOS XE interface oper-status vocabulary used when the state engine
// cannot name a state.
const iosxeOperInvalid = "if-oper-state-invalid"

const (
	iosxeNSNotification = "urn:ietf:params:xml:ns:netconf:notification:1.0"
	iosxeNSYangPush     = "urn:ietf:params:xml:ns:yang:ietf-yang-push"
	iosxeNSYangPatch    = "urn:ietf:params:xml:ns:yang:ietf-yang-patch"
	iosxeNSIfOper       = "http://cisco.com/ns/yang/Cisco-IOS-XE-interfaces-oper"
)

// iosxeLeafSet selects what a subscription renders for an interface.
type iosxeLeafSet uint8

const (
	iosxeLeafOper iosxeLeafSet = iota + 1
	iosxeLeafAdmin
	iosxeLeafRow
)

// iosxeStats holds the counters nl6 serves under statistics.
type iosxeStats struct {
	DiscontinuityTime string
	InOctets, InUnicastPkts, InBroadcastPkts, InMulticastPkts, InDiscards, InErrors,
	OutOctets, OutUnicastPkts, OutBroadcastPkts, OutMulticastPkts, OutDiscards, OutErrors uint64
}

// iosxeRow holds the interface leaves nl6 serves.
type iosxeRow struct {
	Name, InterfaceType, Admin, Oper, LastChange, PhysAddress string
	IfIndex                                                   int
	Speed                                                     uint64
	Stats                                                     iosxeStats
}

func iosxeAdminStatus(admin uint8) string {
	switch admin {
	case AdminUp:
		return "if-state-up"
	case AdminDown:
		return "if-state-down"
	case AdminTesting:
		return "if-state-test"
	}
	return "if-state-unknown"
}

func iosxeOperStatus(admin, oper uint8) string {
	switch admin {
	case AdminDown:
		return "if-oper-state-no-pass"
	case AdminTesting:
		return "if-oper-state-test"
	}
	switch oper {
	case OperUp:
		return "if-oper-state-ready"
	case OperDown, OperLowerLayerDn:
		return "if-oper-state-lower-layer-down"
	case OperTesting:
		return "if-oper-state-test"
	case OperUnknown:
		return "if-oper-state-unknown"
	case OperDormant:
		return "if-oper-state-dormant"
	case OperNotPresent:
		return "if-oper-state-not-present"
	}
	return iosxeOperInvalid
}

func iosxeTargetKey(ifName string) string {
	return "/interfaces/interface=" + url.PathEscape(ifName)
}

func iosxeEventTime(t time.Time) string {
	return t.UTC().Format("2006-01-02T15:04:05.00Z")
}

// iosxeTimestamp formats last-change and discontinuity-time for pushes: UTC,
// six fractional digits at millisecond precision, as the device sends them.
func iosxeTimestamp(t time.Time) string {
	return t.UTC().Format("2006-01-02T15:04:05.000000+00:00")
}

func iosxeLeaf(b *bytes.Buffer, name, val string) {
	b.WriteString("<" + name + ">")
	_ = xml.EscapeText(b, []byte(val))
	b.WriteString("</" + name + ">")
}

func iosxeNum(b *bytes.Buffer, name string, v uint64) {
	iosxeLeaf(b, name, strconv.FormatUint(v, 10))
}

// iosxeLeaves writes the leaves of an interface element for the leaf set.
func iosxeLeaves(b *bytes.Buffer, leaves iosxeLeafSet, r iosxeRow) {
	switch leaves {
	case iosxeLeafOper:
		iosxeLeaf(b, "oper-status", r.Oper)
	case iosxeLeafAdmin:
		iosxeLeaf(b, "admin-status", r.Admin)
	case iosxeLeafRow:
		iosxeLeaf(b, "interface-type", r.InterfaceType)
		iosxeLeaf(b, "admin-status", r.Admin)
		iosxeLeaf(b, "oper-status", r.Oper)
		iosxeLeaf(b, "last-change", r.LastChange)
		iosxeLeaf(b, "if-index", strconv.Itoa(r.IfIndex))
		iosxeLeaf(b, "phys-address", r.PhysAddress)
		iosxeNum(b, "speed", r.Speed)
		s := r.Stats
		b.WriteString("<statistics>")
		iosxeLeaf(b, "discontinuity-time", s.DiscontinuityTime)
		iosxeNum(b, "in-octets", s.InOctets)
		iosxeNum(b, "in-unicast-pkts", s.InUnicastPkts)
		iosxeNum(b, "in-broadcast-pkts", s.InBroadcastPkts)
		iosxeNum(b, "in-multicast-pkts", s.InMulticastPkts)
		iosxeNum(b, "in-discards", s.InDiscards)
		iosxeNum(b, "in-errors", s.InErrors)
		iosxeNum(b, "out-octets", s.OutOctets)
		iosxeNum(b, "out-unicast-pkts", s.OutUnicastPkts)
		iosxeNum(b, "out-broadcast-pkts", s.OutBroadcastPkts)
		iosxeNum(b, "out-multicast-pkts", s.OutMulticastPkts)
		iosxeNum(b, "out-discards", s.OutDiscards)
		iosxeNum(b, "out-errors", s.OutErrors)
		b.WriteString("</statistics>")
	}
}

func iosxeOpen(b *bytes.Buffer, subID uint32, at time.Time, element string) {
	b.WriteString(`<notification xmlns="` + iosxeNSNotification + `"><eventTime>` + iosxeEventTime(at) +
		`</eventTime><` + element + ` xmlns="` + iosxeNSYangPush + `"><subscription-id>` +
		strconv.FormatUint(uint64(subID), 10) + `</subscription-id>`)
}

func renderPushChangeUpdate(subID uint32, at time.Time, leaves iosxeLeafSet, row iosxeRow) []byte {
	var b bytes.Buffer
	iosxeOpen(&b, subID, at, "push-change-update")
	b.WriteString(`<datastore-changes-xml><yang-patch xmlns="` + iosxeNSYangPatch +
		`"><patch-id>null</patch-id><edit><edit-id>edit1</edit-id><operation>merge</operation><target>`)
	_ = xml.EscapeText(&b, []byte(iosxeTargetKey(row.Name)))
	b.WriteString(`</target><value><interface xmlns="` + iosxeNSIfOper + `">`)
	iosxeLeaves(&b, leaves, row)
	b.WriteString(`</interface></value></edit></yang-patch></datastore-changes-xml></push-change-update></notification>`)
	return b.Bytes()
}

func renderPushUpdate(subID uint32, at time.Time, leaves iosxeLeafSet, row *iosxeRow) []byte {
	var b bytes.Buffer
	iosxeOpen(&b, subID, at, "push-update")
	if row == nil {
		b.WriteString(`<datastore-contents-xml/>`)
	} else {
		b.WriteString(`<datastore-contents-xml><interfaces xmlns="` + iosxeNSIfOper + `"><interface>`)
		iosxeLeaf(&b, "name", row.Name)
		iosxeLeaves(&b, leaves, *row)
		b.WriteString(`</interface></interfaces></datastore-contents-xml>`)
	}
	b.WriteString(`</push-update></notification>`)
	return b.Bytes()
}
