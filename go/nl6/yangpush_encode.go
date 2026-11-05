/*
 * Copyright 2026 Ronny Trommer <ronny@no42.org>
 * SPDX-License-Identifier: Apache-2.0
 */

package main

import (
	"bytes"
	"encoding/json"
	"strconv"
	"strings"
	"time"
)

// ypSub describes one YANG-Push subscription a simulated VRP device serves.
type ypSub struct {
	ID               uint32
	XPath, FilterRef string
	Periodic         bool
	PeriodCs         uint32
	Anchor           time.Time
}

const (
	ypXPathStatistics = "/ietf-interfaces:interfaces/interface/statistics"
	ypXPathInterface  = "/ietf-interfaces:interfaces/interface"
	ypXPathOnChange   = "/ietf-interfaces:interfaces/interface/oper-status | /ietf-interfaces:interfaces/interface/admin-status"
)

var ypAnchor = time.Date(2025, 1, 1, 0, 0, 30, 0, time.UTC)

// vrpSubs lists the subscriptions a NE8000 model exposes: ids 8, 9 and 10.
var vrpSubs = [3]ypSub{
	{ID: 8, XPath: ypXPathStatistics, FilterRef: "STATEINTERFACE2", Periodic: true, PeriodCs: 6000, Anchor: ypAnchor},
	{ID: 9, XPath: ypXPathInterface, FilterRef: "STATSINTERFACE2", Periodic: true, PeriodCs: 6000, Anchor: ypAnchor},
	{ID: 10, XPath: ypXPathOnChange, FilterRef: "ONCHANGEINTERFACE"},
}

// ypIface holds the ietf-interfaces leaves nl6 serves for one interface.
type ypIface struct {
	Name, Type, Admin, Oper string
	Enabled                 bool
	IfIndex                 int
	Speed                   uint64
	Stats                   iosxeStats
	InUnknownProtos         uint32
}

// ypIfTypes maps IANA ifType numbers to iana-if-type identities.
var ypIfTypes = map[int]string{
	6:   "ethernetCsmacd",
	23:  "ppp",
	24:  "softwareLoopback",
	53:  "propVirtual",
	131: "tunnel",
	135: "l2vlan",
	136: "l3ipvlan",
	161: "ieee8023adLag",
}

func ypTypeIdentity(ifType int) string {
	if id, ok := ypIfTypes[ifType]; ok {
		return "iana-if-type:" + id
	}
	return "iana-if-type:other"
}

var ypAdminStatus = map[string]string{
	"if-state-up":      "up",
	"if-state-down":    "down",
	"if-state-test":    "testing",
	"if-state-unknown": "unknown",
}

var ypOperStatus = map[string]string{
	"if-oper-state-ready":   "up",
	"if-oper-state-no-pass": "down",
	// The IOS XE string folds IF-MIB down(2) and lowerLayerDown(7) together.
	// The captured NE8000 reports admin up / oper down for a dead link and
	// never lower-layer-down, so it maps to down.
	"if-oper-state-lower-layer-down": "down",
	"if-oper-state-test":             "testing",
	"if-oper-state-unknown":          "unknown",
	"if-oper-state-dormant":          "dormant",
	"if-oper-state-not-present":      "not-present",
}

// ypIfaceFrom converts an IOS XE row into ietf-interfaces values.
func ypIfaceFrom(row iosxeRow, ifType int, inUnknownProtos uint32) ypIface {
	admin, ok := ypAdminStatus[row.Admin]
	if !ok {
		admin = "unknown"
	}
	oper, ok := ypOperStatus[row.Oper]
	if !ok {
		oper = "unknown"
	}
	stats := row.Stats
	if t, err := time.Parse("2006-01-02T15:04:05.000000+00:00", stats.DiscontinuityTime); err == nil {
		stats.DiscontinuityTime = t.UTC().Format("2006-01-02T15:04:05Z")
	}
	return ypIface{
		Name:            row.Name,
		Type:            ypTypeIdentity(ifType),
		Admin:           admin,
		Oper:            oper,
		Enabled:         admin != "down",
		IfIndex:         row.IfIndex,
		Speed:           row.Speed,
		Stats:           stats,
		InUnknownProtos: inUnknownProtos,
	}
}

func ypMillis(t time.Time) string  { return t.UTC().Format("2006-01-02T15:04:05.000Z") }
func ypSeconds(t time.Time) string { return t.UTC().Format("2006-01-02T15:04:05Z") }

// ypStr writes s as a JSON string without HTML escaping.
func ypStr(b *bytes.Buffer, s string) {
	var tmp bytes.Buffer
	enc := json.NewEncoder(&tmp)
	enc.SetEscapeHTML(false)
	_ = enc.Encode(s)
	b.Write(bytes.TrimRight(tmp.Bytes(), "\n"))
}

func ypU64Str(b *bytes.Buffer, v uint64) {
	b.WriteByte('"')
	b.WriteString(strconv.FormatUint(v, 10))
	b.WriteByte('"')
}

// encodeEnvelope wraps contents in the ietf-yp-notification envelope.
func encodeEnvelope(eventTime time.Time, hostname string, seq uint64, contents []byte) []byte {
	var b bytes.Buffer
	b.WriteString(`{"ietf-yp-notification:envelope":{"event-time":"`)
	b.WriteString(ypMillis(eventTime))
	b.WriteString(`","hostname":`)
	ypStr(&b, hostname)
	b.WriteString(`,"sequence-number":`)
	b.WriteString(strconv.FormatUint(seq, 10))
	b.WriteString(`,"contents":`)
	b.Write(contents)
	b.WriteString("}}")
	return b.Bytes()
}

// encodeSubscriptionStarted renders the envelope contents for a started subscription.
func encodeSubscriptionStarted(s ypSub, publisherID uint32) []byte {
	var b bytes.Buffer
	b.WriteString(`{"ietf-subscribed-notifications:subscription-started":{"id":`)
	b.WriteString(strconv.FormatUint(uint64(s.ID), 10))
	b.WriteString(`,"ietf-yang-push:datastore":"ietf-datastores:operational","ietf-yang-push:datastore-xpath-filter":`)
	ypStr(&b, s.XPath)
	b.WriteString(`,"transport":"ietf-udp-notif-transport:udp-notif","encoding":"encode-json","ietf-distributed-notif:message-publisher-id":[`)
	b.WriteString(strconv.FormatUint(uint64(publisherID), 10))
	b.WriteString(`],"ietf-yang-push-revision:module-version":[{"name":"ietf-interfaces","revision":`)
	rev := ""
	if m, ok := vrpYangModule("ietf-interfaces", ""); ok {
		rev = m.Revision
	}
	ypStr(&b, rev)
	b.WriteString(`}],"ietf-yang-push-revision:yang-library-content-id":`)
	ypStr(&b, vrpContentID())
	if s.Periodic {
		b.WriteString(`,"ietf-yang-push:periodic":{"period":`)
		b.WriteString(strconv.FormatUint(uint64(s.PeriodCs), 10))
		b.WriteString(`,"anchor-time":"`)
		b.WriteString(ypSeconds(s.Anchor))
		b.WriteString(`"}`)
	} else {
		b.WriteString(`,"ietf-yang-push:on-change":{"dampening-period":0,"sync-on-start":true}`)
	}
	b.WriteString("}}")
	return b.Bytes()
}

// ypObservation writes the id and the ietf-yp-observation leaves. pit is the
// point-in-time enum: current-accounting for periodic pushes, initial-state for
// the on-change sync push-update and state-changed for push-change-update.
func ypObservation(b *bytes.Buffer, s ypSub, obs time.Time, publisherID uint32, pit string) {
	b.WriteString(`"id":`)
	b.WriteString(strconv.FormatUint(uint64(s.ID), 10))
	b.WriteString(`,"ietf-yp-observation:timestamp":"`)
	b.WriteString(ypMillis(obs))
	b.WriteString(`","ietf-yp-observation:point-in-time":"` + pit + `","ietf-distributed-notif:message-publisher-id":`)
	b.WriteString(strconv.FormatUint(uint64(publisherID), 10))
}

func ypStatistics(b *bytes.Buffer, i ypIface) {
	st := i.Stats
	b.WriteString(`"statistics":{"discontinuity-time":"`)
	b.WriteString(st.DiscontinuityTime)
	b.WriteByte('"')
	u64 := func(k string, v uint64) {
		b.WriteString(`,"` + k + `":`)
		ypU64Str(b, v)
	}
	u32 := func(k string, v uint64) {
		b.WriteString(`,"` + k + `":` + strconv.FormatUint(v&0xffffffff, 10)) // Counter32 wraps
	}
	u64("in-octets", st.InOctets)
	u64("in-unicast-pkts", st.InUnicastPkts)
	u64("in-broadcast-pkts", st.InBroadcastPkts)
	u64("in-multicast-pkts", st.InMulticastPkts)
	u32("in-discards", st.InDiscards)
	u32("in-errors", st.InErrors)
	u32("in-unknown-protos", uint64(i.InUnknownProtos))
	u64("out-octets", st.OutOctets)
	u64("out-unicast-pkts", st.OutUnicastPkts)
	u64("out-broadcast-pkts", st.OutBroadcastPkts)
	u64("out-multicast-pkts", st.OutMulticastPkts)
	u32("out-discards", st.OutDiscards)
	u32("out-errors", st.OutErrors)
	b.WriteByte('}')
}

// ypKeyEscape percent-encodes a list key value for a target path. Only the
// RFC 3986 unreserved set stays literal (RFC 8040 section 3.5.3).
func ypKeyEscape(v string) string {
	const hex = "0123456789ABCDEF"
	var b strings.Builder
	for i := 0; i < len(v); i++ {
		c := v[i]
		if c >= 'A' && c <= 'Z' || c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '-' || c == '.' || c == '_' || c == '~' {
			b.WriteByte(c)
			continue
		}
		b.WriteByte('%')
		b.WriteByte(hex[c>>4])
		b.WriteByte(hex[c&15])
	}
	return b.String()
}

// encodePushUpdate renders a push-update for subscription s. A periodic
// subscription reports current-accounting; the on-change subscription's sync
// snapshot reports initial-state.
func encodePushUpdate(s ypSub, obs time.Time, publisherID uint32, ifs []ypIface) []byte {
	var b bytes.Buffer
	b.WriteString(`{"ietf-yang-push:push-update":{`)
	pit := "current-accounting"
	if !s.Periodic {
		pit = "initial-state"
	}
	ypObservation(&b, s, obs, publisherID, pit)
	b.WriteString(`,"datastore-contents":{"ietf-interfaces:interfaces":{"interface":[`)
	for n, i := range ifs {
		if n > 0 {
			b.WriteByte(',')
		}
		b.WriteString(`{"name":`)
		ypStr(&b, i.Name)
		switch {
		case s.XPath == ypXPathStatistics:
			b.WriteByte(',')
			ypStatistics(&b, i)
		case s.XPath == ypXPathOnChange:
			// Subscription 10's filter selects only the two status leaves.
			b.WriteString(`,"admin-status":`)
			ypStr(&b, i.Admin)
			b.WriteString(`,"oper-status":`)
			ypStr(&b, i.Oper)
		default:
			b.WriteString(`,"type":`)
			ypStr(&b, i.Type)
			b.WriteString(`,"enabled":` + strconv.FormatBool(i.Enabled))
			b.WriteString(`,"link-up-down-trap-enable":"enabled","admin-status":`)
			ypStr(&b, i.Admin)
			b.WriteString(`,"oper-status":`)
			ypStr(&b, i.Oper)
			b.WriteString(`,"if-index":` + strconv.Itoa(i.IfIndex))
			if i.Speed > 0 {
				b.WriteString(`,"speed":`)
				ypU64Str(&b, i.Speed)
			}
		}
		b.WriteByte('}')
	}
	b.WriteString("]}}}}")
	return b.Bytes()
}

// encodePushChangeUpdate renders an on-change push-change-update carrying the
// changed status leaves of ifc as one merge edit.
func encodePushChangeUpdate(s ypSub, obs time.Time, publisherID uint32, editID string, ifc ypIface, changed StateLeafBits) []byte {
	var b bytes.Buffer
	b.WriteString(`{"ietf-yang-push:push-change-update":{`)
	ypObservation(&b, s, obs, publisherID, "state-changed")
	b.WriteString(`,"datastore-changes":{"yang-patch":{"patch-id":"0","edit":[{"edit-id":`)
	ypStr(&b, editID)
	b.WriteString(`,"operation":"merge","target":`)
	ypStr(&b, "/ietf-interfaces:interfaces/interface="+ypKeyEscape(ifc.Name))
	b.WriteString(`,"value":{"ietf-interfaces:interface":[{"name":`)
	ypStr(&b, ifc.Name)
	if changed&LeafAdminStatus != 0 {
		b.WriteString(`,"admin-status":`)
		ypStr(&b, ifc.Admin)
	}
	if changed&LeafOperStatus != 0 {
		b.WriteString(`,"oper-status":`)
		ypStr(&b, ifc.Oper)
	}
	b.WriteString("}]}}]}}}}")
	return b.Bytes()
}
