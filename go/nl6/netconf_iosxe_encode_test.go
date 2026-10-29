/*
 * Copyright 2026 Ronny Trommer <ronny@no42.org>
 * SPDX-License-Identifier: Apache-2.0
 */

package main

import (
	"os"
	"strings"
	"testing"
	"time"
)

func iosxeFixture(t *testing.T, name string) string {
	t.Helper()
	b, err := os.ReadFile("testdata/netconf/" + name)
	if err != nil {
		t.Fatal(err)
	}
	return strings.TrimSpace(string(b))
}

func TestNetconfIosxeOperMapping(t *testing.T) {
	cases := []struct {
		admin, oper uint8
		want        string
	}{
		{AdminDown, OperUp, "if-oper-state-no-pass"},
		{AdminDown, OperDown, "if-oper-state-no-pass"},
		{AdminTesting, OperUp, "if-oper-state-test"},
		{AdminUp, OperUp, "if-oper-state-ready"},
		{AdminUp, OperDown, "if-oper-state-lower-layer-down"},
		{AdminUp, OperLowerLayerDn, "if-oper-state-lower-layer-down"},
		{AdminUp, OperTesting, "if-oper-state-test"},
		{AdminUp, OperUnknown, "if-oper-state-unknown"},
		{AdminUp, OperDormant, "if-oper-state-dormant"},
		{AdminUp, OperNotPresent, "if-oper-state-not-present"},
	}
	for _, c := range cases {
		if got := iosxeOperStatus(c.admin, c.oper); got != c.want {
			t.Errorf("iosxeOperStatus(%d,%d) = %q, want %q", c.admin, c.oper, got, c.want)
		}
	}
	admins := map[uint8]string{
		AdminUp: "if-state-up", AdminDown: "if-state-down",
		AdminTesting: "if-state-test", 99: "if-state-unknown",
	}
	for a, want := range admins {
		if got := iosxeAdminStatus(a); got != want {
			t.Errorf("iosxeAdminStatus(%d) = %q, want %q", a, got, want)
		}
	}
	if iosxeOperInvalid != "if-oper-state-invalid" {
		t.Errorf("iosxeOperInvalid = %q", iosxeOperInvalid)
	}
}

func TestNetconfTargetKeyEscaping(t *testing.T) {
	cases := map[string]string{
		"GigabitEthernet1/0/24": "/interfaces/interface=GigabitEthernet1%2F0%2F24",
		"Loopback999":           "/interfaces/interface=Loopback999",
		"Gi1/0/1.100":           "/interfaces/interface=Gi1%2F0%2F1.100",
		"a b":                   "/interfaces/interface=a%20b",
		"x:y":                   "/interfaces/interface=x:y",
	}
	for in, want := range cases {
		if got := iosxeTargetKey(in); got != want {
			t.Errorf("iosxeTargetKey(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestNetconfTimeFormats(t *testing.T) {
	if got := iosxeEventTime(time.Date(2026, 10, 29, 11, 10, 17, 420_000_000, time.UTC)); got != "2026-10-29T11:10:17.42Z" {
		t.Errorf("iosxeEventTime = %q", got)
	}
	if got := iosxeTimestamp(time.Date(2026, 10, 28, 23, 52, 46, 271_000_000, time.UTC)); got != "2026-10-28T23:52:46.271000+00:00" {
		t.Errorf("iosxeTimestamp = %q", got)
	}
}

func TestNetconfPushChangeUpdateMatchesCat9300(t *testing.T) {
	at := time.Date(2026, 10, 29, 11, 12, 49, 200_000_000, time.UTC)
	row := iosxeRow{Name: "GigabitEthernet1/0/24", Admin: "if-state-up", Oper: "if-oper-state-lower-layer-down"}
	got := string(renderPushChangeUpdate(2147483651, at, iosxeLeafOper, row))
	if want := iosxeFixture(t, "cat9300-push-change-update-oper.xml"); got != want {
		t.Errorf("oper leaf mismatch\n got: %s\nwant: %s", got, want)
	}
	at = time.Date(2026, 10, 29, 11, 12, 49, 590_000_000, time.UTC)
	got = string(renderPushChangeUpdate(2147483652, at, iosxeLeafAdmin, row))
	if !strings.Contains(got, "<subscription-id>2147483652</subscription-id>") ||
		!strings.Contains(got, "<value><interface xmlns=\"http://cisco.com/ns/yang/Cisco-IOS-XE-interfaces-oper\"><admin-status>if-state-up</admin-status></interface></value>") ||
		!strings.Contains(got, "<eventTime>2026-10-29T11:12:49.59Z</eventTime>") {
		t.Errorf("admin leaf unexpected: %s", got)
	}

	at = time.Date(2026, 10, 29, 11, 12, 49, 980_000_000, time.UTC)
	full := iosxeRow{
		Name: "GigabitEthernet1/0/24", InterfaceType: "iana-iftype-ethernet-csmacd",
		Admin: "if-state-up", Oper: "if-oper-state-lower-layer-down",
		LastChange: "2026-10-28T23:52:45.647000+00:00", IfIndex: 66,
		PhysAddress: "68:e5:9e:cd:02:18", Speed: 1000000000,
		Stats: iosxeStats{DiscontinuityTime: "2026-10-28T23:44:58.400000+00:00"},
	}
	got = string(renderPushChangeUpdate(2147483653, at, iosxeLeafRow, full))
	want := stripUnservedRowLeaves(t, iosxeFixture(t, "cat9300-push-change-update-row.xml"))
	if got != want {
		t.Errorf("row mismatch\n got: %s\nwant: %s", got, want)
	}
	// The stripped fixture must still carry the served leaves.
	if !strings.Contains(want, "<speed>1000000000</speed>") || !strings.Contains(want, "<out-errors>0</out-errors></statistics></interface>") {
		t.Errorf("stripper removed served leaves: %s", want)
	}
}

func TestNetconfPushUpdateEmptyMatchesCat9300(t *testing.T) {
	at := time.Date(2026, 10, 29, 12, 8, 10, 490_000_000, time.UTC)
	got := string(renderPushUpdate(2147483656, at, iosxeLeafOper, nil))
	if want := iosxeFixture(t, "cat9300-push-update-empty.xml"); got != want {
		t.Errorf("empty mismatch\n got: %s\nwant: %s", got, want)
	}
}

func TestNetconfPushUpdateFirstMatchesCat9300(t *testing.T) {
	at := time.Date(2026, 10, 29, 11, 10, 17, 420_000_000, time.UTC)
	row := iosxeRow{Name: "AppGigabitEthernet1/0/1", Admin: "if-state-up", Oper: "if-oper-state-ready"}
	got := string(renderPushUpdate(2147483648, at, iosxeLeafOper, &row))
	if want := iosxeFixture(t, "cat9300-push-update-first.xml"); got != want {
		t.Errorf("first mismatch\n got: %s\nwant: %s", got, want)
	}
}

// stripUnservedRowLeaves removes the interface and statistics children that
// nl6 does not source, keeping the device's exact bytes for the rest.
func stripUnservedRowLeaves(t *testing.T, doc string) string {
	t.Helper()
	servedTop := map[string]bool{
		"interface-type": true, "admin-status": true, "oper-status": true, "last-change": true,
		"if-index": true, "phys-address": true, "speed": true, "statistics": true,
	}
	servedStats := map[string]bool{
		"discontinuity-time": true, "in-octets": true, "in-unicast-pkts": true, "in-broadcast-pkts": true,
		"in-multicast-pkts": true, "in-discards": true, "in-errors": true, "out-octets": true,
		"out-unicast-pkts": true, "out-broadcast-pkts": true, "out-multicast-pkts": true,
		"out-discards": true, "out-errors": true,
	}
	const open = `<interface xmlns="http://cisco.com/ns/yang/Cisco-IOS-XE-interfaces-oper">`
	i := strings.Index(doc, open)
	j := strings.Index(doc, "</interface>")
	if i < 0 || j < 0 {
		t.Fatalf("no interface element in fixture")
	}
	i += len(open)
	body := filterChildren(t, doc[i:j], servedTop, func(name, raw string) string {
		if name != "statistics" {
			return raw
		}
		inner := strings.TrimSuffix(strings.TrimPrefix(raw, "<statistics>"), "</statistics>")
		return "<statistics>" + filterChildren(t, inner, servedStats, nil) + "</statistics>"
	})
	return doc[:i] + body + doc[j:]
}

// filterChildren keeps the named direct children of an XML fragment.
func filterChildren(t *testing.T, frag string, keep map[string]bool, rewrite func(name, raw string) string) string {
	t.Helper()
	var out strings.Builder
	for len(frag) > 0 {
		if frag[0] != '<' {
			t.Fatalf("unexpected text in fragment: %.40s", frag)
		}
		end := strings.IndexByte(frag, '>')
		tag := frag[1:end]
		name := tag
		if k := strings.IndexAny(tag, " /"); k >= 0 {
			name = tag[:k]
		}
		var raw string
		if strings.HasSuffix(tag, "/") {
			raw = frag[:end+1]
		} else {
			depth, pos := 0, 0
			for {
				lt := strings.IndexByte(frag[pos:], '<')
				if lt < 0 {
					t.Fatalf("unterminated element %s", name)
				}
				pos += lt
				gt := strings.IndexByte(frag[pos:], '>')
				tg := frag[pos+1 : pos+gt]
				switch {
				case strings.HasPrefix(tg, "/"):
					depth--
				case !strings.HasSuffix(tg, "/"):
					depth++
				}
				pos += gt + 1
				if depth == 0 {
					break
				}
			}
			raw = frag[:pos]
		}
		frag = frag[len(raw):]
		if keep[name] {
			if rewrite != nil {
				raw = rewrite(name, raw)
			}
			out.WriteString(raw)
		}
	}
	return out.String()
}
