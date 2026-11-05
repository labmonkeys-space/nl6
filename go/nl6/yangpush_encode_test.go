/*
 * Copyright 2026 Ronny Trommer <ronny@no42.org>
 * SPDX-License-Identifier: Apache-2.0
 */

package main

import (
	"bytes"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"
)

const (
	ypTestPublisher = uint32(3221225997)
	ypTestHost      = "ne8000-sim-1"
)

func ypFixture(t *testing.T, name string) []byte {
	t.Helper()
	b, err := os.ReadFile(filepath.Join("testdata", "yangpush", "huawei", name))
	if err != nil {
		t.Fatal(err)
	}
	return bytes.TrimRight(b, "\n")
}

func ypMustTime(t *testing.T, s string) time.Time {
	t.Helper()
	v, err := time.Parse(time.RFC3339Nano, s)
	if err != nil {
		t.Fatal(err)
	}
	return v
}

func ypCompare(t *testing.T, got []byte, fixture string) {
	t.Helper()
	want := ypFixture(t, fixture)
	if !bytes.Equal(got, want) {
		t.Errorf("%s mismatch\n got: %s\nwant: %s", fixture, got, want)
	}
	if !json.Valid(got) {
		t.Errorf("%s: output is not valid JSON", fixture)
	}
}

func ypTestIfaces(stats bool) []ypIface {
	st := iosxeStats{DiscontinuityTime: "2026-01-07T06:46:41Z"}
	first := ypIface{Name: "GigabitEthernet0/1/0", Type: "iana-if-type:ethernetCsmacd", Admin: "up", Oper: "up",
		Enabled: true, IfIndex: 1, Speed: 1000000000, Stats: st}
	second := ypIface{Name: "GigabitEthernet0/1/1", Type: "iana-if-type:ethernetCsmacd", Admin: "up", Oper: "down",
		Enabled: true, IfIndex: 2, Speed: 1000000000, Stats: st}
	if stats {
		first.Stats = iosxeStats{DiscontinuityTime: st.DiscontinuityTime,
			InOctets: 138303671, InUnicastPkts: 166138, InBroadcastPkts: 24780, InMulticastPkts: 1184847,
			OutOctets: 17399464, OutUnicastPkts: 29798, OutBroadcastPkts: 617, OutMulticastPkts: 37558}
	}
	return []ypIface{first, second}
}

func ypStarted(t *testing.T, s ypSub) []byte {
	return encodeEnvelope(ypMustTime(t, "2026-01-20T08:14:55.372Z"), ypTestHost, 0, encodeSubscriptionStarted(s, ypTestPublisher))
}

func TestEncodeSubscriptionStartedPeriodic(t *testing.T) {
	ypCompare(t, ypStarted(t, vrpSubs[0]), "subscription-started-8.json")
	ypCompare(t, ypStarted(t, vrpSubs[1]), "subscription-started-9.json")
}

func TestEncodeSubscriptionStartedOnChange(t *testing.T) {
	ypCompare(t, ypStarted(t, vrpSubs[2]), "subscription-started-10.json")
}

func ypUpdate(t *testing.T, s ypSub, ifs []ypIface) []byte {
	c := encodePushUpdate(s, ypMustTime(t, "2026-01-20T08:16:30.365Z"), ypTestPublisher, ifs)
	return encodeEnvelope(ypMustTime(t, "2026-01-20T08:16:33.401Z"), ypTestHost, 1, c)
}

func TestEncodePushUpdateStatistics(t *testing.T) {
	ypCompare(t, ypUpdate(t, vrpSubs[0], ypTestIfaces(true)), "push-update-8.json")
}

func TestEncodePushUpdateInterface(t *testing.T) {
	ypCompare(t, ypUpdate(t, vrpSubs[1], ypTestIfaces(false)), "push-update-9.json")
}

func TestEncodePushUpdateOnChangeSync(t *testing.T) {
	ypCompare(t, ypUpdate(t, vrpSubs[2], ypTestIfaces(false)), "push-update-10.json")
}

func ypChange(t *testing.T, ifc ypIface, changed StateLeafBits) []byte {
	c := encodePushChangeUpdate(vrpSubs[2], ypMustTime(t, "2026-01-20T08:17:12.240Z"), ypTestPublisher, "edit1", ifc, changed)
	return encodeEnvelope(ypMustTime(t, "2026-01-20T08:17:12.250Z"), ypTestHost, 1, c)
}

func TestEncodePushChangeUpdateOper(t *testing.T) {
	ifc := ypTestIfaces(false)[0]
	ifc.Oper = "down"
	ypCompare(t, ypChange(t, ifc, LeafOperStatus), "push-change-update-10.json")
}

func TestEncodePushChangeUpdateAdmin(t *testing.T) {
	ifc := ypTestIfaces(false)[0]
	ifc.Admin, ifc.Oper = "down", "down"
	got := ypChange(t, ifc, LeafAdminStatus|LeafOperStatus)
	want := `{"ietf-yp-notification:envelope":{"event-time":"2026-01-20T08:17:12.250Z","hostname":"ne8000-sim-1","sequence-number":1,"contents":{"ietf-yang-push:push-change-update":{"id":10,"ietf-yp-observation:timestamp":"2026-01-20T08:17:12.240Z","ietf-yp-observation:point-in-time":"current-accounting","ietf-distributed-notif:message-publisher-id":3221225997,"datastore-changes":{"yang-patch":{"patch-id":"0","edit":[{"edit-id":"edit1","operation":"merge","target":"/ietf-interfaces:interfaces/interface=GigabitEthernet0%2F1%2F0","value":{"ietf-interfaces:interface":[{"name":"GigabitEthernet0/1/0","admin-status":"down","oper-status":"down"}]}}]}}}}}}`
	if string(got) != want {
		t.Errorf("got:  %s\nwant: %s", got, want)
	}
}

func TestEncodeEnvelopeSequence(t *testing.T) {
	ts := ypMustTime(t, "2026-01-20T08:14:55.372Z")
	for _, seq := range []uint64{0, 1, 4294967296} {
		got := encodeEnvelope(ts, "a<b>&\"", seq, []byte(`{}`))
		var v struct {
			E struct {
				EventTime string `json:"event-time"`
				Hostname  string `json:"hostname"`
				Seq       uint64 `json:"sequence-number"`
			} `json:"ietf-yp-notification:envelope"`
		}
		if err := json.Unmarshal(got, &v); err != nil {
			t.Fatalf("seq %d: %v: %s", seq, err, got)
		}
		if v.E.Seq != seq || v.E.Hostname != "a<b>&\"" || v.E.EventTime != "2026-01-20T08:14:55.372Z" {
			t.Errorf("seq %d: decoded %+v", seq, v.E)
		}
	}
}

func TestYpIfaceTypeIdentity(t *testing.T) {
	for ifType, want := range map[int]string{
		6: "iana-if-type:ethernetCsmacd", 24: "iana-if-type:softwareLoopback",
		23: "iana-if-type:ppp", 9999: "iana-if-type:other", 0: "iana-if-type:other",
	} {
		if got := ypIfaceFrom(iosxeRow{}, ifType, 0).Type; got != want {
			t.Errorf("ifType %d = %q, want %q", ifType, got, want)
		}
	}
}

func TestYpIfaceFromStatus(t *testing.T) {
	cases := []struct {
		admin, oper, wantAdmin, wantOper string
		enabled                          bool
	}{
		{iosxeAdminStatus(AdminUp), iosxeOperStatus(AdminUp, OperUp), "up", "up", true},
		{iosxeAdminStatus(AdminUp), iosxeOperStatus(AdminUp, OperDown), "up", "down", true},
		{iosxeAdminStatus(AdminUp), iosxeOperStatus(AdminUp, OperLowerLayerDn), "up", "down", true},
		{iosxeAdminStatus(AdminDown), iosxeOperStatus(AdminDown, OperDown), "down", "down", false},
		{iosxeAdminStatus(AdminTesting), iosxeOperStatus(AdminTesting, OperUp), "testing", "testing", true},
		{iosxeAdminStatus(AdminUp), iosxeOperStatus(AdminUp, OperDormant), "up", "dormant", true},
		{iosxeAdminStatus(AdminUp), iosxeOperStatus(AdminUp, OperNotPresent), "up", "not-present", true},
		{iosxeAdminStatus(AdminUp), iosxeOperInvalid, "up", "unknown", true},
	}
	for _, c := range cases {
		got := ypIfaceFrom(iosxeRow{Admin: c.admin, Oper: c.oper, Stats: iosxeStats{DiscontinuityTime: "2026-01-07T06:46:41.000000+00:00"}}, 6, 7)
		if got.Admin != c.wantAdmin || got.Oper != c.wantOper || got.Enabled != c.enabled {
			t.Errorf("%s/%s = %s/%s enabled=%v", c.admin, c.oper, got.Admin, got.Oper, got.Enabled)
		}
		if got.InUnknownProtos != 7 || got.Stats.DiscontinuityTime != "2026-01-07T06:46:41Z" {
			t.Errorf("unknown protos / discontinuity: %+v", got)
		}
	}
}

func TestYangPushPayloadsValidateWithYanglint(t *testing.T) {
	yl, err := exec.LookPath("yanglint")
	if err != nil {
		t.Skip("yanglint not on PATH")
	}
	dir := t.TempDir()
	for _, m := range vrpYangModules() {
		if err := os.WriteFile(filepath.Join(dir, m.Name+"@"+m.Revision+".yang"), m.Source, 0o644); err != nil {
			t.Fatal(err)
		}
	}
	// The envelope is an sx:structure, which yanglint cannot take as data.
	// Validate the notification inside "contents" as a top-level notification.
	for _, name := range []string{"subscription-started-8", "subscription-started-9", "subscription-started-10",
		"push-update-8", "push-update-9", "push-change-update-10"} {
		var env struct {
			E struct {
				Contents json.RawMessage `json:"contents"`
			} `json:"ietf-yp-notification:envelope"`
		}
		if err := json.Unmarshal(ypFixture(t, name+".json"), &env); err != nil {
			t.Fatal(err)
		}
		file := filepath.Join(dir, name+".json")
		if err := os.WriteFile(file, env.E.Contents, 0o644); err != nil {
			t.Fatal(err)
		}
		args := []string{"-p", dir, "-f", "json", "-t", "notif",
			"-F", "ietf-subscribed-notifications:*", "-F", "ietf-yang-push:*",
			filepath.Join(dir, "ietf-interfaces@2018-02-20.yang")}
		for _, mod := range []string{"ietf-subscribed-notifications", "ietf-yang-push", "ietf-yang-push-revision",
			"ietf-distributed-notif", "ietf-udp-notif-transport", "ietf-yp-observation", "ietf-yang-patch"} {
			if m, ok := vrpYangModule(mod, ""); ok {
				args = append(args, filepath.Join(dir, m.Name+"@"+m.Revision+".yang"))
			}
		}
		args = append(args, file)
		if out, err := exec.Command(yl, args...).CombinedOutput(); err != nil {
			t.Errorf("%s: yanglint: %v\n%s", name, err, out)
		}
	}
}
