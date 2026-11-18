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
		Enabled: true, IfIndex: 1, Speed: 1000000000, Stats: st,
		Description: "uplink-a", LastChange: "2026-01-07T06:46:41Z", PhysAddress: "00:00:5e:00:53:01"}
	second := ypIface{Name: "GigabitEthernet0/1/1", Type: "iana-if-type:ethernetCsmacd", Admin: "up", Oper: "down",
		Enabled: true, IfIndex: 2, Speed: 1000000000, Stats: st,
		LastChange: "2026-01-07T06:46:41Z", PhysAddress: "00:00:5e:00:53:02"}
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

func ypChange(t *testing.T, patchID uint64, ifcs []ypIface) []byte {
	c := encodePushChangeUpdate(vrpSubs[2], ypMustTime(t, "2026-01-20T08:17:12.240Z"), ypTestPublisher, patchID, ifcs)
	return encodeEnvelope(ypMustTime(t, "2026-01-20T08:17:12.250Z"), ypTestHost, 1, c)
}

// ypEdits decodes the yang-patch of a change-update envelope.
func ypEdits(t *testing.T, raw []byte) (patchID string, edits []struct {
	EditID string          `json:"edit-id"`
	Target string          `json:"target"`
	Value  json.RawMessage `json:"value"`
}) {
	t.Helper()
	var env struct {
		E struct {
			C struct {
				U struct {
					D struct {
						P struct {
							ID   string `json:"patch-id"`
							Edit []struct {
								EditID string          `json:"edit-id"`
								Target string          `json:"target"`
								Value  json.RawMessage `json:"value"`
							} `json:"edit"`
						} `json:"yang-patch"`
					} `json:"datastore-changes"`
				} `json:"ietf-yang-push:push-change-update"`
			} `json:"contents"`
		} `json:"ietf-yp-notification:envelope"`
	}
	if err := json.Unmarshal(raw, &env); err != nil {
		t.Fatalf("change-update is not valid JSON: %v\n%s", err, raw)
	}
	return env.E.C.U.D.P.ID, env.E.C.U.D.P.Edit
}

func TestEncodePushChangeUpdateOneEdit(t *testing.T) {
	ifc := ypTestIfaces(false)[0]
	ifc.Oper, ifc.LastChange = "down", "2026-01-20T08:17:12Z"
	ypCompare(t, ypChange(t, 0, []ypIface{ifc}), "push-change-update-10.json")
}

func TestEncodePushChangeUpdateTwoEdits(t *testing.T) {
	id, edits := ypEdits(t, ypChange(t, 7, ypTestIfaces(false)))
	if id != "7" {
		t.Errorf("patch-id = %q, want 7", id)
	}
	if len(edits) != 2 || edits[0].EditID != "edit1" || edits[1].EditID != "edit2" {
		t.Fatalf("edits = %+v, want edit1 and edit2", edits)
	}
	if want := "/ietf-interfaces:interfaces/interface[name=GigabitEthernet0/1/1]"; edits[1].Target != want {
		t.Errorf("second target = %q, want %q", edits[1].Target, want)
	}
}

// The device writes the list key into the target as it is. Only JSON string
// escaping applies.
func TestEncodePushChangeUpdateNameIsUnescaped(t *testing.T) {
	ifc := ypTestIfaces(false)[0]
	ifc.Name = `Eth 1/0]"x`
	_, edits := ypEdits(t, ypChange(t, 0, []ypIface{ifc}))
	if want := `/ietf-interfaces:interfaces/interface[name=Eth 1/0]"x]`; len(edits) != 1 || edits[0].Target != want {
		t.Errorf("target = %+v, want %q", edits, want)
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
		if got := ypIfaceFrom(iosxeRow{}, ifType, 0, "").Type; got != want {
			t.Errorf("ifType %d = %q, want %q", ifType, got, want)
		}
	}
}

// The entry leaves beyond status come from the row and the caller: last-change
// in seconds, phys-address as six lower-case bytes, description as given.
func TestYpIfaceFromEntryLeaves(t *testing.T) {
	row := iosxeRow{Name: "x", Admin: "if-state-up", Oper: "if-oper-state-ready",
		LastChange: "2026-01-07T06:46:41.123456+00:00", PhysAddress: "00:00:5E:00:53:01"}
	got := ypIfaceFrom(row, 6, 0, "uplink-a")
	if got.LastChange != "2026-01-07T06:46:41Z" {
		t.Errorf("LastChange = %q, want 2026-01-07T06:46:41Z", got.LastChange)
	}
	if got.PhysAddress != "00:00:5e:00:53:01" {
		t.Errorf("PhysAddress = %q, want 00:00:5e:00:53:01", got.PhysAddress)
	}
	if got.Description != "uplink-a" {
		t.Errorf("Description = %q, want uplink-a", got.Description)
	}
	for _, bad := range []string{"", "00:00:5E:00:53", "00:00:5E:00:53:0G", "not a mac"} {
		row.PhysAddress, row.LastChange = bad, ""
		got := ypIfaceFrom(row, 6, 0, "")
		if got.PhysAddress != "" || got.LastChange != "" {
			t.Errorf("phys %q: PhysAddress = %q, LastChange = %q, want both empty", bad, got.PhysAddress, got.LastChange)
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
		got := ypIfaceFrom(iosxeRow{Admin: c.admin, Oper: c.oper, Stats: iosxeStats{DiscontinuityTime: "2026-01-07T06:46:41.000000+00:00"}}, 6, 7, "")
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
	// Validate against the library nl6 serves: the whole get reply. libyang
	// rejects it without <modules-state>, whose module-set-id is mandatory.
	lib := vrpYangLibraryXML()
	libFile := filepath.Join(dir, "yang-library.xml")
	if err := os.WriteFile(libFile, lib, 0o644); err != nil {
		t.Fatal(err)
	}
	// A module the library names must exist in the search path. Never drop one.
	for _, m := range vrpYangModules() {
		if !bytes.Contains(lib, []byte("<name>"+m.Name+"</name>")) {
			t.Fatalf("served library does not name module %s", m.Name)
		}
		if _, err := os.Stat(filepath.Join(dir, m.Name+"@"+m.Revision+".yang")); err != nil {
			t.Fatalf("module %s@%s missing from the search path: %v", m.Name, m.Revision, err)
		}
	}
	// The envelope is an sx:structure, which yanglint cannot take as data.
	// Validate the notification inside "contents" as a top-level notification.
	for _, name := range []string{"subscription-started-8", "subscription-started-9", "subscription-started-10",
		"push-update-8", "push-update-9", "push-update-10", "push-change-update-10"} {
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
		args := []string{"-p", dir, "-Y", libFile, "-f", "json", "-t", "notif"}
		args = append(args, file)
		if out, err := exec.Command(yl, args...).CombinedOutput(); err != nil {
			t.Errorf("%s: yanglint: %v\n%s", name, err, out)
		}
	}
}
