/*
 * Copyright 2026 Ronny Trommer <ronny@no42.org>
 * SPDX-License-Identifier: Apache-2.0
 */

package main

import (
	"bytes"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"
)

// A resource profile can carry one OID in two entries (nl6#1090): the same
// string twice, the same OID with and without its leading dot, or an arc
// written with a leading zero (.18.03 next to .18.3). Before the fix the walk
// index could map such an OID to itself, so a GETNEXT answered the OID it was
// asked about and a walker that does not check for increasing OIDs never
// finished.

const (
	dupSysDescr    = ".1.3.6.1.2.1.1.1.0"
	dupSysContact  = ".1.3.6.1.2.1.1.4.0"
	dupSysServices = ".1.3.6.1.2.1.1.7.0"
	dupRunName1    = ".1.3.6.1.2.1.25.4.2.1.2.1"
	dupRunName2    = ".1.3.6.1.2.1.25.4.2.1.2.2"
	dupRunName3    = ".1.3.6.1.2.1.25.4.2.1.2.3"
)

// dupBaseRows is the fixture without any duplicate, in resource-file order.
func dupBaseRows() []SNMPResource {
	return []SNMPResource{
		{OID: dupSysDescr, Response: "descr"},
		{OID: dupSysContact, Response: "contact"},
		{OID: dupSysServices, Response: "72"},
		{OID: dupRunName1, Response: "run-1"},
		{OID: dupRunName2, Response: "run-2"},
		{OID: dupRunName3, Response: "run-3"},
	}
}

// dupWalkOrder is what a walk of the fixture must return, in order:
// sysName.0 and sysLocation.0 are served from the device, not the index.
var dupWalkOrder = []string{
	dupSysDescr, dupSysContact, sysNameOID, sysLocationOID, dupSysServices,
	dupRunName1, dupRunName2, dupRunName3,
}

// dupSpellings are the three ways a profile can name an OID it already has.
var dupSpellings = []struct {
	name  string
	spell func(oid string) string
}{
	{"same-string", func(oid string) string { return oid }},
	{"no-leading-dot", func(oid string) string { return strings.TrimPrefix(oid, ".") }},
	{"leading-zero", func(oid string) string {
		i := strings.LastIndex(oid, ".")
		return oid[:i+1] + "0" + oid[i+1:]
	}},
}

// dupPositions are where the duplicate sits. The last OID has no successor to
// overwrite its self-entry. A mid-table OID takes the fast path; sysContact.0
// takes the slow path, because its successor steps over sysName.0.
var dupPositions = []struct{ name, twin string }{
	{"last", dupRunName3},
	{"mid-fast-path", dupRunName2},
	{"mid-slow-path", dupSysContact},
}

// dupRows returns the fixture with a second entry for twin, spelled by spell,
// placed just before or just after the original. The fixture is small enough
// that the sort keeps that order between the two, so both orders are reached.
func dupRows(twin string, spell func(string) string, plantedFirst bool) []SNMPResource {
	planted := SNMPResource{OID: spell(twin), Response: "planted"}
	var rows []SNMPResource
	for _, r := range dupBaseRows() {
		if r.OID == twin && plantedFirst {
			rows = append(rows, planted)
		}
		rows = append(rows, r)
		if r.OID == twin && !plantedFirst {
			rows = append(rows, planted)
		}
	}
	return rows
}

func dupServer(res *DeviceResources) *SNMPServer {
	return &SNMPServer{device: &DeviceSimulator{
		ID:          "dup-oid",
		IP:          net.IPv4(10, 42, 0, 1),
		resources:   res,
		sysName:     "dup-oid",
		sysLocation: "lab",
	}}
}

// assertWalkIndexAdvances checks the index itself: the sorted OIDs strictly
// increase, and no successor in oidNextMap is equal to or before its key.
func assertWalkIndexAdvances(t *testing.T, res *DeviceResources) {
	t.Helper()
	for i := 1; i < len(res.sortedOIDs); i++ {
		if compareOIDs(res.sortedOIDs[i], res.sortedOIDs[i-1]) <= 0 {
			t.Errorf("sortedOIDs[%d] = %s does not follow sortedOIDs[%d] = %s",
				i, res.sortedOIDs[i], i-1, res.sortedOIDs[i-1])
		}
	}
	res.oidNextMap.Range(func(k, v any) bool {
		if compareOIDs(v.(string), k.(string)) <= 0 {
			t.Errorf("oidNextMap[%s] = %s does not advance", k, v)
		}
		return true
	})
}

// assertWalkEnds walks the whole fixture with GETNEXT and requires every step
// to advance and the walk to end, on exactly dupWalkOrder. The bound is far
// above the fixture size, so a self-loop fails instead of hanging.
func assertWalkEnds(t *testing.T, s *SNMPServer) {
	t.Helper()
	var got []string
	cur := ".1.3.6.1.2.1.1"
	for step := 0; step < 50; step++ {
		next, _ := s.findNextOID(cur)
		if next == "" {
			if !slices.Equal(got, dupWalkOrder) {
				t.Errorf("walk returned\n  %q\nwant\n  %q", got, dupWalkOrder)
			}
			return
		}
		if compareOIDs(next, cur) <= 0 {
			t.Fatalf("GETNEXT(%s) = %s: the walk does not advance (walked %q)", cur, next, got)
		}
		got = append(got, next)
		cur = next
	}
	t.Fatalf("the walk did not end within 50 steps: %q", got)
}

// assertGetAndWalkAgree requires the value a walk serves at twin to be the
// value a GET of twin serves: whichever of the two entries wins, it wins on
// both paths.
func assertGetAndWalkAgree(t *testing.T, s *SNMPServer, twin string) {
	t.Helper()
	i := slices.Index(dupWalkOrder, twin)
	next, walked := s.findNextOID(dupWalkOrder[i-1])
	if next != twin {
		t.Fatalf("GETNEXT(%s) = %s, want %s", dupWalkOrder[i-1], next, twin)
	}
	if got := s.findResponse(twin); got != walked {
		t.Errorf("GET %s = %q but the walk serves %q", twin, got, walked)
	}
}

func TestNormaliseResourceOIDIsCanonical(t *testing.T) {
	for _, tc := range []struct{ in, want string }{
		{"1.3.6.1.2.1.1.1.0", ".1.3.6.1.2.1.1.1.0"},
		{".1.3.6.1.2.1.1.1.0", ".1.3.6.1.2.1.1.1.0"},
		{".1.3.6.1.2.1.31.1.1.1.18.03", ".1.3.6.1.2.1.31.1.1.1.18.3"},
		{"1.3.6.1.2.1.31.1.1.1.018.3", ".1.3.6.1.2.1.31.1.1.1.18.3"},
		{".1.3.6.1.2.1.1.4.00", ".1.3.6.1.2.1.1.4.0"},
		{".1.3.6.1.2.1.2.2.1.10.100", ".1.3.6.1.2.1.2.2.1.10.100"},
		{".0.0", ".0.0"},
		// Not validated here, so anything that is not an all-digit arc is
		// left as written apart from the leading dot.
		{"", ""},
		{".", "."},
		{".1..03", ".1..3"},
		{".1.3.0x", ".1.3.0x"},
		{".1.3.-01", ".1.3.-01"},
		{".1.3.+03", ".1.3.+03"},
	} {
		if got := normaliseResourceOID(tc.in); got != tc.want {
			t.Errorf("normaliseResourceOID(%q) = %q, want %q", tc.in, got, tc.want)
		}
	}
}

// TestDuplicateOIDNeverStallsAWalk plants every spelling of a duplicate at
// every position, in both orders, and requires the index to advance, the walk
// to end, and GET and walk to serve the same value.
func TestDuplicateOIDNeverStallsAWalk(t *testing.T) {
	for _, pos := range dupPositions {
		for _, sp := range dupSpellings {
			for _, plantedFirst := range []bool{true, false} {
				name := fmt.Sprintf("%s/%s/planted-first=%v", pos.name, sp.name, plantedFirst)
				t.Run(name, func(t *testing.T) {
					res := &DeviceResources{SNMP: dupRows(pos.twin, sp.spell, plantedFirst)}
					(&SimulatorManager{}).buildResourceIndexes(res)
					if _, ok := res.oidNextMap.Load(dupRunName3); ok {
						t.Errorf("the last OID %s has a successor in oidNextMap", dupRunName3)
					}
					assertWalkIndexAdvances(t, res)
					s := dupServer(res)
					assertWalkEnds(t, s)
					assertGetAndWalkAgree(t, s, pos.twin)
				})
			}
		}
	}
}

// TestDuplicateOIDFromResourceFilesInEitherOrder is the same property through
// a real loader, with the duplicate in the part read first and in the part
// read last, which is how the issue reproduced it.
func TestDuplicateOIDFromResourceFilesInEitherOrder(t *testing.T) {
	const slug = "zzdupoid"
	rowJSON := func(rows []SNMPResource) string {
		parts := make([]string, len(rows))
		for i, r := range rows {
			parts[i] = fmt.Sprintf(`{"oid":%q,"response":%q}`, r.OID, r.Response)
		}
		return `{"snmp":[` + strings.Join(parts, ",") + `]}`
	}
	for _, pos := range dupPositions {
		for _, sp := range dupSpellings {
			for _, dupFile := range []string{slug + "_snmp_000.json", slug + "_snmp_zzz.json"} {
				t.Run(pos.name+"/"+sp.name+"/"+dupFile, func(t *testing.T) {
					t.Chdir(t.TempDir())
					dir := filepath.Join("resources", slug)
					if err := os.MkdirAll(dir, 0o755); err != nil {
						t.Fatal(err)
					}
					baseFile := slug + "_snmp_000.json"
					if dupFile == baseFile {
						baseFile = slug + "_snmp_zzz.json"
					}
					planted := []SNMPResource{{OID: sp.spell(pos.twin), Response: "planted"}}
					for file, rows := range map[string][]SNMPResource{baseFile: dupBaseRows(), dupFile: planted} {
						if err := os.WriteFile(filepath.Join(dir, file), []byte(rowJSON(rows)), 0o644); err != nil {
							t.Fatal(err)
						}
					}
					sm := &SimulatorManager{resourcesCache: make(map[string]*DeviceResources)}
					res, err := sm.LoadSpecificResources(slug + ".json")
					if err != nil {
						t.Fatalf("LoadSpecificResources: %v", err)
					}
					if len(res.SNMP) != len(dupBaseRows())+1 {
						t.Fatalf("loaded %d entries, want %d", len(res.SNMP), len(dupBaseRows())+1)
					}
					assertWalkIndexAdvances(t, res)
					s := dupServer(res)
					assertWalkEnds(t, s)
					assertGetAndWalkAgree(t, s, pos.twin)
				})
			}
		}
	}
}

// TestNonAdvancingSuccessorEndsTheWalkAtEveryVersion corrupts the index the
// way a future defect could and requires every GETNEXT and GETBULK path to
// answer end of MIB instead of the stalled OID: the check sits in
// findNextOIDWithServed, which all of them call.
func TestNonAdvancingSuccessorEndsTheWalkAtEveryVersion(t *testing.T) {
	cases := []struct{ name, at, next string }{
		{"fast-path/self", dupRunName2, dupRunName2},
		{"fast-path/backwards", dupRunName2, dupRunName1},
		{"slow-path/self", dupSysContact, dupSysContact},
		{"last/self", dupRunName3, dupRunName3},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			fixture := make(map[string]string)
			for _, r := range dupBaseRows() {
				fixture[r.OID] = r.Response
			}
			s := v3TestServer(fixture)
			s.device.ID = "dup-oid"
			s.device.resources.oidNextMap.Store(tc.at, tc.next)

			var next, val string
			logged := captureLog(t, func() {
				next, val = s.findNextOID(tc.at)
				s.findNextOID(tc.at)
			})
			if next != "" || val != valueEndOfMibView {
				t.Fatalf("findNextOID(%s) = (%q, %q), want end of MIB", tc.at, next, val)
			}
			if n := strings.Count(logged, "does not advance"); n != 1 {
				t.Errorf("logged %d non-advance lines over two calls, want 1:\n%s", n, logged)
			}

			t.Run("v1-getnext", func(t *testing.T) {
				hdr := decodeResponseHeader(t, s.handleSNMPv2cRequest(v1GetNext(tc.at)))
				if hdr.errStatus != snmpErrNoSuchName {
					t.Errorf("error-status = %d, want noSuchName (%d)", hdr.errStatus, snmpErrNoSuchName)
				}
			})
			t.Run("v2c-getnext", func(t *testing.T) {
				vbs := decodeV2cVarbinds(t, s.handleSNMPv2cRequest(v2cGetNext(tc.at)))
				assertEndOfMIBBindings(t, vbs, tc.at, 1)
			})
			t.Run("v2c-getbulk", func(t *testing.T) {
				vbs := decodeV2cVarbinds(t, s.handleSNMPv2cRequest(v2cGetBulkRequest(0, 5, []string{tc.at})))
				assertEndOfMIBBindings(t, vbs, tc.at, 5)
			})
			t.Run("v2c-getbulk-non-repeater", func(t *testing.T) {
				vbs := decodeV2cVarbinds(t, s.handleSNMPv2cRequest(v2cGetBulkRequest(1, 0, []string{tc.at})))
				assertEndOfMIBBindings(t, vbs, tc.at, 1)
			})
			t.Run("v3-getnext", func(t *testing.T) {
				msg, err := s.parseSNMPv3Message(s.handleSNMPv3Request(v3GetNextRequest(t, s, 7, tc.at)))
				if err != nil {
					t.Fatalf("response does not parse as SNMPv3: %v", err)
				}
				_, oid, value := decodeScopedPDU(t, msg.ScopedPDU)
				if oid != tc.at || !bytes.Equal(value, wireEndOfMibView) {
					t.Errorf("binding %s = % x, want %s = endOfMibView", oid, value, tc.at)
				}
			})
			t.Run("v3-getbulk", func(t *testing.T) {
				// A single-column v3 walk stops at the end of its view and
				// answers it as one binding (nl6#526).
				assertEndOfMIBBindings(t, v3Bulk(t, s, 0, 5, []string{tc.at}).varbinds, tc.at, 1)
			})
		})
	}
}

// assertEndOfMIBBindings requires want bindings, each named with the
// requested OID and carrying endOfMibView.
func assertEndOfMIBBindings(t *testing.T, vbs []v3Varbind, requested string, want int) {
	t.Helper()
	if len(vbs) != want {
		t.Fatalf("%d bindings, want %d: %+v", len(vbs), want, vbs)
	}
	for i, vb := range vbs {
		if vb.oid != requested || vb.valueTag != wireEndOfMibView[0] {
			t.Errorf("binding %d: %s tag 0x%02X, want %s = endOfMibView", i, vb.oid, vb.valueTag, requested)
		}
	}
}

// TestShippedWalksNeverHitTheNonAdvanceCheck walks every shipped profile end to
// end, dynamic sources included, and requires every step to advance without the
// check in findNextOIDWithServed firing: a check that fired on a legitimate
// successor would end a real walk early and look like a short MIB.
func TestShippedWalksNeverHitTheNonAdvanceCheck(t *testing.T) {
	for _, p := range shippedProfileNames(t) {
		s := bootedShippedDevice(t, p, time.Now().Add(-time.Hour), nil)
		steps := 0
		logged := captureLog(t, func() {
			for cur := ".0"; steps < 200000; steps++ {
				next, _ := s.findNextOID(cur)
				if next == "" {
					return
				}
				if compareOIDs(next, cur) <= 0 {
					t.Errorf("%s: GETNEXT(%s) = %s does not advance", p, cur, next)
					return
				}
				cur = next
			}
			t.Errorf("%s: the walk did not end within %d steps", p, steps)
		})
		if strings.Contains(logged, "does not advance") {
			t.Errorf("%s: the non-advance check fired on a shipped walk:\n%s", p, logged)
		}
		if steps < len(s.device.resources.sortedOIDs) {
			t.Errorf("%s: the walk ended after %d steps, fewer than the %d static OIDs", p, steps, len(s.device.resources.sortedOIDs))
		}
	}
}
