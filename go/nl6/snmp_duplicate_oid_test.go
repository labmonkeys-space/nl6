/*
 * Copyright 2026 Ronny Trommer <ronny@no42.org>
 * SPDX-License-Identifier: Apache-2.0
 */

package main

import (
	"fmt"
	"net"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
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
