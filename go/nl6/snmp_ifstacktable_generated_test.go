/*
 * Copyright 2026 Ronny Trommer <ronny@no42.org>
 * SPDX-License-Identifier: Apache-2.0
 */

package main

import (
	"sort"
	"strconv"
	"strings"
	"testing"
)

const ifStackStatusRoot = "1.3.6.1.2.1.31.1.2.1.3"

// walkIfStackStatus walks the served ifStackStatus column through the GETNEXT
// path and returns "<higher>.<lower>" per active row. A walk, not a JSON
// read: a row the serve path shadowed or mis-sorted would still be in the file.
func walkIfStackStatus(t *testing.T, srv *SNMPServer) []string {
	t.Helper()
	served := srv.lldpServedOIDs()
	var rows []string
	cur := ifStackStatusRoot
	for steps := 0; steps < 10000; steps++ {
		next, val := srv.findNextOIDWithServed(cur, served)
		rest, ok := strings.CutPrefix(strings.TrimPrefix(next, "."), ifStackStatusRoot+".")
		if next == "" || !ok || compareOIDs(next, cur) <= 0 {
			break
		}
		if val != "1" {
			t.Errorf("%s = %q, want active(1)", next, val)
		}
		rows = append(rows, rest)
		cur = next
	}
	return rows
}

// expectedStackRows derives the table from the device's own served ifDescr
// rows (the <parent>.<n> rule) and the aggregate members the cycler read,
// then completes it as RFC 2863 asks.
func expectedStackRows(t *testing.T, srv *SNMPServer, ic *IfCounterCycler) []string {
	t.Helper()
	byName := map[string]int{}
	idxs := ic.IfIndices()
	for _, idx := range idxs {
		byName[srv.findResponse(ifTablePrefix+"2."+strconv.Itoa(idx))] = idx
	}
	hasAbove, hasBelow := map[int]bool{}, map[int]bool{}
	var rows []string
	stack := func(h, l int) {
		rows = append(rows, strconv.Itoa(h)+"."+strconv.Itoa(l))
		hasAbove[l], hasBelow[h] = true, true
	}
	for _, idx := range idxs {
		if p, _, ok := splitSubinterfaceName(srv.findResponse(ifTablePrefix + "2." + strconv.Itoa(idx))); ok {
			if pIdx, ok := byName[p]; ok {
				stack(idx, pIdx)
			}
		}
	}
	for slot, ms := range ic.members { // slot = ifIndex - 1, values are ifIndexes
		for _, m := range ms {
			stack(slot+1, m)
		}
	}
	for _, idx := range idxs {
		if !hasAbove[idx] {
			rows = append(rows, "0."+strconv.Itoa(idx))
		}
		if !hasBelow[idx] {
			rows = append(rows, strconv.Itoa(idx)+".0")
		}
	}
	sort.Strings(rows)
	return rows
}

// The generated profiles serve a complete ifStackTable: each unit or VLAN
// subinterface over its port or bundle, the bundle over its members, and
// the RFC 2863 markers for everything else. The hierarchy the engine derives
// is unchanged, because the rows say what the names already said.
func TestGeneratedProfilesServeACompleteIfStackTable(t *testing.T) {
	for _, tc := range []struct {
		profile string
		spot    map[string]string // ifDescr child -> ifDescr parent the issue names
		top     []string          // interfaces that must carry neither marker
	}{
		{"juniper_mx10004.json", map[string]string{"xe-0/0/0.0": "xe-0/0/0", "xe-0/0/0.999": "xe-0/0/0"}, nil},
		{"cisco_asr9902.json", map[string]string{"HundredGigE0/0/0/8.100": "HundredGigE0/0/0/8", "HundredGigE0/0/0/8.200": "HundredGigE0/0/0/8", "Bundle-Ether1.300": "Bundle-Ether1"}, []string{"Bundle-Ether1"}},
	} {
		t.Run(tc.profile, func(t *testing.T) {
			dev := shippedDevice(t, tc.profile)
			srv := &SNMPServer{device: dev}
			ic := dev.metricsCycler.ifCounters.Load()
			got := walkIfStackStatus(t, srv)
			sort.Strings(got)
			want := expectedStackRows(t, srv, ic)
			if strings.Join(got, " ") != strings.Join(want, " ") {
				t.Errorf("served ifStackStatus rows:\n got %v\nwant %v", got, want)
			}
			set := map[string]bool{}
			seen := map[int]int{}
			for _, r := range got {
				set[r] = true
				h, l, _ := strings.Cut(r, ".")
				hi, _ := strconv.Atoi(h)
				li, _ := strconv.Atoi(l)
				seen[hi]++
				seen[li]++
			}
			byName := map[string]int{}
			for _, idx := range ic.IfIndices() {
				byName[srv.findResponse(ifTablePrefix+"2."+strconv.Itoa(idx))] = idx
				if seen[idx] < 2 {
					t.Errorf("ifIndex %d appears in %d rows, RFC 2863 wants at least two", idx, seen[idx])
				}
			}
			st := ic.State()
			for child, parent := range tc.spot {
				c, p := byName[child], byName[parent]
				if c == 0 || p == 0 {
					t.Fatalf("%s or %s is not served", child, parent)
				}
				if !set[strconv.Itoa(c)+"."+strconv.Itoa(p)] {
					t.Errorf("no row %d.%d for %s over %s", c, p, child, parent)
				}
				if set["0."+strconv.Itoa(p)] || set[strconv.Itoa(c)+".0"] {
					t.Errorf("%s has a 0.<port> marker or %s a <child>.0 marker", parent, child)
				}
				if st.Parent(c) != p || !st.NamedSubinterface(c) {
					t.Errorf("engine: %s parent = %d, NamedSubinterface = %v; want %d and true (the name rule, not the stack row)", child, st.Parent(c), st.NamedSubinterface(c), p)
				}
			}
			for _, name := range tc.top {
				idx := byName[name]
				if set["0."+strconv.Itoa(idx)] || set[strconv.Itoa(idx)+".0"] {
					t.Errorf("%s has members below and a subinterface above, so neither marker; rows %v", name, got)
				}
			}
			if byName["xe-0/0/0.0"] != 0 && !set["73.1"] {
				t.Errorf("juniper_mx10004: ifStackStatus.73.1 missing; rows %v", got)
			}
		})
	}
}
