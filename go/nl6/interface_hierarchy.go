/*
 * Copyright 2026 Ronny Trommer <ronny@no42.org>
 * SPDX-License-Identifier: Apache-2.0
 */

package main

import (
	"fmt"
	"log"
	"sort"
	"strconv"
	"strings"
	"sync"
)

// splitSubinterfaceName splits an ifDescr of the form <parent>.<unit> into its
// parent name and unit. This is the ONE rule for what a subinterface is: the
// gNMI catalogue's subinterfaces key source, the state engine's parent table
// and the legacy gNMI resolver all call it, so they cannot disagree about which
// rows are logical units.
//
// A subinterface index is an OpenConfig uint32 and the suffix is the path key,
// so it must be canonical: unit 0 (Junos's default unit) counts, a sign, a
// leading zero or an out-of-range suffix does not.
func splitSubinterfaceName(name string) (parent, unit string, ok bool) {
	dot := strings.LastIndexByte(name, '.')
	if dot <= 0 {
		return "", "", false
	}
	suffix := name[dot+1:]
	v, err := strconv.ParseUint(suffix, 10, 32)
	if err != nil || strconv.FormatUint(v, 10) != suffix {
		return "", "", false
	}
	return name[:dot], suffix, true
}

// subinterfaceParents is interfaceParents with no ifStackTable.
func subinterfaceParents(names map[int]string) map[int]int {
	return interfaceParents(names, nil)
}

// ifTypeSoftwareLoopback is IANAifType softwareLoopback(24) as a resource
// file spells it.
const ifTypeSoftwareLoopback = "24"

// ifStackStatusPrefix is ifStackStatus (IF-MIB), indexed <higher>.<lower>.
const ifStackStatusPrefix = "1.3.6.1.2.1.31.1.2.1.3."

// stackLayers is a profile's active(1) ifStackTable read two ways: parents
// maps a higher layer with exactly ONE lower layer to it, which the state
// engine follows; members maps a higher layer with two or more lower layers,
// an aggregate such as a bundle, to them in row order, which the counter
// cycler sums. An aggregate has no parent: the engine follows one, so its
// oper-status stays its own. A row naming ifIndex 0 on either side is the
// RFC 2863 marker for "nothing above" or "nothing below", which a complete
// table carries for every interface: it is skipped silently and is not a
// row of its higher layer. A row naming a non-zero ifIndex outside known is
// ignored with a log line. The same row repeated, as when two resource parts
// carry it, is one row.
type stackLayers struct {
	parents map[int]int
	members map[int][]int
}

func readStackLayers(entries []SNMPResource, known map[int]bool) stackLayers {
	lower := map[int][]int{}
	// rows counts every well-formed row per higher layer, resolvable or not,
	// so a higher layer whose rows name an unknown lower layer is never
	// read as having ONE lower layer: a bundle with a typo in one member
	// row would otherwise become a child of the other member.
	rows := map[int]int{}
	seen := map[[2]int]bool{}
	for _, e := range entries {
		rest, ok := strings.CutPrefix(strings.TrimPrefix(e.OID, "."), ifStackStatusPrefix)
		if !ok || e.Response != "1" {
			continue
		}
		hs, ls, ok := strings.Cut(rest, ".")
		h, err1 := strconv.Atoi(hs)
		l, err2 := strconv.Atoi(ls)
		if !ok || err1 != nil || err2 != nil || !known[h] || l == 0 || h == l {
			continue
		}
		if seen[[2]int{h, l}] {
			continue
		}
		seen[[2]int{h, l}] = true
		rows[h]++
		if !known[l] {
			logHierarchyOnce(fmt.Sprintf("interface hierarchy: ifStackStatus row %d.%d names an unknown lower layer; ignored", h, l))
			continue
		}
		lower[h] = append(lower[h], l)
	}
	out := stackLayers{parents: map[int]int{}, members: map[int][]int{}}
	for h, ls := range lower {
		switch {
		case len(ls) >= 2:
			out.members[h] = ls
		case rows[h] >= 2:
			logHierarchyOnce(fmt.Sprintf("interface hierarchy: ifIndex %d is stacked on %d rows of which %d resolve; treating it as top-level", h, rows[h], len(ls)))
		default:
			out.parents[h] = ls[0]
		}
	}
	return out
}

// stackedParents is the one-lower-layer half of readStackLayers.
func stackedParents(entries []SNMPResource, known map[int]bool) map[int]int {
	return readStackLayers(entries, known).parents
}

// interfaceParents maps each subinterface ifIndex to its parent's ifIndex,
// given the device's ifDescr per ifIndex and its ifStackTable. The name rule
// decides first; a stack row gives a parent only to an ifIndex the name rule
// left top-level, which is how an interface whose name does not say
// <port>.<unit> (an SR OS router interface) names the port beneath it.
//
// A name is a subinterface only when its parent name is itself an interface of
// the device. When two ifIndexes share the parent name the lower one wins,
// matching the legacy resolver's reverse lookup.
//
// One level only: a child whose parent is itself a child is dropped with a log
// line, because the engine cascades one level and no shipped profile nests.
func interfaceParents(names map[int]string, stacked map[int]int) map[int]int {
	byName := make(map[string]int, len(names))
	idxs := make([]int, 0, len(names))
	for idx := range names {
		idxs = append(idxs, idx)
	}
	sort.Ints(idxs)
	for _, idx := range idxs {
		if _, dup := byName[names[idx]]; !dup && names[idx] != "" {
			byName[names[idx]] = idx
		}
	}
	parents := map[int]int{}
	for _, idx := range idxs {
		p, _, ok := splitSubinterfaceName(names[idx])
		if !ok {
			continue
		}
		if pIdx, ok := byName[p]; ok && pIdx != idx {
			parents[idx] = pIdx
		}
	}
	for h, l := range stacked {
		if _, ok := parents[h]; !ok {
			parents[h] = l
		}
	}
	var nested []int
	for _, idx := range idxs {
		if p, ok := parents[idx]; ok {
			if _, isChild := parents[p]; isChild {
				nested = append(nested, idx)
			}
		}
	}
	for _, idx := range nested {
		logHierarchyOnce(fmt.Sprintf("interface hierarchy: %q (ifIndex %d) is a subinterface of a subinterface; treating it as top-level", names[idx], idx))
		delete(parents, idx)
	}
	return parents
}

// hierarchyLogged dedupes the hierarchy warnings. They are properties of a
// profile, and the hierarchy is rebuilt for every device, so an unguarded line
// would repeat once per device of a 30,000-device fleet.
var hierarchyLogged sync.Map

func logHierarchyOnce(msg string) {
	if _, seen := hierarchyLogged.LoadOrStore(msg, struct{}{}); !seen {
		log.Print(msg)
	}
}

// stackCache holds stackedParents per loaded profile. The result depends only
// on the profile, and scanning its whole SNMP slice once per device would cost
// a fleet of N devices N full scans. A reload loads a new *DeviceResources, so
// a stale entry is never read; it is only kept.
var stackCache sync.Map // *DeviceResources -> stackLayers

func cachedStackLayers(res *DeviceResources, known map[int]bool) stackLayers {
	if v, ok := stackCache.Load(res); ok {
		return v.(stackLayers)
	}
	m := readStackLayers(res.SNMP, known)
	stackCache.Store(res, m)
	return m
}
