/*
 * Copyright 2026 Ronny Trommer <ronny@no42.org>
 * SPDX-License-Identifier: Apache-2.0
 */

package main

import (
	"log"
	"sort"
	"strconv"
	"strings"
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

// stackedParents reads the active(1) ifStackTable rows of a profile as
// higher-layer ifIndex -> lower-layer ifIndex. Rows naming ifIndex 0 (the
// table's "nothing above/below" marker) or an ifIndex outside known are
// ignored, as is a higher layer stacked on more than one lower layer, since
// the engine follows one parent.
func stackedParents(entries []SNMPResource, known map[int]bool) map[int]int {
	out := map[int]int{}
	multi := map[int]bool{}
	for _, e := range entries {
		rest, ok := strings.CutPrefix(strings.TrimPrefix(e.OID, "."), ifStackStatusPrefix)
		if !ok || e.Response != "1" {
			continue
		}
		hs, ls, ok := strings.Cut(rest, ".")
		h, err1 := strconv.Atoi(hs)
		l, err2 := strconv.Atoi(ls)
		if !ok || err1 != nil || err2 != nil || !known[h] || !known[l] || h == l {
			continue
		}
		if _, dup := out[h]; dup {
			multi[h] = true
		}
		out[h] = l
	}
	for h := range multi {
		log.Printf("interface hierarchy: ifIndex %d is stacked on more than one interface; treating it as top-level", h)
		delete(out, h)
	}
	return out
}

// interfaceParents maps each subinterface ifIndex to its parent's ifIndex,
// given the device's ifDescr per ifIndex and its ifStackTable. The name rule
// decides first; a stack row gives a parent only to an ifIndex the name rule
// left top-level, which is how an interface whose name does not say
// <port>.<unit> (an SR OS router interface) names the port beneath it. A name is a subinterface only when
// its parent name is itself an interface of the device. When two ifIndexes
// share the parent name the lower one wins, matching the legacy resolver's
// reverse lookup.
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
		log.Printf("interface hierarchy: %q (ifIndex %d) is a subinterface of a subinterface; treating it as top-level", names[idx], idx)
		delete(parents, idx)
	}
	return parents
}
