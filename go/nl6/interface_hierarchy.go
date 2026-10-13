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

// subinterfaceParents maps each subinterface ifIndex to its parent's ifIndex,
// given the device's ifDescr per ifIndex. A name is a subinterface only when
// its parent name is itself an interface of the device. When two ifIndexes
// share the parent name the lower one wins, matching the legacy resolver's
// reverse lookup.
//
// One level only: a child whose parent is itself a child is dropped with a log
// line, because the engine cascades one level and no shipped profile nests.
func subinterfaceParents(names map[int]string) map[int]int {
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
