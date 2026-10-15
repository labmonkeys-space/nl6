/*
 * Copyright 2026 Ronny Trommer <ronny@no42.org>
 * SPDX-License-Identifier: Apache-2.0
 */

package main

import (
	"fmt"
	"hash/fnv"
	"sort"
)

// Counter roll-up: a child's counters are a fixed share of its parent's, an
// aggregate's are the sum of its members'.
//
// Composition is on the SERVED delta, after the parent's or member's own
// hold ledger, never on the raw dial: composing on raw dials lets a child
// grow while its held parent stands still, which breaks the bound on every
// flap. On served deltas the bound holds by construction, since the shares
// of one parent's children sum below 1 and skipped totals are non-negative.
//
// A child inherits its parent's packet size, mix and error bands, and its
// bases are floor(share x parent base) per column, so the bound is exact on
// every column, not only on octets. Members of an aggregate share the
// aggregate's packet profile and the aggregate's packet bases are the sums of
// its members', so the aggregate equals the member sum exactly on the octet
// columns and within (members - 1) packets on the packet columns, the floor
// of a sum against the sum of floors.
//
// Depth is bounded by construction: a member that is itself a child or an
// aggregate is dropped with one log line, and the engine already drops a
// child of a child, so a read recurses at most child -> aggregate -> member.

// rollupShareCap is the fraction of a parent its children may claim together;
// the remainder is the parent's untagged traffic.
const rollupShareCap = 0.8

// childShare is a deterministic share for one of n children of a parent: the
// even split jittered by up to 20 % from a hash of the child's ifIndex, so it
// consumes no RNG draw and moves no other interface's dial. The jittered
// shares of n children sum to at most 0.96.
func childShare(ifIndex, n int) float64 {
	h := fnv.New32a()
	_, _ = fmt.Fprintf(h, "share:%d", ifIndex)
	u := float64(h.Sum32())/float64(1<<32)*2 - 1 // [-1, 1)
	return rollupShareCap / float64(n) * (1 + 0.2*u)
}

// buildRollup records the hierarchy and re-seeds the dependent slots. parents
// is the engine's child -> parent table; members is the stack table's
// aggregate -> members table. Runs once, before publish.
func (ic *IfCounterCycler) buildRollup(parents map[int]int, members map[int][]int) {
	n := ic.maxIfIndex
	ic.counterParent = make([]int, n)
	ic.share = make([]float64, n)
	ic.members = make([][]int, n)

	aggregates := make([]int, 0, len(members))
	for agg := range members {
		if _, isChild := parents[agg]; isChild {
			// The engine follows its parent for oper-status; summing members
			// as well would seed it twice and bound it by nothing.
			logHierarchyOnce(fmt.Sprintf("interface hierarchy: ifIndex %d is an aggregate and has a parent; summing nothing, it follows its parent", agg))
			continue
		}
		aggregates = append(aggregates, agg)
	}
	sort.Ints(aggregates)
	claimed := map[int]int{}
	for _, agg := range aggregates {
		var ms []int
		for _, m := range members[agg] {
			switch {
			case claimed[m] != 0:
				logHierarchyOnce(fmt.Sprintf("interface hierarchy: ifIndex %d is a member of aggregates %d and %d; counted in %d only", m, claimed[m], agg, claimed[m]))
				continue
			case parents[m] != 0:
				logHierarchyOnce(fmt.Sprintf("interface hierarchy: ifIndex %d is a member of aggregate %d and has a parent; not summed", m, agg))
				continue
			case members[m] != nil:
				logHierarchyOnce(fmt.Sprintf("interface hierarchy: ifIndex %d is a member of aggregate %d and an aggregate itself; not summed", m, agg))
				continue
			}
			ms = append(ms, m)
		}
		if len(ms) < 2 {
			logHierarchyOnce(fmt.Sprintf("interface hierarchy: aggregate %d keeps %d usable members; serving its own dial", agg, len(ms)))
			continue
		}
		for _, m := range ms {
			claimed[m] = agg
		}
		ic.members[agg-1] = ms
		ic.seedAggregate(agg-1, ms)
	}

	// A child that declares no speed carries no traffic on its own dial and
	// keeps that contract: it takes no share and counts as no sibling.
	siblings := map[int]int{}
	children := make([]int, 0, len(parents))
	for c, p := range parents {
		if ic.ifSpeedBps[c-1] == 0 {
			continue
		}
		siblings[p]++
		children = append(children, c)
	}
	sort.Ints(children)
	for _, c := range children {
		p := parents[c]
		ic.counterParent[c-1] = p
		ic.share[c-1] = childShare(c, siblings[p])
		ic.seedChild(c-1, p-1, ic.share[c-1])
	}
}

// seedAggregate gives the members the aggregate's packet profile and makes
// the aggregate's bases the sums of theirs.
func (ic *IfCounterCycler) seedAggregate(slot int, members []int) {
	var inOct, outOct, inU, inM, inB, outU, outM, outB, inE, outE, inD, outD uint64
	for _, m := range members {
		ms := m - 1
		ic.pktSizeIn[ms], ic.pktSizeOut[ms] = ic.pktSizeIn[slot], ic.pktSizeOut[slot]
		ic.ucastRatioIn[ms], ic.mcastRatioIn[ms], ic.bcastRatioIn[ms] = ic.ucastRatioIn[slot], ic.mcastRatioIn[slot], ic.bcastRatioIn[slot]
		ic.ucastRatioOut[ms], ic.mcastRatioOut[ms], ic.bcastRatioOut[ms] = ic.ucastRatioOut[slot], ic.mcastRatioOut[slot], ic.bcastRatioOut[slot]
		ic.errPpmIn[ms], ic.errPpmOut[ms], ic.discPpmIn[ms], ic.discPpmOut[ms] = ic.errPpmIn[slot], ic.errPpmOut[slot], ic.discPpmIn[slot], ic.discPpmOut[slot]
		// The member's packet bases follow its own octet base through the
		// profile it now shares, so the aggregate's sum is a sum of consistent
		// rows.
		ic.reseedPacketBases(ms)
		inOct += ic.baseInOctets[ms]
		outOct += ic.baseOutOctets[ms]
		inU += ic.baseInUcast[ms]
		inM += ic.baseInMcast[ms]
		inB += ic.baseInBcast[ms]
		outU += ic.baseOutUcast[ms]
		outM += ic.baseOutMcast[ms]
		outB += ic.baseOutBcast[ms]
		inE += ic.baseInErr[ms]
		outE += ic.baseOutErr[ms]
		inD += ic.baseInDisc[ms]
		outD += ic.baseOutDisc[ms]
	}
	ic.baseInOctets[slot], ic.baseOutOctets[slot] = inOct, outOct
	ic.baseInUcast[slot], ic.baseInMcast[slot], ic.baseInBcast[slot] = inU, inM, inB
	ic.baseOutUcast[slot], ic.baseOutMcast[slot], ic.baseOutBcast[slot] = outU, outM, outB
	ic.baseInErr[slot], ic.baseOutErr[slot], ic.baseInDisc[slot], ic.baseOutDisc[slot] = inE, outE, inD, outD
}

// seedChild gives the child its parent's packet profile and share-scaled
// bases per column.
func (ic *IfCounterCycler) seedChild(slot, parent int, share float64) {
	ic.pktSizeIn[slot], ic.pktSizeOut[slot] = ic.pktSizeIn[parent], ic.pktSizeOut[parent]
	ic.ucastRatioIn[slot], ic.mcastRatioIn[slot], ic.bcastRatioIn[slot] = ic.ucastRatioIn[parent], ic.mcastRatioIn[parent], ic.bcastRatioIn[parent]
	ic.ucastRatioOut[slot], ic.mcastRatioOut[slot], ic.bcastRatioOut[slot] = ic.ucastRatioOut[parent], ic.mcastRatioOut[parent], ic.bcastRatioOut[parent]
	ic.errPpmIn[slot], ic.errPpmOut[slot], ic.discPpmIn[slot], ic.discPpmOut[slot] = ic.errPpmIn[parent], ic.errPpmOut[parent], ic.discPpmIn[parent], ic.discPpmOut[parent]
	scale := func(v uint64) uint64 { return uint64(float64(v) * share) }
	ic.baseInOctets[slot], ic.baseOutOctets[slot] = scale(ic.baseInOctets[parent]), scale(ic.baseOutOctets[parent])
	ic.baseInUcast[slot], ic.baseInMcast[slot], ic.baseInBcast[slot] = scale(ic.baseInUcast[parent]), scale(ic.baseInMcast[parent]), scale(ic.baseInBcast[parent])
	ic.baseOutUcast[slot], ic.baseOutMcast[slot], ic.baseOutBcast[slot] = scale(ic.baseOutUcast[parent]), scale(ic.baseOutMcast[parent]), scale(ic.baseOutBcast[parent])
	ic.baseInErr[slot], ic.baseOutErr[slot], ic.baseInDisc[slot], ic.baseOutDisc[slot] = scale(ic.baseInErr[parent]), scale(ic.baseOutErr[parent]), scale(ic.baseInDisc[parent]), scale(ic.baseOutDisc[parent])
}

// reseedPacketBases recomputes a slot's packet, error and discard bases from
// its octet bases through its current packet profile, the same arithmetic
// the init loop uses.
func (ic *IfCounterCycler) reseedPacketBases(slot int) {
	totalIn := uint64(float64(ic.baseInOctets[slot]) / ic.pktSizeIn[slot])
	totalOut := uint64(float64(ic.baseOutOctets[slot]) / ic.pktSizeOut[slot])
	ic.baseInUcast[slot] = uint64(float64(totalIn) * ic.ucastRatioIn[slot])
	ic.baseInMcast[slot] = uint64(float64(totalIn) * ic.mcastRatioIn[slot])
	ic.baseInBcast[slot] = uint64(float64(totalIn) * ic.bcastRatioIn[slot])
	ic.baseOutUcast[slot] = uint64(float64(totalOut) * ic.ucastRatioOut[slot])
	ic.baseOutMcast[slot] = uint64(float64(totalOut) * ic.mcastRatioOut[slot])
	ic.baseOutBcast[slot] = uint64(float64(totalOut) * ic.bcastRatioOut[slot])
	ic.baseInErr[slot] = totalIn * uint64(ic.errPpmIn[slot]) / 1_000_000
	ic.baseOutErr[slot] = totalOut * uint64(ic.errPpmOut[slot]) / 1_000_000
	ic.baseInDisc[slot] = totalIn * uint64(ic.discPpmIn[slot]) / 1_000_000
	ic.baseOutDisc[slot] = totalOut * uint64(ic.discPpmOut[slot]) / 1_000_000
}

// rawDeltaAt is a slot's octet delta before its own hold: its dial for a
// standalone interface, a share of the parent's SERVED delta for a child,
// the sum of the members' SERVED deltas for an aggregate. Called inside the
// seqlock bracket only.
func (ic *IfCounterCycler) rawDeltaAt(slot int, t float64, inbound bool) uint64 {
	if ic.members == nil {
		return ic.deltaOctetsAt(slot, t, inbound)
	}
	if ms := ic.members[slot]; ms != nil {
		var sum uint64
		for _, m := range ms {
			sum += ic.servedDeltaAt(m-1, t, inbound)
		}
		return sum
	}
	if p := ic.counterParent[slot]; p != 0 {
		return uint64(float64(ic.servedDeltaAt(p-1, t, inbound)) * ic.share[slot])
	}
	return ic.deltaOctetsAt(slot, t, inbound)
}

// servedDeltaAt is rawDeltaAt through the slot's own hold ledger.
func (ic *IfCounterCycler) servedDeltaAt(slot int, t float64, inbound bool) uint64 {
	return ic.heldDeltaFor(ic.hold[slot].Load(), slot, t, inbound)
}
