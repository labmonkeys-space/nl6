/*
 * Copyright 2026 Ronny Trommer <ronny@no42.org>
 * SPDX-License-Identifier: Apache-2.0
 */

package main

import "time"

// Flow tick phase: why a fleet is not swept all at once.
//
// Real exporters run independent cache timers whose phases are random across a
// fleet, so a collector sees a near-flat stream of small bursts. A single
// ticker that sweeps every device on the same firing instead produces one
// fleet-wide burst per period: at 13,600 flows/s on a 5s tick that is ~68,000
// records landing on the collector at one instant, then nothing for 5s. A
// capacity test against that pattern measures burst absorption, not sustained
// throughput.
//
// The period is therefore divided into flowTickPhaseSlots. The ticker fires at
// period/slots and each firing sweeps only the devices whose phase falls in
// that slot, so every device is still swept exactly once per period (its
// batching, datagram sizes and the pacing sweep term are untouched) while the
// fleet's sweeps are spread across the period. The phase derives from the
// device IP rather than from the device RNG, because a draw from the RNG would
// shift the flow stream and break seeded reproducibility and the flow digest.
//
// -flow-tick-sync collapses the slot count to one, which is the synchronized
// pattern exactly, kept for restart-storm tests.

// flowTickPhaseSlots is the number of phase slots a tick period is divided
// into when the sub-period allows it: 100ms firings at the 5s default.
const flowTickPhaseSlots = 50

// flowTickSubPeriodFloor bounds how fast the ticker fires. Below it the slot
// count shrinks; a period at or under the floor is a single slot.
const flowTickSubPeriodFloor = 50 * time.Millisecond

// flowTickSlots returns how many phase slots period is divided into. sync
// forces one slot (every device swept on every firing).
func flowTickSlots(period time.Duration, sync bool) int {
	if sync || period <= 0 {
		return 1
	}
	slots := flowTickPhaseSlots
	if period/time.Duration(slots) < flowTickSubPeriodFloor {
		slots = int(period / flowTickSubPeriodFloor)
	}
	if slots < 1 {
		slots = 1
	}
	return slots
}

// flowTickPhase maps a device's domainID (its IPv4) to a phase in [0, 2^32).
// Fibonacci hashing: consecutive IPs, which is what an auto-start batch is,
// land golden-ratio apart, so any prefix of the sequence is spread evenly.
func flowTickPhase(domainID uint32) uint32 {
	return domainID * 0x9E3779B1
}

// flowTickSlotOf returns the slot in [0, slots) a phase falls in, taking the
// TOP bits of the phase; the low bits of a multiplicative hash are the ones
// that step through a residue class.
func flowTickSlotOf(phase uint32, slots int) int {
	return int(uint64(phase) * uint64(slots) >> 32)
}

// inTickSlot reports whether the exporter is swept on the given firing.
func (fe *FlowExporter) inTickSlot(slot, slots int) bool {
	return slots <= 1 || flowTickSlotOf(fe.phase, slots) == slot
}
