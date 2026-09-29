/*
 * Copyright 2026 Ronny Trommer <ronny@no42.org>
 * SPDX-License-Identifier: Apache-2.0
 */

package main

import (
	"context"
	"fmt"
	"net"
	"testing"
	"time"
)

// TestFlowTickSlots pins how the tick period is divided into phase slots.
//
// The fleet ticker fires at period/slots and sweeps one slot per firing, so
// slots is what turns one fleet-wide burst per period into `slots` smaller
// ones. The sub-period is floored so a sub-second cadence does not turn into
// a busy loop, and sync collapses everything to a single slot, which is the
// pre-desync behaviour exactly.
func TestFlowTickSlots(t *testing.T) {
	for _, tc := range []struct {
		period time.Duration
		sync   bool
		want   int
	}{
		{5 * time.Second, false, flowTickPhaseSlots},
		{5 * time.Second, true, 1},
		{time.Second, false, 20},
		{100 * time.Millisecond, false, 2},
		{50 * time.Millisecond, false, 1},
		{20 * time.Millisecond, false, 1},
		{time.Hour, false, flowTickPhaseSlots},
	} {
		if got := flowTickSlots(tc.period, tc.sync); got != tc.want {
			t.Errorf("flowTickSlots(%s, sync=%v) = %d, want %d", tc.period, tc.sync, got, tc.want)
		}
	}
}

// TestFlowTickPhase_ConsecutiveIPsSpreadAcrossSlots: an auto-start batch is a
// run of consecutive IPv4 addresses, and the phase is derived from the IP, so
// the derivation must not map a consecutive run onto a handful of slots. The
// bound is loose (no slot above twice its share, none empty) because the
// property under test is "spread", not a particular hash.
func TestFlowTickPhase_ConsecutiveIPsSpreadAcrossSlots(t *testing.T) {
	const n, slots = 1000, flowTickPhaseSlots
	counts := make([]int, slots)
	base := uint32(10<<24 | 42<<16 | 1) // 10.42.0.1
	for i := uint32(0); i < n; i++ {
		counts[flowTickSlotOf(flowTickPhase(base+i), slots)]++
	}
	mean := n / slots
	for s, c := range counts {
		if c == 0 {
			t.Errorf("slot %d is empty over %d consecutive IPs", s, n)
		}
		if c > 2*mean {
			t.Errorf("slot %d holds %d of %d consecutive IPs (mean %d): phase does not spread a batch", s, c, n, mean)
		}
	}
}

// slotExporters builds one exporter per requested slot, choosing IPs whose
// phase lands in that slot, and registers them on a bare manager. Returns the
// exporters keyed by slot.
func slotExporters(t *testing.T, sm *SimulatorManager, slots int, want []int) map[int]*FlowExporter {
	t.Helper()
	send := testSender(t)
	t.Cleanup(func() { send.Close() })
	out := map[int]*FlowExporter{}
	for host := uint32(1); len(out) < len(want) && host < 100000; host++ {
		ip := fmt.Sprintf("10.%d.%d.%d", (host>>16)&0xff, (host>>8)&0xff, host&0xff)
		fe := newIPFIXTestExporter(ip, time.Millisecond, time.Millisecond, 10*time.Minute)
		slot := flowTickSlotOf(fe.phase, slots)
		if _, have := out[slot]; have {
			continue
		}
		wanted := false
		for _, w := range want {
			wanted = wanted || w == slot
		}
		if !wanted {
			continue
		}
		fe.conn.Store(send)
		sm.devices[ip] = &DeviceSimulator{ID: ip, IP: net.ParseIP(ip).To4(), flowExporter: fe}
		out[slot] = fe
	}
	if len(out) != len(want) {
		t.Fatalf("could not find IPs for slots %v, got %v", want, out)
	}
	return out
}

func attemptsOf(fe *FlowExporter) uint64 { return fe.statPackets.Load() + fe.statFailures.Load() }

// TestFlowTicker_SweepsOnlyTheSlotsExporters: a firing of the fleet ticker
// sweeps the exporters whose phase falls in the firing's slot and no other.
// This is the whole desync mechanism; remove the slot filter and every
// exporter is swept on every sub-tick, i.e. the burst returns at 50x the rate.
func TestFlowTicker_SweepsOnlyTheSlotsExporters(t *testing.T) {
	const slots = flowTickPhaseSlots
	sm := &SimulatorManager{devices: map[string]*DeviceSimulator{}, devicesByIP: map[string]*DeviceSimulator{}}
	sm.flowBufPool.New = func() any { b := make([]byte, 1500); return &b }
	fes := slotExporters(t, sm, slots, []int{3, 17, 42})

	now := time.Now()
	for _, fe := range fes {
		injectExpiredFlows(fe, 2, now)
	}
	sm.tickAllFlowExporters(context.Background(), now, 17, slots)

	if attemptsOf(fes[17]) == 0 {
		t.Fatal("exporter in slot 17 was not swept on slot 17's firing")
	}
	for _, s := range []int{3, 42} {
		if got := attemptsOf(fes[s]); got != 0 {
			t.Errorf("exporter in slot %d swept on slot 17's firing (%d attempts): slot filter missing", s, got)
		}
	}
}

// TestFlowTicker_SingleSlotSweepsEveryone: slots == 1 is the synchronized
// fleet, and it must sweep every exporter on every firing regardless of phase.
func TestFlowTicker_SingleSlotSweepsEveryone(t *testing.T) {
	sm := &SimulatorManager{devices: map[string]*DeviceSimulator{}, devicesByIP: map[string]*DeviceSimulator{}}
	sm.flowBufPool.New = func() any { b := make([]byte, 1500); return &b }
	fes := slotExporters(t, sm, flowTickPhaseSlots, []int{0, 25, 49})

	now := time.Now()
	for _, fe := range fes {
		injectExpiredFlows(fe, 2, now)
	}
	sm.tickAllFlowExporters(context.Background(), now, 0, 1)
	for s, fe := range fes {
		if attemptsOf(fe) == 0 {
			t.Errorf("exporter of phase slot %d not swept by a single-slot firing", s)
		}
	}
}

// TestFlowTicker_LatchesSlots: the running ticker latches its slot count
// alongside its period, and the sync option collapses it to one. The latched
// PERIOD is unchanged by desync: each device is still swept once per period.
func TestFlowTicker_LatchesSlots(t *testing.T) {
	for _, tc := range []struct {
		sync bool
		want int64
	}{{false, flowTickPhaseSlots}, {true, 1}} {
		sm := &SimulatorManager{}
		WithFlowTickInterval(5 * time.Second)(sm)
		WithFlowTickSync(tc.sync)(sm)
		sm.flowStopCh = make(chan struct{})
		sm.startFlowTicker()
		got := sm.flowTickerSlots.Load()
		period := time.Duration(sm.flowTickerPeriod.Load())
		close(sm.flowStopCh)
		sm.flowWg.Wait()
		if got != tc.want {
			t.Errorf("sync=%v: latched %d slots, want %d", tc.sync, got, tc.want)
		}
		if period != 5*time.Second {
			t.Errorf("sync=%v: latched period %s, want 5s (desync must not change the per-device cadence)", tc.sync, period)
		}
	}
}

// TestFlowStatus_ReportsTickSynchronized: the status endpoint says which
// arrival pattern a run was measured under, from the LATCHED slot count rather
// than the flag, so a sub-period floor that collapsed to one slot reads as
// synchronized because it is.
func TestFlowStatus_ReportsTickSynchronized(t *testing.T) {
	for _, tc := range []struct {
		slots int64
		sync  bool
	}{{flowTickPhaseSlots, false}, {1, true}} {
		sm := &SimulatorManager{devices: map[string]*DeviceSimulator{}}
		sm.flowTickerSlots.Store(tc.slots)
		st := sm.GetFlowStatus()
		if st.TickSynchronized != tc.sync {
			t.Errorf("slots=%d: tick_synchronized=%v, want %v", tc.slots, st.TickSynchronized, tc.sync)
		}
		if st.TickPhaseSlots != int(tc.slots) {
			t.Errorf("slots=%d: tick_phase_slots=%d", tc.slots, st.TickPhaseSlots)
		}
	}
}

// TestScenarioFlowTicker_SweepsOnlyTheSlot: the scenario-owned ticker takes
// the same slot scheme, because a scenario at fleet cadence would otherwise
// reproduce the fleet-wide burst inside the measured window.
func TestScenarioFlowTicker_SweepsOnlyTheSlot(t *testing.T) {
	const slots = flowTickPhaseSlots
	sm := &SimulatorManager{devices: map[string]*DeviceSimulator{}, devicesByIP: map[string]*DeviceSimulator{}}
	sm.flowBufPool.New = func() any { b := make([]byte, 1500); return &b }
	fes := slotExporters(t, sm, slots, []int{5, 30})
	c := &ScenarioController{sm: sm}

	now := time.Now()
	list := []*FlowExporter{fes[5], fes[30]}
	for _, fe := range list {
		injectExpiredFlows(fe, 2, now)
	}
	c.tickScenarioFlowSlot(context.Background(), context.Background(), list, now, 30, slots)
	if attemptsOf(fes[30]) == 0 {
		t.Fatal("scenario ticker did not sweep the exporter in its slot")
	}
	if got := attemptsOf(fes[5]); got != 0 {
		t.Errorf("scenario ticker swept an exporter outside the slot (%d attempts)", got)
	}
}
