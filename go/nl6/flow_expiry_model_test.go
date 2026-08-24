/*
 * Copyright 2026 Ronny Trommer <ronny@no42.org>
 * SPDX-License-Identifier: Apache-2.0
 */

package main

import (
	"math/rand"
	"net"
	"testing"
	"time"
)

// expiryProbe drives the real cache over a horizon of synthetic time and
// returns records harvested per tick. It exercises GenerateFlows/Expire in the
// same order FlowExporter.Tick does.
func expiryProbe(t *testing.T, profile *FlowProfile, tick, active, inactive, horizon time.Duration) []int {
	t.Helper()
	// MaxFlows, matching NewFlowExporter — not ConcurrentFlows. With the
	// smaller cap the probe can take GenerateFlows' `break` path that
	// production never reaches, and the whole-cache guard below would then be
	// measuring the cap rather than the cohort.
	fc := NewFlowCache(active, inactive, profile.MaxFlows)
	rng := rand.New(rand.NewSource(42))
	ip := net.ParseIP("10.1.2.3")
	base := time.Now()

	var perTick []int
	for el := time.Duration(0); el <= horizon; el += tick {
		now := base.Add(el)
		// Same order as FlowExporter.Tick: expire, then refill the vacated
		// slots. Probing the other order measures a loop production does not
		// run.
		n := len(fc.Expire(now))
		fc.GenerateFlows(profile, ip, rng, now, uint32(el.Milliseconds()))
		perTick = append(perTick, n)
	}
	return perTick
}

// TestFlowExpiry_BothTimeoutsAreReachable is the nl6#446-adjacent defect: with
// lastSeenAt pinned to createdAt, `now-lastSeenAt` equalled `now-createdAt`, so
// expiry collapsed to min(active, inactive) and -flow-active-timeout could
// never bind above the inactive one. It was configuration that could not
// affect behaviour.
//
// It asserts the expiry REASON, not the total. An earlier version compared
// total record counts across active timeouts and assumed equal totals would
// betray the collapse; review showed that assertion could not fire, because
// warmStartOffset itself reads activeTimeout, so the totals shift a few percent
// even when expiry ignores the flag entirely.
func TestFlowExpiry_BothTimeoutsAreReachable(t *testing.T) {
	fc := NewFlowCache(30*time.Second, 15*time.Second, flowProfileEdgeRouter.MaxFlows)
	rng := rand.New(rand.NewSource(42))
	ip := net.ParseIP("10.1.2.3")
	base := time.Now()
	for el := time.Duration(0); el <= 600*time.Second; el += 5 * time.Second {
		now := base.Add(el)
		fc.Expire(now)
		fc.GenerateFlows(flowProfileEdgeRouter, ip, rng, now, uint32(el.Milliseconds()))
	}

	active, inactive := fc.ExpiryReasons()
	if active == 0 {
		t.Error("no flow expired by the ACTIVE timeout — the collapsed model is back " +
			"(lastSeenAt must be the flow's modelled end, not its creation instant)")
	}
	if inactive == 0 {
		t.Error("no flow expired by the INACTIVE timeout — only flows shorter than " +
			"(active-inactive) can reach it, but some must")
	}
	// Under the shipped profile the active path dominates. Pin the ORDER, not a
	// precise split: the exact ratio is a property of the duration distribution
	// and would make this test a change-detector.
	if active <= inactive {
		t.Errorf("expected the active timeout to dominate under the shipped profile, got active=%d inactive=%d",
			active, inactive)
	}
	t.Logf("expiry split: active=%d (%.1f%%) inactive=%d (%.1f%%)",
		active, 100*float64(active)/float64(active+inactive),
		inactive, 100*float64(inactive)/float64(active+inactive))
}

// TestFlowExpiry_NoCohortSawtooth pins the emission SHAPE, which is the
// user-visible point of the change and the thing an average conceals.
//
// Before: the whole cache shared one createdAt, so 128 records left on one tick
// and the next three carried nothing. A generator that bursts its entire cache
// and then goes silent misrepresents the load it claims to offer, because a
// collector's capacity responds to batch shape rather than to mean rate.
func TestFlowExpiry_NoCohortSawtooth(t *testing.T) {
	// ACROSS CADENCES, not just the default. An earlier version probed only the
	// 5s default and passed while `-flow-tick-interval 30s` — the cadence this
	// change exists to make reachable — still produced a literal
	// [0 128 0 128 ...]: the whole cache on one tick, then a silent one. Two
	// reviewers found it independently. Testing at the default only was the
	// defect; generalising from one sample point was the mistake behind it.
	for _, tick := range []time.Duration{time.Second, 5 * time.Second, 15 * time.Second, 30 * time.Second} {
		t.Run(tick.String(), func(t *testing.T) {
			perTick := expiryProbe(t, flowProfileEdgeRouter, tick, 30*time.Second, 15*time.Second, 600*time.Second)

			// Skip the first few ticks: the cache is filling and legitimately quiet.
			const settle = 4
			if len(perTick) <= settle {
				t.Fatalf("probe too short: %d ticks", len(perTick))
			}
			steady := perTick[settle:]

			var silent, maxBatch, total int
			for _, n := range steady {
				if n == 0 {
					silent++
				}
				if n > maxBatch {
					maxBatch = n
				}
				total += n
			}
			mean := float64(total) / float64(len(steady))

			// The old behaviour: at 5s, 3 of every 4 ticks silent; at 30s, every
			// other tick. Under steady load there is no reason for a silent tick
			// at any cadence — expire-then-generate refills the vacated slots in
			// the same tick.
			if silent > len(steady)/10 {
				t.Errorf("%d of %d steady ticks emitted nothing — the cohort sawtooth is back",
					silent, len(steady))
			}
			// Peak vs mean. At coarse cadences a full cache legitimately leaves
			// every tick (peak == mean == 128), which is a big BATCH, not a
			// burst-then-silence cohort; the silent-tick check above is what
			// distinguishes them.
			if float64(maxBatch) > 3*mean {
				t.Errorf("peak batch %d is %.1fx the mean %.1f — emission is too bursty",
					maxBatch, float64(maxBatch)/mean, mean)
			}
		})
	}
}

// TestFlowExpiry_VolumeDoesNotScaleWithCadence pins design D3.
//
// It deliberately does NOT assert a flat rate. Export is a polling process, so
// a flow sits cached up to one interval past its deadline and volume keeps a
// residual dependence bounded by roughly T/2 — genuine polling latency, not an
// artefact. What must not exist is the old staircase, where volume stepped with
// cadence (5s vs 30s was a 3.00x cliff).
func TestFlowExpiry_VolumeDoesNotScaleWithCadence(t *testing.T) {
	const horizon = 300 * time.Second
	rate := func(tick time.Duration) float64 {
		n := 0
		for _, x := range expiryProbe(t, flowProfileEdgeRouter, tick, 30*time.Second, 15*time.Second, horizon) {
			n += x
		}
		return float64(n) / horizon.Seconds()
	}

	fast, slow := rate(time.Second), rate(10*time.Second)
	ratio := fast / slow

	// A 10x cadence change must NOT produce anything close to a 10x rate
	// change; before the fix the same comparison was a hard step.
	if ratio > 2.0 {
		t.Errorf("rate scaled %.2fx across a 10x cadence change (%.2f vs %.2f rec/s); "+
			"cadence is behaving as a volume knob again", ratio, fast, slow)
	}
	if ratio < 1.0 {
		t.Errorf("a slower tick emitted MORE than a faster one (%.2f vs %.2f rec/s)", slow, fast)
	}
}
