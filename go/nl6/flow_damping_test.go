/*
 * Copyright 2026 Ronny Trommer <ronny@no42.org>
 * SPDX-License-Identifier: Apache-2.0
 */

// The damping assertion for the flow-expiry echo.
//
// The property under test is NOT "emission is smooth". A bursty-but-forgetting
// emitter and a bursty-and-echoing one can share a coefficient of variation, so
// a dispersion threshold cannot tell them apart — and it would be a number
// someone later tunes to fit. What distinguishes them is whether a disturbance
// REPEATS: with a deterministic expiry offset, the creation profile is a pure
// delay of itself, so an irregularity is re-emitted every flow lifetime forever.
//
// The signature of that is autocorrelation across MULTIPLES of the lifetime. A
// pure delay correlates about as strongly at four lifetimes as at one; a damped
// system falls off. Measured on the shipped profiles at jitter 0, edge-router
// emission holds +0.87 at one lifetime and +0.59 at four, and a GPU server
// +0.96 and +0.89 — that is a system with no forgetting.

package main

import (
	"math/rand"
	"net"
	"testing"
	"time"
)

// autocorrelation of x at `lag`, normalised by the full-series variance.
func autocorrelation(x []int, lag int) float64 {
	if len(x) <= lag {
		return 0
	}
	mean := 0.0
	for _, v := range x {
		mean += float64(v)
	}
	mean /= float64(len(x))

	var num, den float64
	for i := range x {
		d := float64(x[i]) - mean
		den += d * d
		if i+lag < len(x) {
			num += d * (float64(x[i+lag]) - mean)
		}
	}
	if den == 0 {
		return 0
	}
	return num / den
}

// disturbedEmission warms a cache to `from` flows, then RE-PACES it to `to` and
// returns the per-tick expiry counts over `lifetimes` active timeouts.
//
// The disturbance is a real one: re-pacing is exactly what a scenario does when
// it arms, and it is the production path that injects a synchronised cohort —
// the refill creates `to-from` flows at a single instant, which then expire at a
// single instant one lifetime later, and again, and again. A synthetic spike
// would test a shape the emission loop never produces.
func disturbedEmission(t *testing.T, p *FlowProfile, jitter float64, from, to, lifetimes int,
	tick, active, inactive time.Duration) []int {
	t.Helper()
	fc := NewFlowCache(active, inactive, p.MaxFlows)
	fc.activeJitterFraction = jitter
	rng := rand.New(rand.NewSource(7))
	ip := net.ParseIP("10.1.2.3")
	base := time.Now()

	el := time.Duration(0)
	for ; el < 20*active; el += tick { // settle at the starting population
		now := base.Add(el)
		fc.Expire(now)
		fc.GenerateFlows(p, from, ip, rng, now, uint32(el.Milliseconds()))
	}

	out := make([]int, 0, lifetimes*int(active/tick))
	for end := el + time.Duration(lifetimes)*active; el <= end; el += tick {
		now := base.Add(el)
		n := len(fc.Expire(now))
		fc.GenerateFlows(p, to, ip, rng, now, uint32(el.Milliseconds()))
		out = append(out, n)
	}
	return out
}

// TestFlowEmission_EchoIsDamped asserts the damping RELATIVE to the same probe
// with the jitter disabled, rather than against a fixed correlation threshold.
//
// That matters for two reasons. A threshold is a constant nobody can later
// justify moving, and — more concretely — the profiles differ in how much echo
// they have to begin with: CampusSwitch's DurationMax sits on the active
// timeout, so most of its flows already leave by the inactive branch, which
// carries sampled variance and damps itself. Measured undamped, campus holds
// only +0.54 at one lifetime against the GPU server's +0.96. A single threshold
// would either pass campus vacuously or fail it unfairly.
//
// The undamped baseline is therefore computed in-test, and its strength is
// asserted as a PRECONDITION: if the fixture stops echoing, the comparison
// below proves nothing and must fail loudly rather than pass.
func TestFlowEmission_EchoIsDamped(t *testing.T) {
	const tick, active, inactive = 5 * time.Second, 30 * time.Second, 15 * time.Second
	const lifetimes = 40
	lag := int(active / tick)

	for _, tc := range []struct {
		name string
		p    *FlowProfile
	}{
		{"edge", flowProfileEdgeRouter},
		{"gpu", flowProfileGPUServer},
	} {
		t.Run(tc.name, func(t *testing.T) {
			from, to := tc.p.ConcurrentFlows, 2*tc.p.ConcurrentFlows

			plain := disturbedEmission(t, tc.p, 0, from, to, lifetimes, tick, active, inactive)
			damped := disturbedEmission(t, tc.p, flowActiveJitterFraction, from, to, lifetimes, tick, active, inactive)

			p1, p4 := autocorrelation(plain, lag), autocorrelation(plain, 4*lag)
			d1, d4 := autocorrelation(damped, lag), autocorrelation(damped, 4*lag)
			t.Logf("undamped r1=%+.2f r4=%+.2f    damped r1=%+.2f r4=%+.2f", p1, p4, d1, d4)

			// Precondition, not the assertion: the fixture must reproduce the
			// echo this change exists to remove.
			if p1 < 0.6 || p4 < 0.4 {
				t.Fatalf("fixture no longer echoes without jitter (r1=%+.2f r4=%+.2f); "+
					"the comparison below would pass vacuously", p1, p4)
			}

			// One lifetime later, the echo is at most half of what it was.
			if d1 >= p1/2 {
				t.Errorf("at one lifetime the echo is %+.2f against an undamped %+.2f — not damped", d1, p1)
			}
			// Four lifetimes later it is gone, where undamped it is still there.
			if d4 >= p4/2 {
				t.Errorf("at four lifetimes the echo is %+.2f against an undamped %+.2f — "+
					"it repeats rather than decaying", d4, p4)
			}
		})
	}
}
