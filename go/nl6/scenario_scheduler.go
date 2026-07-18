/*
 * Copyright 2026 Ronny Trommer <ronny@no42.org>
 * SPDX-License-Identifier: Apache-2.0
 */

package main

import (
	"hash/fnv"
	"math/rand"
	"net"
	"time"

	"golang.org/x/time/rate"
)

// backgroundSyslogFirer adapts a device's SyslogExporter for registration
// in the BACKGROUND scheduler: fires carry the background source flag so
// the scenario gate can suppress the device's regular cadence for the
// scenario lifetime (generation-suppressed + informational disclosure).
// For non-participants this is a zero-cost pass-through.
type backgroundSyslogFirer struct{ e *SyslogExporter }

func (f backgroundSyslogFirer) Fire(entry *SyslogCatalogEntry, overrides map[string]string) error {
	return f.e.fireBackground(entry, overrides)
}

// scenarioSyslogFirer adapts a participant's SyslogExporter for the
// SCENARIO-owned scheduler: fires carry the scenario source flag (allowed
// in [T0,T1), counted `sent` at write-return).
type scenarioSyslogFirer struct{ e *SyslogExporter }

func (f scenarioSyslogFirer) Fire(entry *SyslogCatalogEntry, overrides map[string]string) error {
	return f.e.fireScenario(entry, overrides)
}

// newScenarioSyslogScheduler builds the scenario-owned scheduler instance
// (architecture D1b): the SAME min-heap scheduler type as the fleet's, but
// with its own seed and clock (determinism isolation — NFR-A5), the
// constant-rate FixedInterval stub (FR4; Epic 3 replaces it with Λ-inversion
// profiles), and the background scheduler's SHARED limiter so fleet +
// scenario honor one global cap budget (FR36 — never construct a second
// limiter; nil limiter = fleet uncapped, scenario too).
func newScenarioSyslogScheduler(spec *Scenario, catalogFor func(net.IP) *SyslogCatalog, sharedLimiter *rate.Limiter, now func() time.Time) (*SyslogScheduler, error) {
	profile, err := spec.rateProfile()
	if err != nil {
		return nil, err
	}
	opts := SyslogSchedulerOptions{
		CatalogFor:    catalogFor,
		MeanInterval:  spec.interval(),
		Seed:          spec.Seed,
		Now:           now,
		SharedLimiter: sharedLimiter,
	}
	if _, isConstant := profile.(constantProfile); isConstant {
		// Constant λ: keep the exact fixed-interval cadence (deterministic
		// rate×window count — FR4). NHPP is reserved for time-varying λ.
		opts.FixedInterval = true
	} else {
		// Time-varying λ(t): each device fires at its own NHPP arrivals drawn
		// by Λ-inversion, seeded deterministically per (scenario seed, device).
		opts.ArrivalStreamFor = nhppStreamFor(profile, spec.Window, spec.Seed)
	}
	return NewSyslogScheduler(opts), nil
}

// nhppStreamFor returns a per-device NHPP arrival-offset generator (offsets
// from T0). Each device draws its own independent arrival stream from a seed
// derived from (scenario seed, device IP), so the fleet is deterministic yet
// devices are not phase-locked (FR5/FR6).
func nhppStreamFor(profile rateProfile, window time.Duration, seed int64) func(net.IP) []time.Duration {
	w := window.Seconds()
	return func(ip net.IP) []time.Duration {
		h := fnv.New64a()
		_, _ = h.Write(ip)
		rnd := rand.New(rand.NewSource(seed ^ int64(h.Sum64())))
		arr := nhppArrivals(profile, w, rnd)
		out := make([]time.Duration, len(arr))
		for i, a := range arr {
			out[i] = time.Duration(a * float64(time.Second))
		}
		return out
	}
}
