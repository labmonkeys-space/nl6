/*
 * Copyright 2026 Ronny Trommer <ronny@no42.org>
 * SPDX-License-Identifier: Apache-2.0
 */

package main

import (
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
func newScenarioSyslogScheduler(spec *Scenario, catalogFor func(net.IP) *SyslogCatalog, sharedLimiter *rate.Limiter, now func() time.Time) *SyslogScheduler {
	return NewSyslogScheduler(SyslogSchedulerOptions{
		CatalogFor:    catalogFor,
		MeanInterval:  spec.interval(),
		Seed:          spec.Seed,
		Now:           now,
		SharedLimiter: sharedLimiter,
		FixedInterval: true,
	})
}
