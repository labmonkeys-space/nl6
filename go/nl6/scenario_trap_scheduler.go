/*
 * Copyright 2026 Ronny Trommer <ronny@no42.org>
 * SPDX-License-Identifier: Apache-2.0
 */

package main

import (
	"context"
	"math/rand"
	"time"
)

// scenario_trap_scheduler.go — SNMP trap/INFORM scenario glue (story 4.4).
// The fleet trap scheduler fires each participant with the BACKGROUND source
// (suppressed for the scenario's lifetime — same shape as syslog); the
// scenario drives trap emission at its own cadence via a controller ticker
// that fires with the SCENARIO source (allowed + counted in [T0,T1)).

// backgroundTrapFirer wraps a TrapExporter so the fleet scheduler's fires
// carry the background source flag for the scenario gate. Byte-for-byte
// pass-through for a non-participant.
type backgroundTrapFirer struct{ e *TrapExporter }

func (f backgroundTrapFirer) Fire(entry *CatalogEntry, overrides map[string]string) uint32 {
	return f.e.fireBackground(entry, overrides)
}

// startScenarioTrapTicker drives participant trap emission at the scenario
// cadence during [T0,T1). Each tick fires one weighted-random catalog entry
// (seeded per scenario for determinism) with the scenario source. Runs on
// schedCtx, so finalize (which cancels schedStop) stops it.
func (c *ScenarioController) startScenarioTrapTicker(ctx context.Context) {
	c.sm.mu.RLock()
	type target struct {
		e  *TrapExporter
		ip string
	}
	targets := make([]target, 0, len(c.parts))
	for ip := range c.parts {
		if dev := c.sm.devicesByIP[ip]; dev != nil && dev.trapExporter != nil {
			targets = append(targets, target{dev.trapExporter, ip})
		}
	}
	c.sm.mu.RUnlock()

	rng := rand.New(rand.NewSource(c.spec.Seed))
	interval := c.spec.interval()
	go func() {
		ticker := time.NewTicker(interval)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				for _, t := range targets {
					cat := c.sm.CatalogFor(t.ip)
					if cat == nil {
						continue
					}
					if entry := cat.Pick(rng); entry != nil {
						t.e.fireScenario(entry, nil)
					}
				}
			}
		}
	}()
}
