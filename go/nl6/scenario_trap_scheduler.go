/*
 * Copyright 2026 Ronny Trommer <ronny@no42.org>
 * SPDX-License-Identifier: Apache-2.0
 */

package main

import (
	"context"
	"math/rand"
	"runtime"
	"sync"
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

	// Emission runs on a worker pool for the same reason the fleet scheduler's
	// does: firing every participant inline on the ticker goroutine serialised
	// the whole scenario behind one core, so a run's achievable rate was
	// 1/(per-fire cost) no matter how many participants or cores there were.
	// The tick still draws the catalog entry (rng is not concurrency-safe and
	// the per-scenario seed is the determinism contract — see FR6/FR33), so
	// only the encode-and-send half is parallel.
	workers := runtime.GOMAXPROCS(0)
	if workers > len(targets) {
		workers = len(targets)
	}
	if workers < 1 {
		workers = 1
	}
	type fire struct {
		e     *TrapExporter
		entry *CatalogEntry
	}
	// Blocking sends on a shallow queue: when the pool cannot keep up the tick
	// falls behind honestly instead of queueing fires whose scenario-window
	// attribution would then be wrong.
	jobs := make(chan fire, workers*8)
	var wg sync.WaitGroup
	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := range jobs {
				j.e.fireScenario(j.entry, nil)
			}
		}()
	}

	go func() {
		defer func() {
			close(jobs)
			wg.Wait()
		}()
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
					entry := cat.Pick(rng)
					if entry == nil {
						continue
					}
					select {
					case jobs <- fire{t.e, entry}:
					case <-ctx.Done():
						return
					}
				}
			}
		}
	}()
}
