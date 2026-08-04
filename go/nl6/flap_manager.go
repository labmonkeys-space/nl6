/*
 * Copyright 2026 Ronny Trommer <ronny@no42.org>
 * SPDX-License-Identifier: Apache-2.0
 */

package main

import (
	"context"
	"fmt"
	"log"
)

// FlapSubsystemConfig groups the once-per-process knobs StartFlapSubsystem
// needs. GlobalCap=0 disables the rate limiter; DefaultScenario applies to
// devices created via the auto-start batch (-if-flap-scenario) and to the
// fallback when a REST device omits if_flap_scenario.
type FlapSubsystemConfig struct {
	GlobalCap       int
	DefaultScenario IfFlapScenario
}

// StartFlapSubsystem creates the shared flap scheduler and starts its
// goroutine under a manager-owned cancellable context. Mirrors
// StartTrapSubsystem / StartSyslogSubsystem. Idempotent guard: returns
// an error if already started.
//
// The Run goroutine is paired with `sm.flapRunCancel`; StopFlapSubsystem
// invokes the cancel func so any blocking call inside Run (notably
// `limiter.Wait(ctx)`) is unblocked promptly. Without this pairing,
// Stop could only signal the loop at non-limiter rendezvous points,
// leaving the goroutine stuck across shutdown.
//
// Per-device opt-in happens later via the device-add path which calls
// `scheduler.Register` for non-clean scenarios.
func (sm *SimulatorManager) StartFlapSubsystem(cfg FlapSubsystemConfig) error {
	if sm.flapScheduler.Load() != nil {
		return fmt.Errorf("flap subsystem: already started")
	}
	if cfg.GlobalCap < 0 {
		return fmt.Errorf("flap subsystem: -if-flap-global-cap must be non-negative, got %d", cfg.GlobalCap)
	}
	if cfg.DefaultScenario != "" && !ValidFlapScenario(cfg.DefaultScenario) {
		return fmt.Errorf("flap subsystem: -if-flap-scenario %q is not one of clean|rare|typical|aggressive", cfg.DefaultScenario)
	}
	if cfg.DefaultScenario == "" {
		cfg.DefaultScenario = IfFlapClean
	}

	scheduler := NewFlapScheduler(FlapSchedulerOptions{
		GlobalCapPerSecond: cfg.GlobalCap,
	})

	runCtx, runCancel := context.WithCancel(context.Background())

	sm.mu.Lock()
	sm.flapGlobalCap = cfg.GlobalCap
	sm.flapDefaultIfs = cfg.DefaultScenario
	sm.flapRunCancel = runCancel
	// Publish under sm.mu so any reader holding RLock sees scheduler-set
	// alongside the dependent fields. The atomic.Pointer is only here
	// to give getFlapScheduler a lock-free Load for the DeleteDevice
	// hot path.
	sm.flapScheduler.Store(scheduler)
	sm.mu.Unlock()

	capStr := "unlimited"
	if cfg.GlobalCap > 0 {
		capStr = fmt.Sprintf("%d/s", cfg.GlobalCap)
	}
	log.Printf("Flap subsystem: ready (cap=%s, default-scenario=%s) — awaiting per-device registration",
		capStr, cfg.DefaultScenario)

	go scheduler.Run(runCtx)
	return nil
}

// StopFlapSubsystem stops the scheduler and clears the manager-side
// pointers. Shutdown-only — not safe to call concurrently with device
// AddDevice; the existing trap/syslog convention applies.
//
// Cancels the Run context BEFORE calling Stop for promptness; Stop is
// self-sufficient since #414 (it awaits Run's exit and Run derives its
// limiter context from stopCh), so on return no flap fire is in flight.
func (sm *SimulatorManager) StopFlapSubsystem() {
	scheduler := sm.flapScheduler.Swap(nil)
	if scheduler == nil {
		return
	}
	sm.mu.Lock()
	cancel := sm.flapRunCancel
	sm.flapRunCancel = nil
	sm.mu.Unlock()
	if cancel != nil {
		cancel()
	}
	scheduler.Stop()
}

// getFlapScheduler returns the manager's flap scheduler pointer via a
// lock-free atomic Load so callers that already hold sm.mu (notably
// DeleteDevice) cannot self-deadlock. Safe with nil manager.
func getFlapScheduler(sm *SimulatorManager) *FlapScheduler {
	if sm == nil {
		return nil
	}
	return sm.flapScheduler.Load()
}
