/*
 * Copyright 2026 Ronny Trommer <ronny@no42.org>
 * SPDX-License-Identifier: Apache-2.0
 */

package main

import (
	"time"
)

// export_interval_disclosure.go — reports the intervals actually in force.
//
// Three per-device settings USED TO BE stored, echoed, and ignored: syslog
// `interval`, trap `interval`, and flow `tick_interval`. The syslog and trap
// schedulers fire every device at their simulator-wide MeanInterval; flow
// drives every device from one simulator-wide ticker. That the feature is
// missing is defensible. That the API reported a value the engine did not use
// was not: a configuration surface which confirms a wrong belief is worse than
// one that stays silent, because the operator's natural check is to read the
// value back.
//
// nl6#445 resolved that by REJECTING those fields with a 400 rather than
// disclosing them, so the wrong belief is now impossible rather than merely
// annotated. What remains in this file is the other half: telling a caller what
// the intervals actually ARE, through the effective_intervals block on
// GET /api/v1/devices.
//
// THREE THINGS LIVE HERE
//
//  1. (REMOVED in nl6#445) intervalDisclosure, the inert-field predicate. The
//     fields it warned about are rejected outright now, so the warning has no
//     subject left.
//
//  2. The effectiveIntervals block. The effective values are reported in a
//     SIBLING object on the device read-back, NOT as extra fields inside the
//     `flow` / `traps` / `syslog` blocks. Nesting them there made the GET
//     blocks un-POSTable: `createDevicesHandler` decodes with
//     DisallowUnknownFields, and that strictness reaches into nested objects,
//     so any read-modify-write client broke — including the repo's own
//     `scripts/fleet.sh import`, which re-POSTs the GET blocks verbatim and
//     whose round trip `docs/getting-started/fleet.md` advertises. A sibling
//     object keeps the config blocks byte-identical between GET and POST, so
//     the round trip works by construction and strict decoding keeps its full
//     typo-detection value.
//
//  3. The effective* accessors.
//
// WHAT "EFFECTIVE" MEANS HERE, AND WHAT IT DOES NOT
//
// These report the cadence the scheduler is CONFIGURED with. That is strictly
// more truthful than the inert per-device field, but it is NOT an observed
// emission rate, and the difference is load-bearing enough to name:
//
//   - the global cap throttles by BLOCKING (syslog_scheduler.go, limiter.Wait),
//     so -syslog-global-cap 5 across 30k devices yields a real cadence near
//     100 minutes while these accessors still report the 10s mean
//   - -fidelity mutes background emission entirely, so the device emits
//     nothing while these accessors still report the mean
//   - a running scenario drives its participants from a scenario-owned
//     scheduler at the scenario's own rate, which these accessors never see
//
// Folding those in would mean reporting a per-device, time-varying observed
// rate, which is a different feature (a status surface, not a config echo).
// Until then the contract is "configured cadence", and the docs and spec say
// so rather than claiming "what actually runs".

// exportWarning is one machine-readable disclosure attached to a create
// response. Message is self-contained so a human reading a raw response body
// needs no other field to understand it.
type exportWarning struct {
	Field     string `json:"field"`
	Requested string `json:"requested"`
	Effective string `json:"effective"`
	Message   string `json:"message"`
}

// intervalDisclosure was removed in nl6#445. It reported an interval the
// caller asked for that the engine would not honour — a warning attached to a
// request that had nonetheless stored the value. Those fields are now rejected
// with a 400 in the three Validate methods (export_config.go), so there is
// nothing left to disclose: an inert value can no longer be accepted at all.
//
// The exportWarning type above survives on purpose: it is the general "your
// request was accepted, but here is something you should know" channel and part
// of the response shape. Nothing populates it today.

// effectiveIntervals is the sibling block on a device read-back reporting the
// cadences actually configured, for whichever export subsystems the device
// participates in. Fields are omitted for subsystems the device does not use.
//
// It sits BESIDE the config blocks rather than inside them so that the config
// blocks stay valid POST bodies. See the file header.
type effectiveIntervals struct {
	SyslogInterval   string `json:"syslog_interval,omitempty"`
	TrapInterval     string `json:"traps_interval,omitempty"`
	FlowTickInterval string `json:"flow_tick_interval,omitempty"`
}

// effectiveIntervalSnapshot is the simulator-wide cadence set, resolved ONCE
// per response.
//
// These values are identical for every device — they are scheduler
// configuration, not device state — so resolving them per device did 3x30k
// Duration.String() calls inside sm.mu.RLock on the fleet-list path.
type effectiveIntervalSnapshot struct{ syslog, trap, flow string }

// snapshotEffectiveIntervals resolves the three cadences once. Call outside the
// per-device loop.
func (sm *SimulatorManager) snapshotEffectiveIntervals() effectiveIntervalSnapshot {
	return effectiveIntervalSnapshot{
		syslog: sm.effectiveSyslogInterval().String(),
		trap:   sm.effectiveTrapInterval().String(),
		flow:   sm.effectiveFlowTickInterval().String(),
	}
}

// buildEffectiveIntervals returns the block for a device, or nil when the
// device participates in no export subsystem (so `omitempty` drops it).
//
// It carries no explanatory note. An earlier version embedded a 175-character
// caveat per device, which on a 30k fleet meant ~7 MB of identical boilerplate
// in one response. The caveat belongs in the docs and in this file's header,
// not replicated once per row.
func buildEffectiveIntervals(dev *DeviceSimulator, snap effectiveIntervalSnapshot) *effectiveIntervals {
	if dev == nil || (dev.syslogConfig == nil && dev.trapConfig == nil && dev.flowConfig == nil) {
		return nil
	}
	e := &effectiveIntervals{}
	if dev.syslogConfig != nil {
		e.SyslogInterval = snap.syslog
	}
	if dev.trapConfig != nil {
		e.TrapInterval = snap.trap
	}
	if dev.flowConfig != nil {
		e.FlowTickInterval = snap.flow
	}
	return e
}

// effectiveSyslogInterval reports the mean firing interval the syslog
// scheduler is configured with. Sourced from the live scheduler rather than a
// re-derived constant, so it cannot go stale if the default or the
// -syslog-interval seed changes. See the file header for what it excludes.
//
// The scheduler is read through an atomic.Pointer and MeanInterval is fixed at
// construction, so this is lock-free and safe to call while sm.mu is held.
// A nil scheduler means the subsystem is not running — either never started, or
// already stopped during shutdown. The package default is returned as a defined
// answer rather than a zero that would render as a misleading "0s".
func (sm *SimulatorManager) effectiveSyslogInterval() time.Duration {
	if s := sm.syslogScheduler.Load(); s != nil {
		return s.MeanInterval()
	}
	return defaultSyslogInterval
}

// effectiveTrapInterval is the trap equivalent of effectiveSyslogInterval.
func (sm *SimulatorManager) effectiveTrapInterval() time.Duration {
	if s := sm.trapScheduler.Load(); s != nil {
		return s.MeanInterval()
	}
	return defaultTrapInterval
}

// effectiveFlowTickInterval reports the cadence the flow ticker is running at,
// which is deliberately not sm.flowTickInterval.
//
// Those two can disagree. startFlowTicker runs from the SimulatorManager
// constructor and latches the value then; a late field write would be
// afterwards from the flag path and only writes the field, never restarting
// the ticker. So a simulator started with -flow-tick-interval 30s holds 30s in
// the field while flow records leave every 5s.
//
// Reporting the field would make this accessor state a cadence nothing runs
// at, so it reports the latched period instead. Since nl6#446 was fixed the two
// agree in production; reading the latch keeps that true by CONSTRUCTION rather
// than by the constructor's call order happening to be right.
func (sm *SimulatorManager) effectiveFlowTickInterval() time.Duration {
	if latched := sm.flowTickerPeriod.Load(); latched > 0 {
		return time.Duration(latched)
	}
	// Ticker not started (a bare manager, i.e. tests). Deliberately does NOT
	// fall back to sm.flowTickInterval: that field is written during
	// construction without synchronisation, and this accessor runs on HTTP
	// goroutines via ListDevices and the create handler. Reading it here would
	// reintroduce, on a new path, the very race the latch removed.
	return defaultFlowTickInterval
}

// echoSyslogConfig returns the config as it should appear in a read-back.
//
// When the caller never supplied an interval, the stored value is whatever
// ApplyDefaults stamped, and echoing it reports a choice nobody made. Worse, it
// is not inert on re-submission: `scripts/fleet.sh import` re-POSTs the echoed
// block, `markIntervalProvenance` sees a non-zero duration, and the operator
// gets one "you set an inert interval" warning per device for a value the
// simulator itself invented.
//
// So a defaulted interval is omitted from the echo. The cadence in force is
// reported by effective_intervals, which is the honest place for it, and a GET
// block round-trips through POST unchanged and silent.
//
// Returns the original pointer when nothing needs hiding, so the common
// explicit-interval case allocates nothing.
func echoSyslogConfig(c *DeviceSyslogConfig) *DeviceSyslogConfig {
	if c == nil || c.intervalSet {
		return c
	}
	cp := *c
	cp.Interval = 0 // omitempty drops it
	return &cp
}

func echoTrapConfig(c *DeviceTrapConfig) *DeviceTrapConfig {
	if c == nil || c.intervalSet {
		return c
	}
	cp := *c
	cp.Interval = 0
	return &cp
}

func echoFlowConfig(c *DeviceFlowConfig) *DeviceFlowConfig {
	if c == nil || c.tickIntervalSet {
		return c
	}
	cp := *c
	cp.TickInterval = 0
	return &cp
}
