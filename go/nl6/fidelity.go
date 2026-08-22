/*
 * Copyright 2026 Ronny Trommer <ronny@no42.org>
 * SPDX-License-Identifier: Apache-2.0
 */

package main

import "sync/atomic"

// fidelity.go — global "fidelity mode" (-fidelity). When on, the fleet is
// SILENT: no autonomous background push telemetry (flow, SNMP trap, syslog,
// gNMI dial-out) leaves any device that is not currently inside a running
// load-test scenario window. Devices still answer polls (SNMP/SSH/HTTPS), and
// a scenario still emits its gated traffic during [T0,T1) — so an operator
// gets a clean measurement window: silent before the run, only the scenario
// during it, silent again after. Without a scenario, nothing is pushed at all.
//
// With several scenarios able to run at once (#392), read that promise
// PER DEVICE rather than fleet-wide, which is how the mute already works: the
// check below is in the non-participant branch, so a device holding any
// participation handle emits under its own scenario's gate and one holding
// none stays silent. What is no longer true is the fleet-wide reading — with
// overlapping windows a shared collector sees both runs at once. Per-scenario
// reconciliation survives that: run tagging (FR37) isolates each run, and
// participants are disjoint by construction, so the source IPs are too.
//
// It is a thin mute checked in each exporter's non-participant fire path (the
// `scenPart == nil` branch); the participant path is untouched, so scenario
// accounting and the gate are byte-for-byte unchanged.

// fidelitySilent is set once at startup from -fidelity and read (atomically,
// from many exporter goroutines) on every non-participant fire. 0 = off.
var fidelitySilent atomic.Bool

// fidelityMutesBackground reports whether fidelity mode should drop a
// non-participant fire of this source. It mutes autonomous noise — the Poisson
// background cadence and flap-driven state notifications — but lets explicit
// on-demand operator fires (POST /devices/{ip}/{trap,syslog}) through, since
// those are a deliberate action, not fleet chatter.
func fidelityMutesBackground(src fireSource) bool {
	return fidelitySilent.Load() && (src == sourceBackground || src == sourceStateDriven)
}
