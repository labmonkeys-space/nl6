/*
 * Copyright 2026 Ronny Trommer <ronny@no42.org>
 * SPDX-License-Identifier: Apache-2.0
 */

package main

import (
	"fmt"
	"math"
	"net/netip"
	"time"
)

// Scenario is the declarative spec for one load-test experiment: which
// devices participate, on which protocol, at what rate, over what window.
// Story 1.2 scope: constructed directly (no HTTP); structural validation
// only — semantic resolution (device existence) happens at arm time, per
// the two-stage validation pattern (FR2/FR3, architecture D6).
type Scenario struct {
	// Participants are device management IPs (dotted quad).
	Participants []string
	// Protocol is the participating push protocol. MVP: "syslog" only.
	Protocol string
	// Rate is the per-device emission rate in events/second (FR4). The
	// constant-rate stub emits at exactly this rate (fixed interval);
	// λ(t) profiles arrive in Epic 3.
	Rate float64
	// Window is the measurement window length: T1 = T0 + Window.
	Window time.Duration
	// Drain is the grace period after T1 during which in-flight sends may
	// complete (bucketed `drain`). Zero selects the default.
	Drain time.Duration
	// Seed pins every random draw the scenario makes (FR6/FR33).
	Seed int64
	// RateProfile is the optional time-varying intensity λ(t) (FR5). Nil or
	// kind "constant" keeps the flat `Rate` with an exact fixed-interval
	// cadence; linear/sine/staged emit an NHPP via Λ-inversion.
	RateProfile *RateProfileSpec
	// AbortPredicate optionally self-aborts a runaway run when a mid-run
	// ledger metric exceeds a threshold for a grace period (FR7).
	AbortPredicate *AbortPredicateSpec
}

// scenarioProtocols is the set of push protocols a scenario may gate. Widened
// per Epic 4 as each protocol's exporter gains gate wiring.
var scenarioProtocols = map[string]bool{
	"syslog":       true,
	"netflow9":     true,
	"ipfix":        true,
	"gnmi-dialout": true,
	"snmp-trap":    true,
	"sflow":        true,
	"netflow5":     true,
}

// flowScenarioProtocols are the FlowExporter-backed scenario protocols (gated
// in FlowExporter.Tick, emitted via the flow ticker — no syslog scheduler).
var flowScenarioProtocols = map[string]bool{
	"netflow9": true,
	"ipfix":    true,
	"sflow":    true,
	"netflow5": true,
}

// isFlowScenarioProtocol reports whether p is emitted by a FlowExporter.
func isFlowScenarioProtocol(p string) bool { return flowScenarioProtocols[p] }

const defaultScenarioDrain = 2 * time.Second

// scenarioMaxWindow bounds runaway configs (mirrors the 24h cap convention
// of the REST auto-revert timers).
const scenarioMaxWindow = 24 * time.Hour

// scenarioMaxRate caps per-device events/second so the fixed interval stays
// >= the scheduler's 1ms floor (1s / 1000 = 1ms).
const scenarioMaxRate = 1000

// scenarioMaxParticipants bounds the participant list. 100k mirrors the
// createDevices device-count ceiling ("comfortably covers the 30k+ target
// fleet and a flat /16 management plane") so the codebase carries one scale
// constant instead of two differently-justified ones.
//
// It is a semantic bound, not a capability claim and not an allocation guard.
// Not a capability claim: a participant that resolves to no live device becomes
// an arm-time exclusion, not a submit-time failure. Not an allocation guard:
// this check can only run once the whole slice is decoded, so the byte cap
// (scenarioMaxBody) is what actually bounds how much a single request can make
// the server allocate.
//
// Before this bound existed, the REST submit body cap was the only thing
// limiting the slice — which made the *accidental* limit (~4,400 participants
// at 64 KiB) the binding one, well under the 30k fleet the subsystem targets.
const scenarioMaxParticipants = 100_000

// Validate performs structural validation (bounds, enums). It deliberately
// does NOT check device existence — that is arm-time semantics surfaced via
// the excluded set (FR9), mirroring the -topology-config lazy pattern.
func (s *Scenario) Validate() error {
	if len(s.Participants) == 0 {
		return fmt.Errorf("scenario: participants must not be empty")
	}
	// Bound the list before parsing it, so an over-ceiling request is rejected
	// without running 100k+ address parses. (It cannot save the *allocation* —
	// the decoder has already materialised every string by the time Validate
	// runs; scenarioMaxBody is the guard for that.) Checked here rather than in
	// the HTTP handler so the in-process construction path is bounded too.
	if len(s.Participants) > scenarioMaxParticipants {
		return fmt.Errorf("scenario: participants has %d entries, exceeding the %d cap",
			len(s.Participants), scenarioMaxParticipants)
	}
	// `participants` is a SET, and a repeat is rejected rather than collapsed.
	// A duplicate has no meaningful semantics — the ledger reconciles on
	// (protocol, source_ip, collector), so a device named twice is one source —
	// and silently collapsing leaves seams: config_sha256 would still fingerprint
	// the raw list, so two distinguishable submits would produce identical runs,
	// and the collapse would be invisible in the readiness response. Rejecting is
	// also consistent with how the other guaranteed-useless input (a non-IPv4
	// participant) is handled, and keeps the check outside the manager lock that
	// Arm holds while resolving.
	seen := make(map[string]struct{}, len(s.Participants))
	for _, ip := range s.Participants {
		addr, err := netip.ParseAddr(ip)
		if err != nil {
			return fmt.Errorf("scenario: participant %q is not a valid IP", ip)
		}
		// IPv4 dotted quad only: the simulated fleet is v4 throughout (TUN
		// interfaces, the management plane, To4()-based route generation), so a
		// v6 participant could only ever resolve to a "device not found"
		// exclusion at arm. Rejecting it here reports a guaranteed-useless
		// request at submit and keeps the worst-case wire cost of an entry at
		// scenarioParticipantWireBytes.
		//
		// Is4() — NOT net.IP.To4() — is the predicate that means "dotted quad".
		// To4() is non-nil for IPv4-MAPPED IPv6 as well ("::ffff:10.42.0.1",
		// and its expanded 45-character spelling), which would sail through
		// here, canonicalise to 10.42.0.1, and then MISS Arm's devicesByIP
		// lookup, because that map is keyed by the canonical dotted quad while
		// Arm looks up the raw request string. That is precisely the useless
		// exclusion this check exists to prevent — and at 48 wire bytes for the
		// expanded form it would also falsify scenarioParticipantWireBytes.
		// netip.Addr.Is4 reports false for Is4In6 addresses, which is what
		// makes it the right question.
		if !addr.Is4() {
			return fmt.Errorf("scenario: participant %q must be an IPv4 dotted quad", ip)
		}
		if _, dup := seen[ip]; dup {
			return fmt.Errorf("scenario: participant %q appears more than once; participants is a set", ip)
		}
		seen[ip] = struct{}{}
	}
	if !scenarioProtocols[s.Protocol] {
		return fmt.Errorf("scenario: unknown protocol %q (supported: syslog, netflow9, ipfix, gnmi-dialout, snmp-trap, sflow, netflow5)", s.Protocol)
	}
	if s.Rate <= 0 || math.IsNaN(s.Rate) || math.IsInf(s.Rate, 0) {
		return fmt.Errorf("scenario: rate must be a finite value > 0 events/second, got %g", s.Rate)
	}
	// The scheduler floors inter-fire intervals at 1ms (NewSyslogScheduler
	// panics below that), so cap the rate at 1000/s per device — bounding
	// it here turns a would-be Start-time panic into a submit-time 400.
	if s.Rate > scenarioMaxRate {
		return fmt.Errorf("scenario: rate %g exceeds the %g events/second cap", s.Rate, float64(scenarioMaxRate))
	}
	if s.Window <= 0 {
		return fmt.Errorf("scenario: window must be > 0, got %s", s.Window)
	}
	if s.Window > scenarioMaxWindow {
		return fmt.Errorf("scenario: window %s exceeds the %s cap", s.Window, scenarioMaxWindow)
	}
	if s.Drain < 0 {
		return fmt.Errorf("scenario: drain must be >= 0, got %s", s.Drain)
	}
	// Rate profile (FR5): structural validation now so a bad profile is a
	// submit-time 400, not a Start-time failure. The built profile is
	// discarded here (rebuilt at Start); validation is the only goal.
	if _, err := buildRateProfile(s.RateProfile, s.Rate, s.Window); err != nil {
		return fmt.Errorf("scenario: %w", err)
	}
	if _, err := buildAbortPredicate(s.AbortPredicate); err != nil {
		return fmt.Errorf("scenario: %w", err)
	}
	return nil
}

// rateProfileOrDefault builds the scenario's rate profile (or the constant
// default). Callers have already passed Validate, so the error is
// unexpected — surfaced for defensive handling at Start.
func (s *Scenario) rateProfile() (rateProfile, error) {
	return buildRateProfile(s.RateProfile, s.Rate, s.Window)
}

// drainOrDefault returns the configured drain grace, defaulting when zero.
func (s *Scenario) drainOrDefault() time.Duration {
	if s.Drain == 0 {
		return defaultScenarioDrain
	}
	return s.Drain
}

// interval returns the fixed inter-fire interval for the constant-rate stub.
func (s *Scenario) interval() time.Duration {
	return time.Duration(float64(time.Second) / s.Rate)
}
