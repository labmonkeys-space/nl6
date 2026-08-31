/*
 * Copyright 2026 Ronny Trommer <ronny@no42.org>
 * SPDX-License-Identifier: Apache-2.0
 */

package main

import (
	"fmt"
	"math"
	"net/netip"
	"slices"
	"time"
)

// Scenario is the declarative spec for one load-test experiment: which
// devices participate, on which protocol, at what rate, over what window.
// Story 1.2 scope: constructed directly (no HTTP); structural validation
// only — semantic resolution (device existence) happens at arm time, per
// the two-stage validation pattern (FR2/FR3, architecture D6).
type Scenario struct {
	// Participants are device management IPs (dotted quad). Closed-world
	// selector: an entry that resolves to no live device is a loud arm-time
	// exclusion.
	Participants []string
	// ParticipantsCIDR are IPv4 prefixes in canonical (masked) form. Open-world
	// selector: the participant set is the union of Participants and every live
	// device whose management IP falls inside any listed prefix. An address
	// inside a prefix that matches no device is silent (non-matches are not
	// enumerable); an explicit Participants entry covered by a prefix is
	// therefore a deliberate assertion, not a redundancy — it upgrades that one
	// address to the loud-miss semantics of the explicit list.
	ParticipantsCIDR []string
	// Protocol is the participating push protocol. MVP: "syslog" only.
	Protocol string
	// Rate is the per-device emission rate in events/second (FR4). The
	// constant-rate stub emits at exactly this rate (fixed interval);
	// λ(t) profiles arrive in Epic 3.
	Rate float64
	// Window is the measurement window length: T1 = T0 + Window.
	Window time.Duration
	// Seed pins every random draw the scenario makes (FR6/FR33).
	Seed int64
	// RateProfile is the optional time-varying intensity λ(t) (FR5). Nil or
	// kind "constant" keeps the flat `Rate` with an exact fixed-interval
	// cadence; linear/sine/staged emit an NHPP via Λ-inversion.
	RateProfile *RateProfileSpec
	// AbortPredicate optionally self-aborts a runaway run when a mid-run
	// ledger metric exceeds a threshold for a grace period (FR7).
	AbortPredicate *AbortPredicateSpec
	// ExpectParticipants is the declared participant cardinality: how many
	// devices the operator expects the selectors to resolve to. Nil means
	// undeclared (today's behaviour). It extends FR40's zero-armed guard from
	// zero to N and is enforced at the same two points in startLocked, never at
	// arm — arm-time membership is not what runs.
	//
	// EXACT, in both directions: a surplus is refused as loudly as a shortfall,
	// because the value of the guard is comparability against a baseline, and a
	// silently different denominator is what ruins it. "At least N" is a
	// different intent and would get a different field name.
	//
	// A POINTER, not an int, so that an explicit 0 is distinguishable from an
	// omitted field and can be rejected at submit. Silently reading 0 as
	// "undeclared" would make a caller that computes N programmatically and hits
	// a zero-length bug lose the guard exactly when it was needed — the silent
	// failure this whole field exists to prevent.
	ExpectParticipants *int
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

// scenarioMaxPrefixes bounds the participants_cidr list. The field's entire
// purpose is compactness — an operator who needs thousands of prefixes has an
// enumeration, and the explicit list is the shape for enumerations. The bound
// also keeps the containment validation honest: the body cap is derived from
// the 100k participant ceiling (~MB-scale), which would otherwise admit enough
// prefixes to make even a sorted overlap check a request-controlled cost. At
// the cap, worst-case compact wire cost is ~21 KiB ("255.255.255.255/32" plus
// quotes and comma), comfortably inside scenarioMaxBody's 64 KiB envelope
// budget for non-participant fields.
const scenarioMaxPrefixes = 1024

// Validate performs structural validation (bounds, enums). It deliberately
// does NOT check device existence — that is arm-time semantics surfaced via
// the excluded set (FR9), mirroring the -topology-config lazy pattern.
func (s *Scenario) Validate() error {
	// At least one selector must be non-empty. Both empty could only ever
	// produce FR40's 0/N start refusal, so the guaranteed-useless request is
	// reported at submit (same philosophy as the non-IPv4 rejection below).
	if len(s.Participants) == 0 && len(s.ParticipantsCIDR) == 0 {
		return fmt.Errorf("scenario: at least one of participants and participants_cidr must not be empty")
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
	if err := s.validatePrefixSelector(); err != nil {
		return err
	}
	// A declared expectation must be reachable: below 1 no run could ever
	// satisfy it (FR40 refuses a zero-armed start), and above the ceiling no
	// participant set may legally get that large. Both are guaranteed-useless
	// declarations, reported at submit like every other one.
	if s.ExpectParticipants != nil {
		n := *s.ExpectParticipants
		if n < 1 || n > scenarioMaxParticipants {
			return fmt.Errorf("scenario: expect_participants must be between 1 and %d, got %d",
				scenarioMaxParticipants, n)
		}
		// With no prefix selector the armed set cannot exceed the declared list,
		// so an expectation above it is unsatisfiable by construction — the same
		// class of guaranteed-useless declaration as the bounds above, and known
		// with the same submit-time information. A prefix makes the resolved size
		// unknowable until arm, so no bound is derivable then.
		if len(s.ParticipantsCIDR) == 0 && n > len(s.Participants) {
			return fmt.Errorf("scenario: expect_participants is %d but only %d participants are declared and no participants_cidr is set, so it can never be satisfied",
				n, len(s.Participants))
		}
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
	// Rate profile (FR5): structural validation now so a bad profile is a
	// submit-time 400, not a Start-time failure. The built profile is
	// discarded here (rebuilt at Start); validation is the only goal.
	if _, err := buildRateProfile(s.RateProfile, s.Rate, s.Window); err != nil {
		return fmt.Errorf("scenario: %w", err)
	}
	// A flow scenario is paced by sizing the device's flow cache, and the cache
	// reaches a new population only as flows age out — a lag of roughly one mean
	// flow lifetime, measured at 1.03x it. A ramp shorter than that comes out
	// smeared into something that is neither the requested shape nor a constant.
	//
	// Refused rather than accepted-and-disclosed: the operator's chance to pick
	// a different protocol or shape is here, not in the report afterwards.
	// Protocol alone decides this, so it belongs at submit.
	if s.RateProfile != nil && isFlowScenarioProtocol(s.Protocol) {
		return fmt.Errorf("scenario: rate_profile is not supported for flow protocols (%s): flow is paced by "+
			"resizing the device's flow cache, which follows a change with a lag of about one mean flow "+
			"lifetime (~29s at the shipped defaults), so a time-varying rate would be smeared rather than "+
			"reproduced. Use a constant rate, or drive the shape with syslog", s.Protocol)
	}
	if _, err := buildAbortPredicate(s.AbortPredicate); err != nil {
		return fmt.Errorf("scenario: %w", err)
	}
	return nil
}

// validatePrefixSelector validates participants_cidr: canonical IPv4 prefixes,
// bounded count, and no within-field redundancy. An explicit participant
// covered by a prefix is deliberately NOT checked here — cross-world overlap
// is assertion semantics (see the ParticipantsCIDR field comment), and the
// arm-side merge deduplicates through the parts map it fills anyway.
func (s *Scenario) validatePrefixSelector() error {
	if len(s.ParticipantsCIDR) == 0 {
		return nil
	}
	// Bound before parsing, mirroring the participant-ceiling ordering above.
	if len(s.ParticipantsCIDR) > scenarioMaxPrefixes {
		return fmt.Errorf("scenario: participants_cidr has %d entries, exceeding the %d cap",
			len(s.ParticipantsCIDR), scenarioMaxPrefixes)
	}
	type rawPrefix struct {
		p   netip.Prefix
		raw string
	}
	prefixes := make([]rawPrefix, 0, len(s.ParticipantsCIDR))
	for _, raw := range s.ParticipantsCIDR {
		p, err := netip.ParsePrefix(raw)
		if err != nil {
			return fmt.Errorf("scenario: participants_cidr entry %q is not a valid CIDR prefix", raw)
		}
		// Same Is4 discipline as the participant loop above: an Is4In6 prefix
		// ("::ffff:10.42.0.0/120") canonicalises away from the dotted-quad keys
		// the arm-time membership test parses, so it is the prefix-shaped
		// spelling of the same guaranteed-useless request.
		if !p.Addr().Is4() {
			return fmt.Errorf("scenario: participants_cidr entry %q must be an IPv4 prefix", raw)
		}
		// Canonical (masked) form only. Silently masking would make two
		// distinguishable submits fingerprint differently yet run identically
		// (config_sha256 hashes the raw spelling), and a host address where a
		// network was meant is the classic typo — reject loudly, naming the
		// canonical form for self-service.
		if p != p.Masked() {
			return fmt.Errorf("scenario: participants_cidr entry %q has host bits set; the canonical form is %q",
				raw, p.Masked().String())
		}
		prefixes = append(prefixes, rawPrefix{p: p, raw: raw})
	}
	// Within-field redundancy. CIDR prefixes form a laminar family — two
	// prefixes are either disjoint or nested — so after sorting by (address,
	// bits) every containment surfaces as an adjacent pair: anything sorted
	// between a container and its containee starts inside the container's range
	// and is therefore itself contained. That makes this O(n log n), not the
	// pairwise O(n²) the raw laminar property would suggest. A duplicate or
	// nested prefix adds no address and no assertion, so it is rejected as
	// guaranteed-useless (unlike a covered explicit participant, which upgrades
	// an address to loud-miss semantics and is allowed).
	slices.SortFunc(prefixes, func(a, b rawPrefix) int {
		if c := a.p.Addr().Compare(b.p.Addr()); c != 0 {
			return c
		}
		return a.p.Bits() - b.p.Bits()
	})
	for i := 1; i < len(prefixes); i++ {
		prev, cur := prefixes[i-1], prefixes[i]
		if prev.p == cur.p {
			return fmt.Errorf("scenario: prefix %q appears more than once; participants_cidr is a set", cur.raw)
		}
		// Sorted order guarantees the earlier prefix is the container.
		if prev.p.Overlaps(cur.p) {
			return fmt.Errorf("scenario: prefix %q is covered by %q; a nested prefix adds nothing to the union",
				cur.raw, prev.raw)
		}
	}
	return nil
}

// rateProfileOrDefault builds the scenario's rate profile (or the constant
// default). Callers have already passed Validate, so the error is
// unexpected — surfaced for defensive handling at Start.
func (s *Scenario) rateProfile() (rateProfile, error) {
	return buildRateProfile(s.RateProfile, s.Rate, s.Window)
}

// selectorSummary renders the declared selector cardinality for 0/N refusal
// messages. The explicit-only form is the historical "%d"; with prefixes the
// denominator is not an address count, so both selector shapes are named
// (a CIDR-only scenario would otherwise read as a nonsensical "0/0").
func (s *Scenario) selectorSummary() string {
	if len(s.ParticipantsCIDR) == 0 {
		return fmt.Sprintf("%d", len(s.Participants))
	}
	return fmt.Sprintf("%d explicit + %d prefixes", len(s.Participants), len(s.ParticipantsCIDR))
}

// interval returns the fixed inter-fire interval for the constant-rate stub.
func (s *Scenario) interval() time.Duration {
	return time.Duration(float64(time.Second) / s.Rate)
}
