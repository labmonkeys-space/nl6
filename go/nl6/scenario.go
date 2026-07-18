/*
 * Copyright 2026 Ronny Trommer <ronny@no42.org>
 * SPDX-License-Identifier: Apache-2.0
 */

package main

import (
	"fmt"
	"math"
	"net"
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
}

const defaultScenarioDrain = 2 * time.Second

// scenarioMaxWindow bounds runaway configs (mirrors the 24h cap convention
// of the REST auto-revert timers).
const scenarioMaxWindow = 24 * time.Hour

// scenarioMaxRate caps per-device events/second so the fixed interval stays
// >= the scheduler's 1ms floor (1s / 1000 = 1ms).
const scenarioMaxRate = 1000

// Validate performs structural validation (bounds, enums). It deliberately
// does NOT check device existence — that is arm-time semantics surfaced via
// the excluded set (FR9), mirroring the -topology-config lazy pattern.
func (s *Scenario) Validate() error {
	if len(s.Participants) == 0 {
		return fmt.Errorf("scenario: participants must not be empty")
	}
	for _, ip := range s.Participants {
		if net.ParseIP(ip) == nil {
			return fmt.Errorf("scenario: participant %q is not a valid IP", ip)
		}
	}
	if s.Protocol != "syslog" {
		return fmt.Errorf("scenario: unknown protocol %q (supported: syslog)", s.Protocol)
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
