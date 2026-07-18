/*
 * Copyright 2026 Ronny Trommer <ronny@no42.org>
 * SPDX-License-Identifier: Apache-2.0
 */

package main

import (
	"fmt"
	"math"
	"math/rand"
	"time"
)

// scenario_rate_profile.go — time-varying emission profiles λ(t) for the
// scenario scheduler (FR5). Arrival times are drawn as a non-homogeneous
// Poisson process (NHPP) by **inversion of the integrated intensity**
// Λ(t) = ∫₀ᵗ λ(s) ds: draw a unit-rate Poisson stream E₁<E₂<… (each a running
// sum of Exp(1) — ONE seeded draw per event) and map T_i = Λ⁻¹(E_i). This is
// unbiased for any λ(t).
//
// The tempting anti-pattern — at each step draw the next gap as Exp(λ(t_now))
// using the CURRENT instantaneous rate — is biased for time-varying λ (it
// samples the rate at the wrong instant). It is deliberately NOT used here;
// `scenario_rate_profile_test.go` proves the two differ and that production
// takes the inversion path (time-rescaling theorem).

// RateProfileSpec is the wire/config description of a rate profile. Omitted
// (or kind="constant") selects the flat `rate`. Fields are per-kind:
//   - linear: start_rate, end_rate (events/sec at T0 and T1)
//   - sine:   mean_rate (defaults to `rate`), amplitude (< mean), period
//   - staged: stages[]{duration, rate} — piecewise-constant, last extends
type RateProfileSpec struct {
	Kind      string         `json:"kind"`
	StartRate float64        `json:"start_rate,omitempty"`
	EndRate   float64        `json:"end_rate,omitempty"`
	MeanRate  float64        `json:"mean_rate,omitempty"`
	Amplitude float64        `json:"amplitude,omitempty"`
	Period    string         `json:"period,omitempty"`
	Stages    []ProfileStage `json:"stages,omitempty"`
}

// ProfileStage is one piecewise-constant segment of a staged profile.
type ProfileStage struct {
	Duration string  `json:"duration"`
	Rate     float64 `json:"rate"`
}

// rateProfile is a positive intensity λ(t) over elapsed seconds t∈[0,window]
// together with its closed-form cumulative Λ(t). λ must be > 0 on the window
// so Λ is strictly increasing and invertible.
type rateProfile interface {
	lambda(t float64) float64     // instantaneous events/sec at elapsed t
	cumulative(t float64) float64 // Λ(t) = ∫₀ᵗ λ
	kind() string
}

// --- constant: λ(t) = r ------------------------------------------------

type constantProfile struct{ r float64 }

func (p constantProfile) lambda(float64) float64       { return p.r }
func (p constantProfile) cumulative(t float64) float64 { return p.r * t }
func (p constantProfile) kind() string                 { return "constant" }

// --- linear: λ(t) = r0 + slope·t over [0, window] ----------------------

type linearProfile struct{ r0, slope float64 }

func (p linearProfile) lambda(t float64) float64     { return p.r0 + p.slope*t }
func (p linearProfile) cumulative(t float64) float64 { return p.r0*t + p.slope*t*t/2 }
func (p linearProfile) kind() string                 { return "linear" }

// --- sine: λ(t) = mean + amp·sin(ω t), ω = 2π/period, amp < mean -------

type sineProfile struct{ mean, amp, omega float64 }

func (p sineProfile) lambda(t float64) float64 { return p.mean + p.amp*math.Sin(p.omega*t) }
func (p sineProfile) cumulative(t float64) float64 {
	// ∫ mean + amp·sin(ω s) ds = mean·t + (amp/ω)(1 − cos(ω t))
	return p.mean*t + (p.amp/p.omega)*(1-math.Cos(p.omega*t))
}
func (p sineProfile) kind() string { return "sine" }

// --- staged: piecewise-constant rates, last stage extends to window ----

type stagedProfile struct {
	durs  []float64 // stage durations (seconds)
	rates []float64 // stage rates
	cum   []float64 // cumulative Λ at each stage boundary (len == len(durs)+1)
	total float64   // sum of stage durations
}

func newStagedProfile(durs, rates []float64) stagedProfile {
	cum := make([]float64, len(durs)+1)
	total := 0.0
	for i := range durs {
		cum[i+1] = cum[i] + rates[i]*durs[i]
		total += durs[i]
	}
	return stagedProfile{durs: durs, rates: rates, cum: cum, total: total}
}

func (p stagedProfile) stageAt(t float64) int {
	acc := 0.0
	for i, d := range p.durs {
		if t < acc+d {
			return i
		}
		acc += d
	}
	return len(p.durs) - 1 // past the last boundary → last stage extends
}

func (p stagedProfile) lambda(t float64) float64 { return p.rates[p.stageAt(t)] }
func (p stagedProfile) cumulative(t float64) float64 {
	acc := 0.0
	for i, d := range p.durs {
		if t < acc+d {
			return p.cum[i] + p.rates[i]*(t-acc)
		}
		acc += d
	}
	// Past the last boundary: the last stage's rate extends.
	last := len(p.durs) - 1
	return p.cum[last+1] + p.rates[last]*(t-p.total)
}
func (p stagedProfile) kind() string { return "staged" }

// invertCumulative solves Λ(t) = y for t ∈ [0, window] by bisection. Λ is
// strictly increasing (λ > 0), so 60 halvings converge to ~window/2⁶⁰.
func invertCumulative(p rateProfile, y, window float64) float64 {
	lo, hi := 0.0, window
	for i := 0; i < 60; i++ {
		mid := (lo + hi) / 2
		if p.cumulative(mid) < y {
			lo = mid
		} else {
			hi = mid
		}
	}
	return (lo + hi) / 2
}

// nhppArrivals generates the ordered arrival times (seconds from T0) of an
// NHPP with intensity p over [0, window) by Λ-inversion. One rnd.ExpFloat64()
// (Exp(1)) draw per event; deterministic given rnd's seed.
func nhppArrivals(p rateProfile, window float64, rnd *rand.Rand) []float64 {
	emax := p.cumulative(window)
	var out []float64
	e := 0.0
	for {
		e += rnd.ExpFloat64()
		if e > emax {
			return out
		}
		out = append(out, invertCumulative(p, e, window))
	}
}

// maxScenarioEventsPerDevice bounds Λ(window) for a materialized NHPP profile
// so a pathological high-rate × long-window config cannot OOM (the arrival
// stream is precomputed per device). 5M offsets ≈ 40 MB/device — generous for
// any realistic fidelity check. The constant profile is exempt (its cadence is
// computed, not materialized).
const maxScenarioEventsPerDevice = 5_000_000

// boundedProfile rejects a materialized profile whose expected per-device
// event count over the window would exceed the memory bound.
func boundedProfile(p rateProfile, window time.Duration) (rateProfile, error) {
	if n := p.cumulative(window.Seconds()); n > maxScenarioEventsPerDevice {
		return nil, fmt.Errorf("rate_profile %s: ~%.0f events/device over the window exceeds the %d cap (shorten the window or lower the rate)",
			p.kind(), n, maxScenarioEventsPerDevice)
	}
	return p, nil
}

// buildRateProfile constructs the profile for a scenario from its spec, the
// base per-device rate (the `rate` field, used by the default/constant
// profile and as the sine mean default), and the window. Validated: every
// profile must be strictly positive across the window.
func buildRateProfile(spec *RateProfileSpec, baseRate float64, window time.Duration) (rateProfile, error) {
	w := window.Seconds()
	if spec == nil || spec.Kind == "" || spec.Kind == "constant" {
		return constantProfile{r: baseRate}, nil
	}
	switch spec.Kind {
	case "linear":
		if spec.StartRate <= 0 || spec.EndRate <= 0 {
			return nil, fmt.Errorf("rate_profile linear: start_rate and end_rate must be > 0")
		}
		if math.Max(spec.StartRate, spec.EndRate) > scenarioMaxRate {
			return nil, fmt.Errorf("rate_profile linear: peak rate exceeds the %d events/second cap", scenarioMaxRate)
		}
		return boundedProfile(linearProfile{r0: spec.StartRate, slope: (spec.EndRate - spec.StartRate) / w}, window)
	case "sine":
		mean := spec.MeanRate
		if mean <= 0 {
			mean = baseRate
		}
		if spec.Amplitude < 0 || spec.Amplitude >= mean {
			return nil, fmt.Errorf("rate_profile sine: amplitude must be in [0, mean_rate) to keep λ(t) > 0")
		}
		if mean+spec.Amplitude > scenarioMaxRate {
			return nil, fmt.Errorf("rate_profile sine: peak rate (mean+amplitude) exceeds the %d events/second cap", scenarioMaxRate)
		}
		period, err := time.ParseDuration(nonEmpty(spec.Period, "60s"))
		if err != nil || period <= 0 {
			return nil, fmt.Errorf("rate_profile sine: period must be a positive duration")
		}
		return boundedProfile(sineProfile{mean: mean, amp: spec.Amplitude, omega: 2 * math.Pi / period.Seconds()}, window)
	case "staged":
		if len(spec.Stages) == 0 {
			return nil, fmt.Errorf("rate_profile staged: at least one stage required")
		}
		durs := make([]float64, len(spec.Stages))
		rates := make([]float64, len(spec.Stages))
		for i, st := range spec.Stages {
			d, err := time.ParseDuration(st.Duration)
			if err != nil || d <= 0 {
				return nil, fmt.Errorf("rate_profile staged: stage %d duration must be a positive duration", i)
			}
			if st.Rate <= 0 || st.Rate > scenarioMaxRate {
				return nil, fmt.Errorf("rate_profile staged: stage %d rate must be in (0, %d]", i, scenarioMaxRate)
			}
			durs[i], rates[i] = d.Seconds(), st.Rate
		}
		return boundedProfile(newStagedProfile(durs, rates), window)
	default:
		return nil, fmt.Errorf("rate_profile: unknown kind %q (constant|linear|sine|staged)", spec.Kind)
	}
}

func nonEmpty(s, dflt string) string {
	if s == "" {
		return dflt
	}
	return s
}
