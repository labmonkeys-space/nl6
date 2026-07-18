/*
 * Copyright 2026 Ronny Trommer <ronny@no42.org>
 * SPDX-License-Identifier: Apache-2.0
 */

package main

import (
	"math"
	"math/rand"
	"testing"
	"time"
)

// scenario_rate_profile_test.go — FR5 correctness: Λ closed forms match their
// λ, the NHPP empirical mean matches ∫λ dt, arrival draws are deterministic,
// and the biased per-step Exp(λ(t_now)) anti-pattern is proven NOT in use.

// TestRateProfile_CumulativeMatchesLambda numerically integrates each λ and
// checks the closed-form Λ agrees — guards the analytic cumulative formulas.
func TestRateProfile_CumulativeMatchesLambda(t *testing.T) {
	profiles := map[string]rateProfile{
		"constant": constantProfile{r: 20},
		"linear":   linearProfile{r0: 10, slope: 10}, // 10→110 over 10s
		"sine":     sineProfile{mean: 50, amp: 30, omega: 2 * math.Pi / 10},
		"staged":   newStagedProfile([]float64{3, 4, 3}, []float64{10, 40, 20}),
	}
	for name, p := range profiles {
		t.Run(name, func(t *testing.T) {
			const dt = 1e-4
			numeric := 0.0
			for x := 0.0; x < 10; x += dt {
				numeric += p.lambda(x+dt/2) * dt // midpoint rule
				want := p.cumulative(x + dt)
				if rel := math.Abs(numeric-want) / (want + 1e-9); rel > 1e-3 {
					t.Fatalf("Λ mismatch at t=%.4f: numeric=%.4f closed=%.4f (rel %.4f)", x+dt, numeric, want, rel)
				}
			}
		})
	}
}

// TestNHPP_EmpiricalMeanMatchesIntegral (FR5 NHPP sanity): over many seeded
// runs the mean event count converges to Λ(window), and for a rising λ the
// second half carries proportionally more events than the first.
func TestNHPP_EmpiricalMeanMatchesIntegral(t *testing.T) {
	p := linearProfile{r0: 10, slope: 10} // λ: 10→110 over 10s; Λ(10)=600
	const window, runs = 10.0, 200
	wantTotal := p.cumulative(window) // 600
	half := p.cumulative(window / 2)  // 175

	var sumTotal, sumFirst, sumSecond float64
	for s := 0; s < runs; s++ {
		rnd := rand.New(rand.NewSource(int64(s) + 1))
		arr := nhppArrivals(p, window, rnd)
		sumTotal += float64(len(arr))
		for _, ta := range arr {
			if ta < window/2 {
				sumFirst++
			} else {
				sumSecond++
			}
		}
	}
	meanTotal := sumTotal / runs
	if rel := math.Abs(meanTotal-wantTotal) / wantTotal; rel > 0.03 {
		t.Fatalf("mean count %.1f vs Λ(window)=%.1f (rel %.3f > 3%%)", meanTotal, wantTotal, rel)
	}
	meanFirst, meanSecond := sumFirst/runs, sumSecond/runs
	if rel := math.Abs(meanFirst-half) / half; rel > 0.08 {
		t.Fatalf("first-half mean %.1f vs Λ(5)=%.1f (rel %.3f)", meanFirst, half, rel)
	}
	// Rising λ ⇒ the back half must carry clearly more load than the front.
	if meanSecond < 2*meanFirst {
		t.Fatalf("density not rising: first=%.1f second=%.1f (want second ≳ 2×first)", meanFirst, meanSecond)
	}
}

// TestNHPP_Deterministic: same seed + profile ⇒ byte-identical arrival stream.
func TestNHPP_Deterministic(t *testing.T) {
	p := sineProfile{mean: 50, amp: 30, omega: 2 * math.Pi / 7}
	a := nhppArrivals(p, 10, rand.New(rand.NewSource(99)))
	b := nhppArrivals(p, 10, rand.New(rand.NewSource(99)))
	if len(a) != len(b) {
		t.Fatalf("non-deterministic length: %d vs %d", len(a), len(b))
	}
	for i := range a {
		if a[i] != b[i] {
			t.Fatalf("non-deterministic arrival at %d: %.9f vs %.9f", i, a[i], b[i])
		}
	}
}

// biasedArrivals is the ANTI-PATTERN (not used in production): draw each gap
// as Exp(1)/λ(t_now) using the current instantaneous rate. Present only in
// this test as the negative control for the regression guard below.
func biasedArrivals(p rateProfile, window float64, rnd *rand.Rand) []float64 {
	var out []float64
	tt := 0.0
	for {
		tt += rnd.ExpFloat64() / p.lambda(tt) // biased: rate sampled at t_now
		if tt >= window {
			return out
		}
		out = append(out, tt)
	}
}

// meanRescaledGap applies the time-rescaling theorem: Λ(T_i) − Λ(T_{i-1}).
// For a correct NHPP these gaps are Exp(1) (mean → 1); the biased method,
// under a rising λ, systematically overshoots (mean > 1).
func meanRescaledGap(p rateProfile, arr []float64) float64 {
	if len(arr) == 0 {
		return 0
	}
	prev, sum := 0.0, 0.0
	for _, ta := range arr {
		sum += p.cumulative(ta) - p.cumulative(prev)
		prev = ta
	}
	return sum / float64(len(arr))
}

// TestNHPP_AntiPatternGuard (FR5): proves the production inversion path yields
// unit-mean rescaled gaps (time-rescaling theorem), while the biased per-step
// draw does not — so a regression to the biased method would be caught.
func TestNHPP_AntiPatternGuard(t *testing.T) {
	// A LOW start rate makes λ change a lot within an inter-arrival gap,
	// where the biased "λ(t_now)" draw diverges most from inversion. We
	// discriminate on the EVENT COUNT (a low-variance, deterministic, and
	// operationally meaningful statistic) rather than the outlier-driven
	// rescaled-gap mean: inversion yields a Poisson(Λ) count; the biased
	// method (sampling the rate too early on a rising λ) systematically
	// UNDER-counts.
	p := linearProfile{r0: 0.5, slope: 4.95} // 0.5 → 50 over 10s; Λ(10)=252.5
	const window, runs = 10.0, 200
	lambdaW := p.cumulative(window)

	var correctN, biasedN, correctGap, biasedGap float64
	for s := 0; s < runs; s++ {
		ca := nhppArrivals(p, window, rand.New(rand.NewSource(int64(s)+1)))
		ba := biasedArrivals(p, window, rand.New(rand.NewSource(int64(s)+1)))
		correctN += float64(len(ca))
		biasedN += float64(len(ba))
		correctGap += meanRescaledGap(p, ca)
		biasedGap += meanRescaledGap(p, ba)
	}
	correctN, biasedN = correctN/runs, biasedN/runs

	// Inversion reproduces Λ(window) — the NHPP count is Poisson(Λ).
	if rel := math.Abs(correctN-lambdaW) / lambdaW; rel > 0.03 {
		t.Fatalf("inversion count %.1f vs Λ(window)=%.1f (rel %.3f) — not the NHPP", correctN, lambdaW, rel)
	}
	// Inversion's rescaled gaps obey the time-rescaling theorem (mean ≈ 1).
	if g := correctGap / runs; math.Abs(g-1) > 0.05 {
		t.Fatalf("inversion rescaled-gap mean %.4f, want ≈ 1", g)
	}
	// The biased anti-pattern produces a materially different (lower) count —
	// a regression to it would move the count by ~9% here.
	if rel := math.Abs(correctN-biasedN) / lambdaW; rel < 0.04 {
		t.Fatalf("inversion (%.1f) and biased (%.1f) counts indistinguishable — guard would miss a regression", correctN, biasedN)
	}
	t.Logf("count: inversion=%.1f biased=%.1f (Λ=%.1f); rescaled-gap: inversion=%.4f biased=%.4f",
		correctN, biasedN, lambdaW, correctGap/runs, biasedGap/runs)
}

// TestBuildRateProfile_Validation covers the config-to-profile mapping and its
// rejections.
func TestBuildRateProfile_Validation(t *testing.T) {
	w := 10 * time.Second
	ok := func(spec *RateProfileSpec, wantKind string) {
		p, err := buildRateProfile(spec, 20, w)
		if err != nil {
			t.Fatalf("build %+v: %v", spec, err)
		}
		if p.kind() != wantKind {
			t.Fatalf("kind = %s, want %s", p.kind(), wantKind)
		}
	}
	ok(nil, "constant")
	ok(&RateProfileSpec{Kind: "constant"}, "constant")
	ok(&RateProfileSpec{Kind: "linear", StartRate: 5, EndRate: 50}, "linear")
	ok(&RateProfileSpec{Kind: "sine", MeanRate: 50, Amplitude: 20, Period: "30s"}, "sine")
	ok(&RateProfileSpec{Kind: "staged", Stages: []ProfileStage{{Duration: "3s", Rate: 10}, {Duration: "2s", Rate: 40}}}, "staged")

	for _, bad := range []*RateProfileSpec{
		{Kind: "sine", MeanRate: 10, Amplitude: 10}, // amp not < mean
		{Kind: "linear", StartRate: 0, EndRate: 10}, // start ≤ 0
		{Kind: "staged"}, // no stages
		{Kind: "staged", Stages: []ProfileStage{{Duration: "x", Rate: 1}}}, // bad duration
		{Kind: "weird"}, // unknown kind
	} {
		if _, err := buildRateProfile(bad, 20, w); err == nil {
			t.Fatalf("expected rejection for %+v", bad)
		}
	}

	// Over-memory: 1000/s for 24h ⇒ Λ ≈ 86M events/device > the 5M bound.
	if _, err := buildRateProfile(&RateProfileSpec{Kind: "linear", StartRate: 1000, EndRate: 1000}, 20, 24*time.Hour); err == nil {
		t.Fatal("expected rejection for a profile exceeding the per-device event bound")
	}
	// Over-cap peak: 2000/s exceeds the 1000/s rate cap.
	if _, err := buildRateProfile(&RateProfileSpec{Kind: "linear", StartRate: 10, EndRate: 2000}, 20, w); err == nil {
		t.Fatal("expected rejection for a profile exceeding the rate cap")
	}
}
