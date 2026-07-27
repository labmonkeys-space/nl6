/*
 * Copyright 2026 Ronny Trommer <ronny@no42.org>
 * SPDX-License-Identifier: Apache-2.0
 */

package main

import (
	"fmt"
	"math"
	"math/rand"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// Optical leaf names, as defined by the pinned OpenConfig revision
// (openconfig-terminal-device@2026-01-14 plus the
// openconfig-platform-transceiver@2026-03-25 groupings it reuses). Every
// one of these is reachable under
// `/components/component[name=$och]/optical-channel/`.
//
// Names are NOT invented: serving a path the published model does not
// define would fail collector-side schema validation, which is the exact
// failure this device type exists to avoid.
const (
	// Receive-side spine — these degrade together.
	OpticalLeafInputPower  = "input-power"
	OpticalLeafOSNR        = "osnr"
	OpticalLeafESNR        = "esnr"
	OpticalLeafQValue      = "q-value"
	OpticalLeafPreFECBER   = "pre-fec-ber"
	OpticalLeafUncorrBlock = "fec-uncorrectable-blocks"

	// Off-spine — these must stay flat under a receive-side fault, which
	// is what makes the fibre-vs-transponder diagnosis possible.
	OpticalLeafOutputPower       = "output-power"
	OpticalLeafTargetOutputPower = "target-output-power"
	OpticalLeafLaserBias         = "laser-bias-current"
	OpticalLeafChromaticDisp     = "chromatic-dispersion"
	OpticalLeafPMD               = "polarization-mode-dispersion"
	OpticalLeafPDL               = "polarization-dependent-loss"
	OpticalLeafFrequency         = "frequency"
	OpticalLeafOperationalMode   = "operational-mode"
	OpticalLeafLinePort          = "line-port"
)

// Statistic selectors on a measured quantity's statistics container.
const (
	OpticalStatInstant = "instant"
	OpticalStatAvg     = "avg"
	OpticalStatMin     = "min"
	OpticalStatMax     = "max"
)

// Precision mandated by the pinned model. These come from the YANG
// `fraction-digits` of the reused statistics groupings, NOT from Ciena's
// native model — Ciena's `decimal-3-dig` / `string-sci` describe the
// NETCONF surface nl6 does not serve, and emitting them here would fail
// schema validation.
const (
	opticalStatFractionDigits = 2  // avg-min-max-instant-stats-precision2-*
	opticalBERFractionDigits  = 18 // avg-min-max-instant-stats-precision18-ber
)

const (
	// opticalDialPeriodSec is the fundamental period of both master
	// dials. They deliberately share it: with a common period the
	// difference of the two sinusoids collapses to a single sinusoid
	// (see initOsnrPhasor), which makes the above-threshold integral
	// behind fec-uncorrectable-blocks exactly solvable and O(1) instead
	// of requiring numeric integration over elapsed time. Independence
	// between the dials is preserved where it matters — amplitude,
	// phase, and (via bands and future degradation episodes) their means.
	opticalDialPeriodSec = 3600.0

	// opticalThermalPeriodSec is the slow chassis/modem thermal cycle.
	// It only drives off-spine leaves, so it need not share the dial
	// period.
	opticalThermalPeriodSec = 21600.0

	// opticalStatWindowSec is the trailing window the statistics
	// container summarises.
	opticalStatWindowSec = 900.0

	// opticalStatSamples is how many points the window is sampled at.
	// Sampling (rather than a closed form over the sinusoid) is
	// deliberate: it keeps `min <= instant <= max` true by construction
	// even once degradation episodes perturb the dials into a shape with
	// no analytic extremum, and it costs a handful of flops.
	opticalStatSamples = 33

	// opticalQOffsetDB converts OSNR to Q-factor: q_dB = osnr_dB -
	// offset, the linear approximation within an operating band. The
	// value places a 18.3 dB OSNR at 11.42 dB Q (pre-FEC BER ~1e-4),
	// matching a healthy 400G 16QAM line.
	opticalQOffsetDB = 6.88

	// opticalSDFECThresholdBER is the soft-decision FEC threshold. Above
	// it the FEC can no longer correct and uncorrectable blocks accrue.
	//
	// Worth knowing: at this operating point the erfc tail is SHALLOW —
	// Q 5.2 -> 7.2 dB moves pre-FEC BER only ~3x (3.4e-2 -> 1.1e-2), not
	// an order of magnitude. Decade-scale behaviour lives ~6 dB higher.
	// So tests should assert monotonicity here, and reserve step-change
	// assertions for the uncorrectable-block counter.
	opticalSDFECThresholdBER = 2e-2

	// opticalESNRPenaltyDB is how far electrical SNR sits below optical
	// SNR — the modem's implementation penalty.
	opticalESNRPenaltyDB = 0.9

	// opticalQFloorDB / opticalQCeilDB clamp the Q derivation so an
	// extreme band or degradation cannot produce a nonsensical value.
	opticalQFloorDB = 0.5
	opticalQCeilDB  = 20.0
)

// opticalBand is the steady-state operating band for a channel. It sets
// the means of both master dials, which is what makes all four
// diagnostic quadrants reachable: depressing pInMeanDBm alone models
// attenuation (power falls, OSNR holds, because signal and accumulated
// noise attenuate together); raising nAseMeanDBm alone models noise
// accumulation or a sick amplifier (OSNR falls, power holds).
//
// opticalBandFor maps the clean|typical|degraded|failing scenario onto
// concrete instances of this type.
type opticalBand struct {
	// pInMeanDBm is the mean received signal power.
	pInMeanDBm float64
	// nAseMeanDBm is the mean accumulated noise power. OSNR is the
	// difference of the two in the dB domain.
	nAseMeanDBm float64
	// pInAmpDB / nAseAmpDB are the sine amplitudes. Both are jittered
	// per channel around these values.
	pInAmpDB  float64
	nAseAmpDB float64
}

// OpticalScenario selects a channel's steady-state optical health band.
// It is the optical peer of IfErrorScenario and follows the same
// contract: a per-device value, settable by a seed flag for the
// auto-start batch and by a per-device REST field, where a REST request
// that omits it gets `clean` regardless of the seed.
type OpticalScenario string

const (
	OpticalClean    OpticalScenario = "clean"
	OpticalTypical  OpticalScenario = "typical"
	OpticalDegraded OpticalScenario = "degraded"
	OpticalFailing  OpticalScenario = "failing"
)

// ParseOpticalScenario canonicalises s (case-insensitive) to one of the
// four known scenarios. Empty input maps to OpticalClean. Unknown values
// return an error naming the accepted scenarios so the message is
// self-service on both the CLI and the REST surface.
func ParseOpticalScenario(s string) (OpticalScenario, error) {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "", string(OpticalClean):
		return OpticalClean, nil
	case string(OpticalTypical):
		return OpticalTypical, nil
	case string(OpticalDegraded):
		return OpticalDegraded, nil
	case string(OpticalFailing):
		return OpticalFailing, nil
	default:
		return "", fmt.Errorf("invalid optical_scenario %q (accepted: clean, typical, degraded, failing)", s)
	}
}

// opticalBandFor returns the steady-state band for a scenario.
//
// Each tier moves BOTH dial means, not just one: a worse span carries
// more accumulated ASE *and* delivers less power, and moving only one
// would collapse the two-dial model back into the single-dial one the
// engine deliberately avoids. Amplitude also grows with degradation,
// because a marginal span wanders more than a healthy one.
//
// The resulting operating points (derived, not guessed — the OSNR-to-BER
// chain is the cascade's own, and the values below are measured off it):
//
//	tier      OSNR     Q     pre-FEC BER   uncorrectable blocks
//	clean    18.30  11.42       9.8e-05    never
//	typical  16.68   9.80       1.0e-03    never
//	degraded 15.60   8.72       3.2e-03    never (FEC still coping)
//	failing  10.10   3.22       7.4e-02    always — every channel sits
//	                                       above the 2e-2 SD-FEC threshold
//	                                       for the whole dial period, so it
//	                                       is genuinely service-affecting
//
// `degraded` deliberately sits above the FEC threshold: the interesting
// case for a collector is a channel with a visibly elevated BER that is
// nonetheless still error-free at the service layer, because that is the
// window in which a proactive alarm has any value.
//
// Those two contracts are sized to hold for EVERY channel of EVERY seed,
// not merely at the nominal operating point. The binding constraint is the
// worst-case excursion envelope: the OSNR mean spreads over
// +-2*opticalMeanJitterDB (0.4 dB) because it is the difference of two
// independently jittered dials, and the OSNR sine amplitude reaches at
// most 1.1*(pInAmpDB+nAseAmpDB) when the two dials land in antiphase.
// Against the 13.13 dB threshold:
//
//	degraded worst-case minimum = 15.60 - 0.4 - 1.60 = 13.60  (clear by 0.47)
//	failing  best-case maximum  = 10.10 + 0.4 + 2.20 = 12.70  (under by 0.43)
//
// Changing any mean, any amplitude, or opticalMeanJitterDB invalidates
// that arithmetic. TestOpticalBandContractsHoldAcrossSeeds sweeps seeds to
// catch it — a single-seed test cannot, because the envelope's tails are
// what break.
func opticalBandFor(s OpticalScenario) opticalBand {
	switch s {
	case OpticalTypical:
		return opticalBand{pInMeanDBm: -9.5, nAseMeanDBm: -26.18, pInAmpDB: 0.75, nAseAmpDB: 0.35}
	case OpticalDegraded:
		return opticalBand{pInMeanDBm: -10.35, nAseMeanDBm: -25.95, pInAmpDB: 0.95, nAseAmpDB: 0.50}
	case OpticalFailing:
		return opticalBand{pInMeanDBm: -13.0, nAseMeanDBm: -23.10, pInAmpDB: 1.30, nAseAmpDB: 0.70}
	default: // OpticalClean, and any unknown value (defensive)
		return defaultOpticalBand
	}
}

// opticalMeanJitterDB is the per-channel jitter applied to EACH dial mean
// (uniform over +-this value). The two dial draws are independent, so the
// OSNR mean — their difference — spreads over +-2x this figure, and that
// spread stacks on top of the OSNR sine amplitude. Every tier gap in
// opticalBandFor is sized against the doubled envelope; see the
// arithmetic there before widening it.
const opticalMeanJitterDB = 0.2

// defaultOpticalBand is the `clean` band: OSNR ~18.3 dB, Q ~11.4 dB,
// pre-FEC BER ~1e-4, comfortably clear of the SD-FEC threshold (which
// sits at OSNR 13.13 dB) so a healthy channel accrues no uncorrectable
// blocks. The amplitude is anchored on measured testbed behaviour, where
// a span under normal conditions wanders roughly 2 dB peak-to-peak.
var defaultOpticalBand = opticalBand{
	pInMeanDBm:  -8.5,
	nAseMeanDBm: -26.8,
	pInAmpDB:    0.60,
	nAseAmpDB:   0.25,
}

// OpticalCycler generates coherent optical telemetry analytically.
//
// It is the optical peer of IfCounterCycler and shares its contract: a
// pure function of (component, leaf, elapsed time), no per-channel
// goroutine, and immutable after publication. Every field is written
// once by InitOpticalCycler before the cycler is published, and only
// read thereafter.
//
// Determinism is guaranteed at equal ELAPSED OFFSETS from startTime, not
// at equal absolute timestamps: like the interface cycler, the engine is
// start-time-relative, so two engines constructed at different wall-clock
// instants necessarily differ at the same absolute instant. Within one
// process every protocol surface reads one engine with one startTime, so
// cross-protocol agreement at an instant is unaffected.
type OpticalCycler struct {
	startTime time.Time

	// names is the channel set in sorted order. Sorted rather than map
	// order because per-channel jitter is assigned positionally, and Go
	// map iteration order is randomised per process — ranging a map here
	// would make the engine irreproducible across restarts.
	names []string
	slot  map[string]int

	// Static per-channel inventory, straight from the resource file.
	linePort     []string
	freqMHz      []uint64
	opMode       []uint16
	targetOutDBm []float64

	// Master dial parameters (per channel, jittered at init).
	pInMean   []float64
	pInAmp    []float64
	pInPhase  []float64
	nAseMean  []float64
	nAseAmp   []float64
	nAsePhase []float64

	// Collapsed OSNR sinusoid: osnr(t) = osnrMean + osnrAmp*sin(wt+osnrPhase).
	// Precomputed from the two dials at init — see initOsnrPhasor.
	osnrMean  []float64
	osnrAmp   []float64
	osnrPhase []float64

	// Off-spine values (per channel). Flat with respect to the receive
	// dials by construction: nothing here reads pInAt or nAseAt.
	outPowerDBm []float64
	biasMA      []float64
	biasAmpMA   []float64
	biasPhase   []float64
	cdPsNm      []float64
	pmdPs       []float64
	pdlDB       []float64

	// Uncorrectable-block accrual.
	uncorrBase []uint64  // pre-seed so a fresh device is not suspiciously at 0
	uncorrRate []float64 // blocks per second while above the FEC threshold

	// episodes holds the per-channel append-only degradation list
	// (optical_degrade.go) — the ONE mutable part of an otherwise
	// publish-once engine. The immutability contract above is preserved
	// rather than weakened: a published episode's window is frozen, its t0 is
	// never in the past, and readers take a lock-free snapshot, so no value a
	// reader could already have observed can change. One slice pointer per
	// channel, in the same slot order as every other field.
	episodes []atomic.Pointer[opticalEpisodeLog]
}

// positiveInf is the open-ended episode end. Named because `math.Inf(1)`
// sprinkled through window arithmetic reads like an accident.
var positiveInf = math.Inf(1)

// initOsnrPhasor collapses the two master dials into a single sinusoid.
//
// Both dials share a period, so
//
//	pIn(t) - nAse(t) = (pInMean - nAseMean)
//	                 + pInAmp*sin(wt+pInPhase) - nAseAmp*sin(wt+nAsePhase)
//
// and the bracketed term is itself a sinusoid at the same frequency:
// summing A*sin(θ+φ) terms gives (Σ A cos φ)·sin θ + (Σ A sin φ)·cos θ,
// i.e. R*sin(θ+ψ) with R = hypot and ψ = atan2. Precomputing R and ψ
// makes osnrAt O(1) and — more importantly — makes the time spent above
// the FEC threshold solvable in closed form.
func (oc *OpticalCycler) initOsnrPhasor(slot int) {
	x := oc.pInAmp[slot]*math.Cos(oc.pInPhase[slot]) - oc.nAseAmp[slot]*math.Cos(oc.nAsePhase[slot])
	y := oc.pInAmp[slot]*math.Sin(oc.pInPhase[slot]) - oc.nAseAmp[slot]*math.Sin(oc.nAsePhase[slot])
	oc.osnrMean[slot] = oc.pInMean[slot] - oc.nAseMean[slot]
	oc.osnrAmp[slot] = math.Hypot(x, y)
	oc.osnrPhase[slot] = math.Atan2(y, x)
}

// ---- master dials -------------------------------------------------

func opticalOmega(periodSec float64) float64 { return 2 * math.Pi / periodSec }

// pInAt is the received signal power in dBm — the first master dial. Any
// active degradation episode (optical_degrade.go) sags it, and because the
// whole receive cascade reads through the dials, the sag propagates to OSNR,
// Q, pre-FEC BER and the uncorrectable-block counter without any of them
// knowing degradation exists.
func (oc *OpticalCycler) pInAt(slot int, t float64) float64 {
	w := opticalOmega(opticalDialPeriodSec)
	base := oc.pInMean[slot] + oc.pInAmp[slot]*math.Sin(w*t+oc.pInPhase[slot])
	return base - oc.offsetsAt(slot, t).pInSagDB
}

// nAseAt is the accumulated noise power in dBm — the second, independent
// master dial. Deriving OSNR from received power alone would make the
// "normal power, low OSNR" quadrant unreachable and so could never
// exercise a collector rule that keys on it.
func (oc *OpticalCycler) nAseAt(slot int, t float64) float64 {
	w := opticalOmega(opticalDialPeriodSec)
	base := oc.nAseMean[slot] + oc.nAseAmp[slot]*math.Sin(w*t+oc.nAsePhase[slot])
	off := oc.offsetsAt(slot, t)
	// Accumulated ASE is attenuated by a span loss just as the signal is —
	// they travel the same fibre — so pInSagDB is subtracted here too. That
	// cancellation is the whole point of modelling two dials: it makes the
	// ATTENUATION quadrant (power down, OSNR held) reachable, and a collector
	// rule that tells a dirty connector from a sick amplifier depends on it.
	// Omitting it would drop OSNR 1:1 with power and collapse the two
	// quadrants into one.
	return base + off.nAseRiseDB - off.pInSagDB
}

// ---- derived receive-side cascade ---------------------------------

// osnrAt is the optical signal-to-noise ratio in dB: the difference of
// the two master dials, evaluated through the precomputed phasor.
//
// The degradation offset is subtracted HERE as well as in the two dials, not
// only in pInAt: the phasor is a precomputed collapse of pIn − nAse, so a sag
// applied to pInAt alone would move the input-power leaf while leaving OSNR
// (and therefore the entire cascade) untouched — a silently half-degraded
// channel. Subtracting the summed drop keeps the identity osnr = pIn − nAse
// exact under degradation.
func (oc *OpticalCycler) osnrAt(slot int, t float64) float64 {
	w := opticalOmega(opticalDialPeriodSec)
	base := oc.osnrMean[slot] + oc.osnrAmp[slot]*math.Sin(w*t+oc.osnrPhase[slot])
	return base - oc.offsetsAt(slot, t).osnrDropDB()
}

// esnrAt is electrical SNR. A real WaveLogic modem reports electrical
// rather than optical SNR, so it is served alongside OSNR; it tracks
// OSNR with a small implementation penalty.
func (oc *OpticalCycler) esnrAt(slot int, t float64) float64 {
	return oc.osnrAt(slot, t) - opticalESNRPenaltyDB
}

// qDbAt is the Q-factor in dB, linear in OSNR within an operating band.
func (oc *OpticalCycler) qDbAt(slot int, t float64) float64 {
	q := oc.osnrAt(slot, t) - opticalQOffsetDB
	return clampFloat(q, opticalQFloorDB, opticalQCeilDB)
}

// preFecBerAt is the pre-FEC bit error rate, from Q through the Gaussian
// tail: BER = 0.5*erfc(q_lin/sqrt(2)).
func (oc *OpticalCycler) preFecBerAt(slot int, t float64) float64 {
	return berFromQDB(oc.qDbAt(slot, t))
}

func berFromQDB(qDB float64) float64 {
	qLin := math.Pow(10, qDB/20)
	return 0.5 * math.Erfc(qLin/math.Sqrt2)
}

// osnrThresholdDB is the OSNR at which pre-FEC BER reaches the SD-FEC
// threshold. Derived from the same constants as the cascade so the two
// can never drift apart — rather than hard-coded, which would let them.
//
// Memoised because it is a constant of constants but costs ~16us to
// derive (100 bisection steps, each an Erfc and a Pow), and it sits on
// the uncorrectable-block read path that every subscribe tick hits.
var osnrThresholdDB = sync.OnceValue(func() float64 {
	// BER is monotonically decreasing in Q, so bisect.
	lo, hi := opticalQFloorDB, opticalQCeilDB
	for i := 0; i < 100; i++ {
		mid := (lo + hi) / 2
		if berFromQDB(mid) > opticalSDFECThresholdBER {
			lo = mid
		} else {
			hi = mid
		}
	}
	return lo + opticalQOffsetDB
})

// uncorrBlocksAt is the FEC uncorrectable block count: monotonically
// non-decreasing, accruing only while pre-FEC BER exceeds the SD-FEC
// threshold.
//
// It is the time integral of an indicator, computed in closed form. BER
// exceeds the threshold exactly when OSNR falls below
// osnrThresholdDB(), and OSNR is a single sinusoid, so the elapsed
// above-threshold time is an exact arcsine expression rather than a
// numeric integration over however long the device has been running.
// That keeps the read O(1) and the result exactly monotonic.
func (oc *OpticalCycler) uncorrBlocksAt(slot int, t float64) uint64 {
	if t <= 0 {
		return oc.uncorrBase[slot]
	}
	above := oc.aboveThresholdSeconds(slot, t)
	blocks := above * oc.uncorrRate[slot]
	// Converting a NaN or Inf to uint64 is undefined in Go, and a negative
	// value would wrap to a huge count and break monotonicity. Neither is
	// reachable from the current dials, but the counter's monotonicity is
	// a contract downstream collectors rely on, so it is guarded rather
	// than argued about.
	if math.IsNaN(blocks) || math.IsInf(blocks, 0) || blocks < 0 {
		return oc.uncorrBase[slot]
	}
	return oc.uncorrBase[slot] + uint64(math.Floor(blocks))
}

// aboveThresholdSeconds returns how much of [0, t] the channel spent with
// pre-FEC BER above the SD-FEC threshold.
//
// Without degradation this is one closed-form arcsine expression over the
// whole interval. With degradation the OSNR mean is piecewise-constant — it
// steps at each episode boundary — so the interval is split at those
// boundaries and the same closed form is applied per segment. Segments are
// disjoint and an episode's window is frozen once published, so a segment's
// contribution can never change after the fact: the sum is monotonic in t by
// construction, which is what keeps `fec-uncorrectable-blocks` from ever
// walking backwards across a degrade→revert cycle.
//
// Cost is O(number of episode boundaries before t), not O(t) — still no
// numeric integration over uptime, and an undegraded channel takes exactly
// the single-segment path it always did.
func (oc *OpticalCycler) aboveThresholdSeconds(slot int, t float64) float64 {
	var log *opticalEpisodeLog
	if slot >= 0 && slot < len(oc.episodes) {
		log = oc.episodes[slot].Load()
	}
	var settled, from float64
	if log != nil {
		settled, from = log.settledAbove, log.settledUntil
	}
	if t <= from {
		// Before the collapse point the discarded episodes are no longer
		// available to integrate, so the settled total is the answer. Every
		// production read is at ~now, which is at or after `from`; only a
		// backdated query lands here. See collapseSettled.
		return settled
	}
	return settled + oc.aboveThresholdOver(slot, log, from, t)
}

// aboveThresholdOver integrates [from, to] against an EXPLICIT log, splitting
// at that log's episode boundaries. Taking the log as a parameter is what lets
// collapseSettled fold a not-yet-published log.
func (oc *OpticalCycler) aboveThresholdOver(slot int, log *opticalEpisodeLog, from, to float64) float64 {
	if to <= from {
		return 0
	}
	bounds := breakpointsIn(log, from, to)
	if len(bounds) == 0 {
		return oc.aboveThresholdSegment(slot, log, from, to)
	}
	total := 0.0
	prev := from
	for _, b := range bounds {
		total += oc.aboveThresholdSegment(slot, log, prev, b)
		prev = b
	}
	return total + oc.aboveThresholdSegment(slot, log, prev, to)
}

// aboveThresholdSegment is the closed form over one segment [ta, tb) on which
// the degradation offset — and therefore the effective OSNR mean — is
// constant. The offset is sampled at the segment's midpoint: episode
// boundaries are exactly the instants it can change, so any interior point
// reports the value that holds across the whole segment, and the midpoint
// avoids landing on a half-open boundary.
func (oc *OpticalCycler) aboveThresholdSegment(slot int, log *opticalEpisodeLog, ta, tb float64) float64 {
	if tb <= ta {
		return 0
	}
	drop := offsetsIn(log, ta+(tb-ta)/2).osnrDropDB()
	amp := oc.osnrAmp[slot]
	// u is the threshold expressed in units of the sinusoid: BER is above
	// threshold when sin(theta) < u.
	target := osnrThresholdDB() - (oc.osnrMean[slot] - drop)
	if amp <= 0 {
		// Degenerate dial: either always above or always below.
		if target > 0 {
			return tb - ta
		}
		return 0
	}
	u := target / amp
	if u >= 1 {
		return tb - ta // never clears the threshold
	}
	if u <= -1 {
		return 0 // never reaches it
	}
	w := opticalOmega(opticalDialPeriodSec)
	thetaA := w*ta + oc.osnrPhase[slot]
	thetaB := w*tb + oc.osnrPhase[slot]
	return (sinBelowMeasure(thetaB, u) - sinBelowMeasure(thetaA, u)) / w
}

// sinBelowMeasure returns the measure (in radians) of
// {x in [0, theta] : sin(x) < u}, for u in (-1, 1). Negative theta is
// handled by antisymmetry so callers can pass a phase offset directly.
//
// Within one turn, sin(x) < u on the arc (pi-a, 2pi+a) where
// a = asin(u); reduced modulo 2pi that is [0, a) plus (pi-a, 2pi) when a
// is positive, and the single interval (pi-a, 2pi+a) when it is not.
func sinBelowMeasure(theta, u float64) float64 {
	if theta < 0 {
		// measure over [theta, 0] mirrored: sin is odd, so
		// |{x in [-T,0] : sin x < u}| = T - |{x in [0,T] : sin x < -u}|.
		return -(-theta - sinBelowMeasure(-theta, -u))
	}
	a := math.Asin(u)
	arcLen := math.Pi + 2*a // measure per full turn
	turns := math.Floor(theta / (2 * math.Pi))
	rem := theta - turns*2*math.Pi
	total := turns * arcLen
	if a >= 0 {
		total += overlapLen(0, rem, 0, a)
		total += overlapLen(0, rem, math.Pi-a, 2*math.Pi)
	} else {
		total += overlapLen(0, rem, math.Pi-a, 2*math.Pi+a)
	}
	return total
}

// overlapLen returns the length of the intersection of [a0,a1] and [b0,b1].
func overlapLen(a0, a1, b0, b1 float64) float64 {
	lo := math.Max(a0, b0)
	hi := math.Min(a1, b1)
	if hi <= lo {
		return 0
	}
	return hi - lo
}

// ---- off-spine leaves ---------------------------------------------
//
// None of these read pInAt / nAseAt / osnrAt. That is the whole point:
// an operator distinguishes a span problem from a transponder problem by
// seeing the receive spine degrade while the transmit side holds, so a
// simulator whose every needle moves together teaches a collector
// nothing.

func (oc *OpticalCycler) outPowerAt(slot int, t float64) float64 {
	// Transmit power is actively levelled; only a slow thermal ripple.
	w := opticalOmega(opticalThermalPeriodSec)
	return oc.outPowerDBm[slot] + 0.05*math.Sin(w*t)
}

func (oc *OpticalCycler) laserBiasAt(slot int, t float64) float64 {
	w := opticalOmega(opticalThermalPeriodSec)
	return oc.biasMA[slot] + oc.biasAmpMA[slot]*math.Sin(w*t+oc.biasPhase[slot])
}

func (oc *OpticalCycler) chromaticDispAt(slot int, t float64) float64 {
	w := opticalOmega(opticalThermalPeriodSec)
	return oc.cdPsNm[slot] + 1.5*math.Sin(w*t+oc.biasPhase[slot])
}

func (oc *OpticalCycler) pmdAt(slot int, t float64) float64 {
	w := opticalOmega(opticalThermalPeriodSec)
	return oc.pmdPs[slot] + 0.4*math.Sin(w*t+oc.nAsePhase[slot])
}

func (oc *OpticalCycler) pdlAt(slot int, t float64) float64 {
	w := opticalOmega(opticalThermalPeriodSec)
	return oc.pdlDB[slot] + 0.08*math.Sin(w*t+oc.pInPhase[slot])
}

// ---- statistics ---------------------------------------------------

// statsFor summarises a leaf over the trailing window, returning
// (instant, avg, min, max).
//
// The window is sampled rather than solved analytically so that
// `min <= instant <= max` holds BY CONSTRUCTION: instant is the final
// sample, so it is necessarily within the min/max of the sample set.
// That invariant then survives any later perturbation of the dials
// (a degradation episode need not leave an analytically tractable
// shape), which a closed form over the sinusoid would not.
func (oc *OpticalCycler) statsFor(slot int, t float64, f func(int, float64) float64) (instant, avg, min, max float64) {
	start := t - opticalStatWindowSec
	if start < 0 {
		start = 0
	}
	step := (t - start) / float64(opticalStatSamples-1)
	sum := 0.0
	min = math.Inf(1)
	max = math.Inf(-1)
	var last float64
	for i := 0; i < opticalStatSamples; i++ {
		ti := start + float64(i)*step
		if i == opticalStatSamples-1 {
			ti = t // exact, so instant is a genuine member of the sample set
		}
		v := f(slot, ti)
		sum += v
		min = math.Min(min, v)
		max = math.Max(max, v)
		last = v
	}
	// Clamp the mean into [min,max] rather than trusting floating-point
	// summation to respect it. Summing n samples and dividing can land an
	// ULP outside their own range — most visibly at t=0, where the window
	// collapses to a single point and every sample is identical. The
	// invariant is part of the contract, so it is enforced, not assumed.
	avg = clampFloat(sum/float64(opticalStatSamples), min, max)
	return last, avg, min, max
}

// ---- dispatcher ---------------------------------------------------

// opticalLeafFn maps a spine/off-spine leaf name to its generator, or
// nil when the leaf is not a statistics-bearing measurement.
func (oc *OpticalCycler) opticalLeafFn(leaf string) func(int, float64) float64 {
	switch leaf {
	case OpticalLeafInputPower:
		return oc.pInAt
	case OpticalLeafOSNR:
		return oc.osnrAt
	case OpticalLeafESNR:
		return oc.esnrAt
	case OpticalLeafQValue:
		return oc.qDbAt
	case OpticalLeafPreFECBER:
		return oc.preFecBerAt
	case OpticalLeafOutputPower:
		return oc.outPowerAt
	case OpticalLeafLaserBias:
		return oc.laserBiasAt
	case OpticalLeafChromaticDisp:
		return oc.chromaticDispAt
	case OpticalLeafPMD:
		return oc.pmdAt
	case OpticalLeafPDL:
		return oc.pdlAt
	}
	return nil
}

// GetDynamicAt is the single dispatcher every protocol surface reads
// through — the optical peer of IfCounterCycler.GetDynamicAt. Because
// there is exactly one dispatcher, any two surfaces evaluating the same
// (component, leaf, t) necessarily agree.
//
// leaf is either a scalar name ("frequency") or a statistics path
// ("input-power/instant"), mirroring the "counters/in-octets" shape the
// interface resolver already uses. The returned value is typed for the
// gNMI encoder: gnmiDecimal for analog leaves, uint64 for counters,
// uint32/string for scalars. ok is false for an unknown component or
// leaf, which callers surface as NotFound.
func (oc *OpticalCycler) GetDynamicAt(component, leaf string, t float64) (value any, ok bool) {
	if oc == nil {
		return nil, false
	}
	slot, found := oc.slot[component]
	if !found {
		return nil, false
	}

	// Scalars first — no statistics container.
	switch leaf {
	case OpticalLeafFrequency:
		return oc.freqMHz[slot], true
	case OpticalLeafOperationalMode:
		return uint32(oc.opMode[slot]), true
	case OpticalLeafLinePort:
		return oc.linePort[slot], true
	case OpticalLeafTargetOutputPower:
		return gnmiDecimal{val: oc.targetOutDBm[slot], digits: opticalStatFractionDigits}, true
	case OpticalLeafUncorrBlock:
		// A bare counter leaf in the pinned model: no instant/avg/min/max.
		return oc.uncorrBlocksAt(slot, t), true
	}

	name, stat, hasStat := strings.Cut(leaf, "/")
	if !hasStat {
		return nil, false
	}
	fn := oc.opticalLeafFn(name)
	if fn == nil {
		return nil, false
	}
	instant, avg, min, max := oc.statsFor(slot, t, fn)
	var v float64
	switch stat {
	case OpticalStatInstant:
		v = instant
	case OpticalStatAvg:
		v = avg
	case OpticalStatMin:
		v = min
	case OpticalStatMax:
		v = max
	default:
		return nil, false
	}
	digits := opticalStatFractionDigits
	if name == OpticalLeafPreFECBER {
		digits = opticalBERFractionDigits
	}
	return gnmiDecimal{val: v, digits: digits}, true
}

// Components returns the channel names in sorted order. Sorted so that a
// wildcard gNMI subscription expands deterministically.
func (oc *OpticalCycler) Components() []string {
	if oc == nil {
		return nil
	}
	return oc.names
}

// StartTime is the epoch every elapsed offset is measured from.
func (oc *OpticalCycler) StartTime() time.Time {
	if oc == nil {
		return time.Time{}
	}
	return oc.startTime
}

// ---- init ---------------------------------------------------------

// opticalSeedSalt is XOR-ed into the per-device seed so the optical
// engine's jitter is independent of the interface counter engine's.
// ("OC" in ASCII; verified not to collide with the interface cycler's
// salt.)
const opticalSeedSalt = 0x4F43_0000

// InitOpticalCycler builds and publishes the optical value engine from a
// device's OCH inventory.
//
// Single-init only. A second call panics rather than replacing a
// published engine, mirroring InitIfCountersWithScenario: a swap would
// silently orphan anything already reading the old engine. A device's
// type is fixed at creation, so exactly one call per device is both
// sufficient and correct — and it must happen in the creation window,
// before the device starts serving.
func (c *MetricsCycler) InitOpticalCycler(resources *DeviceResources, seed int64, band opticalBand) {
	if resources == nil || len(resources.Optical) == 0 {
		return
	}
	if existing := c.optical.Load(); existing != nil {
		panic("InitOpticalCycler: re-init unsafe — an optical engine is already published; " +
			"a swap would orphan readers mid-flight")
	}

	// Sort the inventory by component name before assigning any jitter.
	// Jitter is positional, so ranging the inventory in its file order
	// would make values depend on file layout, and ranging a map would
	// make them differ per process.
	chans := make([]OpticalChannel, len(resources.Optical))
	copy(chans, resources.Optical)
	sort.Slice(chans, func(i, j int) bool { return chans[i].Name < chans[j].Name })

	n := len(chans)
	oc := &OpticalCycler{
		startTime:    time.Now(),
		names:        make([]string, n),
		slot:         make(map[string]int, n),
		linePort:     make([]string, n),
		freqMHz:      make([]uint64, n),
		opMode:       make([]uint16, n),
		targetOutDBm: make([]float64, n),
		pInMean:      make([]float64, n),
		pInAmp:       make([]float64, n),
		pInPhase:     make([]float64, n),
		nAseMean:     make([]float64, n),
		nAseAmp:      make([]float64, n),
		nAsePhase:    make([]float64, n),
		osnrMean:     make([]float64, n),
		osnrAmp:      make([]float64, n),
		osnrPhase:    make([]float64, n),
		outPowerDBm:  make([]float64, n),
		biasMA:       make([]float64, n),
		biasAmpMA:    make([]float64, n),
		biasPhase:    make([]float64, n),
		cdPsNm:       make([]float64, n),
		pmdPs:        make([]float64, n),
		pdlDB:        make([]float64, n),
		uncorrBase:   make([]uint64, n),
		uncorrRate:   make([]float64, n),
		episodes:     make([]atomic.Pointer[opticalEpisodeLog], n),
	}

	rng := rand.New(rand.NewSource(seed ^ opticalSeedSalt))
	for i, ch := range chans {
		oc.names[i] = ch.Name
		oc.slot[ch.Name] = i
		oc.linePort[i] = ch.LinePort
		oc.freqMHz[i] = ch.FrequencyMHz
		oc.opMode[i] = ch.OperationalMode
		oc.targetOutDBm[i] = ch.TargetOutputPowerDBm

		// Receive dials, jittered +-10% on amplitude and +-0.2 dB on mean.
		//
		// The mean jitter is deliberately HALF the per-dial spread it looks
		// like it could afford. OSNR is the difference of the two dials, so
		// independent draws on each widen the OSNR mean by twice the
		// per-dial figure (opticalMeanJitterDB) — and that spread stacks on
		// top of the OSNR sine amplitude. At +-0.4 dB per dial the resulting
		// +-0.8 dB envelope pushed the low tail of `degraded` across the FEC
		// threshold for ~1.6% of channels, breaking the tier's documented
		// "never accrues uncorrectable blocks" contract, and it overlapped
		// the tier means so a `degraded` channel could report better OSNR
		// than a `typical` one. opticalBandFor's tier gaps are sized against
		// this constant; see the envelope arithmetic there.
		oc.pInMean[i] = band.pInMeanDBm + (rng.Float64()-0.5)*2*opticalMeanJitterDB
		oc.pInAmp[i] = band.pInAmpDB * (0.9 + rng.Float64()*0.2)
		oc.pInPhase[i] = rng.Float64() * 2 * math.Pi
		oc.nAseMean[i] = band.nAseMeanDBm + (rng.Float64()-0.5)*2*opticalMeanJitterDB
		oc.nAseAmp[i] = band.nAseAmpDB * (0.9 + rng.Float64()*0.2)
		oc.nAsePhase[i] = rng.Float64() * 2 * math.Pi
		oc.initOsnrPhasor(i)

		// Off-spine. Transmit power tracks the configured target.
		oc.outPowerDBm[i] = ch.TargetOutputPowerDBm + (rng.Float64()-0.5)*0.1
		oc.biasMA[i] = 85 + (rng.Float64()-0.5)*6
		oc.biasAmpMA[i] = 0.6 + rng.Float64()*0.4
		oc.biasPhase[i] = rng.Float64() * 2 * math.Pi
		oc.cdPsNm[i] = -140 + (rng.Float64()-0.5)*20
		oc.pmdPs[i] = 4 + rng.Float64()*2
		oc.pdlDB[i] = 0.4 + rng.Float64()*0.3

		oc.uncorrBase[i] = uint64(rng.Int63n(64))
		oc.uncorrRate[i] = 900 + rng.Float64()*600
	}

	c.optical.Store(oc)
}

// OpticalCyclerOf returns the published optical engine, or nil.
func (c *MetricsCycler) OpticalCyclerOf() *OpticalCycler {
	if c == nil {
		return nil
	}
	return c.optical.Load()
}

func clampFloat(v, lo, hi float64) float64 {
	if v < lo {
		return lo
	}
	if v > hi {
		return hi
	}
	return v
}
