/*
 * Copyright 2026 Ronny Trommer <ronny@no42.org>
 * SPDX-License-Identifier: Apache-2.0
 */

package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/csv"
	"encoding/hex"
	"sort"
	"strconv"
	"time"
)

// scenario_report.go — serialization of the immutable finalized
// ScenarioResult into the wire report (D5). The report is a pure projection:
// the top-level `summary` block serializes BEFORE the per-device
// `counters[]` (declaration order → JSON order), counters are keyed by the
// `(protocol, source_ip, collector)` join tuple, and every ledger field is
// explicit (no omitempty) so a monitor can diff zero-valued rows.

// rfc3339ms is the timestamp format for all scenario wire fields (ms
// precision per the RFC3339-ms pattern).
const rfc3339ms = "2006-01-02T15:04:05.000Z07:00"

// scenarioReport is the immutable report served by GET .../report. Summary
// first, then per-device counters, then the fleet-wide application traffic
// block — the field order IS the JSON order. `applications` is an additive
// top-level block per the schema evolution policy (always present; [] for
// non-flow and sflow scenarios).
type scenarioReport struct {
	Summary      scenarioReportSummary `json:"summary"`
	Counters     []scenarioCounterRow  `json:"counters"`
	Applications []scenarioAppRow      `json:"applications"`
}

// scenarioAppRow is one fleet-wide application's sent-basis traffic ground
// truth (scenario-app-traffic). The (l4_proto, dst_port) tuple is the
// authoritative join key against a collector's classification; app_hint is
// informational (collector rules are user-configurable). bytes/packets/
// records follow the `sent` (in_window + drain) convention; sub_window_bytes
// buckets in-window bytes only and is informational — collectors interpolate
// flow bytes across [start, end], so totals, not buckets, are the
// reconciliation target.
type scenarioAppRow struct {
	L4Proto string `json:"l4_proto"`
	DstPort uint16 `json:"dst_port"`
	AppHint string `json:"app_hint"`
	Records uint64 `json:"records"`
	Bytes   uint64 `json:"bytes"`
	Packets uint64 `json:"packets"`
	// AvgBytesPerSecond = in-window bytes / actual window duration
	// (T1Actual−T0Actual) — drain bytes stay in Bytes (reconciliation
	// total) but are excluded here, since the denominator excludes drain
	// time. Named to avoid the bits-per-second ambiguity of "bps".
	AvgBytesPerSecond float64                        `json:"avg_bytes_per_second"`
	SubWindowBytes    [scenarioSubWindowCount]uint64 `json:"sub_window_bytes"`
}

// scenarioReportSummary is the top-level aggregate block: identity,
// fingerprint, window, and fleet-wide ledger totals. The five loss buckets
// plus `emitted` are flat (they form the ledger identity, FR23); the
// disclosure counter lives in a separate `informational` sub-object (FR21)
// so it can never be mistaken for an identity term.
type scenarioReportSummary struct {
	ID                   string              `json:"id"`
	Phase                string              `json:"phase"`
	Protocol             string              `json:"protocol"`
	Metadata             reportMetadata      `json:"metadata"`
	Duration             string              `json:"duration"` // T1Actual-T0Actual (monotonic)
	ParticipantsArmed    int                 `json:"participants_armed"`
	ParticipantsExcluded int                 `json:"participants_excluded"`
	Emitted              uint64              `json:"emitted"`
	Sent                 uint64              `json:"sent"` // in_window + drain (loss denominator)
	InWindow             uint64              `json:"in_window"`
	Drain                uint64              `json:"drain"`
	SuppressedPreWindow  uint64              `json:"suppressed_pre_window"`
	SendFailures         uint64              `json:"send_failures"`
	Dropped              uint64              `json:"dropped"`
	Informational        reportInformational `json:"informational"`
	// SubWindows localizes fleet-wide in-window sends across the N equal time
	// buckets of [T0,T1) (FR28); element-wise sum of the per-participant rows,
	// and sums to `in_window`. See metadata.sub_window_count/_duration.
	SubWindows [scenarioSubWindowCount]uint64 `json:"sub_windows"`
	Excluded   []scenarioExcludedRow          `json:"excluded"`
	// ExcludedTruncated reports that `excluded` is a sample: it holds at most
	// scenarioMaxExcludedRows rows while participants_excluded counts them all.
	// ExcludedByReason accounts for the full total regardless.
	ExcludedTruncated bool           `json:"excluded_truncated,omitempty"`
	ExcludedByReason  map[string]int `json:"excluded_by_reason,omitempty"`
}

// reportMetadata is the reproducibility fingerprint + actual window
// timestamps (FR25/FR27): the `(config_sha256, seed, nl6_version)` triple
// that pins a re-run, plus the RFC3339-ms T0/T1/drain-end the run actually
// observed. Grouping them makes "reproduce this run" a single copy-paste.
type reportMetadata struct {
	ConfigSHA256 string `json:"config_sha256"`
	// ResolvedParticipantsSHA256 identifies the devices that actually ran.
	// config_sha256 fingerprints DECLARED INTENT and is the submit-time
	// idempotency key; with a derived-membership selector the same declaration
	// resolves to different fleets on different days, so "same config sha,
	// different counts" needs a second field to be diagnosable at all. This is
	// it: one comparison instead of a full counters diff.
	//
	// Declared adjacent to config_sha256 so the two fingerprints serialize
	// together — declaration order is JSON order for this report.
	ResolvedParticipantsSHA256 string `json:"resolved_participants_sha256"`
	Seed                       int64  `json:"seed"`
	Nl6Version                 string `json:"nl6_version"`
	T0                         string `json:"t0"`
	T1                         string `json:"t1"`
	DrainEnd                   string `json:"drain_end"`
	// DrainStragglers is how many admitted sends were still in flight when the
	// drain barrier gave up at its ceiling (nl6#567). Omitted on every healthy
	// run, which keeps the common report byte-identical to before the ceiling
	// existed; present and non-zero ONLY when finalize was truncated.
	//
	// When it is present, this report was snapshotted while that many sends were
	// still moving, so the affected participants' counters may not add up. It is
	// its own field rather than part of any participant's `dropped`, because a
	// straggler's outcome is unknown: it may still have reached the collector.
	DrainStragglers int64 `json:"drain_stragglers,omitempty"`
	// IncompleteJoins names the finalize waits that did not complete within the
	// budget (nl6#618): the scenario scheduler and the trap/flow tickers, which
	// run AHEAD of the drain barrier. Absent on a healthy run. Present means
	// those goroutines were still running when this report was taken, so it
	// carries the same lower-bound caveat as drain_stragglers, for the same
	// reason: nothing cancels them.
	IncompleteJoins []string `json:"incomplete_joins,omitempty"`
	// SubWindowCount / SubWindowDuration describe the loss-localization
	// granularity (FR28): the PLANNED window [T0,T1) is sliced into
	// SubWindowCount equal buckets, each SubWindowDuration wide (planned
	// window/N as a Go duration). Bucket i covers [T0+i·d, T0+(i+1)·d); an
	// early abort leaves the buckets past the abort instant empty.
	SubWindowCount    int    `json:"sub_window_count"`
	SubWindowDuration string `json:"sub_window_duration"`
	// RunTags records how this run's traffic is isolated from background noise
	// per its protocol's native lever (FR37) — mechanism + value, plus PEN
	// status so a PEN-degraded fallback is visible.
	RunTags runTags `json:"run_tags"`
	// RateCap discloses the fleet-wide rate ceiling in force for this run's
	// protocol, and which same-protocol scenarios overlapped it. Absent when
	// the protocol has no cap (flow protocols and gNMI dial-out never do), so
	// the common case is unchanged.
	//
	// A capped run that shared its bucket did not measure what it would have
	// measured alone. Forbidding concurrency under a cap would disable the
	// feature precisely for operators deliberately rate-limiting; a silent
	// numeric dependency on what else happened to be running is the failure
	// this subsystem keeps designing against, so it is disclosed instead.
	RateCap *rateCapDisclosure `json:"rate_cap,omitempty"`
	// Fidelity discloses whether the fleet was silent for this window, and
	// whether that changed mid-run.
	//
	// Always present, unlike RateCap: "was the rest of the fleet quiet?" is a
	// question every collector-side reconciliation depends on, and absence
	// would be indistinguishable from "silent". Fidelity became runtime-mutable
	// and a pre-armed auto-revert can fire inside a window with no request
	// behind it, so this is not inferable from the run's own inputs.
	Fidelity fidelityDisclosure `json:"fidelity"`
	// Rate discloses what the run was asked for and what it actually did.
	//
	// A requested rate alone is what made nl6#456 a reporting defect rather
	// than a configuration one: an archived report named a target that the run
	// may never have pursued, indistinguishable from one that hit it. Pacing a
	// flow scenario works by sizing an integer flow cache, so the achievable
	// rate lands NEAR the request rather than on it — reporting only the
	// request would hide that rounding, and reporting only the achievement
	// would hide the intent.
	Rate rateDisclosure `json:"rate"`
}

// rateDisclosure records the run's requested per-device rate, whether the
// protocol paces to it at all, and what was achieved.
type rateDisclosure struct {
	RequestedPerDevice float64 `json:"requested_per_device"`
	// Paced is false for protocols whose emission cadence is not driven by
	// the scenario rate — gnmi-dialout streams at its own SAMPLE interval.
	// When false, AchievedPerDevice still reports what happened, but the
	// request explains nothing about it.
	Paced             bool    `json:"paced"`
	AchievedPerDevice float64 `json:"achieved_per_device"`
}

// fidelityDisclosure records fleet silence across one run.
type fidelityDisclosure struct {
	// SilentAtStart is the value in force at T0.
	SilentAtStart bool `json:"silent_at_start"`
	// ChangedDuringWindow is true when fleet silence was toggled, or a timed
	// revert fired, between T0 and finalize.
	//
	// A true here means the run did NOT measure what its operator believes:
	// non-participant devices resumed or ceased autonomous push part-way
	// through, so the collector-side accept rate covers a mixture. The ledger
	// stays exact either way (the mute lives in the non-participant branch),
	// which is precisely why this needs saying out loud — the numbers look
	// clean.
	ChangedDuringWindow bool `json:"changed_during_window"`
}

// rateCapDisclosure is the shared-cap record for one run.
type rateCapDisclosure struct {
	// PerSecond is the fleet-wide ceiling for this protocol (> 0, or the field
	// would be absent).
	PerSecond int `json:"per_second"`
	// SharedWith names the same-protocol SCENARIOS whose windows overlapped
	// this one, sequence-ordered. Only same-protocol runs contend, because
	// limiters are per protocol.
	//
	// Empty means no peer scenario overlapped — NOT that the bucket was
	// uncontended. The scenario scheduler shares the FLEET limiter, and the
	// background scheduler spends a token per pop even for fires the scenario
	// gate then suppresses, so on a busy non-fidelity fleet a solo run is still
	// throttled by background traffic. Run with -fidelity for a bucket this
	// scenario genuinely has to itself.
	SharedWith []string `json:"shared_with"`
}

// resolvedParticipantsSHA256 digests the set of devices that actually
// participated. See reportMetadata.ResolvedParticipantsSHA256 for why it exists.
//
// The input is the FINAL per-device ledger set — post-prune membership, the
// same map the counters serialize from — never the arm-time participant list.
// A run that quietly lost devices between arm and start must not be able to
// digest identically to one that did not, and the arm-time set is a superset.
//
// The digest is a function of the participating addresses ALONE: not the
// selector that produced them, not the configuration that declared them, not
// their install order. That is the property that makes it useful — an explicit
// list and a participants_cidr prefix resolving to the same live devices agree,
// so a baseline stays comparable to a re-declared repeat of it.
//
// Encoding is deliberately the dumbest reproducible one: each address followed
// by "\n", in BYTE order (sort.Strings), SHA-256, hex. Byte order rather than
// the address order used for the operator-facing excluded[] rows, because those
// are read by humans (where 10.42.0.10 before 10.42.0.2 looks wrong) while this
// is input to a hash, where any total order serves. A collector-side check
// reproduces it in one line:
//
//	printf '%s\n' "$IPS" | LC_ALL=C sort | sha256sum
//
// LC_ALL=C is load-bearing: under a UTF-8 locale glibc's collation ignores
// punctuation at the primary level and orders 10.42.10.1 before 10.42.1.2,
// which byte order reverses — a different digest, and a false "different fleet"
// for whoever compares. BSD sort agrees with byte order, so the mistake shows
// up only on the Linux hosts the one-liner is written for.
//
// No empty case exists: a run with zero participants is refused at start, so a
// report always covers at least one address.
func resolvedParticipantsSHA256(perDevice map[string]ledgerSnapshot) string {
	ips := make([]string, 0, len(perDevice))
	for ip := range perDevice {
		ips = append(ips, ip)
	}
	sort.Strings(ips)
	h := sha256.New()
	for _, ip := range ips {
		h.Write([]byte(ip))
		h.Write([]byte("\n"))
	}
	return hex.EncodeToString(h.Sum(nil))
}

// scenarioCounterRow is one participant's ledger, keyed by the join tuple.
// Same flat-identity + separate-informational split as the summary.
type scenarioCounterRow struct {
	Protocol            string              `json:"protocol"`
	SourceIP            string              `json:"source_ip"`
	Collector           string              `json:"collector"`
	Emitted             uint64              `json:"emitted"`
	Sent                uint64              `json:"sent"` // in_window + drain (loss denominator)
	InWindow            uint64              `json:"in_window"`
	Drain               uint64              `json:"drain"`
	SuppressedPreWindow uint64              `json:"suppressed_pre_window"`
	SendFailures        uint64              `json:"send_failures"`
	Dropped             uint64              `json:"dropped"`
	Informational       reportInformational `json:"informational"`
	// SubWindows localizes this participant's in-window sends across the N
	// equal time buckets of [T0,T1) (FR28); sums to `in_window`.
	SubWindows [scenarioSubWindowCount]uint64 `json:"sub_windows"`
}

// reportInformational holds disclosure counters that are deliberately OUTSIDE
// the ledger identity (FR21/FR22). background_suppressed counts background-
// cadence fires the gate suppressed; requested is the scheduler demand (pops,
// pre-limiter) and deferred the fires the shared global cap had no token for.
// None was generated as a sent record, so none appears as an identity term or
// in the loss denominator — a throttle is never mistaken for pipeline loss.
type reportInformational struct {
	BackgroundSuppressed uint64 `json:"background_suppressed"`
	Requested            uint64 `json:"requested"`
	Deferred             uint64 `json:"deferred"`
	// SNMP INFORM ack settlement (best-effort, collector-side; outside the
	// identity). informs_acked ≤ sent; informs_pending = sent − acked at
	// report time (originations not yet acknowledged). Zero for non-INFORM.
	InformsAcked   uint64 `json:"informs_acked"`
	InformsPending uint64 `json:"informs_pending"`
}

// excludedTruncated reports whether the retained rows are a sample of the total.
// One definition, used by both the readiness response and the report: derived
// twice it was two implementations of one invariant over two different row
// sources, free to disagree about the same run.
func excludedTruncated(total, retainedRows int) bool { return total > retainedRows }

// scenarioExcludedRow is the {device, reason, remediation_hint} shape the
// readiness contract mandates (FR9); reused verbatim in the report.
type scenarioExcludedRow struct {
	Device          string `json:"device"`
	Reason          string `json:"reason"`
	RemediationHint string `json:"remediation_hint"`
}

// buildScenarioReport projects a finalized ScenarioResult into the wire
// report. Returns nil when the scenario has not reached a terminal phase
// (no result yet → caller maps to 409). Collector is resolved best-effort
// from the live device's syslog config; a device deleted post-window yields
// an empty collector rather than failing the report.
func buildScenarioReport(sm *SimulatorManager, c *ScenarioController) *scenarioReport {
	res := c.Result()
	if res == nil {
		return nil
	}

	rep := &scenarioReport{
		Summary: scenarioReportSummary{
			ID:       res.ID,
			Phase:    string(res.Phase),
			Protocol: c.spec.Protocol,
			Metadata: reportMetadata{
				ConfigSHA256:    c.configSHA,
				Seed:            c.spec.Seed,
				Nl6Version:      Version,
				T0:              res.T0Actual.Format(rfc3339ms),
				T1:              res.T1Actual.Format(rfc3339ms),
				DrainEnd:        res.DrainEnd.Format(rfc3339ms),
				DrainStragglers: res.DrainStragglers,
				IncompleteJoins: res.IncompleteJoins,
				SubWindowCount:  scenarioSubWindowCount,
				// Bucket width is over the PLANNED window (spec.Window), matching
				// what recordSubWindow used at fire time (the gate keeps the
				// planned t1 even after an early abort). Reporting the actual
				// (shortened) window here would misalign an operator's own
				// per-bucket received tally for aborted runs.
				SubWindowDuration: subWindowDuration(c.spec.Window).String(),
				RunTags:           buildRunTags(c.spec.Protocol, sm.scenarioPEN, res.ID),
				// Derived from the same map ParticipantsArmed counts, so the
				// digest and the count can never describe different sets.
				ResolvedParticipantsSHA256: resolvedParticipantsSHA256(res.PerDevice),
				RateCap:                    buildRateCapDisclosure(c),
				Rate: rateDisclosure{
					RequestedPerDevice: c.spec.Rate,
					Paced:              c.pacesRate(),
					AchievedPerDevice:  achievedPerDeviceRate(res),
				},
				Fidelity: fidelityDisclosure{
					SilentAtStart:       c.fidelitySilentAtStart,
					ChangedDuringWindow: fidelityTransitions.Load() != c.fidelityTransitionsAtStart,
				},
			},
			Duration:             res.T1Actual.Sub(res.T0Actual).String(),
			ParticipantsArmed:    len(res.PerDevice),
			ParticipantsExcluded: res.ExcludedTotal,
			Excluded:             make([]scenarioExcludedRow, 0, len(res.Excluded)),
		},
	}
	for _, ex := range res.Excluded {
		rep.Summary.Excluded = append(rep.Summary.Excluded, scenarioExcludedRow(ex))
	}
	rep.Summary.ExcludedByReason = res.ExcludedByReason
	rep.Summary.ExcludedTruncated = excludedTruncated(res.ExcludedTotal, len(res.Excluded))

	// Stable output: sort participant rows by source IP so two runs of the
	// same scenario serialize byte-identically (determinism contract).
	ips := make([]string, 0, len(res.PerDevice))
	for ip := range res.PerDevice {
		ips = append(ips, ip)
	}
	sort.Strings(ips)

	rep.Counters = make([]scenarioCounterRow, 0, len(ips))
	for _, ip := range ips {
		led := res.PerDevice[ip]
		rep.Counters = append(rep.Counters, scenarioCounterRow{
			Protocol:            c.spec.Protocol,
			SourceIP:            ip,
			Collector:           sm.scenarioCollectorFor(ip, c.spec.Protocol),
			Emitted:             led.Emitted,
			Sent:                led.InWindow + led.Drain,
			InWindow:            led.InWindow,
			Drain:               led.Drain,
			SuppressedPreWindow: led.SuppressedPreWindow,
			SendFailures:        led.SendFailures,
			Dropped:             led.Dropped,
			Informational: reportInformational{
				BackgroundSuppressed: led.BackgroundSuppressed,
				Requested:            led.Requested,
				Deferred:             led.Deferred,
				InformsAcked:         led.InformsAcked,
				InformsPending:       informsPending(led),
			},
			SubWindows: led.SubWindows,
		})
		// Fleet-wide element-wise sub-window sum.
		for i := range led.SubWindows {
			rep.Summary.SubWindows[i] += led.SubWindows[i]
		}
		// Roll into the fleet-wide summary totals.
		rep.Summary.Emitted += led.Emitted
		rep.Summary.Sent += led.InWindow + led.Drain
		rep.Summary.InWindow += led.InWindow
		rep.Summary.Drain += led.Drain
		rep.Summary.SuppressedPreWindow += led.SuppressedPreWindow
		rep.Summary.SendFailures += led.SendFailures
		rep.Summary.Dropped += led.Dropped
		rep.Summary.Informational.BackgroundSuppressed += led.BackgroundSuppressed
		rep.Summary.Informational.Requested += led.Requested
		rep.Summary.Informational.Deferred += led.Deferred
		rep.Summary.Informational.InformsAcked += led.InformsAcked
		rep.Summary.Informational.InformsPending += informsPending(led)
	}
	rep.Applications = buildAppRows(res)
	return rep
}

// buildAppRows projects the finalized fleet-wide application fold into
// report rows: sorted ascending by the numeric (proto, dst_port) key — not
// the rendered name, so an unmapped protocol number can never sort
// lexicographically — with the average byte rate computed on the IN-WINDOW
// byte basis over the actual window (drain bytes stay in `bytes` for
// reconciliation but never inflate a rate whose denominator excludes drain
// time). Always returns a non-nil slice so the block serializes as [] rather
// than null for non-flow and sflow scenarios.
func buildAppRows(res *ScenarioResult) []scenarioAppRow {
	keys := make([]appKey, 0, len(res.Apps))
	for k := range res.Apps {
		keys = append(keys, k)
	}
	sort.Slice(keys, func(i, j int) bool {
		if keys[i].proto != keys[j].proto {
			return keys[i].proto < keys[j].proto
		}
		return keys[i].dstPort < keys[j].dstPort
	})
	rows := make([]scenarioAppRow, 0, len(keys))
	seconds := res.T1Actual.Sub(res.T0Actual).Seconds()
	for _, k := range keys {
		v := res.Apps[k]
		row := scenarioAppRow{
			L4Proto:        l4ProtoName(k.proto),
			DstPort:        k.dstPort,
			AppHint:        appHintForPort(k.dstPort),
			Records:        v.records,
			Bytes:          v.bytes,
			Packets:        v.packets,
			SubWindowBytes: v.subWindowBytes,
		}
		if seconds > 0 {
			row.AvgBytesPerSecond = float64(v.inWindowBytes) / seconds
		}
		rows = append(rows, row)
	}
	return rows
}

// l4ProtoName renders a transport protocol number the way operators write
// collector-side queries; numeric fallback for anything unmapped.
func l4ProtoName(proto uint8) string {
	switch proto {
	case 1:
		return "icmp"
	case 6:
		return "tcp"
	case 17:
		return "udp"
	default:
		return strconv.FormatUint(uint64(proto), 10)
	}
}

// appHints maps the well-known destination ports the shipped flow profiles
// use to conventional service names. Informational only — the authoritative
// join key is (l4_proto, dst_port); collector classification is
// user-configurable and may disagree.
var appHints = map[uint16]string{
	22:   "ssh",
	25:   "smtp",
	53:   "domain",
	67:   "bootps",
	80:   "http",
	161:  "snmp",
	179:  "bgp",
	389:  "ldap",
	443:  "https",
	445:  "microsoft-ds",
	2049: "nfs",
	3260: "iscsi",
	3389: "ms-wbt-server",
	4789: "vxlan",
	4791: "roce",
	8080: "http-alt",
}

func appHintForPort(port uint16) string {
	return appHints[port]
}

// reportCSVHeader is the flat CSV projection column order — the join keys
// (protocol, source_ip, collector) first, then the identity buckets and the
// informational counter, so a monitor's export joins on the first three.
var reportCSVHeader = []string{
	"protocol", "source_ip", "collector",
	"emitted", "in_window", "drain", "suppressed_pre_window",
	"send_failures", "dropped", "background_suppressed",
}

// reportCSV projects the report's counters[] as text/csv with a header row
// (FR27). One row per participant; join-ready on the first three columns.
func reportCSV(rep *scenarioReport) []byte {
	var buf bytes.Buffer
	w := csv.NewWriter(&buf)
	_ = w.Write(reportCSVHeader)
	u := func(v uint64) string { return strconv.FormatUint(v, 10) }
	for _, r := range rep.Counters {
		_ = w.Write([]string{
			r.Protocol, r.SourceIP, r.Collector,
			u(r.Emitted), u(r.InWindow), u(r.Drain), u(r.SuppressedPreWindow),
			u(r.SendFailures), u(r.Dropped), u(r.Informational.BackgroundSuppressed),
		})
	}
	w.Flush()
	return buf.Bytes()
}

// informsPending is the best-effort still-pending INFORM count: originations
// (sent = in_window + drain) not yet acknowledged at report time. Clamped at
// 0 in case a late ack lands after the sent count was snapshotted.
func informsPending(led ledgerSnapshot) uint64 {
	if led.InformsAcked >= led.InformsOriginated {
		return 0
	}
	return led.InformsOriginated - led.InformsAcked
}

// subWindowDuration is the width of one localization bucket: the PLANNED
// window divided by the fixed bucket count (the basis recordSubWindow buckets
// against). Zero when the window is degenerate (<= 0), matching an all-zero
// sub-window tally.
func subWindowDuration(window time.Duration) time.Duration {
	if window <= 0 {
		return 0
	}
	return window / scenarioSubWindowCount
}

// scenarioCollectorFor resolves a device's configured collector for the
// report's join tuple, per the scenario protocol. Empty string when the
// device is gone or lacks that exporter — the report stays serializable
// regardless of post-window churn.
func (sm *SimulatorManager) scenarioCollectorFor(ip, protocol string) string {
	sm.mu.RLock()
	defer sm.mu.RUnlock()
	dev := sm.devicesByIP[ip]
	if dev == nil {
		return ""
	}
	if isFlowScenarioProtocol(protocol) {
		if dev.flowExporter != nil {
			return dev.flowExporter.collectorStr
		}
		return ""
	}
	if protocol == "gnmi-dialout" {
		if dev.gnmiDialoutExporter != nil {
			return dev.gnmiDialoutExporter.collectorStr
		}
		return ""
	}
	if protocol == "snmp-trap" {
		if dev.trapExporter != nil {
			return dev.trapExporter.collectorStr
		}
		return ""
	}
	if protocol == "syslog" && dev.syslogConfig != nil {
		return dev.syslogConfig.Collector
	}
	return ""
}

// buildRateCapDisclosure records the rate ceiling this run competed under, or
// nil when its protocol has none. See reportMetadata.RateCap.
func buildRateCapDisclosure(c *ScenarioController) *rateCapDisclosure {
	capPerSec := c.rateCapAtStart
	if capPerSec <= 0 {
		return nil
	}
	shared := c.overlapIDs()
	if shared == nil {
		shared = []string{} // an explicit empty list reads as "had it to itself"
	}
	return &rateCapDisclosure{PerSecond: capPerSec, SharedWith: shared}
}

// achievedPerDeviceRate is the mean per-device emission rate actually attained
// over the window: total in-window records divided by the window and by the
// number of participants.
//
// In-window only. Drain records were produced during the window but written
// after it, so counting them would inflate the rate by the drain's share while
// the window's own duration stayed the denominator — the same mistake the
// per-application block avoids by keeping drain bytes out of its rate.
//
// This is an IN-WINDOW rate, and that is the whole of its definition (nl6#463).
// Comparing it against a packet capture therefore means bounding the capture to
// [T0, T1) — not correcting the figure by a drain, which was never the term. The
// drain tail is bounded by the work admitted before T1, not by a duration: one
// write on the syslog path, where drain_end was measured at T1 + 9ms with a 30s
// drain configured, and a whole paginated batch on the flow path, which admits
// around Tick. Either way it is orders of magnitude short of moving a 120s
// window by percent (nl6#500).
//
// Since nl6#567 the tail also has a hard ceiling, drainBarrierTimeout, after
// which the barrier gives up and drain_stragglers records how many sends were
// still outstanding. That path does not lengthen the tail; it is what stops one
// stalled write lengthening it without limit. On such a run the numbers above
// are a snapshot of a set that was still moving, which is exactly what the field
// is there to tell the reader. The
// gap nl6#463 chased was measurement-side — template phantoms, post-window
// emission, and a span-versus-window denominator — with zero ledger error.
// Documented in docs/reference/loadtest-report-schema.md; do not "fix" it by
// folding drain records in.
func achievedPerDeviceRate(res *ScenarioResult) float64 {
	if res == nil || len(res.PerDevice) == 0 {
		return 0
	}
	window := res.T1Actual.Sub(res.T0Actual).Seconds()
	if window <= 0 {
		return 0
	}
	var inWindow uint64
	for _, s := range res.PerDevice {
		inWindow += s.InWindow
	}
	return float64(inWindow) / window / float64(len(res.PerDevice))
}
