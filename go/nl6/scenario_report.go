/*
 * Copyright 2026 Ronny Trommer <ronny@no42.org>
 * SPDX-License-Identifier: Apache-2.0
 */

package main

import (
	"bytes"
	"encoding/csv"
	"sort"
	"strconv"
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
// first, then per-device counters — the field order IS the JSON order.
type scenarioReport struct {
	Summary  scenarioReportSummary `json:"summary"`
	Counters []scenarioCounterRow  `json:"counters"`
}

// scenarioReportSummary is the top-level aggregate block: identity,
// fingerprint, window, and fleet-wide ledger totals. The five loss buckets
// plus `emitted` are flat (they form the ledger identity, FR23); the
// disclosure counter lives in a separate `informational` sub-object (FR21)
// so it can never be mistaken for an identity term.
type scenarioReportSummary struct {
	ID                   string                `json:"id"`
	Phase                string                `json:"phase"`
	Protocol             string                `json:"protocol"`
	Metadata             reportMetadata        `json:"metadata"`
	Duration             string                `json:"duration"` // T1Actual-T0Actual (monotonic)
	ParticipantsArmed    int                   `json:"participants_armed"`
	ParticipantsExcluded int                   `json:"participants_excluded"`
	Emitted              uint64                `json:"emitted"`
	Sent                 uint64                `json:"sent"` // in_window + drain (loss denominator)
	InWindow             uint64                `json:"in_window"`
	Drain                uint64                `json:"drain"`
	SuppressedPreWindow  uint64                `json:"suppressed_pre_window"`
	SendFailures         uint64                `json:"send_failures"`
	Dropped              uint64                `json:"dropped"`
	Informational        reportInformational   `json:"informational"`
	Excluded             []scenarioExcludedRow `json:"excluded"`
}

// reportMetadata is the reproducibility fingerprint + actual window
// timestamps (FR25/FR27): the `(config_sha256, seed, nl6_version)` triple
// that pins a re-run, plus the RFC3339-ms T0/T1/drain-end the run actually
// observed. Grouping them makes "reproduce this run" a single copy-paste.
type reportMetadata struct {
	ConfigSHA256 string `json:"config_sha256"`
	Seed         int64  `json:"seed"`
	Nl6Version   string `json:"nl6_version"`
	T0           string `json:"t0"`
	T1           string `json:"t1"`
	DrainEnd     string `json:"drain_end"`
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
}

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
				ConfigSHA256: c.configSHA,
				Seed:         c.spec.Seed,
				Nl6Version:   Version,
				T0:           res.T0Actual.Format(rfc3339ms),
				T1:           res.T1Actual.Format(rfc3339ms),
				DrainEnd:     res.DrainEnd.Format(rfc3339ms),
			},
			Duration:             res.T1Actual.Sub(res.T0Actual).String(),
			ParticipantsArmed:    len(res.PerDevice),
			ParticipantsExcluded: len(res.Excluded),
			Excluded:             make([]scenarioExcludedRow, 0, len(res.Excluded)),
		},
	}
	for _, ex := range res.Excluded {
		rep.Summary.Excluded = append(rep.Summary.Excluded, scenarioExcludedRow(ex))
	}

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
			},
		})
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
	}
	return rep
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
	if protocol == "syslog" && dev.syslogConfig != nil {
		return dev.syslogConfig.Collector
	}
	return ""
}
