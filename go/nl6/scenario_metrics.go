/*
 * Copyright 2026 Ronny Trommer <ronny@no42.org>
 * SPDX-License-Identifier: Apache-2.0
 */

package main

import (
	"net/http"
	"sort"
	"strconv"
	"strings"
)

// scenario_metrics.go — the scrapeable live-metrics surface (story 5.2,
// FR32/NFR-O2). GET /api/v1/scenarios/{id}/metrics renders a single
// scenario's state in Prometheus text-exposition format (v0.0.4) with no
// third-party client dependency (NFR-M1): two gauges (phase, target rate) and
// the ledger identity buckets as per-participant counters labeled on the
// report join tuple `(protocol, source_ip, collector)`. Because every counter
// increments only in-window and its value is exactly the finalized report
// bucket, a Prometheus range query (increase over [T0,T1]) reproduces the
// report totals (NFR-O2): sum(sent_total) == report.summary.sent.

// prometheusTextVersion is the exposition Content-Type version nl6 emits.
const prometheusTextVersion = "text/plain; version=0.0.4; charset=utf-8"

// scenarioMetricFamily is one identity bucket projected as a Prometheus
// counter family, with the accessor pulling its value out of a snapshot.
type scenarioMetricFamily struct {
	name  string
	help  string
	value func(ledgerSnapshot) uint64
}

// scenarioCounterFamilies enumerates the report identity buckets as counters,
// each labeled on the report tuple. sent_total (in_window+drain) is the loss
// denominator and the AC's named gauge; the rest let a monitor reproduce every
// summary total from the same scrape.
var scenarioCounterFamilies = []scenarioMetricFamily{
	{"nl6_scenario_sent_total", "Records sent (in_window + drain) per participant.",
		func(s ledgerSnapshot) uint64 { return s.InWindow + s.Drain }},
	{"nl6_scenario_emitted_total", "Records emitted (identity total) per participant.",
		func(s ledgerSnapshot) uint64 { return s.Emitted }},
	{"nl6_scenario_in_window_total", "Records sent inside the measurement window per participant.",
		func(s ledgerSnapshot) uint64 { return s.InWindow }},
	{"nl6_scenario_drain_total", "Records sent during the drain tail per participant.",
		func(s ledgerSnapshot) uint64 { return s.Drain }},
	{"nl6_scenario_suppressed_pre_window_total", "Fires suppressed before T0 per participant.",
		func(s ledgerSnapshot) uint64 { return s.SuppressedPreWindow }},
	{"nl6_scenario_send_failures_total", "Transport send failures per participant.",
		func(s ledgerSnapshot) uint64 { return s.SendFailures }},
	{"nl6_scenario_dropped_total", "Records dropped after the drain end per participant.",
		func(s ledgerSnapshot) uint64 { return s.Dropped }},
}

// renderScenarioMetrics builds the Prometheus text exposition for one
// scenario. Output is deterministic (participants sorted by source IP) so two
// scrapes of a finalized scenario are byte-identical.
func renderScenarioMetrics(sm *SimulatorManager, c *ScenarioController) []byte {
	id := c.id
	phase := string(c.Phase())
	protocol := c.spec.Protocol

	var b strings.Builder
	// phase gauge — categorical value carried as a label (info-style), so a
	// dashboard can `nl6_scenario_phase{phase="running"}`.
	b.WriteString("# HELP nl6_scenario_phase Current lifecycle phase (value 1 on the active phase label).\n")
	b.WriteString("# TYPE nl6_scenario_phase gauge\n")
	b.WriteString("nl6_scenario_phase{id=\"" + escapePromLabel(id) + "\",phase=\"" + escapePromLabel(phase) + "\"} 1\n")

	// target rate gauge — the configured events/second the scenario paces to.
	// For a rate_profile scenario this is the constant base rate, not the
	// instantaneous λ(t): the profile's shape (linear/sine/staged) varies the
	// live rate, which this gauge does not track.
	b.WriteString("# HELP nl6_scenario_target_rate Configured base emission rate in events per second (constant base rate for a rate_profile scenario, not instantaneous λ(t)).\n")
	b.WriteString("# TYPE nl6_scenario_target_rate gauge\n")
	b.WriteString("nl6_scenario_target_rate{id=\"" + escapePromLabel(id) + "\"} " + strconv.FormatFloat(c.spec.Rate, 'g', -1, 64) + "\n")

	perDevice := c.LivePerDevice()
	ips := make([]string, 0, len(perDevice))
	for ip := range perDevice {
		ips = append(ips, ip)
	}
	sort.Strings(ips)

	// Resolve the collector once per IP (shared across every counter family).
	collectors := make(map[string]string, len(ips))
	for _, ip := range ips {
		collectors[ip] = sm.scenarioCollectorFor(ip, protocol)
	}

	for _, fam := range scenarioCounterFamilies {
		b.WriteString("# HELP " + fam.name + " " + fam.help + "\n")
		b.WriteString("# TYPE " + fam.name + " counter\n")
		for _, ip := range ips {
			labels := "id=\"" + escapePromLabel(id) + "\",protocol=\"" + escapePromLabel(protocol) +
				"\",source_ip=\"" + escapePromLabel(ip) + "\",collector=\"" + escapePromLabel(collectors[ip]) + "\""
			b.WriteString(fam.name + "{" + labels + "} " + strconv.FormatUint(fam.value(perDevice[ip]), 10) + "\n")
		}
	}
	return []byte(b.String())
}

// escapePromLabel escapes a Prometheus label value per the exposition format: backslash,
// double-quote, and newline. IPs/collectors are normally safe, but a
// sysName-derived collector could contain a quote, so escape defensively.
func escapePromLabel(s string) string {
	if !strings.ContainsAny(s, "\\\"\n") {
		return s
	}
	r := strings.NewReplacer(`\`, `\\`, `"`, `\"`, "\n", `\n`)
	return r.Replace(s)
}

// scenarioMetricsHandler: GET /api/v1/scenarios/{id}/metrics → Prometheus text
// exposition for the scenario (200), or 404 for an unknown id.
func scenarioMetricsHandler(w http.ResponseWriter, r *http.Request) {
	ctrl, ok := lookupScenario(w, r)
	if !ok {
		return
	}
	w.Header().Set("Content-Type", prometheusTextVersion)
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(renderScenarioMetrics(manager, ctrl))
}
