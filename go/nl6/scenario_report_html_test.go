/*
 * Copyright 2026 Ronny Trommer <ronny@no42.org>
 * SPDX-License-Identifier: Apache-2.0
 */

package main

import (
	"strings"
	"testing"
)

// sampleReport builds a representative finalized report for the HTML renderer.
func sampleReport() *scenarioReport {
	rep := &scenarioReport{
		Summary: scenarioReportSummary{
			ID: "s-000042", Phase: "stopped", Protocol: "ipfix",
			Metadata: reportMetadata{
				ConfigSHA256: "9b8d8c9cdeadbeef", Seed: 7, Nl6Version: "v0.16.0",
				T0: "2026-07-20T09:00:05.000Z", T1: "2026-07-20T09:01:05.000Z",
				DrainEnd:       "2026-07-20T09:01:10.000Z",
				SubWindowCount: scenarioSubWindowCount, SubWindowDuration: "6s",
				RunTags: runTags{Protocol: "ipfix", Mechanism: tagIPFIXODID, Value: "s-000042", Note: "isolate by ODID"},
			},
			Duration: "1m0s", ParticipantsArmed: 2, ParticipantsExcluded: 1,
			Emitted: 100, Sent: 100, InWindow: 90, Drain: 10,
		},
		Counters: []scenarioCounterRow{
			{Protocol: "ipfix", SourceIP: "10.42.0.1", Collector: "10.0.0.9:4739", Sent: 50, InWindow: 45, Drain: 5},
			{Protocol: "ipfix", SourceIP: "10.42.0.2", Collector: "10.0.0.9:4739", Sent: 50, InWindow: 45, Drain: 5, SendFailures: 3},
		},
	}
	for i := range rep.Summary.SubWindows {
		rep.Summary.SubWindows[i] = uint64(i + 1) // ascending → a visible ramp
	}
	rep.Summary.Excluded = []scenarioExcludedRow{
		{Device: "10.42.0.9", Reason: "device not found", RemediationHint: "create it first"},
	}
	return rep
}

// TestReportHTML_Structure: the rendered page is a self-contained HTML document
// carrying the headline identity, the localization chart, run tags, both
// participant rows (with a per-row status), and the excluded table.
func TestReportHTML_Structure(t *testing.T) {
	html := string(reportHTML(sampleReport()))

	for _, want := range []string{
		"<!DOCTYPE html>", "</html>",
		"<style>",                // embedded CSS, self-contained
		"s-000042",               // scenario id
		"pill-ok",                // stopped → ok phase pill
		"ipfix",                  // protocol
		"Records sent",           // stat card
		"Loss localization",      // chart section
		"class=\"col\"",          // at least one bar column
		"9b8d8c9cdeadbeef",       // config sha
		tagIPFIXODID,             // run-tag mechanism
		"10.42.0.1", "10.42.0.2", // both participants
		"10.0.0.9:4739", // collector
		"Excluded",      // excluded section rendered
		"device not found",
	} {
		if !strings.Contains(html, want) {
			t.Errorf("rendered HTML missing %q", want)
		}
	}

	// No external dependencies: no <script>, no remote fonts/stylesheets.
	for _, bad := range []string{"<script", "http://", "https://", "<link"} {
		if strings.Contains(html, bad) {
			t.Errorf("HTML must be self-contained; found %q", bad)
		}
	}

	// The row with send_failures=3 is flagged; a clean row is not.
	if !strings.Contains(html, "tag bad") || !strings.Contains(html, "tag ok") {
		t.Error("participant rows must carry both clean and issue status tags")
	}
}

// TestReportHTML_EmptyLocalization: a report with no in-window sends renders the
// empty-chart note instead of bars.
func TestReportHTML_EmptyLocalization(t *testing.T) {
	rep := sampleReport()
	rep.Summary.SubWindows = [scenarioSubWindowCount]uint64{} // all zero
	html := string(reportHTML(rep))
	if !strings.Contains(html, "No in-window sends to localize") {
		t.Error("empty localization should render the no-data note")
	}
}

// TestReportHTML_Escaping: attacker-controlled string fields (collector,
// exclusion text) are HTML-escaped by html/template — no injection.
func TestReportHTML_Escaping(t *testing.T) {
	rep := sampleReport()
	rep.Counters[0].Collector = "<script>alert(1)</script>"
	rep.Summary.Excluded[0].Reason = "<img src=x onerror=alert(2)>"
	html := string(reportHTML(rep))

	if strings.Contains(html, "<script>alert(1)</script>") || strings.Contains(html, "<img src=x") {
		t.Fatal("raw HTML from report fields reached the output — auto-escaping broken")
	}
	if !strings.Contains(html, "&lt;script&gt;") {
		t.Error("expected the collector value to be HTML-escaped")
	}
}
