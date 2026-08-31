/*
 * Copyright 2026 Ronny Trommer <ronny@no42.org>
 * SPDX-License-Identifier: Apache-2.0
 */

package main

import (
	"context"
	"strings"
	"testing"
	"testing/synctest"
	"time"
)

// scenario_run_tags_test.go — per-protocol run tagging (story 5.5, FR37): each
// protocol's isolation lever is recorded in metadata.run_tags; PEN-dependent
// levers (syslog SD-PARAM, SNMP enterprise varbind) degrade to window+source-IP
// when no PEN is configured.

// TestBuildRunTags_NoPEN: with no PEN, the no-PEN levers are named directly and
// the PEN-dependent ones degrade to window+source-IP (marked degraded).
func TestBuildRunTags_NoPEN(t *testing.T) {
	cases := []struct {
		protocol      string
		wantMechanism string
		wantDegraded  bool
		wantPENReq    bool
	}{
		{"netflow9", tagNetflow9SourceID, false, false},
		{"ipfix", tagIPFIXODID, false, false},
		{"sflow", tagSFlowSubAgentID, false, false},
		{"gnmi-dialout", tagGNMISyntheticPath, false, false},
		{"netflow5", tagWindowSourceIP, false, false},
		{"syslog", tagWindowSourceIP, true, true},    // no PEN → degraded
		{"snmp-trap", tagWindowSourceIP, true, true}, // no PEN → degraded
	}
	for _, tc := range cases {
		t.Run(tc.protocol, func(t *testing.T) {
			rt := buildRunTags(tc.protocol, 0, "s-000001")
			if rt.Mechanism != tc.wantMechanism {
				t.Errorf("mechanism = %q, want %q", rt.Mechanism, tc.wantMechanism)
			}
			if rt.Degraded != tc.wantDegraded {
				t.Errorf("degraded = %v, want %v", rt.Degraded, tc.wantDegraded)
			}
			if rt.PENRequired != tc.wantPENReq {
				t.Errorf("pen_required = %v, want %v", rt.PENRequired, tc.wantPENReq)
			}
			if rt.PEN != 0 {
				t.Errorf("pen = %d, want 0", rt.PEN)
			}
		})
	}
}

// TestBuildRunTags_WithPEN: a configured PEN activates the PEN-dependent
// levers — syslog carries an SD-PARAM with the runId; neither degrades.
func TestBuildRunTags_WithPEN(t *testing.T) {
	const pen = 32473
	sl := buildRunTags("syslog", pen, "s-000007")
	if sl.Mechanism != tagSyslogSDParam || sl.Degraded {
		t.Fatalf("syslog with PEN: mechanism=%q degraded=%v, want %q/false", sl.Mechanism, sl.Degraded, tagSyslogSDParam)
	}
	if !strings.Contains(sl.Value, "nl6@32473") || !strings.Contains(sl.Value, `runId="s-000007"`) {
		t.Fatalf("syslog SD-PARAM value = %q, want it to carry nl6@32473 runId", sl.Value)
	}
	tr := buildRunTags("snmp-trap", pen, "s-000007")
	if tr.Mechanism != tagSNMPEnterprise || tr.Degraded || tr.PEN != pen {
		t.Fatalf("snmp-trap with PEN: %+v", tr)
	}
	// A no-PEN lever is unaffected by a configured PEN.
	sf := buildRunTags("sflow", pen, "s-000007")
	if sf.Mechanism != tagSFlowSubAgentID || sf.PENRequired {
		t.Fatalf("sflow should not depend on PEN: %+v", sf)
	}
}

// TestReport_CarriesRunTags: a finalized report's metadata carries run_tags for
// its protocol; with no PEN a syslog run is degraded to window+source-IP.
func TestReport_CarriesRunTags(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		sm, _ := scenarioTestManager(t, 1) // scenarioPEN defaults to 0
		c := newScenarioController(sm, nil)
		spec := &Scenario{
			Participants: []string{"10.42.0.1"}, Protocol: "syslog",
			Rate: 10, Window: time.Second, Seed: 42,
		}
		if err := c.Submit(spec, "s-000001"); err != nil {
			t.Fatal(err)
		}
		if _, _, err := c.Arm(); err != nil {
			t.Fatal(err)
		}
		if err := c.Start(context.Background()); err != nil {
			t.Fatal(err)
		}
		time.Sleep(spec.Window + 200*time.Millisecond)
		synctest.Wait()

		rep := buildScenarioReport(sm, c)
		if rep == nil {
			t.Fatal("no report")
		}
		rt := rep.Summary.Metadata.RunTags
		if rt.Protocol != "syslog" {
			t.Fatalf("run_tags.protocol = %q, want syslog", rt.Protocol)
		}
		if !rt.Degraded || rt.Mechanism != tagWindowSourceIP {
			t.Fatalf("no-PEN syslog run should degrade: %+v", rt)
		}

		// With a PEN configured, the same protocol uses the SD-PARAM lever.
		sm.scenarioPEN = 32473
		rep2 := buildScenarioReport(sm, c)
		if rep2.Summary.Metadata.RunTags.Mechanism != tagSyslogSDParam {
			t.Fatalf("with PEN, syslog run should use SD-PARAM, got %q", rep2.Summary.Metadata.RunTags.Mechanism)
		}
	})
}
