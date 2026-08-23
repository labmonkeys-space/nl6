/*
 * Copyright 2026 Ronny Trommer <ronny@no42.org>
 * SPDX-License-Identifier: Apache-2.0
 */

package main

import (
	"strings"
	"testing"
)

func k(proto, ip, coll string) joinKey { return joinKey{proto, ip, coll} }

// TestReconcile_Classification exercises the outer join + tolerance band across
// every status: OK (within tolerance), LOSS, DUP, MISSING, PHANTOM.
func TestReconcile_Classification(t *testing.T) {
	sent := map[joinKey]uint64{
		k("syslog", "10.42.0.1", "c:514"): 1000, // exact → OK
		k("syslog", "10.42.0.2", "c:514"): 1000, // 5% loss → LOSS
		k("syslog", "10.42.0.3", "c:514"): 1000, // within 0.5% → OK
		k("syslog", "10.42.0.4", "c:514"): 1000, // received>sent → DUP
		k("syslog", "10.42.0.5", "c:514"): 500,  // no received row → MISSING
	}
	received := map[joinKey]uint64{
		k("syslog", "10.42.0.1", "c:514"): 1000,
		k("syslog", "10.42.0.2", "c:514"): 950,
		k("syslog", "10.42.0.3", "c:514"): 997, // 0.3% < 0.5% tolerance
		k("syslog", "10.42.0.4", "c:514"): 1100,
		k("syslog", "10.42.0.9", "c:514"): 42, // phantom — not in report
	}
	got := reconcile(sent, received, 0.005, true)

	want := map[string]string{
		"10.42.0.1": statusOK,
		"10.42.0.2": statusLoss,
		"10.42.0.3": statusOK,
		"10.42.0.4": statusDup,
		"10.42.0.5": statusMissing,
		"10.42.0.9": statusPhantom,
	}
	if len(got) != len(want) {
		t.Fatalf("got %d results, want %d", len(got), len(want))
	}
	for _, r := range got {
		if w := want[r.SourceIP]; r.Status != w {
			t.Errorf("%s: status=%s, want %s (sent=%d received=%d ratio=%.4f)", r.SourceIP, r.Status, w, r.Sent, r.Received, r.LossRatio)
		}
	}
	// Deterministic ordering (sorted by tuple).
	if got[0].SourceIP != "10.42.0.1" || got[len(got)-1].SourceIP != "10.42.0.9" {
		t.Fatalf("results not sorted by key: first=%s last=%s", got[0].SourceIP, got[len(got)-1].SourceIP)
	}
}

// TestReconcile_ToleranceBoundary: a loss ratio exactly at the tolerance is OK
// (band is inclusive); just past it flips to LOSS.
func TestReconcile_ToleranceBoundary(t *testing.T) {
	sent := map[joinKey]uint64{k("syslog", "10.0.0.1", "c"): 1000}
	// exactly 0.5% loss → OK; 1.0% loss → LOSS
	if got := reconcile(sent, map[joinKey]uint64{k("syslog", "10.0.0.1", "c"): 995}, 0.005, true); got[0].Status != statusOK {
		t.Fatalf("ratio == tolerance: status=%s, want OK", got[0].Status)
	}
	if got := reconcile(sent, map[joinKey]uint64{k("syslog", "10.0.0.1", "c"): 990}, 0.005, true); got[0].Status != statusLoss {
		t.Fatalf("ratio > tolerance: status=%s, want LOSS", got[0].Status)
	}
}

// TestParseReport_JSON parses the report's JSON contract → sent per key.
func TestParseReport_JSON(t *testing.T) {
	js := `{"summary":{"id":"s-000001"},"counters":[
	  {"protocol":"syslog","source_ip":"10.42.0.1","collector":"c:514","sent":1000,"in_window":900,"drain":100},
	  {"protocol":"syslog","source_ip":"10.42.0.2","collector":"c:514","sent":500,"in_window":500,"drain":0}]}`
	got, err := parseReport([]byte(js))
	if err != nil {
		t.Fatal(err)
	}
	if got[k("syslog", "10.42.0.1", "c:514")] != 1000 || got[k("syslog", "10.42.0.2", "c:514")] != 500 {
		t.Fatalf("parsed sent = %v", got)
	}
}

// TestParseReport_CSV parses the flat CSV projection; sent = in_window + drain.
func TestParseReport_CSV(t *testing.T) {
	csvData := "protocol,source_ip,collector,emitted,in_window,drain,suppressed_pre_window,send_failures,dropped,background_suppressed\n" +
		"syslog,10.42.0.1,c:514,1000,900,100,0,0,0,0\n"
	got, err := parseReport([]byte(csvData))
	if err != nil {
		t.Fatal(err)
	}
	if got[k("syslog", "10.42.0.1", "c:514")] != 1000 {
		t.Fatalf("CSV sent = %v, want 1000 (900+100)", got)
	}
}

// TestParseReceived_CSV parses a collector's CSV export.
func TestParseReceived_CSV(t *testing.T) {
	csvData := "protocol,source_ip,collector,received\nsyslog,10.42.0.1,c:514,998\n"
	got, err := parseReceived([]byte(csvData))
	if err != nil {
		t.Fatal(err)
	}
	if got[k("syslog", "10.42.0.1", "c:514")] != 998 {
		t.Fatalf("received = %v", got)
	}
}

// TestParseReceived_Prometheus takes the LAST sample of each matrix series,
// keyed by the join labels.
func TestParseReceived_Prometheus(t *testing.T) {
	js := `{"status":"success","data":{"resultType":"matrix","result":[
	  {"metric":{"protocol":"syslog","source_ip":"10.42.0.1","collector":"c:514"},
	   "values":[[1700000000,"10"],[1700000010,"998"]]},
	  {"metric":{"__name__":"noise"},"values":[[1,"1"]]}]}}`
	got, err := parseReceived([]byte(js))
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 || got[k("syslog", "10.42.0.1", "c:514")] != 998 {
		t.Fatalf("prometheus received = %v, want {…:998} (last sample, noise skipped)", got)
	}
}

// TestParseReceived_PrometheusWrongType: an instant-vector result (or a
// metric lacking the join labels) fails loudly rather than silently yielding
// an empty received set that would mark every report key MISSING.
func TestParseReceived_PrometheusWrongType(t *testing.T) {
	// Instant vector: series carry `value`, not the range `values`.
	js := `{"data":{"result":[{"metric":{"protocol":"syslog","source_ip":"10.42.0.1","collector":"c"},"value":[1,"5"]}]}}`
	_, err := parseReceived([]byte(js))
	if err == nil || !strings.Contains(err.Error(), "range") {
		t.Fatalf("wrong-type prometheus: err=%v, want a range-query hint", err)
	}
	// An empty result (no series at all) is not an error — nothing received.
	if _, err := parseReceived([]byte(`{"data":{"result":[]}}`)); err != nil {
		t.Fatalf("empty prometheus result should not error: %v", err)
	}
}

// TestRender_Formats smoke-tests the three renderers on one result set.
func TestRender_Formats(t *testing.T) {
	res := reconcile(
		map[joinKey]uint64{k("syslog", "10.0.0.1", "c"): 100},
		map[joinKey]uint64{k("syslog", "10.0.0.1", "c"): 95},
		0.005,
		true, // queue drained: a shortfall here IS loss
	)
	if txt := renderText(res, 0.005, true); !strings.Contains(txt, "LOSS") || !strings.Contains(txt, "Summary:") {
		t.Fatalf("text render missing LOSS/Summary:\n%s", txt)
	}
	if c := renderCSV(res); !strings.HasPrefix(c, "protocol,source_ip,collector,sent,received,delta,loss_ratio,status") {
		t.Fatalf("csv render header wrong:\n%s", c)
	}
	j, err := renderJSON(res)
	if err != nil || !strings.Contains(j, `"status": "LOSS"`) {
		t.Fatalf("json render: err=%v body=%s", err, j)
	}
}

// TestReconcile_EndToEnd_JSONvsPrometheus joins a JSON report against a
// Prometheus received result — the documented reconciliation path.
func TestReconcile_EndToEnd_JSONvsPrometheus(t *testing.T) {
	report := `{"counters":[{"protocol":"syslog","source_ip":"10.42.0.1","collector":"c:514","sent":1000}]}`
	prom := `{"data":{"result":[{"metric":{"protocol":"syslog","source_ip":"10.42.0.1","collector":"c:514"},"values":[[1,"1000"]]}]}}`
	sent, err := parseReport([]byte(report))
	if err != nil {
		t.Fatal(err)
	}
	recv, err := parseReceived([]byte(prom))
	if err != nil {
		t.Fatal(err)
	}
	got := reconcile(sent, recv, 0.005, true)
	if len(got) != 1 || got[0].Status != statusOK || got[0].LossRatio != 0 {
		t.Fatalf("end-to-end: %+v", got)
	}
}

// TestReconcile_ShortfallIsResidualUntilDrainIsAsserted is the whole point of
// design D2c: a shortfall measured while the collector's queue may still be
// draining is BACKLOG, which resolves itself, and calling it LOSS sends an
// operator chasing a network fault that isn't there. The tool cannot see the
// queue, so it must not guess.
func TestReconcile_ShortfallIsResidualUntilDrainIsAsserted(t *testing.T) {
	sent := map[joinKey]uint64{k("syslog", "10.42.0.1", "c:514"): 159500}
	recv := map[joinKey]uint64{k("syslog", "10.42.0.1", "c:514"): 40586}

	undrained := reconcile(sent, recv, 0.005, false)
	if undrained[0].Status != statusResidual {
		t.Errorf("without -drained: got %q, want %q — an unclassified shortfall must not be called loss",
			undrained[0].Status, statusResidual)
	}

	drained := reconcile(sent, recv, 0.005, true)
	if drained[0].Status != statusLoss {
		t.Errorf("with -drained: got %q, want %q", drained[0].Status, statusLoss)
	}

	// Both remain failures — an unresolved residual is not a pass.
	for _, r := range append(undrained, drained...) {
		if r.Status == statusOK {
			t.Error("a beyond-tolerance shortfall must never reconcile as OK")
		}
	}
}

// TestRenderText_DoesNotLabelUndrainedShortfallAsLoss guards the summary line,
// which is where the original harness defect lived: one figure merging backlog
// and loss.
func TestRenderText_DoesNotLabelUndrainedShortfallAsLoss(t *testing.T) {
	res := reconcile(
		map[joinKey]uint64{k("syslog", "10.42.0.1", "c:514"): 159500},
		map[joinKey]uint64{k("syslog", "10.42.0.1", "c:514"): 40586},
		0.005, false,
	)
	txt := renderText(res, 0.005, false)
	if strings.Contains(txt, "fleet_loss") {
		t.Errorf("undrained summary reports fleet_loss, merging backlog and loss:\n%s", txt)
	}
	if !strings.Contains(txt, "fleet_residual") {
		t.Errorf("undrained summary should report fleet_residual:\n%s", txt)
	}
	if !strings.Contains(txt, "-drained") {
		t.Errorf("undrained output should tell the operator how to classify the residual:\n%s", txt)
	}
}

// TestRenderText_NoteOnlyWhenSomethingIsUnclassified: a run whose only flagged
// rows are PHANTOM or DUP has nothing a queue drain would change. Telling that
// operator to re-run with -drained sends them to wait on an event that cannot
// affect the result.
func TestRenderText_NoteOnlyWhenSomethingIsUnclassified(t *testing.T) {
	// PHANTOM only: received traffic with no report row.
	res := reconcile(
		map[joinKey]uint64{},
		map[joinKey]uint64{k("syslog", "10.42.0.9", "c:514"): 500},
		0.005, false,
	)
	if res[0].Status != statusPhantom {
		t.Fatalf("fixture: got %q, want PHANTOM", res[0].Status)
	}
	if txt := renderText(res, 0.005, false); strings.Contains(txt, "-drained") {
		t.Errorf("PHANTOM-only run advises -drained, which cannot change it:\n%s", txt)
	}

	// DUP only: received exceeds sent; a drain cannot reduce it.
	dup := reconcile(
		map[joinKey]uint64{k("syslog", "10.42.0.1", "c:514"): 100},
		map[joinKey]uint64{k("syslog", "10.42.0.1", "c:514"): 130},
		0.005, false,
	)
	if dup[0].Status != statusDup {
		t.Fatalf("fixture: got %q, want DUP", dup[0].Status)
	}
	if txt := renderText(dup, 0.005, false); strings.Contains(txt, "-drained") {
		t.Errorf("DUP-only run advises -drained:\n%s", txt)
	}
}

// TestRenderText_FleetLabelMatchesTheNumber: "residual" names a positive
// shortfall. A clean run has no residual, and a duplication-heavy run has a
// NEGATIVE one, which is not a thing.
func TestRenderText_FleetLabelMatchesTheNumber(t *testing.T) {
	clean := reconcile(
		map[joinKey]uint64{k("syslog", "10.42.0.1", "c:514"): 1000},
		map[joinKey]uint64{k("syslog", "10.42.0.1", "c:514"): 1000},
		0.005, false,
	)
	if txt := renderText(clean, 0.005, false); strings.Contains(txt, "fleet_residual") {
		t.Errorf("a fully reconciled run reports a residual of zero as a residual:\n%s", txt)
	}

	dup := reconcile(
		map[joinKey]uint64{k("syslog", "10.42.0.1", "c:514"): 100},
		map[joinKey]uint64{k("syslog", "10.42.0.1", "c:514"): 130},
		0.005, false,
	)
	if txt := renderText(dup, 0.005, false); strings.Contains(txt, "fleet_residual=-") {
		t.Errorf("duplication rendered as a negative residual:\n%s", txt)
	}
}

// TestReconcile_MissingIsUnclassifiedToo: MISSING is the 100% shortfall. A
// low-rate device whose messages are all still queued produces no received row
// at all, so treating MISSING as settled total loss is the same mislabel this
// change exists to prevent, just at the extreme.
func TestReconcile_MissingIsUnclassifiedToo(t *testing.T) {
	res := reconcile(
		map[joinKey]uint64{k("syslog", "10.42.0.1", "c:514"): 40},
		map[joinKey]uint64{},
		0.005, false,
	)
	if res[0].Status != statusMissing {
		t.Fatalf("fixture: got %q, want MISSING", res[0].Status)
	}
	txt := renderText(res, 0.005, false)
	if !strings.Contains(txt, "-drained") {
		t.Errorf("MISSING without a drain assertion is unclassified and must say so:\n%s", txt)
	}
}
