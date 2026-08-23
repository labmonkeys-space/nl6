/*
 * Copyright 2026 Ronny Trommer <ronny@no42.org>
 * SPDX-License-Identifier: Apache-2.0
 */

package main

import (
	"bytes"
	"encoding/csv"
	"encoding/json"
	"fmt"
	"io"
	"sort"
	"strconv"
	"strings"
	"text/tabwriter"
)

// joinKey is the report's join tuple — the 1:1 reconciliation key shared by
// the report and every collector export.
type joinKey struct {
	Protocol  string
	SourceIP  string
	Collector string
}

// reconciliation status for one joined key.
//
// LOSS vs RESIDUAL is the distinction this tool exists to preserve. A shortfall
// measured while the collector's queue is still draining is BACKLOG, and
// backlog resolves itself; the same shortfall measured after the queue has
// emptied is LOSS, and loss never resolves. They have opposite remedies, so
// collapsing them into one figure reproduces the very defect this method was
// written to eliminate (design D2c).
//
// The tool cannot observe the collector's queue, so it cannot make the call on
// its own: the operator asserts a drained queue with -drained. Absent that
// assertion a shortfall is reported as RESIDUAL — unclassified, and still a
// non-zero exit, because an unresolved residual is not a pass.
const (
	statusOK       = "OK"       // |loss_ratio| within tolerance
	statusLoss     = "LOSS"     // received < sent beyond tolerance, queue drained: real loss
	statusResidual = "RESIDUAL" // received < sent beyond tolerance, drain not asserted: backlog or loss, unclassified
	statusDup      = "DUP"      // received > sent beyond tolerance (duplication)
	statusMissing  = "MISSING"  // in report, no received row (total loss or a join gap)
	statusPhantom  = "PHANTOM"  // in received, no report row (unexpected/background traffic)
)

// shortfallStatus names a beyond-tolerance shortfall according to whether the
// caller attested that the collector's queue had drained.
func shortfallStatus(drained bool) string {
	if drained {
		return statusLoss
	}
	return statusResidual
}

// result is one reconciled key.
type result struct {
	Key       joinKey `json:"-"`
	Protocol  string  `json:"protocol"`
	SourceIP  string  `json:"source_ip"`
	Collector string  `json:"collector"`
	Sent      uint64  `json:"sent"`
	Received  uint64  `json:"received"`
	Delta     int64   `json:"delta"`      // sent − received
	LossRatio float64 `json:"loss_ratio"` // (sent − received)/sent; 0 when sent==0
	Status    string  `json:"status"`
}

// readAll is a thin seam for main's stdin read (kept here so main.go stays
// dependency-light and this file owns the io import).
func readAll(r io.Reader) ([]byte, error) { return io.ReadAll(r) }

// --- report (sent) parsing ---------------------------------------------

// scenarioReportDTO is a minimal decode of the report's wire contract — only
// the fields nl6-reconcile joins on. A consumer defining its own DTO against
// the documented schema is the intended decoupling (the report types live in
// package main and can't be imported).
type scenarioReportDTO struct {
	Counters []struct {
		Protocol  string `json:"protocol"`
		SourceIP  string `json:"source_ip"`
		Collector string `json:"collector"`
		Sent      uint64 `json:"sent"`
	} `json:"counters"`
}

// parseReport reads the report as JSON (leading '{') or the flat CSV
// projection, returning sent per join key. CSV sent = in_window + drain
// (the CSV omits the derived `sent` column).
func parseReport(data []byte) (map[joinKey]uint64, error) {
	if isJSON(data) {
		var dto scenarioReportDTO
		if err := json.Unmarshal(data, &dto); err != nil {
			return nil, fmt.Errorf("report JSON: %w", err)
		}
		out := make(map[joinKey]uint64, len(dto.Counters))
		for _, c := range dto.Counters {
			out[joinKey{c.Protocol, c.SourceIP, c.Collector}] += c.Sent
		}
		return out, nil
	}
	// CSV projection: header-addressed so column order can evolve.
	rows, cols, err := readCSV(data)
	if err != nil {
		return nil, err
	}
	need := []string{"protocol", "source_ip", "collector", "in_window", "drain"}
	if err := requireCols(cols, need); err != nil {
		return nil, fmt.Errorf("report CSV: %w", err)
	}
	out := make(map[joinKey]uint64, len(rows))
	for i, row := range rows {
		inWin, err1 := strconv.ParseUint(row[cols["in_window"]], 10, 64)
		drain, err2 := strconv.ParseUint(row[cols["drain"]], 10, 64)
		if err1 != nil || err2 != nil {
			return nil, fmt.Errorf("report CSV row %d: non-numeric in_window/drain", i+2)
		}
		k := joinKey{row[cols["protocol"]], row[cols["source_ip"]], row[cols["collector"]]}
		out[k] += inWin + drain
	}
	return out, nil
}

// --- received parsing ---------------------------------------------------

// promRangeDTO decodes a Prometheus /api/v1/query_range matrix result. The
// received count for a series is the LAST sample (counters are cumulative).
type promRangeDTO struct {
	Data struct {
		Result []struct {
			Metric map[string]string    `json:"metric"`
			Values [][2]json.RawMessage `json:"values"`
		} `json:"result"`
	} `json:"data"`
}

// parseReceived reads the received-counts input as a Prometheus range result
// (leading '{') or a CSV with protocol/source_ip/collector/received columns.
func parseReceived(data []byte) (map[joinKey]uint64, error) {
	if isJSON(data) {
		return parsePrometheus(data)
	}
	rows, cols, err := readCSV(data)
	if err != nil {
		return nil, err
	}
	need := []string{"protocol", "source_ip", "collector", "received"}
	if err := requireCols(cols, need); err != nil {
		return nil, fmt.Errorf("received CSV: %w", err)
	}
	out := make(map[joinKey]uint64, len(rows))
	for i, row := range rows {
		recv, err := strconv.ParseUint(strings.TrimSpace(row[cols["received"]]), 10, 64)
		if err != nil {
			return nil, fmt.Errorf("received CSV row %d: non-numeric received %q", i+2, row[cols["received"]])
		}
		k := joinKey{row[cols["protocol"]], row[cols["source_ip"]], row[cols["collector"]]}
		out[k] += recv
	}
	return out, nil
}

// parsePrometheus extracts the last sample of each matrix series, keyed by the
// series' protocol/source_ip/collector labels. Series missing any join label
// are skipped (they can't be reconciled against the report tuple).
func parsePrometheus(data []byte) (map[joinKey]uint64, error) {
	var dto promRangeDTO
	if err := json.Unmarshal(data, &dto); err != nil {
		return nil, fmt.Errorf("prometheus JSON: %w", err)
	}
	out := make(map[joinKey]uint64, len(dto.Data.Result))
	for _, s := range dto.Data.Result {
		proto, ok1 := s.Metric["protocol"]
		ip, ok2 := s.Metric["source_ip"]
		coll, ok3 := s.Metric["collector"]
		if !ok1 || !ok2 || !ok3 || len(s.Values) == 0 {
			continue
		}
		// Value is [ <ts number>, "<value string>" ]; take the last sample.
		last := s.Values[len(s.Values)-1]
		var vs string
		if err := json.Unmarshal(last[1], &vs); err != nil {
			return nil, fmt.Errorf("prometheus sample: %w", err)
		}
		f, err := strconv.ParseFloat(vs, 64)
		if err != nil {
			return nil, fmt.Errorf("prometheus sample %q: %w", vs, err)
		}
		out[joinKey{proto, ip, coll}] += uint64(f)
	}
	// A non-empty result that produced zero usable series is almost always the
	// wrong query type (an instant `/api/v1/query` vector carries `value`, not
	// the range `values`) or a metric lacking the join labels — fail loudly
	// instead of silently reporting every report key as MISSING.
	if len(out) == 0 && len(dto.Data.Result) > 0 {
		return nil, fmt.Errorf("prometheus result had %d series but none carried protocol/source_ip/collector labels with range samples "+
			"(use a range query /api/v1/query_range, and label the collector metric with the join tuple)", len(dto.Data.Result))
	}
	return out, nil
}

// --- join + classify ----------------------------------------------------

// reconcile outer-joins sent and received on the tuple and classifies each
// key against the tolerance band. Deterministic order (sorted by key).
func reconcile(sent, received map[joinKey]uint64, tolerance float64, drained bool) []result {
	keys := make(map[joinKey]struct{}, len(sent)+len(received))
	for k := range sent {
		keys[k] = struct{}{}
	}
	for k := range received {
		keys[k] = struct{}{}
	}
	out := make([]result, 0, len(keys))
	for k := range keys {
		s, inReport := sent[k]
		r, inReceived := received[k]
		res := result{
			Key: k, Protocol: k.Protocol, SourceIP: k.SourceIP, Collector: k.Collector,
			Sent: s, Received: r, Delta: int64(s) - int64(r),
		}
		switch {
		case !inReport:
			res.Status = statusPhantom
		case !inReceived:
			// MISSING stays its own status because "no received row at all" is a
			// join-shape fact worth keeping distinct from a partial shortfall —
			// it is as often a join gap as a delivery problem. But it is the
			// 100% case of the same ambiguity, so it counts as UNCLASSIFIED
			// until the drain is asserted, and callers must not read it as
			// total loss on its own.
			res.Status = statusMissing
			res.LossRatio = 1
		default:
			if s == 0 {
				// No sent baseline: any received is duplication, else clean.
				if r == 0 {
					res.Status = statusOK
				} else {
					res.Status = statusDup
				}
				break
			}
			res.LossRatio = float64(int64(s)-int64(r)) / float64(s)
			switch {
			case res.LossRatio > tolerance:
				res.Status = shortfallStatus(drained)
			case res.LossRatio < -tolerance:
				res.Status = statusDup
			default:
				res.Status = statusOK
			}
		}
		out = append(out, res)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Protocol != out[j].Protocol {
			return out[i].Protocol < out[j].Protocol
		}
		if out[i].SourceIP != out[j].SourceIP {
			return out[i].SourceIP < out[j].SourceIP
		}
		return out[i].Collector < out[j].Collector
	})
	return out
}

// --- rendering ----------------------------------------------------------

func renderText(results []result, tolerance float64, drained bool) string {
	var b strings.Builder
	tw := tabwriter.NewWriter(&b, 0, 2, 2, ' ', 0)
	// Writes to a strings.Builder-backed tabwriter never error; ignore explicitly.
	_, _ = fmt.Fprintln(tw, "PROTOCOL\tSOURCE_IP\tCOLLECTOR\tSENT\tRECEIVED\tDELTA\tLOSS%\tSTATUS")
	var okN, badN, unclassifiedN int
	var totSent, totRecv uint64
	for _, r := range results {
		_, _ = fmt.Fprintf(tw, "%s\t%s\t%s\t%d\t%d\t%d\t%.2f%%\t%s\n",
			r.Protocol, r.SourceIP, r.Collector, r.Sent, r.Received, r.Delta, r.LossRatio*100, r.Status)
		totSent += r.Sent
		totRecv += r.Received
		if r.Status == statusOK {
			okN++
		} else {
			badN++
		}
		if r.Status == statusResidual || r.Status == statusMissing {
			unclassifiedN++
		}
	}
	_ = tw.Flush()
	fleetLoss := 0.0
	if totSent > 0 {
		fleetLoss = float64(int64(totSent)-int64(totRecv)) / float64(totSent) * 100
	}
	// The fleet figure is labelled by what was actually established. Calling an
	// undrained shortfall "loss" is precisely the single-number merge of
	// backlog and loss that design D2c rules out.
	label := "fleet_delta"
	switch {
	case fleetLoss <= 0:
	case drained:
		label = "fleet_loss"
	default:
		label = "fleet_residual"
	}
	_, _ = fmt.Fprintf(&b, "\nSummary: %d keys | %d OK | %d flagged | tolerance %.2f%% | sent=%d received=%d %s=%.2f%%\n",
		len(results), okN, badN, tolerance*100, totSent, totRecv, label, fleetLoss)
	// Gate on an actually-unclassified row, not on badN: a run whose only
	// flagged rows are PHANTOM or DUP has nothing a drain would change, and
	// telling that operator to wait for a queue to empty wastes their time.
	if !drained && unclassifiedN > 0 {
		_, _ = fmt.Fprint(&b, "\nNOTE: shortfalls above are UNCLASSIFIED (RESIDUAL, or MISSING with no received row).\n"+
			"Still-queued messages are backlog and resolve themselves; drained-and-missing\n"+
			"messages are loss and do not. Re-run with -drained once the collector's input\n"+
			"queue has emptied to classify them.\n")
	}
	return b.String()
}

func renderCSV(results []result) string {
	var b bytes.Buffer
	w := csv.NewWriter(&b)
	_ = w.Write([]string{"protocol", "source_ip", "collector", "sent", "received", "delta", "loss_ratio", "status"})
	for _, r := range results {
		_ = w.Write([]string{
			r.Protocol, r.SourceIP, r.Collector,
			strconv.FormatUint(r.Sent, 10), strconv.FormatUint(r.Received, 10),
			strconv.FormatInt(r.Delta, 10), strconv.FormatFloat(r.LossRatio, 'g', -1, 64), r.Status,
		})
	}
	w.Flush()
	return b.String()
}

func renderJSON(results []result) (string, error) {
	b, err := json.MarshalIndent(results, "", "  ")
	if err != nil {
		return "", err
	}
	return string(b) + "\n", nil
}

// --- small helpers ------------------------------------------------------

// isJSON reports whether the first non-whitespace byte is '{' (both the report
// JSON and a Prometheus result are objects; the CSV forms never start with it).
func isJSON(data []byte) bool {
	t := bytes.TrimSpace(data)
	return len(t) > 0 && t[0] == '{'
}

// readCSV parses CSV bytes into rows plus a case-insensitive header→index map.
func readCSV(data []byte) ([][]string, map[string]int, error) {
	r := csv.NewReader(bytes.NewReader(data))
	r.TrimLeadingSpace = true
	recs, err := r.ReadAll()
	if err != nil {
		return nil, nil, fmt.Errorf("CSV: %w", err)
	}
	if len(recs) == 0 {
		return nil, nil, fmt.Errorf("CSV: empty input")
	}
	cols := make(map[string]int, len(recs[0]))
	for i, name := range recs[0] {
		cols[strings.ToLower(strings.TrimSpace(name))] = i
	}
	return recs[1:], cols, nil
}

// requireCols verifies every needed header is present.
func requireCols(cols map[string]int, need []string) error {
	for _, n := range need {
		if _, ok := cols[n]; !ok {
			return fmt.Errorf("missing required column %q", n)
		}
	}
	return nil
}
