/*
 * Copyright 2026 Ronny Trommer <ronny@no42.org>
 * SPDX-License-Identifier: Apache-2.0
 */

package main

import (
	"context"
	"fmt"
	"log"
	"time"
)

// scenario_abort_predicate.go — self-aborting runaway scenarios (story 3.4,
// FR7). An optional predicate watches a mid-run ledger metric; when it exceeds
// a threshold and stays exceeded for a grace period, the scenario aborts
// itself through the standard running→aborted pipeline before it drowns the
// collector.
//
// FR7 design note (resolved here): the predicate is
// `{metric, threshold, grace}` over the fleet-wide sum of one ledger counter.
// Evaluation uses APPROXIMATE mid-run atomic reads (no drain barrier) on a
// fixed cadence — the amended ledger boundary permits predicate/live reads
// without waiting for finalize, and this needs nothing from Epic 5.

// predicateEvalInterval is how often the watcher samples the ledger.
const predicateEvalInterval = 1 * time.Second

// AbortPredicateSpec is the wire/config form of an abort predicate. `metric`
// is a fleet-wide-summed ledger counter; the scenario aborts when its value
// exceeds `threshold` continuously for `grace`.
type AbortPredicateSpec struct {
	Metric    string `json:"metric"`
	Threshold uint64 `json:"threshold"`
	Grace     string `json:"grace,omitempty"`
}

// abortPredicate is the resolved predicate.
type abortPredicate struct {
	metric    string
	threshold uint64
	grace     time.Duration
}

// abortMetrics are the ledger counters a predicate may watch. All are
// monotonic cumulative and safe to read mid-run as approximate atomics.
var abortMetrics = map[string]bool{
	"send_failures": true,
	"dropped":       true,
	"deferred":      true,
	"sent":          true, // in_window + drain
}

// buildAbortPredicate validates and resolves the spec (nil → no predicate).
func buildAbortPredicate(spec *AbortPredicateSpec) (*abortPredicate, error) {
	if spec == nil {
		return nil, nil
	}
	if !abortMetrics[spec.Metric] {
		return nil, fmt.Errorf("abort_predicate: unknown metric %q (send_failures|dropped|deferred|sent)", spec.Metric)
	}
	if spec.Threshold == 0 {
		return nil, fmt.Errorf("abort_predicate: threshold must be > 0")
	}
	grace := time.Duration(0)
	if spec.Grace != "" {
		g, err := time.ParseDuration(spec.Grace)
		if err != nil || g < 0 {
			return nil, fmt.Errorf("abort_predicate: grace must be a non-negative duration")
		}
		grace = g
	}
	return &abortPredicate{metric: spec.Metric, threshold: spec.Threshold, grace: grace}, nil
}

// metricSum reads the fleet-wide sum of a ledger metric with APPROXIMATE
// mid-run atomic loads (no drain barrier — this is a live read, not the
// finalized report). Safe during running: c.ledgers is built at arm and not
// mutated until finalize.
func (c *ScenarioController) metricSum(metric string) uint64 {
	c.mu.Lock()
	ledgers := c.ledgers
	c.mu.Unlock()
	var sum uint64
	for _, l := range ledgers {
		switch metric {
		case "send_failures":
			sum += l.sendFailures.Load()
		case "dropped":
			sum += l.dropped.Load()
		case "deferred":
			sum += l.deferred.Load()
		case "sent":
			sum += l.inWindow.Load() + l.drain.Load()
		}
	}
	return sum
}

// watchPredicate samples the metric every predicateEvalInterval; once the
// value exceeds the threshold and has stayed exceeded for `grace`, it aborts
// the scenario through the standard pipeline. Exits when ctx is cancelled
// (finalize) or after it triggers the abort.
func (c *ScenarioController) watchPredicate(ctx context.Context, pred *abortPredicate) {
	ticker := time.NewTicker(predicateEvalInterval)
	defer ticker.Stop()
	var firstCross time.Time
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			if c.metricSum(pred.metric) > pred.threshold {
				if firstCross.IsZero() {
					firstCross = c.now()
				}
				if c.now().Sub(firstCross) >= pred.grace {
					if _, err := c.Abort(); err == nil {
						log.Printf("[scenario] %s aborted by predicate: %s > %d held for %s",
							c.id, pred.metric, pred.threshold, pred.grace)
					}
					return
				}
			} else {
				firstCross = time.Time{} // reset the grace window
			}
		}
	}
}
