/*
 * Copyright 2026 Ronny Trommer <ronny@no42.org>
 * SPDX-License-Identifier: Apache-2.0
 */

package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
)

type checkOptions struct {
	Report    string  // default <state dir>/report.json
	Received  string  // CSV: protocol,source_ip,collector,received
	Tolerance float64 // per device, default 0
	Reconcile string  // default "nl6-reconcile", resolved through PATH
}

// reconcileArgs builds the nl6-reconcile command line. -drained is always
// set: by the time check runs, the measurement window and its grace are over.
func reconcileArgs(o checkOptions) []string {
	return []string{
		"-report", o.Report,
		"-received", o.Received,
		"-tolerance", strconv.FormatFloat(o.Tolerance, 'g', -1, 64),
		"-drained",
	}
}

// check verifies the report, runs nl6-reconcile and returns its exit code.
// The tolerance applies per device row, as nl6-reconcile defines it.
//
// Invariant: check never runs nl6-reconcile on a report it has not verified.
// Zero sent matches zero received, so nl6-reconcile alone would pass a run
// that sent nothing. That holds for the CSV projection of a report too, which
// carries no summary to verify, so check takes only the JSON report that run
// writes.
func check(dir string, o checkOptions, stdout, stderr io.Writer) (int, error) {
	if o.Report == "" {
		o.Report = filepath.Join(dir, "report.json")
	}
	report, err := os.ReadFile(o.Report)
	if err != nil {
		_, _ = fmt.Fprintf(stderr, "nl6-ci check: cannot read report %s: %v. Run nl6-ci run first\n", o.Report, err)
		return 2, nil
	}
	if !json.Valid(report) {
		_, _ = fmt.Fprintf(stderr, "nl6-ci check: report %s is not JSON. "+
			"check needs the JSON report that nl6-ci run writes. "+
			"Call nl6-reconcile directly for other inputs, such as the CSV projection\n", o.Report)
		return 2, nil
	}
	// Without state.json (after down) the fixture is unknown: neither the
	// device count nor the window start is compared.
	s, err := loadState(dir)
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return 0, err
	}
	if err := verifyReport(report, s.Devices, s.Started); err != nil {
		return 0, fmt.Errorf("report %s is refused: %w", o.Report, err)
	}
	if o.Reconcile == "" {
		o.Reconcile = "nl6-reconcile"
	}
	cmd := exec.Command(o.Reconcile, reconcileArgs(o)...)
	cmd.Stdout, cmd.Stderr = stdout, stderr
	err = cmd.Run()
	var ee *exec.ExitError
	switch {
	case err == nil:
		return 0, nil
	case errors.As(err, &ee):
		if ee.ExitCode() < 0 { // killed by a signal; -1 would become exit 255
			return 0, fmt.Errorf("%s did not finish: %v", o.Reconcile, ee)
		}
		return ee.ExitCode(), nil
	default:
		return 0, fmt.Errorf("run %s: %w. It ships in the nl6 package, or install it from the nl6 release", o.Reconcile, err)
	}
}
