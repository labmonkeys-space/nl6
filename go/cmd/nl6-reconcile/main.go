/*
 * Copyright 2026 Ronny Trommer <ronny@no42.org>
 * SPDX-License-Identifier: Apache-2.0
 */

// Command nl6-reconcile joins an nl6 load-test scenario report against a
// collector's received-counts export and emits per-key loss ratios — the
// "one command, not a spreadsheet" reconciliation step of the load-test
// runbook (story 5.4, FR outcome tooling).
//
// It is strictly READ-ONLY: it consumes an already-finalized report (JSON or
// the CSV projection) and a received-counts input (CSV or a Prometheus
// range-query result), outer-joins both on the report's
// (protocol, source_ip, collector) tuple, and prints loss_ratio per key with
// an in-flight tolerance band. Exit status is non-zero when any key exceeds
// tolerance (or is phantom/missing), or, under -nonempty, when the report's
// sent total is zero, so it doubles as a CI gate.
//
// A shortfall is only called LOSS when -drained asserts the collector's queue
// had emptied; otherwise it is RESIDUAL, since a still-queued message is
// backlog and backlog resolves itself. The two have opposite remedies and the
// tool cannot observe the queue, so it does not guess.
package main

import (
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
)

// Version is stamped at build time via -ldflags "-X main.Version=…" (the same
// LDFLAGS the simulator binary uses); "dev" for a plain `go build`.
var Version = "dev"

func main() {
	os.Exit(run(os.Args[1:], os.Stdin, os.Stdout, os.Stderr))
}

// run is the whole command behind a testable seam: it parses args, reads the
// inputs ('-' reads stdin), writes the rendering to stdout and diagnostics to
// stderr, and returns the exit status.
func run(args []string, stdin io.Reader, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("nl6-reconcile", flag.ContinueOnError)
	fs.SetOutput(stderr)
	reportPath := fs.String("report", "", "path to the scenario report (JSON or CSV projection); '-' for stdin")
	receivedPath := fs.String("received", "", "path to the received-counts input (CSV or Prometheus range JSON); '-' for stdin")
	tolerance := fs.Float64("tolerance", 0.005, "in-flight tolerance band on loss_ratio (0.005 = 0.5%); |ratio| within it is OK")
	format := fs.String("format", "text", "output format: text | csv | json")
	drained := fs.Bool("drained", false, "assert the collector's input queue had drained when -received was captured; "+
		"without it a shortfall is reported as RESIDUAL (backlog or loss, unclassified) rather than LOSS")
	nonempty := fs.Bool("nonempty", false, "mark rows with sent 0 and received 0 as EMPTY, and exit 1 when the report's sent total is zero")
	showVersion := fs.Bool("version", false, "print the nl6-reconcile version and exit")
	if err := fs.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return 0
		}
		return 2
	}

	if *showVersion {
		_, _ = fmt.Fprintln(stdout, Version)
		return 0
	}

	if *reportPath == "" || *receivedPath == "" {
		_, _ = fmt.Fprintln(stderr, "nl6-reconcile: both -report and -received are required")
		fs.Usage()
		return 2
	}
	if *tolerance < 0 {
		_, _ = fmt.Fprintf(stderr, "nl6-reconcile: -tolerance must be >= 0 (got %g)\n", *tolerance)
		return 2
	}

	reportData, err := readInput(*reportPath, stdin)
	if err != nil {
		_, _ = fmt.Fprintf(stderr, "nl6-reconcile: read report: %v\n", err)
		return 2
	}
	receivedData, err := readInput(*receivedPath, stdin)
	if err != nil {
		_, _ = fmt.Fprintf(stderr, "nl6-reconcile: read received: %v\n", err)
		return 2
	}

	sent, err := parseReport(reportData)
	if err != nil {
		_, _ = fmt.Fprintf(stderr, "nl6-reconcile: parse report: %v\n", err)
		return 2
	}
	received, err := parseReceived(receivedData)
	if err != nil {
		_, _ = fmt.Fprintf(stderr, "nl6-reconcile: parse received: %v\n", err)
		return 2
	}

	results := reconcile(sent, received, *tolerance, *drained, *nonempty)

	var out string
	switch *format {
	case "text":
		out = renderText(results, *tolerance, *drained, *nonempty)
	case "csv":
		out = renderCSV(results)
	case "json":
		out, err = renderJSON(results)
		if err != nil {
			_, _ = fmt.Fprintf(stderr, "nl6-reconcile: render json: %v\n", err)
			return 2
		}
	default:
		_, _ = fmt.Fprintf(stderr, "nl6-reconcile: unknown -format %q (want text|csv|json)\n", *format)
		return 2
	}
	_, _ = fmt.Fprint(stdout, out)

	// Exit non-zero if any key failed reconciliation, or under -nonempty if
	// nothing was sent. CSV and JSON carry no NOTE, so when -nonempty is the
	// only reason for the failure, say so on stderr; stdout stays byte-stable.
	code := exitCode(results, *nonempty)
	if code != 0 && exitCode(results, false) == 0 {
		_, _ = fmt.Fprintln(stderr, "nl6-reconcile: nothing was sent; failing because -nonempty is set")
	}
	return code
}

// readInput reads a file path, or stdin when the path is "-".
func readInput(path string, stdin io.Reader) ([]byte, error) {
	if path == "-" {
		return readAll(stdin)
	}
	return os.ReadFile(path)
}
