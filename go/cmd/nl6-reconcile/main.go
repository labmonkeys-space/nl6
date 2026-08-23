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
// tolerance (or is phantom/missing), so it doubles as a CI gate.
//
// A shortfall is only called LOSS when -drained asserts the collector's queue
// had emptied; otherwise it is RESIDUAL, since a still-queued message is
// backlog and backlog resolves itself. The two have opposite remedies and the
// tool cannot observe the queue, so it does not guess.
package main

import (
	"flag"
	"fmt"
	"os"
)

// Version is stamped at build time via -ldflags "-X main.Version=…" (the same
// LDFLAGS the simulator binary uses); "dev" for a plain `go build`.
var Version = "dev"

func main() {
	reportPath := flag.String("report", "", "path to the scenario report (JSON or CSV projection); '-' for stdin")
	receivedPath := flag.String("received", "", "path to the received-counts input (CSV or Prometheus range JSON); '-' for stdin")
	tolerance := flag.Float64("tolerance", 0.005, "in-flight tolerance band on loss_ratio (0.005 = 0.5%); |ratio| within it is OK")
	format := flag.String("format", "text", "output format: text | csv | json")
	drained := flag.Bool("drained", false, "assert the collector's input queue had drained when -received was captured; "+
		"without it a shortfall is reported as RESIDUAL (backlog or loss, unclassified) rather than LOSS")
	showVersion := flag.Bool("version", false, "print the nl6-reconcile version and exit")
	flag.Parse()

	if *showVersion {
		fmt.Println(Version)
		return
	}

	if *reportPath == "" || *receivedPath == "" {
		fmt.Fprintln(os.Stderr, "nl6-reconcile: both -report and -received are required")
		flag.Usage()
		os.Exit(2)
	}
	if *tolerance < 0 {
		fmt.Fprintf(os.Stderr, "nl6-reconcile: -tolerance must be >= 0 (got %g)\n", *tolerance)
		os.Exit(2)
	}

	reportData, err := readInput(*reportPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "nl6-reconcile: read report: %v\n", err)
		os.Exit(2)
	}
	receivedData, err := readInput(*receivedPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "nl6-reconcile: read received: %v\n", err)
		os.Exit(2)
	}

	sent, err := parseReport(reportData)
	if err != nil {
		fmt.Fprintf(os.Stderr, "nl6-reconcile: parse report: %v\n", err)
		os.Exit(2)
	}
	received, err := parseReceived(receivedData)
	if err != nil {
		fmt.Fprintf(os.Stderr, "nl6-reconcile: parse received: %v\n", err)
		os.Exit(2)
	}

	results := reconcile(sent, received, *tolerance, *drained)

	var out string
	switch *format {
	case "text":
		out = renderText(results, *tolerance, *drained)
	case "csv":
		out = renderCSV(results)
	case "json":
		out, err = renderJSON(results)
		if err != nil {
			fmt.Fprintf(os.Stderr, "nl6-reconcile: render json: %v\n", err)
			os.Exit(2)
		}
	default:
		fmt.Fprintf(os.Stderr, "nl6-reconcile: unknown -format %q (want text|csv|json)\n", *format)
		os.Exit(2)
	}
	fmt.Print(out)

	// Exit non-zero if any key failed reconciliation — CI-gate friendly.
	for _, r := range results {
		if r.Status != statusOK {
			os.Exit(1)
		}
	}
}

// readInput reads a file path, or stdin when the path is "-".
func readInput(path string) ([]byte, error) {
	if path == "-" {
		return readAll(os.Stdin)
	}
	return os.ReadFile(path)
}
