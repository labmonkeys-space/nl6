/*
 * Copyright 2026 Ronny Trommer <ronny@no42.org>
 * SPDX-License-Identifier: Apache-2.0
 */

// Command nl6-ci drives nl6 as a test fixture in CI pipelines.
//
// Usage: nl6-ci [global flags] <verb> [verb flags]
package main

import (
	"flag"
	"fmt"
	"io"
	"math"
	"os"
	"time"
)

// Version is stamped at build time via -ldflags "-X main.Version=…" (the same
// LDFLAGS the simulator binary uses); "dev" for a plain `go build`.
var Version = "dev"

const usage = `usage: nl6-ci [-state <dir>] <verb> [verb flags]
       nl6-ci -version

The state directory is -state, else $NL6_CI_STATE, else ./.nl6-ci.

verbs:
  preflight   check that this runner can run nl6
  up          start nl6 and create the devices: up -manifest <file> [-port 18080] [-nl6 path] [-workdir dir] [-create-timeout 5m] [-- <nl6 flags>]
  run         drive one scenario window: run -protocol <p> -rate <n> -window <dur> [-seed <n>] [-report <path>] [-request-timeout 10s]
  check       compare sent with received: check -received <csv> [-report <path>] [-tolerance <ratio>]
  down        stop nl6: down [-log-tail]
`

func main() {
	os.Exit(runCLI(os.Args[1:], os.Stdout, os.Stderr))
}

func runCLI(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("nl6-ci", flag.ContinueOnError)
	fs.SetOutput(stderr)
	fs.Usage = func() { _, _ = fmt.Fprint(stderr, usage) }
	stateFlag := fs.String("state", "", "state directory (default $NL6_CI_STATE, else ./.nl6-ci)")
	showVersion := fs.Bool("version", false, "print the nl6-ci version and exit")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	if *showVersion {
		_, _ = fmt.Fprintln(stdout, Version)
		return 0
	}
	if fs.NArg() == 0 {
		fs.Usage()
		return 2
	}
	verb, rest := fs.Arg(0), fs.Args()[1:]
	switch verb {
	case "preflight":
		return runPreflight(rest, stdout, stderr)
	case "up":
		return runUp(rest, resolveStateDir(*stateFlag), stdout, stderr)
	case "run":
		return runRun(rest, resolveStateDir(*stateFlag), stdout, stderr)
	case "check":
		return runCheck(rest, resolveStateDir(*stateFlag), stdout, stderr)
	case "down":
		return runDown(rest, resolveStateDir(*stateFlag), stdout, stderr)
	default:
		_, _ = fmt.Fprintf(stderr, "nl6-ci: unknown verb %q\n", verb)
		fs.Usage()
		return 2
	}
}

func runPreflight(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("nl6-ci preflight", flag.ContinueOnError)
	fs.SetOutput(stderr)
	if err := fs.Parse(args); err != nil || strayArgs(fs, stderr) {
		return 2
	}
	findings := preflight(liveProbe())
	if len(findings) == 0 {
		_, _ = fmt.Fprintln(stdout, "preflight: ok")
		return 0
	}
	for _, f := range findings {
		_, _ = fmt.Fprintf(stderr, "preflight: FAIL %s: %s. Fix: %s\n", f.ID, f.Problem, f.Fix)
	}
	return 1
}

// strayArgs reports positional arguments left after the flags as a usage
// error. flag stops at the first one, so the flags after it would be lost.
func strayArgs(fs *flag.FlagSet, stderr io.Writer) bool {
	if fs.NArg() == 0 {
		return false
	}
	_, _ = fmt.Fprintf(stderr, "%s: unexpected argument %q\n", fs.Name(), fs.Arg(0))
	return true
}

// resolveStateDir picks -state, else $NL6_CI_STATE, else ./.nl6-ci.
func resolveStateDir(flagVal string) string {
	if flagVal != "" {
		return flagVal
	}
	if v := os.Getenv("NL6_CI_STATE"); v != "" {
		return v
	}
	return ".nl6-ci"
}

func runUp(args []string, dir string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("nl6-ci up", flag.ContinueOnError)
	fs.SetOutput(stderr)
	var o upOptions
	fs.StringVar(&o.Manifest, "manifest", "", "batch manifest file (required)")
	fs.IntVar(&o.Port, "port", 18080, "nl6 API port")
	fs.StringVar(&o.NL6, "nl6", "/usr/bin/nl6", "path to the nl6 binary")
	fs.StringVar(&o.Workdir, "workdir", "/usr/share/nl6", "directory holding resources/, web/ and worldcities/")
	fs.DurationVar(&o.CreateTimeout, "create-timeout", batchBudget, "budget for creating all devices")
	// Everything after the first "--" goes to nl6. flag would swallow the
	// "--" itself, so split before parsing to tell nl6 flags from strays.
	for i, a := range args {
		if a == "--" {
			args, o.Extra = args[:i], args[i+1:]
			break
		}
	}
	if err := fs.Parse(args); err != nil || strayArgs(fs, stderr) {
		return 2
	}
	if o.Manifest == "" {
		_, _ = fmt.Fprintln(stderr, "nl6-ci up: -manifest is required")
		return 2
	}
	if o.Port < 1 || o.Port > 65535 {
		_, _ = fmt.Fprintf(stderr, "nl6-ci up: -port must be between 1 and 65535 (got %d)\n", o.Port)
		return 2
	}
	if o.CreateTimeout <= 0 {
		_, _ = fmt.Fprintf(stderr, "nl6-ci up: -create-timeout must be above 0 (got %s)\n", o.CreateTimeout)
		return 2
	}
	if err := up(dir, o, liveEnv(stdout)); err != nil {
		_, _ = fmt.Fprintf(stderr, "nl6-ci up: %v\n", err)
		return 1
	}
	return 0
}

func runRun(args []string, dir string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("nl6-ci run", flag.ContinueOnError)
	fs.SetOutput(stderr)
	var o runOptions
	var window string
	fs.StringVar(&o.Protocol, "protocol", "", "push protocol, e.g. syslog (required)")
	fs.Float64Var(&o.Rate, "rate", 0, "per-device events per second (required)")
	fs.StringVar(&window, "window", "", "measurement window as a Go duration, e.g. 30s (required)")
	fs.Int64Var(&o.Seed, "seed", 0, "seed of the scenario's random draws")
	fs.StringVar(&o.Report, "report", "", "report path (default <state dir>/report.json)")
	fs.DurationVar(&o.Timeout, "request-timeout", requestTimeout, "budget of one API call: list, arm, start, status")
	if err := fs.Parse(args); err != nil || strayArgs(fs, stderr) {
		return 2
	}
	if o.Timeout <= 0 {
		_, _ = fmt.Fprintf(stderr, "nl6-ci run: -request-timeout must be above 0 (got %s)\n", o.Timeout)
		return 2
	}
	d, err := time.ParseDuration(window)
	// NaN fails every comparison, so "above 0" is written to refuse it too.
	if o.Protocol == "" || !(o.Rate > 0) || math.IsInf(o.Rate, 0) || window == "" || err != nil || d <= 0 {
		_, _ = fmt.Fprintln(stderr, "nl6-ci run: -protocol, -rate and a valid -window (e.g. 30s) are required")
		return 2
	}
	o.Window = d
	if err := run(dir, o, stdout); err != nil {
		_, _ = fmt.Fprintf(stderr, "nl6-ci run: %v\n", err)
		return 1
	}
	return 0
}

func runDown(args []string, dir string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("nl6-ci down", flag.ContinueOnError)
	fs.SetOutput(stderr)
	tail := fs.Bool("log-tail", false, "print the last lines of the nl6 log")
	if err := fs.Parse(args); err != nil || strayArgs(fs, stderr) {
		return 2
	}
	if *tail {
		if s, err := loadState(dir); err == nil {
			_, _ = fmt.Fprint(stdout, tailFile(s.Log, logTail))
		}
	}
	if err := down(dir, liveEnv(stdout)); err != nil {
		_, _ = fmt.Fprintf(stderr, "nl6-ci down: %v\n", err)
		return 1
	}
	return 0
}

func runCheck(args []string, dir string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("nl6-ci check", flag.ContinueOnError)
	fs.SetOutput(stderr)
	var o checkOptions
	fs.StringVar(&o.Received, "received", "", "received counts CSV: protocol,source_ip,collector,received (required)")
	fs.StringVar(&o.Report, "report", "", "report path (default <state dir>/report.json)")
	fs.Float64Var(&o.Tolerance, "tolerance", 0, "loss ratio allowed per device (0.01 = 1%)")
	if err := fs.Parse(args); err != nil || strayArgs(fs, stderr) {
		return 2
	}
	if o.Received == "" {
		_, _ = fmt.Fprintln(stderr, "nl6-ci check: -received is required")
		return 2
	}
	// NaN compares false against every loss ratio, so nl6-reconcile would call
	// any loss OK. An infinite tolerance does the same in plain sight.
	if !(o.Tolerance >= 0) || math.IsInf(o.Tolerance, 0) {
		_, _ = fmt.Fprintf(stderr, "nl6-ci check: -tolerance must be a number of 0 or above (got %g)\n", o.Tolerance)
		return 2
	}
	code, err := check(dir, o, stdout, stderr)
	if err != nil {
		_, _ = fmt.Fprintf(stderr, "nl6-ci check: %v\n", err)
		return 1
	}
	return code
}
