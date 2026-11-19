/*
 * Copyright 2026 Ronny Trommer <ronny@no42.org>
 * SPDX-License-Identifier: Apache-2.0
 */

package main

import (
	"bytes"
	"strings"
	"testing"
)

func TestRunDispatch(t *testing.T) {
	for _, tc := range []struct {
		name string
		args []string
		want int
	}{
		{"no verb", nil, 2},
		{"unknown verb", []string{"frobnicate"}, 2},
		{"version", []string{"-version"}, 0},
		{"up without manifest", []string{"up"}, 2},
		{"run without flags", []string{"run"}, 2},
		{"run bad window", []string{"run", "-protocol", "syslog", "-rate", "5", "-window", "soon"}, 2},
		{"down with nothing", []string{"-state", t.TempDir(), "down"}, 0},
		{"preflight with a stray argument", []string{"preflight", "now"}, 2},
		{"run with a stray argument", []string{"run", "-protocol", "syslog", "-rate", "5", "-window", "10s", "report.json", "-seed", "1"}, 2},
		{"check with a stray argument", []string{"check", "-received", "r.csv", "extra"}, 2},
		{"down with a stray argument", []string{"-state", t.TempDir(), "down", "-log-tail", "now"}, 2},
		{"up with a stray argument", []string{"up", "-manifest", "/nonexistent/m.json", "-netconf-enable"}, 2},
		{"up with stray arguments before --", []string{"up", "-manifest", "/nonexistent/m.json", "x", "--", "-y"}, 2},
		// Past the usage checks: up reads the missing manifest and exits 1.
		{"up with nl6 flags after --", []string{"up", "-manifest", "/nonexistent/m.json", "--", "-netconf-enable"}, 1},
		{"up with port 0", []string{"up", "-manifest", "/nonexistent/m.json", "-port", "0"}, 2},
		{"up with a port above 65535", []string{"up", "-manifest", "/nonexistent/m.json", "-port", "65536"}, 2},
		{"up with a create timeout of 0", []string{"up", "-manifest", "/nonexistent/m.json", "-create-timeout", "0"}, 2},
		{"run with a request timeout of 0", []string{"-state", t.TempDir(), "run", "-protocol", "syslog", "-rate", "5", "-window", "10s", "-request-timeout", "0s"}, 2},
		{"run with rate NaN", []string{"-state", t.TempDir(), "run", "-protocol", "syslog", "-rate", "NaN", "-window", "10s"}, 2},
		{"run with rate Inf", []string{"-state", t.TempDir(), "run", "-protocol", "syslog", "-rate", "Inf", "-window", "10s"}, 2},
	} {
		var out, errb bytes.Buffer
		if got := runCLI(tc.args, &out, &errb); got != tc.want {
			t.Errorf("%s: exit %d, want %d (stderr %q)", tc.name, got, tc.want, errb.String())
		}
	}
}

// A NaN tolerance compares false against every loss ratio, so nl6-reconcile
// would call any loss OK. check refuses it before it reads the report.
func TestCheckRejectsABadTolerance(t *testing.T) {
	for _, v := range []string{"NaN", "Inf", "-0.1"} {
		var out, errb bytes.Buffer
		got := runCLI([]string{"-state", t.TempDir(), "check", "-received", "r.csv", "-tolerance", v}, &out, &errb)
		if got != 2 || !strings.Contains(errb.String(), "-tolerance") {
			t.Errorf("-tolerance %s: exit %d, stderr %q, want exit 2 naming -tolerance", v, got, errb.String())
		}
	}
}
