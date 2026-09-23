/*
 * Copyright 2026 Ronny Trommer <ronny@no42.org>
 * SPDX-License-Identifier: Apache-2.0
 */

package main

import (
	"bytes"
	"flag"
	"strings"
	"testing"
	"time"
)

// newFlowDurationFlagSet registers the four flow duration flags exactly as
// main does, on a private FlagSet so the tests never touch flag.CommandLine.
// Going through registerFlowDurationFlags is what keeps these tests from
// pinning a hand-written mirror of the registration.
func newFlowDurationFlagSet() (*flag.FlagSet, *flowDurationFlags) {
	fs := flag.NewFlagSet("nl6-test", flag.ContinueOnError)
	fs.SetOutput(&bytes.Buffer{})
	return fs, registerFlowDurationFlags(fs)
}

func TestSecondsOrDuration_AcceptsBothForms(t *testing.T) {
	for _, tc := range []struct {
		in   string
		want time.Duration
	}{
		{"30", 30 * time.Second},
		{"30s", 30 * time.Second},
		{"60", time.Minute},
		{"1m", time.Minute},
		{"500ms", 500 * time.Millisecond},
		{"1m30s", 90 * time.Second},
		{"1.5s", 1500 * time.Millisecond},
		{"1", time.Second},
	} {
		var v secondsOrDuration
		if err := v.Set(tc.in); err != nil {
			t.Errorf("Set(%q): %v", tc.in, err)
			continue
		}
		if v.Duration() != tc.want {
			t.Errorf("Set(%q) = %s, want %s", tc.in, v.Duration(), tc.want)
		}
	}
}

func TestSecondsOrDuration_RefusesMalformedAndNonPositive(t *testing.T) {
	for _, in := range []string{"30x", "-5", "0", "-1s", "0s", "1.5", "", "s", "5 s", "20000000000", "10000000000"} {
		v := secondsOrDuration(30 * time.Second)
		err := v.Set(in)
		if err == nil {
			t.Errorf("Set(%q) accepted as %s; want refusal", in, v.Duration())
			continue
		}
		msg := err.Error()
		if !strings.Contains(msg, "seconds") || !strings.Contains(msg, "duration") {
			t.Errorf("Set(%q) error %q does not name both accepted forms", in, msg)
		}
		if v.Duration() != 30*time.Second {
			t.Errorf("Set(%q) moved the value to %s on refusal", in, v.Duration())
		}
	}
}

func TestSecondsOrDuration_StringIsDurationForm(t *testing.T) {
	for _, tc := range []struct {
		d    time.Duration
		want string
	}{
		{5 * time.Second, "5s"},
		{30 * time.Second, "30s"},
		{15 * time.Second, "15s"},
		{60 * time.Second, "1m0s"},
	} {
		v := secondsOrDuration(tc.d)
		if got := v.String(); got != tc.want {
			t.Errorf("String(%s) = %q, want %q", tc.d, got, tc.want)
		}
	}
}

func TestFlowDurationFlags_BareAndDurationFormsAgree(t *testing.T) {
	fsInt, bare := newFlowDurationFlagSet()
	if err := fsInt.Parse([]string{"-flow-tick-interval", "5", "-flow-active-timeout", "30",
		"-flow-inactive-timeout", "15", "-flow-template-interval", "60"}); err != nil {
		t.Fatalf("bare-integer form: %v", err)
	}
	fsDur, dur := newFlowDurationFlagSet()
	if err := fsDur.Parse([]string{"-flow-tick-interval", "5s", "-flow-active-timeout", "30s",
		"-flow-inactive-timeout", "15s", "-flow-template-interval", "1m"}); err != nil {
		t.Fatalf("duration form: %v", err)
	}
	fsDef, def := newFlowDurationFlagSet()
	if err := fsDef.Parse(nil); err != nil {
		t.Fatalf("defaults: %v", err)
	}
	for _, tc := range []struct {
		name          string
		got, dur, def time.Duration
		want          time.Duration
	}{
		{"tick", bare.Tick.Duration(), dur.Tick.Duration(), def.Tick.Duration(), 5 * time.Second},
		{"active", bare.Active.Duration(), dur.Active.Duration(), def.Active.Duration(), 30 * time.Second},
		{"inactive", bare.Inactive.Duration(), dur.Inactive.Duration(), def.Inactive.Duration(), 15 * time.Second},
		{"template", bare.Template.Duration(), dur.Template.Duration(), def.Template.Duration(), 60 * time.Second},
	} {
		if tc.got != tc.want || tc.dur != tc.want || tc.def != tc.want {
			t.Errorf("%s: bare=%s duration=%s default=%s, want all %s", tc.name, tc.got, tc.dur, tc.def, tc.want)
		}
	}
}

func TestFlowDurationFlags_ParseErrorNamesFlagAndForms(t *testing.T) {
	for _, args := range [][]string{
		{"-flow-active-timeout", "30x"},
		{"-flow-active-timeout", "-5"},
		{"-flow-tick-interval", "0"},
		{"-flow-template-interval", "-1s"},
		{"-flow-inactive-timeout", "1.5"},
	} {
		fs, _ := newFlowDurationFlagSet()
		err := fs.Parse(args)
		if err == nil {
			t.Errorf("Parse(%q) accepted; want refusal", args)
			continue
		}
		msg := err.Error()
		if !strings.Contains(msg, args[0]) {
			t.Errorf("Parse(%q) error %q does not name the flag", args, msg)
		}
		if !strings.Contains(msg, "seconds") || !strings.Contains(msg, "duration") {
			t.Errorf("Parse(%q) error %q does not name both accepted forms", args, msg)
		}
	}
}

func TestFlowDurationFlags_HelpShowsDurationDefaultsAndBothForms(t *testing.T) {
	fs, _ := newFlowDurationFlagSet()
	var out bytes.Buffer
	fs.SetOutput(&out)
	fs.PrintDefaults()
	help := out.String()
	for _, tc := range []struct{ flag, def string }{
		{"-flow-tick-interval", "(default 5s)"},
		{"-flow-active-timeout", "(default 30s)"},
		{"-flow-inactive-timeout", "(default 15s)"},
		{"-flow-template-interval", "(default 1m0s)"},
	} {
		i := strings.Index(help, tc.flag)
		if i < 0 {
			t.Errorf("%s missing from help", tc.flag)
			continue
		}
		rest := help[i:]
		if j := strings.Index(rest[1:], "\n  -"); j >= 0 {
			rest = rest[:j+1]
		}
		if !strings.Contains(rest, tc.def) {
			t.Errorf("%s help does not show %q:\n%s", tc.flag, tc.def, rest)
		}
		if !strings.Contains(rest, "seconds") || !strings.Contains(rest, "duration") {
			t.Errorf("%s help does not state both forms:\n%s", tc.flag, rest)
		}
	}
}

// TestFlowDurationFlags_FeedTheRealConsumers drives the three consumers main
// hands the parsed values to (WithFlowTickInterval, SetFlowTemplateInterval
// and the jsonDuration fields of the seed DeviceFlowConfig) from the
// bare-integer command line and asserts the values the old
// time.Duration(n)*time.Second conversion produced.
func TestFlowDurationFlags_FeedTheRealConsumers(t *testing.T) {
	fs, f := newFlowDurationFlagSet()
	if err := fs.Parse([]string{"-flow-tick-interval", "5", "-flow-active-timeout", "30",
		"-flow-inactive-timeout", "15", "-flow-template-interval", "60"}); err != nil {
		t.Fatal(err)
	}
	sm := NewSimulatorManagerWithOptions(false, WithFlowTickInterval(f.Tick.Duration()))
	sm.SetFlowTemplateInterval(f.Template.Duration())
	if sm.flowTickInterval != 5*time.Second || sm.flowTemplateInterval != 60*time.Second {
		t.Errorf("manager got tick=%s template=%s", sm.flowTickInterval, sm.flowTemplateInterval)
	}
	seed := DeviceFlowConfig{
		TickInterval:    jsonDuration(f.Tick.Duration()),
		ActiveTimeout:   jsonDuration(f.Active.Duration()),
		InactiveTimeout: jsonDuration(f.Inactive.Duration()),
	}
	want := DeviceFlowConfig{
		TickInterval:    jsonDuration(5 * time.Second),
		ActiveTimeout:   jsonDuration(30 * time.Second),
		InactiveTimeout: jsonDuration(15 * time.Second),
	}
	if seed != want {
		t.Errorf("seed = %+v, want %+v", seed, want)
	}
}
