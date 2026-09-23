/*
 * Copyright 2026 Ronny Trommer <ronny@no42.org>
 * SPDX-License-Identifier: Apache-2.0
 */

package main

import (
	"errors"
	"flag"
	"math"
	"strconv"
	"time"
)

// secondsOrDuration is a flag.Value that accepts a bare integer (seconds,
// the historical form of the -flow-* interval flags) or a Go duration string
// (30s, 2m, 500ms), so a value copied from the REST flow block works on the
// command line and vice versa (nl6#723).
//
// The two parsers cannot disagree on an accepted value: the only unit-less
// string time.ParseDuration accepts is "0", and the non-positive guard below
// refuses it in either order (measured by mutation: swapping the branches
// fails no test). Integer-first merely states the historical form first.
// Non-positive values are refused HERE rather than downstream:
// WithFlowTickInterval and SetFlowTemplateInterval used to swallow 0 into the
// default silently, which is the accepted-and-ignored shape nl6#445 removed
// elsewhere.
type secondsOrDuration time.Duration

var errSecondsOrDuration = errors.New("want seconds (e.g. 30) or a duration (e.g. 30s, 2m), greater than zero")

// Set implements flag.Value. On error the receiver is left unchanged.
func (v *secondsOrDuration) Set(s string) error {
	var d time.Duration
	if n, err := strconv.Atoi(s); err == nil {
		// Guard the multiply: above ~9.2e9 seconds it wraps, and some wraps
		// land positive and would pass the sign check below.
		if n > int(math.MaxInt64/int64(time.Second)) {
			return errSecondsOrDuration
		}
		d = time.Duration(n) * time.Second
	} else if pd, err := time.ParseDuration(s); err == nil {
		d = pd
	} else {
		return errSecondsOrDuration
	}
	if d <= 0 {
		return errSecondsOrDuration
	}
	*v = secondsOrDuration(d)
	return nil
}

// String implements flag.Value. The flag package captures it at registration
// as the printed default, so -help shows 30s rather than 30.
func (v *secondsOrDuration) String() string { return time.Duration(*v).String() }

// Duration returns the parsed value.
func (v *secondsOrDuration) Duration() time.Duration { return time.Duration(*v) }

// flowDurationFlags holds the four time-valued flow flags.
type flowDurationFlags struct {
	Tick, Active, Inactive, Template secondsOrDuration
}

// registerFlowDurationFlags declares the four flags on fs with their defaults.
// main calls it on flag.CommandLine; tests call it on a private FlagSet, so a
// test cannot pass against a copy of the registration that drifted from the
// one the binary uses.
func registerFlowDurationFlags(fs *flag.FlagSet) *flowDurationFlags {
	// The backquoted `seconds|duration` is what flag.UnquoteUsage prints as
	// the argument name in -help, in place of the generic "value".
	const forms = "as `seconds|duration`: a bare number is seconds (30 = 30 seconds); a duration string is also accepted (30s, 2m)."
	f := &flowDurationFlags{
		Tick:     secondsOrDuration(5 * time.Second),
		Active:   secondsOrDuration(30 * time.Second),
		Inactive: secondsOrDuration(15 * time.Second),
		Template: secondsOrDuration(60 * time.Second),
	}
	fs.Var(&f.Active, "flow-active-timeout", "Active flow timeout, "+forms)
	fs.Var(&f.Inactive, "flow-inactive-timeout", "Inactive flow timeout, "+forms)
	fs.Var(&f.Template, "flow-template-interval", "Template retransmission interval, "+forms)
	fs.Var(&f.Tick, "flow-tick-interval", "Flow ticker interval, "+forms)
	return f
}
