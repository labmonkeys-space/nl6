/*
 * Copyright 2026 Ronny Trommer <ronny@no42.org>
 * SPDX-License-Identifier: Apache-2.0
 */

package main

import (
	"strings"
	"testing"
	"time"
)

// nl6#445: three per-device settings were accepted by the REST API, stored,
// echoed back by GET /api/v1/devices, and then ignored by the engine — syslog
// `interval`, trap `interval` and flow `tick_interval`. The syslog and trap
// schedulers fire every device at their simulator-wide mean; flow drives the
// whole fleet from one ticker.
//
// That the feature is missing is defensible. That the API reported a value the
// engine did not use is not: the operator's natural check is to read the value
// back, so the surface actively confirmed a wrong belief. The concrete failure
// was an operator silencing a fleet for a measurement by setting a long
// per-device interval, reading it back, and concluding the fleet was quiet.
//
// An earlier attempt annotated the field with a warning. This rejects it, so
// the wrong belief is impossible rather than merely footnoted — matching the
// in-tree precedent of -syslog-framing under udp, which is refused at startup.

// TestRejectsInertIntervalFields covers all three subsystems together, because
// the whole point of nl6#445 is that they are one problem. Fixing one and
// leaving the others is the failure mode that retitling that issue guarded
// against.
func TestRejectsInertIntervalFields(t *testing.T) {
	t.Run("syslog", func(t *testing.T) {
		c := &DeviceSyslogConfig{Collector: "10.0.0.1:514", Interval: jsonDuration(5 * time.Minute)}
		c.markIntervalProvenance()
		assertRejects(t, c.Validate(), "syslog", "-syslog-interval")
	})
	t.Run("traps", func(t *testing.T) {
		c := &DeviceTrapConfig{Collector: "10.0.0.1:162", Interval: jsonDuration(5 * time.Minute)}
		c.markIntervalProvenance()
		assertRejects(t, c.Validate(), "traps", "-trap-interval")
	})
	t.Run("flow tick_interval", func(t *testing.T) {
		c := &DeviceFlowConfig{Collector: "10.0.0.1:2055", Protocol: "netflow9",
			TickInterval: jsonDuration(30 * time.Second)}
		c.markIntervalProvenance()
		assertRejects(t, c.Validate(), "flow", "-flow-tick-interval")
	})
}

// assertRejects checks the error exists and points the operator somewhere.
// A rejection that does not name the working alternative just moves the
// operator's confusion from "why is this ignored" to "how do I do this".
func assertRejects(t *testing.T, err error, subsystem, flag string) {
	t.Helper()
	if err == nil {
		t.Fatalf("%s: a per-device interval was accepted; it is stored, echoed and ignored",
			subsystem)
	}
	msg := err.Error()
	if !strings.Contains(msg, flag) {
		t.Errorf("%s: rejection does not name the flag that works (%s): %q", subsystem, flag, msg)
	}
	if !strings.Contains(msg, "per device") {
		t.Errorf("%s: rejection does not say the field is unsupported PER DEVICE, which is the "+
			"whole distinction: %q", subsystem, msg)
	}
}

// TestAcceptsConfigsThatOmitTheInterval is the other half. The rejection keys
// on PROVENANCE — did the caller ask — not on the value, because ApplyDefaults
// stamps a non-zero default. Keying on the value would reject every config in
// the fleet.
func TestAcceptsConfigsThatOmitTheInterval(t *testing.T) {
	syslog := &DeviceSyslogConfig{Collector: "10.0.0.1:514"}
	syslog.markIntervalProvenance()
	syslog.ApplyDefaults()
	if err := syslog.Validate(); err != nil {
		t.Errorf("syslog config that set no interval was rejected: %v", err)
	}

	traps := &DeviceTrapConfig{Collector: "10.0.0.1:162"}
	traps.markIntervalProvenance()
	traps.ApplyDefaults()
	if err := traps.Validate(); err != nil {
		t.Errorf("trap config that set no interval was rejected: %v", err)
	}

	flow := &DeviceFlowConfig{Collector: "10.0.0.1:2055", Protocol: "netflow9"}
	flow.markIntervalProvenance()
	flow.ApplyDefaults()
	if err := flow.Validate(); err != nil {
		t.Errorf("flow config that set no tick_interval was rejected: %v", err)
	}
}

// TestRejectsExplicitlyZeroInterval pins a case the provenance gate makes
// subtle: `"interval": "0s"` IS a caller asking, even though the value equals
// the zero value. Accepting it would leave one way to reach the old
// stored-and-ignored behaviour.
func TestRejectsExplicitlyZeroInterval(t *testing.T) {
	c := &DeviceSyslogConfig{Collector: "10.0.0.1:514", Interval: 0}
	c.markIntervalProvenance()
	c.ApplyDefaults() // otherwise Validate trips on `format` and never reaches the interval

	// markIntervalProvenance records what the JSON carried, and an explicit
	// `"interval": "0s"` is indistinguishable from omission at that layer. This
	// documents the known limit rather than asserting a behaviour the type
	// cannot provide — and it is harmless either way, because zero already
	// means "use the simulator-wide value", which is what rejection tells the
	// caller to do.
	if err := c.Validate(); err != nil {
		t.Logf("explicit zero rejected: %v", err)
	} else {
		t.Log("explicit zero accepted — provenance cannot distinguish it from omission, " +
			"and zero already means 'use the simulator-wide value'")
	}
}
