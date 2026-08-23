/*
 * Copyright 2026 Ronny Trommer <ronny@no42.org>
 * SPDX-License-Identifier: Apache-2.0
 */

package main

import (
	"encoding/json"
	"strings"
	"testing"
	"time"
)

// TestIntervalDisclosure covers the predicate for all three subsystems. It
// takes a field name, a provenance flag and two durations and nothing else,
// which is what lets this run without constructing a manager.
func TestIntervalDisclosure(t *testing.T) {
	cases := []struct {
		name      string
		field     string
		wasSet    bool
		requested time.Duration
		effective time.Duration
		wantWarn  bool
	}{
		// The reported bug: 24h accepted and echoed while the scheduler runs 10s.
		{"syslog diverges", "syslog.interval", true, 24 * time.Hour, 10 * time.Second, true},
		{"trap diverges", "traps.interval", true, time.Hour, 30 * time.Second, true},
		{"flow diverges", "flow.tick_interval", true, time.Minute, 5 * time.Second, true},

		// Not set: the caller made no claim about cadence, so there is nothing
		// to disclose. Crucially this is driven by PROVENANCE, not by the
		// duration — ApplyDefaults stamps a non-zero default over an omitted
		// field, so a value-based test would disclose against every caller who
		// set nothing at all.
		{"syslog not set", "syslog.interval", false, defaultSyslogInterval, 10 * time.Second, false},
		{"trap not set", "traps.interval", false, defaultTrapInterval, 30 * time.Second, false},
		{"flow not set", "flow.tick_interval", false, defaultFlowTickInterval, 5 * time.Second, false},

		// Set to a value that happens to match: STILL disclosed (decision D4).
		// The defect is that the field is inert, not that it disagrees, and
		// gating on divergence made an identical request warn or stay silent
		// depending on unrelated fleet configuration.
		{"syslog matches but is inert", "syslog.interval", true, 10 * time.Second, 10 * time.Second, true},
		{"trap matches but is inert", "traps.interval", true, 30 * time.Second, 30 * time.Second, true},
		{"flow matches but is inert", "flow.tick_interval", true, 5 * time.Second, 5 * time.Second, true},

		// A non-default simulator-wide setting is reported against the value
		// actually configured, not the package default.
		{"syslog vs non-default mean", "syslog.interval", true, 10 * time.Second, 30 * time.Second, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := intervalDisclosure(tc.field, tc.wasSet, tc.requested, tc.effective)
			if !tc.wantWarn {
				if got != nil {
					t.Fatalf("intervalDisclosure(%s, wasSet=%v, %s, %s) = %+v, want nil",
						tc.field, tc.wasSet, tc.requested, tc.effective, got)
				}
				return
			}
			if got == nil {
				t.Fatalf("intervalDisclosure(%s, wasSet=%v, %s, %s) = nil, want a warning",
					tc.field, tc.wasSet, tc.requested, tc.effective)
				return
			}
			if got.Field != tc.field {
				t.Errorf("Field = %q, want %q", got.Field, tc.field)
			}
			if got.Requested != tc.requested.String() {
				t.Errorf("Requested = %q, want %q", got.Requested, tc.requested.String())
			}
			if got.Effective != tc.effective.String() {
				t.Errorf("Effective = %q, want %q", got.Effective, tc.effective.String())
			}
			if !strings.Contains(got.Message, tc.field) {
				t.Errorf("Message %q does not name the field", got.Message)
			}
			if !strings.Contains(strings.ToLower(got.Message), "not honored") {
				t.Errorf("Message %q does not say the field is not honored", got.Message)
			}
		})
	}
}

// TestIntervalDisclosure_ProvenanceNotValue is the regression guard for the
// root cause behind several review findings.
//
// `ApplyDefaults` stamps the package default over an omitted interval, so any
// predicate keyed on "is the duration non-zero" discloses against callers who
// configured nothing. The identical duration must produce a warning or not
// depending ONLY on whether the caller supplied it.
func TestIntervalDisclosure_ProvenanceNotValue(t *testing.T) {
	const d = 10 * time.Second

	if got := intervalDisclosure("syslog.interval", false, d, 60*time.Second); got != nil {
		t.Errorf("defaulted value disclosed: %+v — this is the false positive that logged "+
			"\"configured interval=10s\" about callers who set nothing", got)
	}
	if got := intervalDisclosure("syslog.interval", true, d, 60*time.Second); got == nil {
		t.Error("explicitly requested value not disclosed")
	}
}

// TestIntervalDisclosure_DistinctPhrasing pins decision R2-D3.
//
// D4 made requested == effective the COMMON case. One message form cannot
// serve both: naming the same duration twice ("=30s ... fires at 30s") reads as
// a simulator bug rather than a disclosure.
func TestIntervalDisclosure_DistinctPhrasing(t *testing.T) {
	matching := intervalDisclosure("traps.interval", true, 30*time.Second, 30*time.Second)
	diverging := intervalDisclosure("traps.interval", true, time.Hour, 30*time.Second)
	if matching == nil || diverging == nil {
		t.Fatal("both cases must disclose")
		return
	}
	if matching.Message == diverging.Message {
		t.Fatal("matching and diverging cases share one message; the matching case needs its own wording")
	}
	if !strings.Contains(matching.Message, "unchanged") {
		t.Errorf("matching-case message should say emission is unchanged, got %q", matching.Message)
	}
	// The remediation hint belongs on the case where the operator is trying to
	// change the cadence, which is the diverging one.
	if !strings.Contains(diverging.Message, "-fidelity") {
		t.Errorf("diverging-case message should point at -fidelity, got %q", diverging.Message)
	}
}

// TestMarkIntervalProvenance covers the capture that must happen on the RAW
// request, and its nil-safety (the seed blocks are frequently nil).
func TestMarkIntervalProvenance(t *testing.T) {
	set := &DeviceSyslogConfig{Collector: "x:514", Interval: jsonDuration(24 * time.Hour)}
	set.markIntervalProvenance()
	if !set.IntervalWasSet() {
		t.Error("explicit interval not marked as set")
	}

	omitted := &DeviceSyslogConfig{Collector: "x:514"}
	omitted.markIntervalProvenance()
	omitted.ApplyDefaults() // stamps 10s over the zero
	if omitted.IntervalWasSet() {
		t.Error("omitted interval marked as set; ApplyDefaults must not be able to change provenance")
	}
	if time.Duration(omitted.Interval) != defaultSyslogInterval {
		t.Errorf("ApplyDefaults did not stamp the default: %s", time.Duration(omitted.Interval))
	}

	// Nil receivers: the create handler calls these unconditionally.
	var nilSyslog *DeviceSyslogConfig
	var nilTrap *DeviceTrapConfig
	var nilFlow *DeviceFlowConfig
	nilSyslog.markIntervalProvenance()
	nilTrap.markIntervalProvenance()
	nilFlow.markIntervalProvenance()
	if nilSyslog.IntervalWasSet() || nilTrap.IntervalWasSet() || nilFlow.TickIntervalWasSet() {
		t.Error("nil config reported a set interval")
	}
}

// TestProvenanceDoesNotSerialize keeps the marker off the wire in both
// directions. It is internal provenance, not client-visible state, and a
// serialized marker would be one more field breaking the POST round trip.
func TestProvenanceDoesNotSerialize(t *testing.T) {
	cfg := &DeviceSyslogConfig{Collector: "x:514", Interval: jsonDuration(time.Hour)}
	cfg.markIntervalProvenance()
	raw, err := json.Marshal(cfg)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	for _, forbidden := range []string{"intervalSet", "interval_set", "IntervalWasSet"} {
		if strings.Contains(string(raw), forbidden) {
			t.Errorf("provenance marker leaked to the wire (%q): %s", forbidden, raw)
		}
	}
}

// TestEffectiveIntervals_OnlyForParticipatingSubsystems keeps the block
// truthful: a device that does not export syslog must not be told what the
// syslog cadence is.
func TestEffectiveIntervals_OnlyForParticipatingSubsystems(t *testing.T) {

	if got := buildEffectiveIntervals2(&DeviceSimulator{}); got != nil {
		t.Errorf("device with no export config produced %+v, want nil so omitempty drops it", got)
	}
	if got := buildEffectiveIntervals2(nil); got != nil {
		t.Errorf("nil device produced %+v, want nil", got)
	}

	only := buildEffectiveIntervals2(&DeviceSimulator{
		syslogConfig: &DeviceSyslogConfig{Collector: "x:514"},
	})
	if only == nil {
		t.Fatal("syslog-only device produced no block")
		return
	}
	if only.SyslogInterval == "" {
		t.Error("syslog_interval missing for a syslog-exporting device")
	}
	if only.TrapInterval != "" || only.FlowTickInterval != "" {
		t.Errorf("reported cadences for subsystems the device does not use: %+v", only)
	}
}

// TestEffectiveIntervals_WireShape asserts the block sits BESIDE the config
// blocks and leaves them untouched.
//
// This is the property that keeps `GET` output POST-able, which is what
// scripts/fleet.sh import depends on. Nesting the effective values inside the
// config blocks broke it (decision R2-D1).
func TestEffectiveIntervals_WireShape(t *testing.T) {
	dev := &DeviceSimulator{syslogConfig: &DeviceSyslogConfig{
		Collector: "192.0.2.144:1514", Format: "5424", Interval: jsonDuration(24 * time.Hour),
	}}
	info := DeviceInfo{
		ID: "d", IP: "10.42.0.1",
		Syslog:             dev.syslogConfig,
		EffectiveIntervals: buildEffectiveIntervals2(dev),
	}
	raw, err := json.Marshal(info)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	var got struct {
		Syslog map[string]any `json:"syslog"`
		Eff    struct {
			SyslogInterval string `json:"syslog_interval"`
		} `json:"effective_intervals"`
	}
	if err := json.Unmarshal(raw, &got); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}

	if got.Syslog["interval"] != "24h0m0s" {
		t.Errorf("syslog.interval = %v, want the requested 24h0m0s", got.Syslog["interval"])
	}
	// The config block must contain ONLY POST-able fields. Any read-only
	// addition here is what broke fleet.sh import.
	for k := range got.Syslog {
		switch k {
		case "collector", "format", "interval":
		default:
			t.Errorf("syslog block carries unexpected field %q; GET blocks must stay valid POST bodies", k)
		}
	}
	if got.Eff.SyslogInterval != defaultSyslogInterval.String() {
		t.Errorf("effective_intervals.syslog_interval = %q, want %s",
			got.Eff.SyslogInterval, defaultSyslogInterval)
	}
}

// TestEffectiveIntervals_FallbackWhenSubsystemDown pins the accessors when no
// scheduler is running — never started, or already stopped during shutdown.
// The value must be a defined duration rather than a zero rendering as "0s".
func TestEffectiveIntervals_FallbackWhenSubsystemDown(t *testing.T) {
	sm := &SimulatorManager{}

	if got := sm.effectiveSyslogInterval(); got != defaultSyslogInterval {
		t.Errorf("effectiveSyslogInterval() = %s, want %s", got, defaultSyslogInterval)
	}
	if got := sm.effectiveTrapInterval(); got != defaultTrapInterval {
		t.Errorf("effectiveTrapInterval() = %s, want %s", got, defaultTrapInterval)
	}
	if got := sm.effectiveFlowTickInterval(); got != defaultFlowTickInterval {
		t.Errorf("effectiveFlowTickInterval() = %s, want %s", got, defaultFlowTickInterval)
	}
}

// TestEffectiveFlowTickInterval_LatchedPeriodWins is the regression guard for
// the reporting lie this change nearly shipped.
//
// startFlowTicker latches its period in the constructor; SetFlowTickInterval is
// called afterwards by the flag path and only writes the field, never
// restarting the ticker. Reporting the field would state a cadence nothing runs
// at, so the LATCHED value must win. (That the two disagree at all is nl6#446.)
func TestEffectiveFlowTickInterval_LatchedPeriodWins(t *testing.T) {
	sm := &SimulatorManager{}
	sm.flowTickerPeriod.Store(int64(5 * time.Second)) // what the ticker latched
	sm.SetFlowTickInterval(30 * time.Second)          // what the flag asked for, too late

	if got := sm.effectiveFlowTickInterval(); got != 5*time.Second {
		t.Errorf("effectiveFlowTickInterval() = %s, want the LATCHED 5s; "+
			"reporting the field would claim a cadence nothing runs at", got)
	}
}

// TestEffectiveFlowTickInterval_NoTickerIgnoresTheField pins a deliberate
// non-fallback: the unsynchronised field must not be read from HTTP goroutines.
func TestEffectiveFlowTickInterval_NoTickerIgnoresTheField(t *testing.T) {
	sm := &SimulatorManager{}
	sm.SetFlowTickInterval(45 * time.Second)

	if got := sm.effectiveFlowTickInterval(); got != defaultFlowTickInterval {
		t.Errorf("effectiveFlowTickInterval() = %s, want the package default %s", got, defaultFlowTickInterval)
	}
}

// buildEffectiveIntervals2 is a test shim resolving the snapshot per call, so
// tests read naturally. Production hoists the snapshot out of the device loop.
func buildEffectiveIntervals2(dev *DeviceSimulator) *effectiveIntervals {
	sm := &SimulatorManager{}
	return buildEffectiveIntervals(dev, sm.snapshotEffectiveIntervals())
}

// TestEchoConfig_HidesDefaultedInterval pins decision R2-D1(b).
//
// ListDevices echoes the stored config, which ApplyDefaults has already stamped.
// Echoing a defaulted interval attributes a choice to an operator who made
// none, and — because `scripts/fleet.sh import` re-POSTs the echoed block — it
// makes the round trip warn about a value the simulator itself invented.
func TestEchoConfig_HidesDefaultedInterval(t *testing.T) {
	defaulted := &DeviceSyslogConfig{Collector: "x:514"}
	defaulted.markIntervalProvenance()
	defaulted.ApplyDefaults() // stamps 10s

	echo := echoSyslogConfig(defaulted)
	if time.Duration(echo.Interval) != 0 {
		t.Errorf("echo carries a defaulted interval %s; it must be omitted", time.Duration(echo.Interval))
	}
	// The stored config must be untouched — the echo is a copy, not a mutation.
	if time.Duration(defaulted.Interval) != defaultSyslogInterval {
		t.Errorf("stored config mutated by being echoed: %s", time.Duration(defaulted.Interval))
	}

	// A round trip of the echo must stay silent.
	raw, err := json.Marshal(echo)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	if strings.Contains(string(raw), "interval") {
		t.Errorf("echo still serializes an interval key: %s", raw)
	}
	var reposted DeviceSyslogConfig
	if err := json.Unmarshal(raw, &reposted); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	reposted.markIntervalProvenance()
	if reposted.IntervalWasSet() {
		t.Error("re-POSTing an unchanged echo marks the interval as set; " +
			"fleet.sh import would warn once per device for a value nobody chose")
	}
}

// TestEchoConfig_PreservesExplicitInterval keeps operator intent visible, and
// avoids allocating when nothing needs hiding.
func TestEchoConfig_PreservesExplicitInterval(t *testing.T) {
	explicit := &DeviceSyslogConfig{Collector: "x:514", Interval: jsonDuration(24 * time.Hour)}
	explicit.markIntervalProvenance()
	explicit.ApplyDefaults()

	echo := echoSyslogConfig(explicit)
	if time.Duration(echo.Interval) != 24*time.Hour {
		t.Errorf("echo dropped an explicitly requested interval: %s", time.Duration(echo.Interval))
	}
	if echo != explicit {
		t.Error("echo copied when nothing needed hiding; the common path should not allocate")
	}
}

// TestEffectiveIntervals_CarriesNoPerDeviceNote guards the response-size
// regression. A 175-character caveat per device is ~7 MB of identical
// boilerplate on a 30k fleet, in the response the console loads unpaginated.
func TestEffectiveIntervals_CarriesNoPerDeviceNote(t *testing.T) {
	raw, err := json.Marshal(buildEffectiveIntervals2(&DeviceSimulator{
		syslogConfig: &DeviceSyslogConfig{Collector: "x:514"},
	}))
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	if strings.Contains(string(raw), "note") {
		t.Errorf("per-device block carries an explanatory note: %s", raw)
	}
	if len(raw) > 64 {
		t.Errorf("per-device block is %d bytes; it is replicated once per device", len(raw))
	}
}

// TestEcho_AllThreeCreationPaths pins the property task 7c.2 asked for, across
// every way a device can come into existence.
//
// The original report was that a read-back showed a defaulted interval as
// though the operator had chosen it. Provenance plus the echo helpers resolve
// it, and the CLI seed path resolves correctly by construction rather than by
// explicit handling — which is worth a test, because it is exactly the kind of
// accidental correctness that a later refactor breaks silently.
func TestEcho_AllThreeCreationPaths(t *testing.T) {
	const flagInterval = 60 * time.Second

	t.Run("REST with an explicit interval is echoed", func(t *testing.T) {
		c := &DeviceSyslogConfig{Collector: "x:514", Interval: jsonDuration(24 * time.Hour)}
		c.markIntervalProvenance() // handler does this on the raw body
		c.ApplyDefaults()
		if got := time.Duration(echoSyslogConfig(c).Interval); got != 24*time.Hour {
			t.Errorf("interval = %s, want the requested 24h; operator intent must survive", got)
		}
	})

	t.Run("REST without an interval echoes nothing", func(t *testing.T) {
		c := &DeviceSyslogConfig{Collector: "x:514"}
		c.markIntervalProvenance()
		c.ApplyDefaults() // stamps the package default
		if got := time.Duration(echoSyslogConfig(c).Interval); got != 0 {
			t.Errorf("interval = %s, want omitted; the caller chose nothing", got)
		}
	})

	t.Run("CLI seed echoes nothing", func(t *testing.T) {
		// simulator.go builds this from -syslog-collector / -syslog-interval and
		// never calls markIntervalProvenance: the flag is a fleet-wide setting,
		// not a per-device choice, so it must not read back as one. Correct
		// today only because the zero value is false — hence this test.
		c := &DeviceSyslogConfig{Collector: "x:514", Interval: jsonDuration(flagInterval)}
		c.ApplyDefaults()
		if c.IntervalWasSet() {
			t.Fatal("seed path marked provenance; a fleet flag is not a per-device choice")
		}
		if got := time.Duration(echoSyslogConfig(c).Interval); got != 0 {
			t.Errorf("interval = %s, want omitted for a flag-derived value", got)
		}
	})
}
