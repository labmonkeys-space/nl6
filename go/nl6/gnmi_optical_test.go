/*
 * Copyright 2026 Ronny Trommer <ronny@no42.org>
 * SPDX-License-Identifier: Apache-2.0
 */

package main

import (
	"context"
	"net"
	"strings"
	"testing"
	"time"

	gnmipb "github.com/openconfig/gnmi/proto/gnmi"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// gnmi_optical_test.go — the `/components` resolver branch (#331). The
// surface under test is the pinned OpenConfig one: every path lives under
// `/components/component[name=$och]/optical-channel/`, statistics leaves
// carry {instant,avg,min,max}, and `fec-uncorrectable-blocks` is a bare
// counter with no statistics container.

// newTestOpticalDevice builds an optical DeviceSimulator with the
// two-channel inventory and a published optical engine. withIfCounters
// controls whether the INTERFACE engine is also initialised — false is the
// interesting case, because it is what a resolver bug conflating the two
// engines gets wrong.
func newTestOpticalDevice(t *testing.T, withIfCounters bool) *DeviceSimulator {
	t.Helper()
	mc := &MetricsCycler{}
	if withIfCounters {
		mc.InitIfCounters(buildTestResources(t, []uint64{1_000_000_000}), 1)
	}
	mc.InitOpticalCycler(twoChannelInventory(), 7, opticalBandFor(OpticalTypical))
	if mc.OpticalCyclerOf() == nil {
		t.Fatal("InitOpticalCycler published no engine")
	}
	return &DeviceSimulator{
		ID:            "optical",
		IP:            net.IPv4(10, 42, 0, 9),
		resourceFile:  opticalResourceFile,
		metricsCycler: mc,
	}
}

// TestOpticalResolveShapes is the table-driven shape contract: wildcard
// expansion, specific-name lookup, subtree flattening, and every rejection.
func TestOpticalResolveShapes(t *testing.T) {
	r := newPathResolver(newTestOpticalDevice(t, true))
	now := time.Now()

	// Derived rather than hardcoded so the table cannot drift from the leaf
	// table it is meant to describe.
	perComponent := len(allOpticalSelectors())
	configLeaves := len(opticalSelectorsFor("config"))
	stateLeaves := len(opticalSelectorsFor("state"))

	tests := []struct {
		name      string
		path      string
		wantCount int
		wantCode  codes.Code
		wantErrIn string
	}{
		{"bare /components wildcards every channel", "/components", 2 * perComponent, codes.OK, ""},
		{"explicit wildcard", "/components/component[name=*]", 2 * perComponent, codes.OK, ""},
		{"specific channel subtree", "/components/component[name=OCH-1-1]", perComponent, codes.OK, ""},
		{"optical-channel container", "/components/component[name=OCH-1-1]/optical-channel", perComponent, codes.OK, ""},
		{"config container", "/components/component[name=OCH-1-1]/optical-channel/config", configLeaves, codes.OK, ""},
		{"state container", "/components/component[name=OCH-1-1]/optical-channel/state", stateLeaves, codes.OK, ""},
		{"stats container fans out to 4", "/components/component[name=OCH-1-1]/optical-channel/state/osnr", 4, codes.OK, ""},
		{"single statistic", "/components/component[name=OCH-1-1]/optical-channel/state/osnr/avg", 1, codes.OK, ""},
		{"wildcard single statistic", "/components/component[name=*]/optical-channel/state/osnr/avg", 2, codes.OK, ""},
		{"bare counter leaf", "/components/component[name=OCH-1-1]/optical-channel/state/fec-uncorrectable-blocks", 1, codes.OK, ""},
		{"config scalar", "/components/component[name=OCH-1-1]/optical-channel/config/frequency", 1, codes.OK, ""},
		{"state scalar", "/components/component[name=OCH-1-1]/optical-channel/state/line-port", 1, codes.OK, ""},

		{"unknown channel", "/components/component[name=OCH-9-9]", 0, codes.NotFound, "OCH-9-9"},
		{"empty name key", "/components/component[name=]", 0, codes.InvalidArgument, "name=*"},
		{"non-component child", "/components/subrack", 0, codes.NotFound, "subrack"},
		{"non-optical-channel child", "/components/component[name=OCH-1-1]/properties", 0, codes.NotFound, "properties"},
		{"unknown container", "/components/component[name=OCH-1-1]/optical-channel/telemetry", 0, codes.NotFound, "telemetry"},
		{"unknown leaf", "/components/component[name=OCH-1-1]/optical-channel/state/wander", 0, codes.NotFound, "wander"},
		{"unknown statistic", "/components/component[name=OCH-1-1]/optical-channel/state/osnr/median", 0, codes.NotFound, "median"},
		{"too deep", "/components/component[name=OCH-1-1]/optical-channel/state/osnr/avg/extra", 0, codes.NotFound, "depth"},

		// post-fec-ber exists in OpenConfig but Ciena removed it, so nl6
		// deliberately does not serve it — a rule keyed on it would never fire
		// against real hardware.
		{"post-fec-ber is not served", "/components/component[name=OCH-1-1]/optical-channel/state/post-fec-ber", 0, codes.NotFound, "post-fec-ber"},
		// The measured leaves are state-only; only the 4 scalars have config.
		{"measured leaf has no config", "/components/component[name=OCH-1-1]/optical-channel/config/osnr", 0, codes.NotFound, "state/"},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			ups, err := r.Resolve(pathFromString(t, tc.path), now)
			if tc.wantCode != codes.OK {
				if err == nil {
					t.Fatalf("expected %v, got %d updates", tc.wantCode, len(ups))
				}
				if got := status.Code(err); got != tc.wantCode {
					t.Errorf("code = %v, want %v (err: %v)", got, tc.wantCode, err)
				}
				if tc.wantErrIn != "" && !strings.Contains(err.Error(), tc.wantErrIn) {
					t.Errorf("error %q should mention %q", err.Error(), tc.wantErrIn)
				}
				return
			}
			if err != nil {
				t.Fatalf("Resolve: %v", err)
			}
			if len(ups) != tc.wantCount {
				t.Errorf("got %d updates, want %d", len(ups), tc.wantCount)
			}
			for _, u := range ups {
				if u.Path == nil {
					t.Fatal("update with nil path")
				}
				if got := pathToString(u.Path); !strings.HasPrefix(got, "/components/component[name=OCH-") {
					t.Errorf("path %q is not a keyed optical path", got)
				}
			}
		})
	}
}

// TestOpticalBareCounterRejectsStatistic pins the specific mistake a
// collector author makes by analogy with the other leaves: asking for
// `/instant` on the bare counter. The error has to say why, not just
// "not found".
func TestOpticalBareCounterRejectsStatistic(t *testing.T) {
	r := newPathResolver(newTestOpticalDevice(t, true))
	_, err := r.Resolve(pathFromString(t,
		"/components/component[name=OCH-1-1]/optical-channel/state/fec-uncorrectable-blocks/instant"), time.Now())
	if status.Code(err) != codes.NotFound {
		t.Fatalf("code = %v, want NotFound (err: %v)", status.Code(err), err)
	}
	if !strings.Contains(err.Error(), "bare counter") {
		t.Errorf("error should explain the leaf has no statistics container; got %q", err.Error())
	}
}

// TestOpticalResolveOnPacketDevice: a packet device can never have optical
// channels, so the absence is permanent → NotFound. Unavailable would be
// retryable and wrongly invite a client to poll forever.
func TestOpticalResolveOnPacketDevice(t *testing.T) {
	r := newTestPathResolver(t, 2)
	_, err := r.Resolve(pathFromString(t, "/components/component[name=*]/optical-channel/state/osnr/avg"), time.Now())
	if err == nil {
		t.Fatal("expected an error for an optical path on a packet device")
	}
	if got := status.Code(err); got != codes.NotFound {
		t.Errorf("code = %v, want NotFound (Unavailable is retryable and this is permanent); err: %v", got, err)
	}
}

// TestOpticalResolveMidInitialisation is the other half of that split: an
// optical DEVICE TYPE whose engine has not been published yet is genuinely
// "try again" → Unavailable.
func TestOpticalResolveMidInitialisation(t *testing.T) {
	dev := &DeviceSimulator{
		ID: "optical-initialising", IP: net.IPv4(10, 42, 0, 10),
		resourceFile:  opticalResourceFile,
		metricsCycler: &MetricsCycler{}, // no InitOpticalCycler yet
	}
	r := newPathResolver(dev)
	_, err := r.Resolve(pathFromString(t, "/components/component[name=*]"), time.Now())
	if got := status.Code(err); got != codes.Unavailable {
		t.Errorf("code = %v, want Unavailable for an optical device mid-initialisation; err: %v", got, err)
	}
}

// TestOpticalResolveWithoutIfCounters is the guard-move regression (task
// 4.1). The `ifCounters == nil → Unavailable` check used to run BEFORE
// Resolve inspected the path, so an optical Get on a device with no HC
// counters failed with "interface counters not initialized" — a misleading
// code on a path that never touches that engine.
func TestOpticalResolveWithoutIfCounters(t *testing.T) {
	r := newPathResolver(newTestOpticalDevice(t, false))
	ups, err := r.Resolve(pathFromString(t,
		"/components/component[name=OCH-1-1]/optical-channel/state/osnr/avg"), time.Now())
	if err != nil {
		t.Fatalf("optical Resolve must not depend on the interface engine: %v", err)
	}
	if len(ups) != 1 {
		t.Fatalf("got %d updates, want 1", len(ups))
	}
}

// TestInterfaceResolveStillRequiresIfCounters guards the other direction:
// moving the guard must not have removed it. An interfaces path on a device
// with no counter engine is still Unavailable — there, the engine really is
// the thing being asked for, and it may yet arrive.
func TestInterfaceResolveStillRequiresIfCounters(t *testing.T) {
	r := newPathResolver(newTestOpticalDevice(t, false))
	_, err := r.Resolve(pathFromString(t, "/interfaces/interface[name=*]/state/oper-status"), time.Now())
	if got := status.Code(err); got != codes.Unavailable {
		t.Errorf("code = %v, want Unavailable; err: %v", got, err)
	}
}

// TestOpticalClassifyLeavesTouchesNoEngine pins the shape-only contract
// ClassifyLeaves exists for: the ON_CHANGE validator must be able to
// classify an optical path on a device with NO optical engine at all,
// without ever returning Unavailable.
func TestOpticalClassifyLeavesTouchesNoEngine(t *testing.T) {
	r := newTestPathResolver(t, 1) // packet device: no optical engine
	leaves, err := r.ClassifyLeaves(pathFromString(t,
		"/components/component[name=*]/optical-channel/state/osnr"))
	if err != nil {
		t.Fatalf("ClassifyLeaves must answer on path shape alone: %v", err)
	}
	if len(leaves) != len(opticalStats) {
		t.Fatalf("got %d leaves, want %d", len(leaves), len(opticalStats))
	}
	for _, l := range leaves {
		if isStateOnlyLeaf(l) {
			t.Errorf("optical leaf %q must not be ON_CHANGE-eligible", l)
		}
		if !isOpticalLeafSelector(l) {
			t.Errorf("leaf %q must be recognisable as optical so the rejection message can branch", l)
		}
	}
}

// TestOpticalOnChangeRejectedAsOptical is task 4.5: ON_CHANGE on an optical
// path is rejected, and the message must NOT call an analog measurement a
// counter — an operator would go hunting for a counter that does not exist.
func TestOpticalOnChangeRejectedAsOptical(t *testing.T) {
	dev := newTestOpticalDevice(t, true)
	var active int64
	var sent, dropped uint64
	srv := newGnmiServer(dev, &active, &sent, &dropped)
	srv.resolver = newPathResolver(dev)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	stream := newFakeSubscribeStream(ctx)
	stream.recvQueue <- &gnmipb.SubscribeRequest{
		Request: &gnmipb.SubscribeRequest_Subscribe{
			Subscribe: &gnmipb.SubscriptionList{
				Mode: gnmipb.SubscriptionList_STREAM,
				Subscription: []*gnmipb.Subscription{{
					Path: pathFromString(t, "/components/component[name=*]/optical-channel/state/osnr/avg"),
					Mode: gnmipb.SubscriptionMode_ON_CHANGE,
				}},
			},
		},
	}

	err := srv.Subscribe(stream)
	if err == nil {
		t.Fatal("expected ON_CHANGE on an optical path to be rejected")
	}
	if got := status.Code(err); got != codes.InvalidArgument {
		t.Errorf("code = %v, want InvalidArgument; err: %v", got, err)
	}
	msg := err.Error()
	if strings.Contains(msg, "counter leaf") {
		t.Errorf("optical rejection must not describe an analog measurement as a counter; got %q", msg)
	}
	if !strings.Contains(msg, "optical leaf") {
		t.Errorf("error should name the leaf class; got %q", msg)
	}
	if !strings.Contains(msg, "SAMPLE") {
		t.Errorf("error should recommend SAMPLE; got %q", msg)
	}
	if !strings.Contains(msg, "osnr") {
		t.Errorf("error should name the offending leaf; got %q", msg)
	}
}

// TestOpticalCrossProtocolDeterminism: the resolver must be a pure view
// over the value engine, so a gNMI read equals a direct engine read at the
// same instant. This is the property that makes gNMI, SNMP and any future
// surface agree byte-for-byte.
func TestOpticalCrossProtocolDeterminism(t *testing.T) {
	dev := newTestOpticalDevice(t, true)
	r := newPathResolver(dev)
	oc := dev.metricsCycler.OpticalCyclerOf()

	at := oc.StartTime().Add(1234 * time.Second)
	tSec := at.Sub(oc.StartTime()).Seconds()

	ups, err := r.Resolve(pathFromString(t, "/components/component[name=*]"), at)
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if len(ups) == 0 {
		t.Fatal("no updates")
	}
	for _, u := range ups {
		elems := u.Path.GetElem()
		component := elems[1].GetKey()["name"]
		// Rebuild the engine leaf from the path: everything after the
		// container, which is elems[3].
		var segs []string
		for _, e := range elems[4:] {
			segs = append(segs, e.GetName())
		}
		want, ok := oc.GetDynamicAt(component, strings.Join(segs, "/"), tSec)
		if !ok {
			t.Fatalf("engine has no value for %s %v", component, segs)
		}
		if u.Value != want {
			t.Errorf("%s: gNMI value %v (%T) != engine value %v (%T)",
				pathToString(u.Path), u.Value, u.Value, want, want)
		}
	}
}

// TestOpticalDecimalPrecision pins the two fraction-digit classes the
// pinned model mandates: statistics leaves at 2, pre-FEC BER at 18. A
// wrong precision is exactly the kind of divergence that passes in
// development and breaks a collector's strict schema validation.
func TestOpticalDecimalPrecision(t *testing.T) {
	r := newPathResolver(newTestOpticalDevice(t, true))
	now := time.Now()

	cases := map[string]int{
		"/components/component[name=OCH-1-1]/optical-channel/state/osnr/avg":        opticalStatFractionDigits,
		"/components/component[name=OCH-1-1]/optical-channel/state/pre-fec-ber/avg": opticalBERFractionDigits,
	}
	for path, wantDigits := range cases {
		ups, err := r.Resolve(pathFromString(t, path), now)
		if err != nil || len(ups) != 1 {
			t.Fatalf("%s: Resolve gave %d updates, err %v", path, len(ups), err)
		}
		d, ok := ups[0].Value.(gnmiDecimal)
		if !ok {
			t.Fatalf("%s: value is %T, want gnmiDecimal", path, ups[0].Value)
		}
		if d.digits != wantDigits {
			t.Errorf("%s: fraction digits = %d, want %d", path, d.digits, wantDigits)
		}
	}

	// The bare counter is a uint64, not a decimal — no stats container.
	ups, err := r.Resolve(pathFromString(t,
		"/components/component[name=OCH-1-1]/optical-channel/state/fec-uncorrectable-blocks"), now)
	if err != nil || len(ups) != 1 {
		t.Fatalf("counter Resolve gave %d updates, err %v", len(ups), err)
	}
	if _, ok := ups[0].Value.(uint64); !ok {
		t.Errorf("fec-uncorrectable-blocks is %T, want uint64", ups[0].Value)
	}
}

// TestOpticalCapabilitiesAdvertisesPinnedModels — task 4.6. A client that
// validates against the advertised model set needs all three: the optical
// leaves live in terminal-device, hang off platform's /components, and
// input-power / output-power / laser-bias-current come from
// platform-transceiver's optical-power-state grouping.
func TestOpticalCapabilitiesAdvertisesPinnedModels(t *testing.T) {
	caps := newPathResolver(newTestOpticalDevice(t, true)).Capabilities()
	want := map[string]string{
		"openconfig-terminal-device":      "2026-01-14",
		"openconfig-platform":             "2025-07-15",
		"openconfig-platform-transceiver": "2026-03-25",
		"openconfig-interfaces":           "3.0.0",
	}
	got := map[string]string{}
	for _, m := range caps.GetSupportedModels() {
		got[m.GetName()] = m.GetVersion()
	}
	for name, version := range want {
		v, ok := got[name]
		if !ok {
			t.Errorf("Capabilities does not advertise %q", name)
			continue
		}
		if v != version {
			t.Errorf("%s version = %q, want the pinned %q", name, v, version)
		}
	}
}

// TestOpticalPathManifest is task 4.9's guard, in the manifest form chosen
// over vendoring YANG: the exact served path set is pinned here, so adding,
// renaming or dropping a path fails in CI rather than at a customer's
// collector.
//
// Scope of the guarantee, stated honestly: this proves served == manifest.
// It does NOT prove manifest == YANG — the manifest was transcribed from
// the design's path table, which was traced against openconfig-terminal-device
// 2026-01-14 and openconfig-platform-transceiver 2026-03-25 by hand. A true
// schema check needs the YANG models and ygot; this catches drift, not an
// error in the original tracing.
func TestOpticalPathManifest(t *testing.T) {
	const och = "OCH-1-1"
	prefix := "/components/component[name=" + och + "]/optical-channel/"

	want := []string{
		// config/ — the four scalars, and only these.
		"config/frequency",
		"config/target-output-power",
		"config/operational-mode",
		"config/line-port",
		// state/ — the same four scalars…
		"state/frequency",
		"state/target-output-power",
		"state/operational-mode",
		"state/line-port",
		// …the receive-side spine, each with a 4-way statistics container…
		"state/input-power/instant", "state/input-power/avg", "state/input-power/min", "state/input-power/max",
		"state/osnr/instant", "state/osnr/avg", "state/osnr/min", "state/osnr/max",
		"state/esnr/instant", "state/esnr/avg", "state/esnr/min", "state/esnr/max",
		"state/q-value/instant", "state/q-value/avg", "state/q-value/min", "state/q-value/max",
		"state/pre-fec-ber/instant", "state/pre-fec-ber/avg", "state/pre-fec-ber/min", "state/pre-fec-ber/max",
		// …the off-spine leaves that stay flat under a receive fault…
		"state/output-power/instant", "state/output-power/avg", "state/output-power/min", "state/output-power/max",
		"state/laser-bias-current/instant", "state/laser-bias-current/avg", "state/laser-bias-current/min", "state/laser-bias-current/max",
		"state/chromatic-dispersion/instant", "state/chromatic-dispersion/avg", "state/chromatic-dispersion/min", "state/chromatic-dispersion/max",
		"state/polarization-mode-dispersion/instant", "state/polarization-mode-dispersion/avg", "state/polarization-mode-dispersion/min", "state/polarization-mode-dispersion/max",
		"state/polarization-dependent-loss/instant", "state/polarization-dependent-loss/avg", "state/polarization-dependent-loss/min", "state/polarization-dependent-loss/max",
		// …and the bare counter, with no statistics container.
		"state/fec-uncorrectable-blocks",
	}
	wantSet := make(map[string]bool, len(want))
	for _, w := range want {
		wantSet[prefix+w] = true
	}

	gotSet := make(map[string]bool)
	for _, p := range gnmiOpticalPathManifest(och) {
		gotSet[p] = true
	}

	for p := range wantSet {
		if !gotSet[p] {
			t.Errorf("manifest is missing a pinned path: %s", p)
		}
	}
	for p := range gotSet {
		if !wantSet[p] {
			t.Errorf("manifest serves a path that is not in the pinned set (invented path?): %s", p)
		}
	}

	// post-fec-ber is defined by OpenConfig but deliberately unserved; assert
	// it explicitly so a future contributor "completing" the model has to
	// change a test that says why.
	for p := range gotSet {
		if strings.Contains(p, "post-fec-ber") {
			t.Errorf("post-fec-ber must not be served (Ciena removed it; a rule keyed on it would never fire): %s", p)
		}
	}

	// And the manifest must match what Resolve actually emits, or pinning it
	// proves nothing.
	r := newPathResolver(newTestOpticalDevice(t, true))
	ups, err := r.Resolve(pathFromString(t, "/components/component[name="+och+"]"), time.Now())
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	emitted := make(map[string]bool, len(ups))
	for _, u := range ups {
		emitted[pathToString(u.Path)] = true
	}
	for p := range wantSet {
		if !emitted[p] {
			t.Errorf("subtree Resolve did not emit the pinned path: %s", p)
		}
	}
	if len(emitted) != len(wantSet) {
		t.Errorf("subtree Resolve emitted %d paths, manifest has %d", len(emitted), len(wantSet))
	}
}
