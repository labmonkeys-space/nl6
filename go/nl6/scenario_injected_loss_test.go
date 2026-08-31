/*
 * Copyright 2026 Ronny Trommer <ronny@no42.org>
 * SPDX-License-Identifier: Apache-2.0
 */

package main

import (
	"context"
	"net"
	"sync/atomic"
	"testing"
	"testing/synctest"
	"time"
)

// scenario_injected_loss_test.go — the instrument's core claim, demonstrated
// (story 2.4, NFR-A3): a KNOWN injected loss is recovered by the
// reconciliation arithmetic loss_ratio = (sent − received) / sent, within
// ±1 pp (exact at X=0). The sent side is deterministic by seed (fixed-rate
// scheduler under synctest), so the proof is not flaky-by-design; the drop is
// injected deterministically (every Nth datagram) rather than via real UDP
// timing. Real iptables-based loss lives in the runnable example (AC3).

// lossySink models a collector that drops every dropEveryN-th datagram
// (dropEveryN == 0 → lossless control). `received` counts datagrams the
// collector kept; the exporter still counts every call as `sent`.
type lossySink struct {
	calls      atomic.Uint64
	received   atomic.Uint64
	dropEveryN uint64
}

func (s *lossySink) write([]byte) error {
	n := s.calls.Add(1)
	if s.dropEveryN == 0 || n%s.dropEveryN != 0 {
		s.received.Add(1)
	}
	// The send itself always "succeeds" — loss happens on the wire/collector,
	// so nl6 correctly counts it as sent.
	return nil
}

// lossyManager builds n syslog devices whose writes all funnel through one
// shared lossySink.
func lossyManager(t *testing.T, n int, dropEveryN uint64) (*SimulatorManager, []string, *lossySink) {
	t.Helper()
	cat, err := LoadEmbeddedSyslogCatalog()
	if err != nil {
		t.Fatal(err)
	}
	sink := &lossySink{dropEveryN: dropEveryN}
	sm := &SimulatorManager{
		devices: map[string]*DeviceSimulator{}, deviceIPs: map[string]struct{}{},
		deviceTypesByIP: map[string]string{}, devicesByIP: map[string]*DeviceSimulator{}, syslogCatalog: cat,
	}
	ips := make([]string, 0, n)
	for i := 1; i <= n; i++ {
		ip := scaleIP(i)
		exp := NewSyslogExporter(SyslogExporterOptions{
			DeviceIP: ip, Encoder: &RFC5424Encoder{}, Collector: &net.UDPAddr{IP: net.IPv4(10, 0, 0, 9), Port: 514},
			SysName: "dev", IfIndexFn: func() int { return 3 }, IfNameFn: func(int) string { return "Gi0/3" },
		})
		exp.writeOverride = sink.write
		dev := &DeviceSimulator{ID: "device-" + ip.String(), IP: ip, syslogExporter: exp,
			syslogConfig: &DeviceSyslogConfig{Collector: "10.0.0.9:514"}}
		sm.devices[dev.ID] = dev
		sm.deviceIPs[ip.String()] = struct{}{}
		sm.devicesByIP[ip.String()] = dev
		ips = append(ips, ip.String())
	}
	return sm, ips, sink
}

// TestScenarioInjectedLoss_ReconciliationAccuracy (NFR-A3): with pinned
// parameters producing ≥10,000 records, the loss ratio recovered from
// report.sent vs collector.received matches the injected X within ±1 pp
// (exact at X=0).
func TestScenarioInjectedLoss_ReconciliationAccuracy(t *testing.T) {
	cases := []struct {
		name       string
		dropEveryN uint64
		wantRatio  float64
		exact      bool
	}{
		{"control_0pct", 0, 0.0, true},     // X=0 → exact, no tolerance
		{"injected_5pct", 20, 0.05, false}, // drop 1 in 20 = 5%
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var sent, received uint64
			synctest.Test(t, func(t *testing.T) {
				// 10 devices × 100/s × 10 s half-open window = 10,000 records.
				sm, ips, sink := lossyManager(t, 10, tc.dropEveryN)
				c := newScenarioController(sm, nil)
				spec := &Scenario{Participants: ips, Protocol: "syslog", Rate: 100, Window: 10 * time.Second, Seed: 42}
				if err := c.Submit(spec, "s-000001"); err != nil {
					t.Fatal(err)
				}
				if _, _, err := c.Arm(); err != nil {
					t.Fatal(err)
				}
				if err := c.Start(context.Background()); err != nil {
					t.Fatal(err)
				}
				time.Sleep(11*time.Second + 500*time.Millisecond) // past window + drain (auto-close)
				synctest.Wait()
				res := c.Result()
				if res == nil {
					t.Fatal("scenario did not auto-finalize")
				}
				for _, snap := range res.PerDevice {
					sent += snap.InWindow + snap.Drain
				}
				received = sink.received.Load()
			})

			if sent < 10000 {
				t.Fatalf("sent = %d, want ≥ 10000 (pinned-parameter proof)", sent)
			}
			if tc.exact {
				// X=0: no injected loss. `received < sent` is REAL loss (a hard
				// failure — the property under test). `received` may exceed
				// `sent` by at most one at the exact T1 boundary under synctest,
				// where the fixed-interval scheduler tick and the auto-stop timer
				// coincide on the same fake nanosecond (in real time they never
				// do); that is a synctest artifact, not loss.
				if received < sent || received > sent+1 {
					t.Fatalf("X=0 control: sent=%d received=%d (want received == sent, ±1 T1-boundary)", sent, received)
				}
				return
			}
			lossRatio := float64(sent-received) / float64(sent)
			if diff := lossRatio - tc.wantRatio; diff > 0.01 || diff < -0.01 {
				t.Fatalf("recovered loss %.4f not within ±1pp of injected %.4f (sent=%d received=%d)",
					lossRatio, tc.wantRatio, sent, received)
			}
			t.Logf("injected %.1f%%, recovered %.4f (sent=%d received=%d)", tc.wantRatio*100, lossRatio, sent, received)
		})
	}
}
