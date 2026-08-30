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
)

// nl6#540. An OID the encoder cannot represent used to be emitted as the
// degenerate 06 00 — an empty NAME no manager can match — with no log line and
// no counter, diagnosable only from a packet capture.
//
// nl6#539 stops a literal catalog OID getting that far. What remains is a
// TEMPLATED OID, which cannot be decided until it renders, and a REST
// varbindOverrides value can make it unencodable at that point whatever the
// catalog said. Both encoders now REFUSE, which routes the fault to the
// exporter's existing logFirstEncodeErr and sendFailures.

func unencodableOIDs() []string {
	return []string{
		"3.40.1",         // first arc above 2
		"1.40.1",         // second arc above 39 with first arc 1
		"1.2.4294967296", // arc past the SMI maximum
		"2.4294967290.1", // second arc fits, but 40*first+second overflows 2^32-1 (the nl6#529 fuzz class)
		"1",              // fewer than two arcs
		"1.3.x.7",        // non-numeric component
		"",               // empty
	}
}

func TestFastEncoderRefusesUnencodableVarbindOID(t *testing.T) {
	buf := make([]byte, 4096)
	for _, bad := range unencodableOIDs() {
		t.Run(bad, func(t *testing.T) {
			vbs := []Varbind{{OID: bad, Type: TrapVTOctetString, Value: "x"}}
			_, err := encodeV2cNotificationFast(buf[:0], ASN1_TRAP_V2C, "public", 1,
				nil, "1.3.6.1.6.3.1.1.5.3", "", 42, vbs)
			if err == nil {
				t.Fatalf("OID %q was encoded; it would go on the wire as a degenerate empty "+
					"NAME with nothing logged or counted", bad)
			}
			if !strings.Contains(err.Error(), "not one the encoder can represent") {
				t.Errorf("error does not explain the fault: %v", err)
			}
		})
	}
}

// The two encoders must agree fault for fault, not just byte for byte. A
// parity test that compares only successful output passes while one ships a
// message the other refuses — which is exactly what happened when only the
// fast path was changed here.
func TestBothEncodersRefuseTheSameOIDs(t *testing.T) {
	buf := make([]byte, 4096)
	for _, oid := range append(unencodableOIDs(),
		"1.3.6.1.4.1.9.1.1", "2.999", ".1.3.6.1.4.1.9.1.1") {
		t.Run(oid, func(t *testing.T) {
			vbs := []Varbind{{OID: oid, Type: TrapVTOctetString, Value: "x"}}

			_, fastErr := encodeV2cNotificationFast(buf[:0], ASN1_TRAP_V2C, "public", 1,
				nil, "1.3.6.1.6.3.1.1.5.3", "", 42, vbs)
			_, legacyErr := encodeV2cNotification(ASN1_TRAP_V2C, "public", 1,
				"1.3.6.1.6.3.1.1.5.3", "", 42, vbs, buf)

			if (fastErr == nil) != (legacyErr == nil) {
				t.Errorf("encoders disagree for %q: fast=%v legacy=%v", oid, fastErr, legacyErr)
			}
		})
	}
}

// TestPrecomputeSkipsUnencodableOID pins the seam the parity test found. A
// precomputed OID bypasses the fire-path check entirely, so caching a
// degenerate encoding would make the fast path emit what the legacy path
// refuses. Leaving the slot nil sends the fire path down the checked branch.
// That rule covers all three cached slots: body varbinds, snmpTrapOID and
// snmpTrapEnterprise — the identity varbind is the worst place to cache a
// degenerate encoding.
func TestPrecomputeSkipsUnencodableOID(t *testing.T) {
	for _, bad := range []string{"3.40.1", "1", "1.3.x.7"} {
		t.Run(bad, func(t *testing.T) {
			e := &CatalogEntry{
				SnmpTrapOID:        bad,
				SnmpTrapEnterprise: bad,
				Varbinds:           []VarbindTemplate{{rawOID: bad, rawValue: "x"}},
			}
			pre := precomputeEntry(e)
			if pre == nil || len(pre.varbindOID) == 0 {
				t.Fatal("precompute shape changed; this test pins the degenerate-encoding guard and must be updated, not skipped")
			}
			if pre.varbindOID[0] != nil {
				t.Errorf("an unencodable OID was precomputed as % x; caching the degenerate "+
					"encoding bypasses the fire-path check", pre.varbindOID[0])
			}
			if pre.trapOIDVB != nil {
				t.Errorf("an unencodable snmpTrapOID was precomputed as % x", pre.trapOIDVB)
			}
			if pre.enterpriseVB != nil {
				t.Errorf("an unencodable snmpTrapEnterprise was precomputed as % x", pre.enterpriseVB)
			}
			// The fast path must refuse THROUGH such a pre, not just with a
			// nil one — a cached degenerate slot is exactly the bypass.
			if _, err := encodeV2cNotificationFast(nil, ASN1_TRAP_V2C, "public", 1,
				pre, bad, bad, 42, nil); err == nil {
				t.Error("the fast path encoded an unencodable trapOID through its precomputed entry")
			}
		})
	}

	// Positive control: a valid literal entry still precomputes every slot,
	// or an inverted guard would nil them all and silently retire the fast
	// path's precompute win with the suite green.
	good := precomputeEntry(&CatalogEntry{
		SnmpTrapOID:        "1.3.6.1.6.3.1.1.5.3",
		SnmpTrapEnterprise: "1.3.6.1.4.1.9",
		Varbinds:           []VarbindTemplate{{rawOID: "1.3.6.1.2.1.1.3.0", rawValue: "x"}},
	})
	if good == nil || len(good.trapOIDVB) == 0 || len(good.enterpriseVB) == 0 ||
		len(good.varbindOID) != 1 || good.varbindOID[0] == nil {
		t.Error("a valid literal entry was not fully precomputed")
	}
}

// TestFastEncoderRefusesUnencodableTrapOID covers the identity varbind, which
// is the worst place to emit a degenerate OID: every trap from the entry
// becomes unidentifiable rather than merely carrying one bad binding.
func TestFastEncoderRefusesUnencodableTrapOID(t *testing.T) {
	buf := make([]byte, 4096)
	if _, err := encodeV2cNotificationFast(buf[:0], ASN1_TRAP_V2C, "public", 1, nil, "3.40.1", "", 42, nil); err == nil {
		t.Error("an unencodable snmpTrapOID was encoded")
	}
	if _, err := encodeV2cNotificationFast(buf[:0], ASN1_TRAP_V2C, "public", 1,
		nil, "1.3.6.1.6.3.1.1.5.3", "3.40.1", 42, nil); err == nil {
		t.Error("an unencodable snmpTrapEnterprise was encoded")
	}
	// The positive control: a valid pair still encodes, or a change that
	// refused everything would pass the two assertions above.
	if _, err := encodeV2cNotificationFast(buf[:0], ASN1_TRAP_V2C, "public", 1,
		nil, "1.3.6.1.6.3.1.1.5.3", "1.3.6.1.4.1.9", 42, nil); err != nil {
		t.Errorf("a valid notification was refused: %v", err)
	}
}

// TestBothEncodersRefuseUnencodableOIDValue covers the VALUE slot of an
// oid-typed varbind, which the varbind-NAME guards cannot reach and which
// parity alone cannot catch: both encoders used to agree on shipping the
// degenerate 06 00 there.
func TestBothEncodersRefuseUnencodableOIDValue(t *testing.T) {
	buf := make([]byte, 4096)
	for _, bad := range unencodableOIDs() {
		t.Run(bad, func(t *testing.T) {
			vbs := []Varbind{{OID: "1.3.6.1.2.1.1.2.0", Type: TrapVTOID, Value: bad}}
			_, fastErr := encodeV2cNotificationFast(buf[:0], ASN1_TRAP_V2C, "public", 1,
				nil, "1.3.6.1.6.3.1.1.5.3", "", 42, vbs)
			_, legacyErr := encodeV2cNotification(ASN1_TRAP_V2C, "public", 1,
				"1.3.6.1.6.3.1.1.5.3", "", 42, vbs, buf)
			if fastErr == nil || legacyErr == nil {
				t.Errorf("an unencodable oid VALUE %q was encoded: fast=%v legacy=%v", bad, fastErr, legacyErr)
			}
		})
	}
	// Positive control: a valid oid-typed value still encodes on both paths.
	vbs := []Varbind{{OID: "1.3.6.1.2.1.1.2.0", Type: TrapVTOID, Value: "1.3.6.1.4.1.9.1.1"}}
	if _, err := encodeV2cNotificationFast(buf[:0], ASN1_TRAP_V2C, "public", 1,
		nil, "1.3.6.1.6.3.1.1.5.3", "", 42, vbs); err != nil {
		t.Errorf("fast path refused a valid oid value: %v", err)
	}
	if _, err := encodeV2cNotification(ASN1_TRAP_V2C, "public", 1,
		"1.3.6.1.6.3.1.1.5.3", "", 42, vbs, buf); err != nil {
		t.Errorf("legacy path refused a valid oid value: %v", err)
	}
}

// TestExporterRefusesAndCountsUnencodableFire drives the nl6#540 contract
// through the exporter rather than the encoder units: a varbindOverrides
// value that renders a template unencodable must produce NO datagram, no
// Sent increment, request-id 0, and a SendFailures count that moves on
// EVERY occurrence while the log line stays sync.Once-gated.
func TestExporterRefusesAndCountsUnencodableFire(t *testing.T) {
	cat, err := LoadEmbeddedCatalog()
	if err != nil {
		t.Fatalf("LoadEmbeddedCatalog: %v", err)
	}
	mc := newMockCollector(t, false)
	defer mc.Close()
	conn := openTestUDPConn(t)

	e := NewTrapExporter(TrapExporterOptions{
		DeviceIP:  net.IPv4(127, 0, 0, 1),
		Community: "public",
		Mode:      TrapModeTrap,
		Collector: mc.addr,
	})
	e.SetConn(conn)
	e.StartBackgroundLoops(context.Background())
	defer e.Close()

	bad := map[string]string{"IfIndex": "x"} // renders 1.3.6.1.2.1.2.2.1.1.x
	for i := 1; i <= 2; i++ {
		if reqID := e.Fire(cat.ByName["linkDown"], bad); reqID != 0 {
			t.Fatalf("fire %d: an unencodable fire returned request-id %d, want 0", i, reqID)
		}
		if got := e.stats.SendFailures.Load(); got != uint64(i) {
			t.Errorf("fire %d: SendFailures = %d, want %d (the counter must move on every occurrence)", i, got, i)
		}
	}
	if got := e.stats.Sent.Load(); got != 0 {
		t.Errorf("Sent = %d, want 0", got)
	}
	time.Sleep(100 * time.Millisecond)
	if got := mc.received.Load(); got != 0 {
		t.Errorf("collector received %d datagrams, want 0", got)
	}

	// Positive control: a numeric override fires cleanly through the same
	// entry, so the refusal above is the OID's fault, not the harness's.
	if reqID := e.Fire(cat.ByName["linkDown"], map[string]string{"IfIndex": "3"}); reqID == 0 {
		t.Fatal("a valid override failed to fire")
	}
	if got := e.stats.SendFailures.Load(); got != 2 {
		t.Errorf("SendFailures after the valid fire = %d, want 2", got)
	}
}
