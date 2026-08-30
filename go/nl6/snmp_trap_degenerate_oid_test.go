/*
 * Copyright 2026 Ronny Trommer <ronny@no42.org>
 * SPDX-License-Identifier: Apache-2.0
 */

package main

import (
	"strings"
	"testing"
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
func TestPrecomputeSkipsUnencodableOID(t *testing.T) {
	for _, bad := range []string{"3.40.1", "1", "1.3.x.7"} {
		t.Run(bad, func(t *testing.T) {
			e := &CatalogEntry{
				Varbinds: []VarbindTemplate{{rawOID: bad, rawValue: "x"}},
			}
			pre := precomputeEntry(e)
			if pre == nil || len(pre.varbindOID) == 0 {
				t.Skip("precompute shape differs; the assertion below needs updating")
			}
			if pre.varbindOID[0] != nil {
				t.Errorf("an unencodable OID was precomputed as % x; caching the degenerate "+
					"encoding bypasses the fire-path check", pre.varbindOID[0])
			}
		})
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
