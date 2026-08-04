/*
 * Copyright 2026 Ronny Trommer <ronny@no42.org>
 * SPDX-License-Identifier: Apache-2.0
 */

package main

import (
	"bytes"
	"math"
	"math/rand"
	"os"
	"path/filepath"
	"testing"
)

// The fast encoder exists only as a performance variant of
// encodeV2cNotification. Its entire correctness contract is "byte-for-byte
// identical output", so these tests compare the two directly rather than
// asserting wire structure a second time — trap_v2c_test.go already pins that.

// encodeLegacy runs the reference encoder into a fresh 1500-byte buffer.
func encodeLegacy(t *testing.T, pduTag byte, community string, reqID uint32,
	trapOID, enterpriseOID string, uptime uint32, vbs []Varbind) ([]byte, error) {
	t.Helper()
	buf := make([]byte, maxTrapPDU)
	n, err := encodeV2cNotification(pduTag, community, reqID, trapOID, enterpriseOID, uptime, vbs, buf)
	if err != nil {
		return nil, err
	}
	return buf[:n], nil
}

// assertSameEncoding compares fast against legacy for one input, exercising
// both the pre-encoded path and the nil-pre fallback (the on-demand HTTP path
// and any hand-built entry take the latter).
func assertSameEncoding(t *testing.T, name string, pre *preEncodedEntry, pduTag byte,
	community string, reqID uint32, trapOID, enterpriseOID string, uptime uint32, vbs []Varbind) {
	t.Helper()

	want, wantErr := encodeLegacy(t, pduTag, community, reqID, trapOID, enterpriseOID, uptime, vbs)

	for _, variant := range []struct {
		label string
		pre   *preEncodedEntry
	}{{"pre-encoded", pre}, {"nil-pre", nil}} {
		got, gotErr := encodeV2cNotificationFast(make([]byte, 0, maxTrapPDU), pduTag, community,
			reqID, variant.pre, trapOID, enterpriseOID, uptime, vbs)

		if (wantErr == nil) != (gotErr == nil) {
			t.Errorf("%s/%s: error mismatch: legacy=%v fast=%v", name, variant.label, wantErr, gotErr)
			continue
		}
		if wantErr != nil {
			continue
		}
		if !bytes.Equal(want, got) {
			t.Errorf("%s/%s: encoding differs\n legacy (%d): % x\n fast   (%d): % x",
				name, variant.label, len(want), want, len(got), got)
		}
	}
}

// TestFastEncoderMatchesLegacy_ShippedCatalogs is the load-bearing test: every
// entry of every catalog that ships in the binary, resolved against a realistic
// context, must encode identically through both paths. A new vendor overlay is
// covered automatically.
func TestFastEncoderMatchesLegacy_ShippedCatalogs(t *testing.T) {
	universal, err := LoadEmbeddedCatalog()
	if err != nil {
		t.Fatalf("LoadEmbeddedCatalog: %v", err)
	}
	catalogs := map[string]*Catalog{"_universal": universal}

	// Pull in every per-type overlay the repo ships so vendor entries (which
	// carry enterprise OIDs and richer varbind types) are covered too.
	matches, _ := filepath.Glob(filepath.Join("resources", "*", "traps.json"))
	for _, path := range matches {
		data, err := os.ReadFile(path)
		if err != nil {
			t.Fatalf("read %s: %v", path, err)
		}
		cat, err := parseCatalog(data, path)
		if err != nil {
			t.Fatalf("parse %s: %v", path, err)
		}
		catalogs[path] = cat
	}
	if len(catalogs) < 2 {
		t.Fatal("no per-type trap catalogs found — this test would be near-vacuous")
	}

	ctx := TemplateCtx{
		IfIndex: 7, IfName: "GigabitEthernet0/7", Uptime: 123456, Now: 1770000000,
		DeviceIP: "10.42.0.9", SysName: "sim-9", Model: "Cisco ISR 4451",
		Serial: "SN0a2a0009", ChassisID: "02:42:0a:2a:00:09",
		NowLocal: "2026-08-04 11:22:33", Detail: "OSNR=12.5dB",
	}

	for catName, cat := range catalogs {
		for _, entry := range cat.Entries {
			if entry.pre == nil {
				t.Errorf("%s/%s: compileEntry did not precompute", catName, entry.Name)
				continue
			}
			vbs, err := entry.Resolve(ctx, nil)
			if err != nil {
				t.Fatalf("%s/%s: Resolve: %v", catName, entry.Name, err)
			}
			for _, tag := range []byte{ASN1_TRAP_V2C, ASN1_INFORM_REQUEST} {
				assertSameEncoding(t, catName+"/"+entry.Name+"/"+string(rune('A'+tag%26)), entry.pre,
					tag, "public", 42, entry.SnmpTrapOID, entry.SnmpTrapEnterprise, ctx.Uptime, vbs)
			}
		}
	}
}

// TestFastEncoderMatchesLegacy_Types walks every varbind type and the boundary
// values where the two encoders could plausibly diverge: BER length-form
// transitions, the positive-sign pad byte, negative Integer32, and the
// unsigned types that must NOT get a pad byte.
func TestFastEncoderMatchesLegacy_Types(t *testing.T) {
	cases := []struct {
		name string
		vbs  []Varbind
	}{
		{"integer-zero", []Varbind{{OID: "1.3.6.1.4.1.9.1", Type: TrapVTInteger, Value: "0"}}},
		{"integer-127", []Varbind{{OID: "1.3.6.1.4.1.9.1", Type: TrapVTInteger, Value: "127"}}},
		{"integer-128-signpad", []Varbind{{OID: "1.3.6.1.4.1.9.1", Type: TrapVTInteger, Value: "128"}}},
		{"integer-max", []Varbind{{OID: "1.3.6.1.4.1.9.1", Type: TrapVTInteger, Value: "2147483647"}}},
		{"integer-neg-1", []Varbind{{OID: "1.3.6.1.4.1.9.1", Type: TrapVTInteger, Value: "-1"}}},
		{"integer-neg-128", []Varbind{{OID: "1.3.6.1.4.1.9.1", Type: TrapVTInteger, Value: "-128"}}},
		{"integer-neg-129", []Varbind{{OID: "1.3.6.1.4.1.9.1", Type: TrapVTInteger, Value: "-129"}}},
		{"integer-min", []Varbind{{OID: "1.3.6.1.4.1.9.1", Type: TrapVTInteger, Value: "-2147483648"}}},
		{"octet-empty", []Varbind{{OID: "1.3.6.1.2.1.1.5.0", Type: TrapVTOctetString, Value: ""}}},
		{"octet-127", []Varbind{{OID: "1.3.6.1.2.1.1.5.0", Type: TrapVTOctetString, Value: strRepeat("x", 127)}}},
		{"octet-128-longform", []Varbind{{OID: "1.3.6.1.2.1.1.5.0", Type: TrapVTOctetString, Value: strRepeat("x", 128)}}},
		{"octet-300-longform", []Varbind{{OID: "1.3.6.1.2.1.1.5.0", Type: TrapVTOctetString, Value: strRepeat("x", 300)}}},
		{"oid-value", []Varbind{{OID: "1.3.6.1.6.3.1.1.4.3.0", Type: TrapVTOID, Value: "1.3.6.1.4.1.2636"}}},
		{"oid-large-components", []Varbind{{OID: "1.3.6.1.4.1.99999999", Type: TrapVTOID, Value: "1.3.6.1.4.1.268435456.2"}}},
		// Arcs ≥ 2^35 need six or more base-128 chunks. Reachable from the HTTP
		// API: varbindOverrides {"IfIndex":"68719476736"} against the shipped
		// templated OID ifIndex.{{.IfIndex}} (regression: fixed-size chunk
		// buffer panicked here).
		{"oid-arc-2pow36", []Varbind{{OID: "1.3.6.1.2.1.2.2.1.1.68719476736", Type: TrapVTInteger, Value: "1"}}},
		{"oid-value-arc-2pow36", []Varbind{{OID: "1.3.6.1.6.3.1.1.4.3.0", Type: TrapVTOID, Value: "1.3.6.1.4.1.68719476736"}}},
		// OID bodies at the 0x81 (128..255) and 0x82 (≥256) length-form
		// boundaries (regression: the ≥256 case wrote a truncated one-byte
		// length).
		{"oid-body-130-longform", []Varbind{{OID: longArcOID(43), Type: TrapVTInteger, Value: "1"}}},
		{"oid-body-301-longform", []Varbind{{OID: longArcOID(100), Type: TrapVTInteger, Value: "1"}}},
		{"counter32-max", []Varbind{{OID: "1.3.6.1.2.1.2.2.1.10.1", Type: TrapVTCounter32, Value: "4294967295"}}},
		{"counter32-highbit", []Varbind{{OID: "1.3.6.1.2.1.2.2.1.10.1", Type: TrapVTCounter32, Value: "2147483648"}}},
		{"gauge32-zero", []Varbind{{OID: "1.3.6.1.2.1.2.2.1.5.1", Type: TrapVTGauge32, Value: "0"}}},
		{"timeticks", []Varbind{{OID: "1.3.6.1.2.1.1.3.1", Type: TrapVTTimeTicks, Value: "4294967295"}}},
		{"counter64", []Varbind{{OID: "1.3.6.1.2.1.31.1.1.1.6.1", Type: TrapVTCounter64, Value: "18446744073709551615"}}},
		{"ipaddress", []Varbind{{OID: "1.3.6.1.4.1.9.9.1.1", Type: TrapVTIPAddress, Value: "10.42.0.9"}}},
		{"no-varbinds", nil},
		{"many-varbinds", manyVarbinds(20)},
		// Malformed OIDs: encodeOID does not error on these, it emits a
		// degenerate or zero-component encoding. The fast path must agree.
		{"oid-single-component", []Varbind{{OID: "1", Type: TrapVTInteger, Value: "1"}}},
		{"oid-empty", []Varbind{{OID: "", Type: TrapVTInteger, Value: "1"}}},
		{"oid-leading-dot", []Varbind{{OID: ".1.3.6.1.2.1", Type: TrapVTInteger, Value: "1"}}},
		{"oid-trailing-dot", []Varbind{{OID: "1.3.6.", Type: TrapVTInteger, Value: "1"}}},
		{"oid-double-dot", []Varbind{{OID: "1.3..6", Type: TrapVTInteger, Value: "1"}}},
		{"oid-nonnumeric", []Varbind{{OID: "1.3.x.6", Type: TrapVTInteger, Value: "1"}}},
		// Error paths must agree too.
		{"bad-integer", []Varbind{{OID: "1.3.6.1", Type: TrapVTInteger, Value: "not-a-number"}}},
		{"bad-ipaddress", []Varbind{{OID: "1.3.6.1", Type: TrapVTIPAddress, Value: "2001:db8::1"}}},
		{"unknown-type", []Varbind{{OID: "1.3.6.1", Type: TrapVarbindType("bogus"), Value: "1"}}},
	}

	for _, tc := range cases {
		for _, ent := range []string{"", "1.3.6.1.4.1.9"} {
			for _, tag := range []byte{ASN1_TRAP_V2C, ASN1_INFORM_REQUEST} {
				label := tc.name
				if ent != "" {
					label += "+enterprise"
				}
				// A synthetic entry so the pre-encoded path is exercised with
				// exactly these OIDs.
				e := &CatalogEntry{
					SnmpTrapOID:        "1.3.6.1.6.3.1.1.5.3",
					SnmpTrapEnterprise: ent,
				}
				for _, vb := range tc.vbs {
					e.Varbinds = append(e.Varbinds, VarbindTemplate{Type: vb.Type, rawOID: vb.OID, rawValue: vb.Value})
				}
				assertSameEncoding(t, label, precomputeEntry(e), tag, "public", 7,
					e.SnmpTrapOID, ent, 999999, tc.vbs)
			}
		}
	}
}

// TestFastEncoderMatchesLegacy_Fuzz randomises reqID, uptime, community and
// varbind payloads. Length-form boundaries inside the nested SEQUENCEs are the
// interesting target: the reserve-and-patch shift has to land identically to
// the legacy build-innermost-first assembly at every nesting level.
func TestFastEncoderMatchesLegacy_Fuzz(t *testing.T) {
	rng := rand.New(rand.NewSource(20260804))
	for i := 0; i < 3000; i++ {
		n := rng.Intn(6)
		vbs := make([]Varbind, 0, n)
		for j := 0; j < n; j++ {
			vbs = append(vbs, Varbind{
				OID:   randTrapOID(rng),
				Type:  TrapVTOctetString,
				Value: strRepeat("v", rng.Intn(140)),
			})
		}
		e := &CatalogEntry{SnmpTrapOID: randTrapOID(rng)}
		for _, vb := range vbs {
			e.Varbinds = append(e.Varbinds, VarbindTemplate{Type: vb.Type, rawOID: vb.OID, rawValue: vb.Value})
		}
		community := strRepeat("c", rng.Intn(20))
		assertSameEncoding(t, "fuzz", precomputeEntry(e), ASN1_TRAP_V2C, community,
			uint32(rng.Int31()), e.SnmpTrapOID, "", uint32(rng.Int31()), vbs)
	}
}

// TestFastEncoderRejectsOversize pins that the size at which a notification is
// refused did not move when the fixed 1500-byte buffer became a pooled slice.
func TestFastEncoderRejectsOversize(t *testing.T) {
	vbs := []Varbind{{OID: "1.3.6.1.2.1.1.5.0", Type: TrapVTOctetString, Value: strRepeat("x", maxTrapPDU+64)}}
	if _, err := encodeV2cNotificationFast(nil, ASN1_TRAP_V2C, "public", 1, nil,
		"1.3.6.1.6.3.1.1.5.3", "", 1, vbs); err == nil {
		t.Fatal("fast encoder accepted a PDU larger than maxTrapPDU")
	}
	if _, err := encodeLegacy(t, ASN1_TRAP_V2C, "public", 1, "1.3.6.1.6.3.1.1.5.3", "", 1, vbs); err == nil {
		t.Fatal("legacy encoder accepted an oversize PDU — the two must agree on the limit")
	}
}

// TestPrecomputeConstantDetection pins the conservative direction of the
// templated-OID check: a templated OID must NOT be frozen, because doing so
// would pin one device's ifIndex onto every subsequent fire.
func TestPrecomputeConstantDetection(t *testing.T) {
	e := &CatalogEntry{
		SnmpTrapOID: "1.3.6.1.6.3.1.1.5.3",
		Varbinds: []VarbindTemplate{
			{Type: TrapVTInteger, rawOID: "1.3.6.1.2.1.2.2.1.1.{{.IfIndex}}", rawValue: "{{.IfIndex}}"},
			{Type: TrapVTInteger, rawOID: "1.3.6.1.2.1.2.2.1.7.1", rawValue: "1"},
			{Type: TrapVTOctetString, rawOID: "1.3.6.1.2.1.1.5.0", rawValue: "{{.NowLocal}}"},
		},
	}
	pre := precomputeEntry(e)
	if pre.varbindOID[0] != nil {
		t.Error("templated OID was frozen — a per-fire ifIndex would be pinned to the first value seen")
	}
	if pre.varbindOID[1] == nil {
		t.Error("constant OID was not pre-encoded — the optimisation is not taking effect")
	}
	if !pre.usesNowLocal {
		t.Error("NowLocal reference not detected; the fire path would leave the field empty")
	}

	noLocal := precomputeEntry(&CatalogEntry{
		SnmpTrapOID: "1.3.6.1.6.3.1.1.5.3",
		Varbinds:    []VarbindTemplate{{Type: TrapVTInteger, rawOID: "1.3.6.1.2.1.1.3.0", rawValue: "1"}},
	})
	if noLocal.usesNowLocal {
		t.Error("NowLocal falsely detected; a needless time.Format stays on the hot path")
	}
}

// --- helpers ---

func strRepeat(s string, n int) string {
	b := make([]byte, 0, len(s)*n)
	for i := 0; i < n; i++ {
		b = append(b, s...)
	}
	return string(b)
}

// longArcOID builds "1.3" followed by n arcs of 200000 (three varint chunks
// each), so the encoded body is 1+3n bytes — enough to cross the 0x81 and 0x82
// length-form boundaries.
func longArcOID(n int) string {
	oid := "1.3"
	for i := 0; i < n; i++ {
		oid += ".200000"
	}
	return oid
}

func manyVarbinds(n int) []Varbind {
	out := make([]Varbind, 0, n)
	for i := 0; i < n; i++ {
		out = append(out, Varbind{
			OID:   "1.3.6.1.4.1.9.9.1." + trapItoa(i),
			Type:  TrapVTOctetString,
			Value: "value-" + trapItoa(i),
		})
	}
	return out
}

func randTrapOID(rng *rand.Rand) string {
	oid := "1.3.6.1.4.1"
	for i := 0; i < rng.Intn(6); i++ {
		// Span the base-128 varint boundaries.
		switch rng.Intn(4) {
		case 0:
			oid += "." + trapItoa(rng.Intn(128))
		case 1:
			oid += "." + trapItoa(128+rng.Intn(128))
		case 2:
			oid += "." + trapItoa(16384+rng.Intn(1000))
		default:
			oid += "." + trapItoa(rng.Intn(math.MaxInt32))
		}
	}
	return oid
}

func trapItoa(n int) string {
	if n == 0 {
		return "0"
	}
	var b [12]byte
	i := len(b)
	neg := n < 0
	if neg {
		n = -n
	}
	for n > 0 {
		i--
		b[i] = byte('0' + n%10)
		n /= 10
	}
	if neg {
		i--
		b[i] = '-'
	}
	return string(b[i:])
}
