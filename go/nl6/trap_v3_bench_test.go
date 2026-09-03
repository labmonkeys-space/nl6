/*
 * Copyright 2026 Ronny Trommer <ronny@no42.org>
 * SPDX-License-Identifier: Apache-2.0
 */

package main

import (
	"net"
	"testing"
)

// trap_v3_bench_test.go — what an SNMPv3 notification costs per fire (nl6#98).
//
// PUBLISHED RATHER THAN DISCOVERED. A v3 trap is strictly more work than a v2c
// one and there is no version of this change in which it is not:
//
//   - It SKIPS THE FAST ENCODER. SNMPv2cEncoder implements fastTrapEncoder, so
//     the shipped v2c path appends into a pooled buffer with no intermediate
//     allocation. SNMPv3TrapEncoder does not implement it — deliberately, and
//     for the same reason SNMPv1Encoder does not: encodeV2cNotificationFast's
//     PDU region is entangled with its own community envelope and the maxTrapPDU
//     check, so it is a v2c-only encoder by decision. Every v3 fire therefore
//     goes through the REFERENCE encoder path in fireWithCtx.
//   - It adds an HMAC over the whole message at authNoPriv and above.
//   - It adds a cipher pass, plus 8 bytes of crypto/rand salt, at authPriv.
//
// The Ku derivation — RFC 3414 §A.2's megabyte of hashing, ~2.1 ms — is NOT in
// here and must not appear: it is cached fleet-wide on (password, hash size),
// so a 30k-device v3 fleet pays it once. If a run of BenchmarkTrapEncode/v3
// ever shows milliseconds per op, that cache has been broken, which is a far
// larger regression than anything else this file measures.
//
// Run it with:
//
//	cd go && go test ./nl6/ -bench BenchmarkTrapEncode -benchmem -run '^$'
//
// Absolute numbers do not travel between machines (the CLAUDE.md convention);
// what travels is the RATIO between the rows of one run.

// benchTrapVarbinds is a body of realistic width — the shipped universal
// linkDown carries two, the Ciena optical alarms carry 39.
var benchTrapVarbinds = []Varbind{
	{OID: "1.3.6.1.2.1.2.2.1.1.7", Type: TrapVTInteger, Value: "7"},
	{OID: "1.3.6.1.2.1.2.2.1.7.7", Type: TrapVTInteger, Value: "1"},
	{OID: "1.3.6.1.2.1.2.2.1.8.7", Type: TrapVTInteger, Value: "2"},
	{OID: "1.3.6.1.2.1.1.5.0", Type: TrapVTOctetString, Value: "sim-9"},
}

// BenchmarkTrapEncode compares one fire's encode across every notification
// format nl6 ships, at every SNMPv3 security level.
//
// The v2c rows are the baseline and BOTH are measured: the fast encoder is what
// a v2c fleet actually runs, and the reference encoder is the fair comparison
// for v3 — which uses the reference path — so quoting only one of them either
// overstates or understates the cost of choosing v3.
func BenchmarkTrapEncode(b *testing.B) {
	deviceIP := net.IPv4(10, 42, 0, 9)
	buf := make([]byte, maxTrapPDU)

	b.Run("v2c/fast", func(b *testing.B) {
		enc := SNMPv2cEncoder{}
		var dst []byte
		b.ReportAllocs()
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			out, err := enc.EncodeNotificationFast(dst, TrapModeTrap, "public", uint32(i), nil,
				v3TrapOID, v3TrapEnterprise, v3TrapUptime, benchTrapVarbinds)
			if err != nil {
				b.Fatal(err)
			}
			dst = out[:0]
		}
	})

	b.Run("v2c/reference", func(b *testing.B) {
		enc := SNMPv2cEncoder{}
		b.ReportAllocs()
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			if _, err := enc.EncodeTrap("public", uint32(i), v3TrapOID, v3TrapEnterprise,
				v3TrapUptime, benchTrapVarbinds, buf); err != nil {
				b.Fatal(err)
			}
		}
	})

	b.Run("v1", func(b *testing.B) {
		enc := SNMPv1Encoder{AgentAddr: deviceIP.String()}
		b.ReportAllocs()
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			if _, err := enc.EncodeTrap("public", uint32(i), v3TrapOID, v3TrapEnterprise,
				v3TrapUptime, benchTrapVarbinds, buf); err != nil {
				b.Fatal(err)
			}
		}
	})

	for _, row := range v3TrapRows {
		b.Run("v3/"+row.name, func(b *testing.B) {
			enc, err := NewSNMPv3TrapEncoder(deviceIP, v3TrapTestConfig(row.auth, row.priv))
			if err != nil {
				b.Fatal(err)
			}
			// Force the sync.Once key derivation OUTSIDE the timed loop. It is
			// per-encoder, not per-fire, and letting it land inside would
			// report a per-device cost as a per-message one.
			_ = enc.engine.usmState()
			b.ReportAllocs()
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				if _, err := enc.EncodeTrap("", uint32(i), v3TrapOID, v3TrapEnterprise,
					v3TrapUptime, benchTrapVarbinds, buf); err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}

// BenchmarkSNMPv3TrapEncoderConstruction measures the PER-DEVICE cost, which is
// what a 30k-device fleet pays at attach.
//
// THE POINT OF THIS ROW IS THE Ku CACHE. Localization is H(Ku || engineID ||
// Ku) — two short hashes when privacy is on — while Ku itself is a megabyte of
// hashing that usmPasswordToKey caches on (password, hash size) and NOT on the
// engine ID. That split is exactly what makes a per-device engine ID affordable
// (nl6#624 split them for this caller). A run in the microseconds means the
// cache is working; a run in the milliseconds means someone keyed it on
// something per-device and a fleet start now costs CPU-minutes.
func BenchmarkSNMPv3TrapEncoderConstruction(b *testing.B) {
	cfg := v3TrapTestConfig(SNMPV3_AUTH_SHA1, SNMPV3_PRIV_AES128)
	// Warm the shared cache so the first iteration is not the only one paying
	// for the megabyte expansion.
	if _, err := NewSNMPv3TrapEncoder(net.IPv4(10, 0, 0, 1), cfg); err != nil {
		b.Fatal(err)
	}
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		// A different address each iteration, so every one localizes against a
		// distinct engine ID exactly as a real fleet does.
		ip := net.IPv4(10, 42, byte(i>>8), byte(i))
		if _, err := NewSNMPv3TrapEncoder(ip, cfg); err != nil {
			b.Fatal(err)
		}
	}
}
