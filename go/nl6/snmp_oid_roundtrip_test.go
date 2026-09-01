/*
 * Copyright 2026 Ronny Trommer <ronny@no42.org>
 * SPDX-License-Identifier: Apache-2.0
 */

package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/asn1"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"testing"
)

// X.690 §8.19.4 packs the first two arcs into ONE sub-identifier valued
// 40*first+second, encoded as a base-128 varint like every other one. Both
// encodeOID and decodeOID used to treat it as a single byte: symmetric, and
// both wrong. The round-trip held only while the second arc stayed under 40 and
// fabricated silently above it (nl6#529).
//
// The acceptance criterion for this file is the PROPERTY, not a table:
// decodeOID(encodeOID(x)) == x for every OID X.690 can represent. Two
// hand-derived bounds were proposed and accepted during nl6#523 (127, then 255)
// and both were wrong, because the binding limit was the decoder's %40 rather
// than any varint ceiling. A table of chosen values cannot catch that; driving
// the real decoder over a generated space can.

// oidBody strips the TLV header from an encodeOID result and returns the
// content octets. It parses the length properly rather than assuming enc[2:]:
// an OID with enough arcs uses the long form (06 81 c8 ...), and slicing at a
// fixed offset there silently feeds the length byte to the decoder as if it
// were OID content.
func oidBody(t *testing.T, enc []byte) ([]byte, bool) {
	t.Helper()
	if len(enc) < 2 || enc[0] != ASN1_OID {
		return nil, false
	}
	n, next := parseLength(enc, 1)
	if n < 0 || next+n > len(enc) {
		return nil, false
	}
	return enc[next : next+n], true
}

// canonicalOID renders an OID in the one spelling decodeOID produces, so the
// round-trip property compares OIDs rather than strings. "002.00000" and "2.0"
// are the same OID written two ways; a decoder cannot recover which spelling
// was encoded, and it is not supposed to. Found by the fuzzer, which is exactly
// the sort of over-strong property a hand-written table would never expose.
func canonicalOID(in string) string {
	parts := strings.Split(strings.TrimPrefix(in, "."), ".")
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		v, err := strconv.Atoi(p)
		if err != nil {
			return "" // not an OID; the caller should not be comparing
		}
		out = append(out, strconv.Itoa(v))
	}
	return "." + strings.Join(out, ".")
}

// oidRoundTrips is the property under test: whatever encodeOID accepts must
// decode back to the same OID, in canonical spelling.
func oidRoundTrips(t *testing.T, in string) bool {
	t.Helper()
	body, ok := oidBody(t, encodeOID(in))
	if !ok || len(body) == 0 {
		return false
	}
	return decodeOID(body) == canonicalOID(in)
}

func TestOIDRoundTripProperty(t *testing.T) {
	// Every arc pair X.690 can represent, plus a trailing arc that crosses the
	// single-byte/multi-byte varint boundary in its own right.
	tails := []int{0, 1, 126, 127, 128, 129, 16383, 16384, 4294967295}

	checked := 0
	for first := 0; first <= 2; first++ {
		maxSecond := 39
		if first == 2 {
			maxSecond = 1200 // unbounded in X.690; 1200 spans 1- and 2-byte varints
		}
		for second := 0; second <= maxSecond; second++ {
			for _, tail := range tails {
				in := fmt.Sprintf("%d.%d.%d", first, second, tail)
				if !oidRoundTrips(t, in) {
					enc := encodeOID(in)
					body, _ := oidBody(t, enc)
					t.Errorf("round-trip failed for %q: encoded % x, decoded %q", in, enc, decodeOID(body))
				}
				checked++
			}
		}
	}
	// Shapes the three-arc loop above cannot reach: a bare two-arc OID, and an
	// OID long enough that its TLV uses the BER long-form length. Without the
	// latter nothing in the deterministic suite exercises the branch oidBody
	// was written for, and only the fuzzer's long seed would catch a regression.
	shapes := []string{"1.3", "0.0", "2.999", "2.0"}
	for _, n := range []int{40, 200, 5000} {
		shapes = append(shapes, "1.3"+strings.Repeat(".1", n))
	}
	for _, in := range shapes {
		if !oidRoundTrips(t, in) {
			enc := encodeOID(in)
			body, _ := oidBody(t, enc)
			t.Errorf("round-trip failed for a %d-arc OID %q: encoded %d bytes, decoded %q",
				strings.Count(in, ".")+1, truncateForLog(in), len(enc), truncateForLog(decodeOID(body)))
		}
		checked++
	}

	if checked < 10000 {
		t.Fatalf("only %d OIDs checked; the property test is not covering the space", checked)
	}
	t.Logf("round-trip holds for %d generated OIDs, including long-form-length shapes", checked)
}

// TestOIDRoundTripRegressions pins the specific values that were fabricated
// before this change, with the wrong answer named so a regression is obvious.
func TestOIDRoundTripRegressions(t *testing.T) {
	tests := []struct {
		in           string
		wasDecodedAs string // the fabricated answer before nl6#529
		nowRejected  bool   // true when the pair is not representable at all
	}{
		{in: "3.40.1", wasDecodedAs: ".4.0.1", nowRejected: true},
		{in: "2.87.1", wasDecodedAs: ".4.7.1"},
		{in: "2.175.1", wasDecodedAs: ".6.15.1"},
		{in: "2.999", wasDecodedAs: ".1.15"},
		{in: "1.3.x.7", wasDecodedAs: ".1.3.0.7", nowRejected: true},
		{in: "1.", wasDecodedAs: ".1.0", nowRejected: true},
		{in: "1.40.1", wasDecodedAs: ".2.0.1", nowRejected: true}, // would alias 2.0.1
	}
	for _, tt := range tests {
		t.Run(tt.in, func(t *testing.T) {
			enc := encodeOID(tt.in)

			if tt.nowRejected {
				// Assert the EXACT new behaviour. Checking only "not the old
				// wrong string" would be satisfied by a different fabrication,
				// since the degenerate encoding decodes to "" and "" differs
				// from every historical answer.
				if len(enc) != 2 || enc[0] != ASN1_OID || enc[1] != 0x00 {
					t.Fatalf("encodeOID(%q) = % x, want the degenerate 06 00: this input is not representable", tt.in, enc)
				}
				// Decode the body that was actually produced, not a constant:
				// the degenerate TLV has an empty body and must decode to "".
				body, ok := oidBody(t, enc)
				if !ok {
					t.Fatalf("encodeOID(%q) produced an undecodable TLV: % x", tt.in, enc)
				}
				if got := decodeOID(body); got != "" {
					t.Fatalf("decodeOID of the degenerate body = %q, want \"\"", got)
				}
				return
			}

			body, ok := oidBody(t, enc)
			if !ok {
				t.Fatalf("encodeOID(%q) produced an undecodable TLV: % x", tt.in, enc)
			}
			got := decodeOID(body)
			if got == tt.wasDecodedAs {
				t.Fatalf("%q still decodes as %q: the fabrication is back", tt.in, got)
			}
			if want := canonicalOID(tt.in); got != want {
				t.Errorf("%q decoded as %q, want %q", tt.in, got, want)
			}
		})
	}
}

// TestOIDArcPairsOutsideX690AreRejected pins that an unrepresentable pair takes
// the degenerate path rather than silently becoming a different OID. 1.40 is
// the subtle one: 40*1+40 == 80 == 40*2+0, so it would ALIAS 2.0 on decode.
func TestOIDArcPairsOutsideX690AreRejected(t *testing.T) {
	for _, in := range []string{"3.40.1", "3.0.1", "1.40.1", "0.40.1", "1.100.1"} {
		if got := encodeOID(in); len(got) != 2 || got[0] != ASN1_OID || got[1] != 0x00 {
			t.Errorf("encodeOID(%q) = % x, want the degenerate 06 00: this pair is not representable", in, got)
		}
	}
	// The legal neighbours must still encode.
	for _, in := range []string{"1.39.1", "2.0.1", "2.40.1", "2.999"} {
		if got := encodeOID(in); len(got) == 2 && got[1] == 0x00 {
			t.Errorf("encodeOID(%q) was rejected, but this pair is legal", in)
		}
	}
}

// TestDecodeOIDRejectsMalformed covers the two decode defects found while
// measuring. Both are reachable from the network: decodeOID parses request
// bytes in snmp_handlers.go, snmp.go and snmp_response.go.
func TestDecodeOIDRejectsMalformed(t *testing.T) {
	overflow := []byte{0x2b}
	for i := 0; i < 10; i++ {
		overflow = append(overflow, 0xff)
	}
	overflow = append(overflow, 0x7f)

	tests := []struct {
		name string
		in   []byte
	}{
		{"empty", nil},
		{"unterminated varint", []byte{0x2b, 0xff}},
		{"unterminated first sub-identifier", []byte{0xff}},
		{"overflow past 2^32-1", overflow},
		{"all continuation bytes", []byte{0xff, 0xff, 0xff}},
		// X.690 §8.19.2: a leading 0x80 is a non-minimal varint. Accepting it
		// would let unbounded distinct byte strings decode to one OID.
		{"non-minimal first sub-identifier", []byte{0x80, 0x2b}},
		{"non-minimal later sub-identifier", []byte{0x2b, 0x80, 0x06}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := decodeOID(tt.in); got != "" {
				t.Errorf("decodeOID(% x) = %q, want \"\": malformed input must be refused, not invented", tt.in, got)
			}
		})
	}
}

// TestDecodeOIDNeverReturnsNegativeArc pins the specific old failure: ten
// continuation bytes used to wrap the accumulator and produce the arc -1,
// which then flowed into a response and back out through the encoder.
func TestDecodeOIDNeverReturnsNegativeArc(t *testing.T) {
	for n := 1; n <= 12; n++ {
		b := []byte{0x2b}
		for i := 0; i < n; i++ {
			b = append(b, 0xff)
		}
		b = append(b, 0x7f)
		if got := decodeOID(b); strings.Contains(got, "-") {
			t.Errorf("decodeOID with %d continuation bytes = %q, which contains a negative arc", n, got)
		}
	}
}

// shippedOIDEncodingDigest is the SHA-256 of every shipped OID paired with its
// encoding, taken on main BEFORE the nl6#529 varint change. It is the
// compatibility proof: if the digest still matches, no deployed profile changed
// what it puts on the wire.
//
// A NOTE ON "09546c3", which appears in the constant name below and in three
// comments: it is the short hash of the pre-varint revision as it was named when
// nl6#529 landed, and it does NOT resolve in this checkout — the branch that
// carried it was squash-merged. The digest itself is still meaningful and still
// re-derived by TestRePinIsOnlyTheDeletedOID; read the name as "the pre-varint
// corpus" rather than as a revision you can check out. Renaming the constant is
// a separate, mechanical change and is deliberately not bundled with a data
// transition (nl6#571 review B2).
//
// Recompute deliberately (and only deliberately) by logging the value this test
// prints when it fails. A test that merely re-derives both sides from the
// current code proves nothing about "before"; an earlier draft of this file did
// exactly that while the docs claimed a hash comparison, which is the kind of
// unbacked claim this whole change exists to stop making.
//
// RE-PINNED EIGHT TIMES. Every re-pin is a CORPUS change, not an encoding
// change, and each is re-derived by a test rather than asserted here.
//
// THE ORDER IS NEWEST FIRST, and snmp_hc_counter_table_test.go's account of the
// same history now runs the same way. The two used to run in opposite
// directions, which made an ordinal mean a different change depending on which
// file you were reading.
//
// The eighth re-pin is nl6#590's SECOND ARC, Arista, and it is the only one that
// moves this digest in BOTH directions at once. Five OID NAMES left the corpus
// (they named objects ARISTA-SMI-MIB / ARISTA-SW-IP-FORWARDING-MIB do not define,
// or the not-accessible aristaSwFwdIpStatsTable), AND one OID-typed VALUE was
// replaced: sysObjectID.0 answered 1.3.6.1.4.1.30065.1.3011.7280.3282.32.4, which
// is shaped like an Arista product OID and is not one, and now answers
// aristaDCS7280CR332P4M. This digest covers OID-typed values as well as names, so
// its reversal is a drop-and-add rather than the pure append every earlier link
// uses — see nl6590aristaOIDNamesBeforeAudit.
// TestAristaArcRePinIsOnlyTheAudit performs it and requires the constant below
// it; the seven older reversals each now begin with the same step, so the chain
// is unbroken at every link. As with nl6#591, that link's "before" value is NOT
// declared here: it lives with its ledger, as
// shippedOIDEncodingDigestBeforeAristaArcAudit in
// snmp_shipped_arista_arc_ledger_test.go.
//
// The seventh re-pin is nl6#591, the first ACCESS-MODE defect: 1.3.6.1.4.1.9.2.1.54.0
// is writeMem in OLD-CISCO-SYSTEM-MIB, ACCESS write-only, and cisco_catalyst_9500
// and cisco_crs_x both answered it with a readable integer. Both entries were
// deleted — a write-only object has no correct readable value — and unlike
// nl6#590 the NAME left the corpus entirely: no third profile served it and no
// trap catalog names it. That is measured by TestWriteMemNameLeftTheCorpus rather
// than reasoned about, because nl6#590's own seven-deleted / five-vanished split
// is what a two-row table makes easy to get wrong.
// TestWriteMemRePinIsOnlyTheRemoval restores the one name and requires the
// constant below it; the six older reversals each now begin with the same
// restoration, so the chain is unbroken at every link. As with nl6#590, that
// link's "before" value is NOT declared here: it lives with its ledger, as
// shippedOIDEncodingDigestBeforeWriteMemRemoval in
// snmp_shipped_cisco_writeonly_ledger_test.go.
//
// The sixth re-pin is nl6#590, the first vendor-arc MIB audit: seven Cisco
// enterprise OID names were deleted from the corpus and FIVE of them left it
// entirely — ciscoEnvMonFanStatusDescr.1 still ships on three other Cisco
// profiles and ciscoEnvMonTemperatureStatusValue.1 is still named as a trap
// varbind in resources/cisco_ios/traps.json. That five-not-seven split is exactly
// the kind of thing that has to be measured rather than reasoned about, and it is
// pinned by TestCiscoArcVanishedNamesAreMeasured.
// TestCiscoArcRePinIsOnlyTheAudit restores the five names and requires the
// constant below it; the five older reversals each now begin with the same
// restoration, so the chain is unbroken at every link. As with nl6#588, that
// link's "before" value is NOT declared here: it lives with its ledger, as
// shippedOIDEncodingDigestBeforeCiscoArcAudit in
// snmp_shipped_cisco_arc_ledger_test.go.
//
// The fifth re-pin is nl6#588, and it is the smallest: ONE OID-typed VALUE.
// aws_s3_storage answered sysObjectID.0 with 1.3.6.1.4.1.9999, which IANA
// allocates to Zerna, Koepper & Partner, a German engineering firm unrelated to
// Amazon or to storage; it now answers 1.3.6.1.4.1.32473.1.1, RFC 5612's
// documentation PEN. No OID KEY changed and no tag changed, so this re-pin moves
// THIS digest and NOT shippedTagDigest — measured, not assumed.
// TestAWSPENRePinIsOnlyTheRehoming un-rehomes it and requires the constant below
// it; the four older reversals each now begin with the same un-rehoming, so the
// chain is unbroken at every link. As with nl6#576, that link's "before" value
// is NOT declared here: it lives with its ledger, as
// shippedOIDEncodingDigestBeforeAWSPENRehome in snmp_shipped_aws_pen_ledger_test.go,
// and equals the value of shippedOIDEncodingDigest at the revision before it.
//
// The fourth re-pin is nl6#576, and it is the only one that is a RENAME rather
// than a deletion: the NVIDIA GPU telemetry arc moved from 1.3.6.1.4.1.53246
// (IANA: Mailteck, S.A.) to 1.3.6.1.4.1.5703 (NVIDIA Corporation), changing 74
// OID names per profile plus the three sysObjectID VALUES, which this digest also
// covers because an OID-typed response reaches encodeOID. No name was added or
// dropped and every sub-identifier below the PEN was preserved.
// TestNvidiaArcRePinIsOnlyTheRename un-renames the arc and requires the constant
// below it; the three older reversals each begin with the same un-rename, so the
// chain is unbroken at every link. Unlike the three constants below, that link's
// "before" value is NOT declared here: it lives with its ledger, as
// shippedOIDEncodingDigestBeforeNvidiaArcRehome in
// snmp_shipped_nvidia_arc_ledger_test.go, and equals the current value of
// shippedOIDEncodingDigest at the revision before this change.
//
// The third re-pin is nl6#574 / nl6#571 / nl6#569, which deleted 829 entries
// naming 259 distinct OIDs, 258 of which left the corpus entirely: the dead
// ifTable .9 / .11 / .17 rows, the bare column OIDs (a column with no instance
// sub-identifier is not a legal varbind name), four over-specified instances, a
// Palo Alto subtree served by twelve non-Palo-Alto profiles, and two invalid PAN
// OIDs. The one name that survives is panChassisType, which the Palo Alto profile
// still serves. TestResourceDataDefectRePinIsOnlyTheDeletedOIDs puts
// those names back and requires the constant below it, and
// TestOctetShadowRePinIsOnlyTheDeletedOIDs then continues back to nl6#570's
// value, so the chain is unbroken at every link.
//
// The second re-pin is nl6#570, which deleted every shipped ifTable .10 / .16
// entry (1322 rows across 20 profiles) once the cycler began serving those two
// columns. The corpus lost the distinct OIDs those rows named; nothing about
// what any surviving OID encodes to moved.
// TestOctetShadowRePinIsOnlyTheDeletedOIDs puts them back and requires the
// digest below it, and TestRePinIsOnlyTheDeletedOID then continues back to
// 09546c3, so the chain is unbroken at both ends.
//
// The first re-pin was nl6#541, from the 09546c3 value below to the constant
// after it. The cause is a CORPUS change, not an encoding change: nl6#541
// deleted the bare column OID 1.3.6.1.2.1.4.21.1.1 ("ipRouteDest" with no
// instance, valued "1") from the 14 profiles carrying it, so the corpus lost one
// distinct OID. That is not asserted here as a comment — see
// TestRePinIsOnlyTheDeletedOID, which puts the OID back and requires the
// 09546c3 digest, byte for byte.
const shippedOIDEncodingDigestAt09546c3 = "8156ddae1118381de67c2bb88121eeab4c13489a186f721dc62da6966b717b91"
const shippedOIDEncodingDigestBeforeOctetShadowDeletion = "cda00c701606d63f494d8d85780079609b277e91ce528fa6bffabde3073745a1"
const shippedOIDEncodingDigestBeforeResourceDataDefects = "9c0cdb3d109ad5ef4135b4ba91b4a959b31df7473fef500a0eb9b98cb2e03a76"

// Re-pinned by nl6#602's Juniper arc audit, which removed eight distinct OID
// names, renamed three onto their legal instance arity and swapped one
// OID-typed sysObjectID value for another. The pre-change value lives in
// snmp_shipped_juniper_arc_ledger_test.go as
// shippedOIDEncodingDigestBeforeJuniperArcAudit, and
// TestJuniperArcRePinIsOnlyTheAudit reverses the ledger and requires it back.
const shippedOIDEncodingDigest = "be01d6c675b2cf2950bfc00c3e02c37c878467e5c918a9ccb6f1b2c39b4aca56"

// TestShippedOIDsUnchangedOnTheWire is the compatibility proof: every OID in
// every shipped resource file and trap catalog must encode to the same bytes as
// before nl6#529.
//
// Templated catalog OIDs (containing "{{") are excluded because they are
// rendered before encoding at fire time, so the raw template never reaches the
// wire. They are counted and reported so the exclusion cannot hide growth.
func TestShippedOIDsUnchangedOnTheWire(t *testing.T) {
	oids := collectShippedOIDs(t)
	if len(oids) < 1000 {
		t.Fatalf("only %d shipped OIDs collected; the corpus walk is not working", len(oids))
	}

	h := sha256.New()
	checked, templated := 0, 0
	for _, oid := range oids {
		if strings.Contains(oid, "{{") {
			templated++
			continue
		}
		checked++
		enc := encodeOID(oid)
		// hash.Hash.Write never returns an error, but errcheck cannot know that.
		_, _ = fmt.Fprintf(h, "%s=%x\n", oid, enc)

		if len(enc) == 2 && enc[1] == 0x00 {
			t.Errorf("shipped OID %q now encodes to the degenerate 06 00", oid)
		}
		if fast := appendOID(nil, oid); !bytes.Equal(fast, enc) {
			t.Errorf("shipped OID %q: encodeOID % x != appendOID % x", oid, enc, fast)
		}
		if !oidRoundTrips(t, oid) {
			t.Errorf("shipped OID %q does not round-trip", oid)
		}
	}

	got := fmt.Sprintf("%x", h.Sum(nil))
	if got != shippedOIDEncodingDigest {
		t.Errorf("shipped OID encoding digest changed.\n got %s\nwant %s\n"+
			"%d OIDs checked, %d templated and skipped.\n"+
			"A deployed profile now puts different bytes on the wire. If that is intended, "+
			"update shippedOIDEncodingDigest and say so in the commit.",
			got, shippedOIDEncodingDigest, checked, templated)
	}
	t.Logf("%d shipped OIDs encode identically to main@09546c3 (%d templated, skipped)", checked, templated)
}

func collectShippedOIDs(t *testing.T) []string {
	t.Helper()
	seen := map[string]bool{}
	err := filepath.Walk("resources", func(p string, info os.FileInfo, err error) error {
		if err != nil || info.IsDir() || filepath.Ext(p) != ".json" {
			return err
		}
		b, err := os.ReadFile(p)
		if err != nil {
			return err
		}
		var doc any
		if err := json.Unmarshal(b, &doc); err != nil {
			return fmt.Errorf("%s: %w", p, err)
		}
		var collect func(any)
		collect = func(v any) {
			switch x := v.(type) {
			case map[string]any:
				// OID-typed NAMES and OID-typed VALUES both reach encodeOID,
				// so a corpus of names alone would skip the sysObjectID value,
				// which is the surface nl6#529 is about.
				//
				// Whether a value is an OID is decided by its sibling "oid"
				// key through snmpTypeTag, exactly as the production encoder
				// decides it. A string-shape test cannot: an IPv4 address like
				// "10.0.0.1" is digits and dots too, and is stored as the
				// response of an ipAdEntAddr leaf that goes to encodeIPAddress,
				// never to encodeOID. Sweeping those in made this test report a
				// digest change that no production path would ever produce.
				name, _ := x["oid"].(string)
				for k, vv := range x {
					if str, ok := vv.(string); ok {
						switch k {
						case "oid", "snmpTrapOID", "snmpTrapEnterprise":
							seen[str] = true
						case "response":
							if name != "" && snmpTypeTag(normaliseOIDKey(name)) == ASN1_OBJECT_ID {
								seen[str] = true
							}
						case "value":
							// A trap varbind VALUE declared "oid" goes through
							// appendOID too. No shipped catalog uses that type
							// today, so this adds nothing to the digest yet; it
							// is here so a future one is pinned.
							if typ, _ := x["type"].(string); typ == "oid" {
								seen[str] = true
							}
						}
					}
					collect(vv)
				}
			case []any:
				for _, vv := range x {
					collect(vv)
				}
			}
		}
		collect(doc)
		return nil
	})
	if err != nil {
		t.Fatalf("walking resources: %v", err)
	}
	out := make([]string, 0, len(seen))
	for k := range seen {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// FuzzOIDRoundTrip holds the two invariants the fixed-case tables above cannot:
// the encoders agree byte for byte on ARBITRARY input, and anything encodeOID
// accepts decodes back to itself. Parity alone is not enough, since both
// encoders were changed together during nl6#523 and stayed green over a
// fabricated OID.
func FuzzOIDRoundTrip(f *testing.F) {
	for _, seed := range []string{
		"1.3.6.1.4.1.9.1.1", "2.999", "3.40.1", "1.40.1", "2.175.1", "2.87.1",
		"0.39", "2.39", "1.3", "unknown", "1.3.x.7", "", ".", "1.", "..",
		"1.2.4294967295", "1.2.4294967296", strings.Repeat("1.", 200) + "1",
	} {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, oid string) {
		enc := encodeOID(oid)
		if fast := appendOID(nil, oid); string(fast) != string(enc) {
			t.Fatalf("encoder divergence for %q: encodeOID % x != appendOID % x", oid, enc, fast)
		}
		if len(enc) < 2 || enc[0] != ASN1_OID {
			t.Fatalf("encodeOID(%q) did not produce an OBJECT IDENTIFIER: % x", oid, enc)
		}
		if len(enc) == 2 && enc[1] == 0x00 {
			return // degenerate encoding, nothing to round-trip
		}
		body, ok := oidBody(t, enc)
		if !ok {
			t.Fatalf("encodeOID(%q) produced an undecodable TLV: % x", oid, enc)
		}
		if got, want := decodeOID(body), canonicalOID(oid); got != want {
			t.Fatalf("round-trip failed for %q: encoded % x, decoded %q, want %q", oid, enc, got, want)
		}
	})
}

// TestAppendOIDErrorPathUnwinds pins that appendOID's rejection path truncates
// back past the tag it already wrote WITHOUT corrupting bytes that were already
// in dst. FuzzOIDRoundTrip only ever calls it with a nil dst, but the real
// callers (trap_encode_fast.go, trap_precompute.go) append into a buffer that
// already holds a partly-built PDU, so a wrong unwind would corrupt the
// varbinds before it rather than just this OID.
func TestAppendOIDErrorPathUnwinds(t *testing.T) {
	prefix := []byte{0xAA, 0xBB, 0xCC}

	for _, oid := range []string{
		"1.3.x.7", "3.40.1", "1.40.1", "2.7000000000", "1.", "unknown", "", "1.2.4294967296",
		"1.3.6.1.4.1.9.1.1", "2.999", // accepted ones must be unaffected too
	} {
		dst := append([]byte(nil), prefix...)
		got := appendOID(dst, oid)

		if !bytes.HasPrefix(got, prefix) {
			t.Errorf("appendOID(%q) corrupted the bytes already in dst: % x", oid, got)
			continue
		}
		if tail, want := got[len(prefix):], encodeOID(oid); !bytes.Equal(tail, want) {
			t.Errorf("appendOID(%q) wrote % x after the prefix, but encodeOID produced % x", oid, tail, want)
		}
	}
}

// normaliseOIDKey adds the leading dot buildResourceIndexes adds before any
// oidTypeTable lookup, so snmpTypeTag sees the same string production does.
func normaliseOIDKey(oid string) string {
	if oid == "" || oid[0] == '.' {
		return oid
	}
	return "." + oid
}

// ── independent conformance ─────────────────────────────────────────────────

// TestOIDEncodingMatchesEncodingASN1 is the only check here that does not
// consist of nl6 verifying nl6.
//
// The bug this change fixes was two nl6 functions agreeing with each other
// while both disagreed with X.690: encodeOID emitted a single byte and
// decodeOID read a single byte back, so every round-trip and parity test in
// the package would have passed over a fabricated OID. Go's encoding/asn1 is
// an independent implementation of the same standard, so comparing against it
// pins conformance rather than self-consistency, and it is what would have
// caught the original defect.
func TestOIDEncodingMatchesEncodingASN1(t *testing.T) {
	cases := []string{
		"1.3.6.1.4.1.9.1.1",
		"1.3.6.1.2.1.1.1.0",
		"0.0", "0.39", "1.0", "1.39", "2.0", "2.39", "2.40", "2.100",
		"2.999",   // ITU test arc: two-byte first sub-identifier
		"2.87.1",  // fabricated before nl6#529
		"2.175.1", // fabricated before nl6#529
		"1.2.127", // arc at the one-byte varint boundary
		"1.2.128", // arc just over it
		"1.2.16383", "1.2.16384",
		"1.2.4294967295",       // SMI maximum arc
		"1.0.8802.1.1.2.1.3.2", // LLDP, a real second-arc-0 OID
	}

	for _, in := range cases {
		t.Run(in, func(t *testing.T) {
			var ref asn1.ObjectIdentifier
			for _, p := range strings.Split(in, ".") {
				v, err := strconv.Atoi(p)
				if err != nil {
					t.Fatalf("bad test case %q", in)
				}
				ref = append(ref, v)
			}

			want, err := asn1.Marshal(ref)
			if err != nil {
				// Every case is marshalable; a failure here is a bad table
				// entry, and skipping would silently weaken the only check in
				// this file that is not nl6 verifying nl6.
				t.Fatalf("encoding/asn1 cannot marshal %q: %v", in, err)
			}
			if got := encodeOID(in); !bytes.Equal(got, want) {
				t.Errorf("encodeOID(%q) = % x, encoding/asn1 says % x", in, got, want)
			}
			if got := appendOID(nil, in); !bytes.Equal(got, want) {
				t.Errorf("appendOID(%q) = % x, encoding/asn1 says % x", in, got, want)
			}

			// And decode agrees with the reference in the other direction,
			// where the reference can go there at all: encoding/asn1 decodes
			// arcs into an int with a narrower bound than it will marshal, so
			// it refuses its OWN output for a full-width 2^32-1 arc. That is a
			// limitation of the reference, not of nl6, so the encode-direction
			// comparison above still stands and only this half is skipped.
			var back asn1.ObjectIdentifier
			if _, err := asn1.Unmarshal(want, &back); err != nil {
				t.Logf("encoding/asn1 will not unmarshal its own output for %q (%v); "+
					"encode-direction conformance already checked above", in, err)
				return
			}
			body, ok := oidBody(t, want)
			if !ok {
				t.Fatalf("could not take the body of % x", want)
			}
			if got := decodeOID(body); got != "."+back.String() {
				t.Errorf("decodeOID(% x) = %q, encoding/asn1 says %q", body, got, "."+back.String())
			}
		})
	}
}

// FuzzDecodeOID drives decodeOID on ARBITRARY bytes, which FuzzOIDRoundTrip
// structurally cannot: that one only ever feeds it the encoder's own output.
// decodeOID parses attacker-supplied request bytes at three sites
// (snmp_handlers.go, snmp.go, snmp_response.go), and this package's stated
// policy is a fuzz target per network-facing parser.
//
// The invariants: it never panics, and whatever it accepts must be something
// the encoder agrees on, so a hostile input cannot produce an OID string that
// does not correspond to the bytes that produced it.
func FuzzDecodeOID(f *testing.F) {
	f.Add([]byte{0x2b, 0x06, 0x01})
	f.Add([]byte{0x2b, 0xff})                   // unterminated
	f.Add([]byte{0x80, 0x2b})                   // non-minimal
	f.Add([]byte{0xff})                         // unterminated first sub-identifier
	f.Add([]byte{0x88, 0x37})                   // 2.999
	f.Add([]byte{})                             // empty
	f.Add([]byte{0x00})                         // 0.0
	f.Add([]byte{0x8f, 0xff, 0xff, 0xff, 0x7f}) // at the 2^32-1 boundary

	f.Fuzz(func(t *testing.T, body []byte) {
		got := decodeOID(body) // must not panic
		if got == "" {
			return
		}
		if !strings.HasPrefix(got, ".") {
			t.Fatalf("decodeOID(% x) = %q, which is not dotted form", body, got)
		}
		if strings.Contains(got, "-") {
			t.Fatalf("decodeOID(% x) = %q, which contains a negative arc", body, got)
		}
		// Anything accepted must re-encode to the exact bytes it came from.
		// This is what makes acceptance meaningful: a decoder that invents a
		// plausible OID for hostile bytes would pass every check above.
		if re := encodeOID(got); len(re) < 2 {
			t.Fatalf("decodeOID accepted % x as %q, but encodeOID refuses it", body, got)
		} else if reBody, ok := oidBody(t, re); !ok || !bytes.Equal(reBody, body) {
			t.Fatalf("decodeOID(% x) = %q, but that re-encodes to % x", body, got, reBody)
		}
	})
}

func truncateForLog(s string) string {
	if len(s) <= 60 {
		return s
	}
	return s[:60] + "..."
}

// TestOIDBodyBoundIsSharedByBothEncoders pins maxOIDBodyBytes at its edge:
// a body of exactly 0xFFFF bytes is encoded by both encoders, one byte more
// is refused by both. Above the bound encodeLength would write a three-octet
// length that appendOID's two-octet rewrite cannot, so the two would diverge.
func TestOIDBodyBoundIsSharedByBothEncoders(t *testing.T) {
	// 2^32-1 is a five-byte varint; the first sub-identifier "1.3" is one.
	const wide = "4294967295"
	build := func(bodyLen int) string {
		var sb strings.Builder
		sb.WriteString("1.3")
		body := 1
		for body+5 <= bodyLen {
			sb.WriteString("." + wide)
			body += 5
		}
		for body < bodyLen {
			sb.WriteString(".1")
			body++
		}
		return sb.String()
	}
	degenerate := []byte{ASN1_OID, 0x00}

	at := build(maxOIDBodyBytes)
	enc := encodeOID(at)
	if bytes.Equal(enc, degenerate) {
		t.Fatalf("encodeOID refused a body of exactly %d bytes", maxOIDBodyBytes)
	}
	if body, ok := oidBody(t, enc); !ok || len(body) != maxOIDBodyBytes {
		t.Fatalf("encodeOID at the bound: body length %d, want %d", len(body), maxOIDBodyBytes)
	}
	if fast := appendOID(nil, at); !bytes.Equal(fast, enc) {
		t.Fatalf("encoders disagree at the bound: encodeOID %d bytes, appendOID %d bytes", len(enc), len(fast))
	}

	over := build(maxOIDBodyBytes + 1)
	if enc := encodeOID(over); !bytes.Equal(enc, degenerate) {
		t.Fatalf("encodeOID accepted a body of %d bytes: % x...", maxOIDBodyBytes+1, enc[:4])
	}
	if fast := appendOID(nil, over); !bytes.Equal(fast, degenerate) {
		t.Fatalf("appendOID accepted a body of %d bytes: % x...", maxOIDBodyBytes+1, fast[:4])
	}
}

// TestRePinIsOnlyTheDeletedOID makes the re-pin above self-proving rather than
// a claim in a comment. This repo's rule is that the number is the evidence, so
// the "only cause is one deleted OID" statement is re-derived here: put
// 1.3.6.1.2.1.4.21.1.1 back into the corpus and the 09546c3 digest must return
// exactly. It can only return if every other shipped OID still encodes to the
// same bytes it did then, which is the compatibility claim the re-pin rests on.
func TestRePinIsOnlyTheDeletedOID(t *testing.T) {
	const deleted = "1.3.6.1.2.1.4.21.1.1"

	// This walks the WHOLE chain: every corpus-editing change since 09546c3 is
	// undone, newest first, including nl6#541's own deletion of the OID above.
	// Each stage is pinned separately by its own ledger
	// (TestOctetShadowRePinIsOnlyTheDeletedOIDs,
	// TestResourceDataDefectRePinIsOnlyTheDeletedOIDs, …); this test walks the
	// whole way back, which is what keeps the chain from being provable only in
	// pieces. The walk is fatal if any restored name is shipped again, which is
	// the re-pin's premise.
	restored := restoreCorpusOIDNamesTo(t, collectShippedOIDs(t), dataEditsParentRevision)
	sort.Strings(restored)

	h := sha256.New()
	checked := 0
	for _, oid := range restored {
		if strings.Contains(oid, "{{") {
			continue
		}
		checked++
		// hash.Hash.Write never returns an error, but errcheck cannot know that.
		_, _ = fmt.Fprintf(h, "%s=%x\n", oid, encodeOID(oid))
	}
	got := fmt.Sprintf("%x", h.Sum(nil))

	if got != shippedOIDEncodingDigestAt09546c3 {
		t.Errorf("restoring %s and nl6#570's octet columns gives digest %s, want the 09546c3 value %s over %d OIDs.\n"+
			"So the re-pin of shippedOIDEncodingDigest is NOT explained by that deletion alone: "+
			"something else about what a shipped OID puts on the wire has changed.",
			deleted, got, shippedOIDEncodingDigestAt09546c3, checked)
	}
	t.Logf("%d OIDs with %s and nl6#570's octet columns restored reproduce the 09546c3 digest",
		checked, deleted)
}
