/*
 * Copyright 2026 Ronny Trommer <ronny@no42.org>
 * SPDX-License-Identifier: Apache-2.0
 */

package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

// The SNMP request path is a hand-written BER parser reached by any datagram
// that lands on a device's UDP port, and every device in the fleet runs in one
// process. A panic there is not a per-device fault: it unwinds the shared
// listener goroutine and takes all 30k simulated devices with it, mid-run,
// which is exactly when a benchmark or a collector test is depending on them.
//
// The fuzz targets below are the durable guard. Their seed corpora are the
// concrete inputs that crashed each parser before this file existed, and `go
// test` replays every seed on a normal run — so these double as regression
// tests without needing a checked-in binary corpus.

func robustnessTestServer() *SNMPServer {
	return &SNMPServer{
		device:   &DeviceSimulator{ID: "robustness-test"},
		v3Config: &SNMPv3Config{Enabled: true},
	}
}

// crashers holds one reproducer per parser, kept next to the parser it broke.
var (
	// Ten bytes: the OCTET STRING tag lands as the final byte, so reading the
	// community length byte after it runs one past the end.
	crasherGetPDUType = []byte{0x30, 0x08, 0x02, 0x84, 0x00, 0x00, 0x00, 0x00, 0x00, 0x04}

	// Declares a one-byte version and then ends, so the version read has
	// nothing to read.
	crasherIsSNMPv3 = []byte{0x30, 0x84, 0x30, 0x30, 0x30, 0x30, 0x02, 0x84, 0x00, 0x00, 0x00, 0x01}

	// scopedPduData declares more bytes than the datagram carries.
	crasherParseV3 = []byte{
		0x30, 0x30, 0x02, 0x01, 0x03, 0x30, 0x30, 0x02, 0x00, 0x02,
		0x00, 0x04, 0x01, 0x30, 0x02, 0x04, 0x30, 0x30, 0x30, 0x30,
	}

	// Well formed down to the OID tag, then a long-form length parseLength
	// refuses (five length bytes). The refusal is -1, and slicing with it
	// inverts the range.
	crasherScopedPDU = []byte{
		0x04, 0x00, // contextEngineID, empty
		0x04, 0x00, // contextName, empty
		0xA0, 0x20, // GetRequest
		0x02, 0x01, 0x01, // request-id
		0x02, 0x01, 0x00, // error-status
		0x02, 0x01, 0x00, // error-index
		0x30, 0x12, // varbind list
		0x30, 0x10, // varbind
		0x06, 0x85, 0x00, 0x00, 0x00, 0x00, 0x00, // OID, unparseable length
	}
)

func TestSNMPParsers_MalformedDatagramsDoNotPanic(t *testing.T) {
	s := robustnessTestServer()

	// Shapes that broke a parser, plus the degenerate lengths every hand-written
	// BER parser gets wrong at least once.
	packets := map[string][]byte{
		"getPDUType community-tag-at-end": crasherGetPDUType,
		"isSNMPv3Request truncated":       crasherIsSNMPv3,
		"parseSNMPv3Message overrun":      crasherParseV3,
		"scopedPDU unparseable oid len":   crasherScopedPDU,
		"empty":                           {},
		"single byte":                     {0x30},
		"sequence tag only":               {0x30, 0x82},
		"truncated long-form length":      {0x30, 0x82, 0x00, 0x10, 0x02, 0x01, 0x00, 0x04},
	}

	for name, pkt := range packets {
		t.Run(name, func(t *testing.T) {
			// No recover() here on purpose. A panic must fail this test rather
			// than be absorbed, because the production path has no recover
			// either — the parsers are expected to be total.
			s.getPDUType(pkt)
			s.parseIncomingRequest(pkt)
			_, _ = s.parseAllOIDsFromRequest(pkt)
			isSNMPv3Request(pkt)
			_, _ = s.parseSNMPv3Message(pkt)
			_, _, _ = s.extractOIDAndTypeFromScopedPDU(pkt)
		})
	}
}

// validScopedPDU builds a GetRequest scoped PDU with the package's own
// encoders. Hand-counting the nested lengths is how a "valid packet" test ends
// up asserting against a packet that is not actually valid.
func validScopedPDU(oid string) []byte {
	varbind := encodeSequence(append(encodeOID(oid), encodeNull()...))
	varbindList := encodeSequence(varbind)

	var pduBody []byte
	pduBody = append(pduBody, encodeInteger(1)...) // request-id
	pduBody = append(pduBody, encodeInteger(0)...) // error-status
	pduBody = append(pduBody, encodeInteger(0)...) // error-index
	pduBody = append(pduBody, varbindList...)

	var pdu []byte
	pdu = append(pdu, ASN1_GET_REQUEST)
	pdu = append(pdu, encodeLength(len(pduBody))...)
	pdu = append(pdu, pduBody...)

	var scoped []byte
	scoped = append(scoped, encodeOctetString("")...) // contextEngineID
	scoped = append(scoped, encodeOctetString("")...) // contextName
	scoped = append(scoped, pdu...)
	return scoped
}

func TestExtractOIDAndTypeFromScopedPDU_ValidRequestStillParses(t *testing.T) {
	const want = ".1.3.6.1.2.1.1.1.0"

	oid, pduType, err := robustnessTestServer().extractOIDAndTypeFromScopedPDU(validScopedPDU(want))
	if err != nil {
		t.Fatalf("valid scoped PDU rejected: %v", err)
	}
	if oid != want {
		t.Errorf("oid = %q, want %q", oid, want)
	}
	if pduType != ASN1_GET_REQUEST {
		t.Errorf("pduType = 0x%02X, want 0x%02X", pduType, ASN1_GET_REQUEST)
	}
}

func TestGetPDUType_LongFormCommunityLength(t *testing.T) {
	// A community string of 128 bytes or more encodes its length in long
	// form. Reading that length as a single raw byte lands the cursor in the
	// middle of the community and reports whatever byte is there as the PDU
	// type, so a legitimate GETNEXT gets answered as a GET.
	community := string(bytes.Repeat([]byte("c"), 200))

	var body []byte
	body = append(body, encodeInteger(1)...) // version = v2c
	body = append(body, encodeOctetString(community)...)

	var pdu []byte
	pdu = append(pdu, ASN1_GET_NEXT)
	pdu = append(pdu, encodeLength(0)...)
	body = append(body, pdu...)

	if got := robustnessTestServer().getPDUType(encodeSequence(body)); got != ASN1_GET_NEXT {
		t.Errorf("pduType = 0x%02X, want 0x%02X (GETNEXT behind a long-form community length)", got, ASN1_GET_NEXT)
	}
}

func TestSNMPv3Config_Validate(t *testing.T) {
	tests := []struct {
		name    string
		cfg     *SNMPv3Config
		wantErr bool
	}{
		{"nil config", nil, false},
		{"disabled", &SNMPv3Config{Enabled: false}, false},
		{"privacy off, no password", &SNMPv3Config{Enabled: true, PrivProtocol: SNMPV3_PRIV_NONE}, false},
		{"privacy on, priv password", &SNMPv3Config{Enabled: true, PrivProtocol: SNMPV3_PRIV_AES128, PrivPassword: "s3cret"}, false},
		{"privacy on, auth password only", &SNMPv3Config{Enabled: true, PrivProtocol: SNMPV3_PRIV_DES, Password: "s3cret"}, false},
		{"privacy on, no password", &SNMPv3Config{Enabled: true, PrivProtocol: SNMPV3_PRIV_AES128}, true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if err := tt.cfg.Validate(); (err != nil) != tt.wantErr {
				t.Errorf("Validate() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestPrivacyKeyDerivation_EmptyPasswordYieldsNoKey(t *testing.T) {
	// Reaching key derivation with an empty password used to divide by zero.
	// nil is the correct answer: aes.NewCipher and des.NewCipher reject it
	// with a KeySizeError the callers already handle, whereas a zero-filled
	// key of the right length would encrypt under a key nobody configured.
	s := &SNMPServer{v3Config: &SNMPv3Config{Enabled: true, PrivProtocol: SNMPV3_PRIV_AES128}}

	if key := s.generateAESKey(""); key != nil {
		t.Errorf("generateAESKey(\"\") = %v, want nil", key)
	}
	if key := s.generateDESKey(); key != nil {
		t.Errorf("generateDESKey() with empty passwords = %v, want nil", key)
	}
}

// addGoldenV2cSeeds registers the real-client captures from
// snmp_golden_packets_test.go as fuzz seeds. Each crasher seed above is a
// malformed input; these are well-formed datagrams encoded by third-party
// stacks, so mutations start from shapes nl6's own encoders never produce
// (a zero-length community, a long-form community length).
func addGoldenV2cSeeds(f *testing.F) {
	f.Add(goldenNetSNMPEmptyCommunity)
	f.Add(goldenNetSNMPLongCommunity)
}

// addMalformedVarbindSeeds registers datagrams whose varbind LIST is present
// but not a valid ASN.1 encoding, so the nl6#537 discard branch (and the
// GETNEXT gate that feeds it) is replayed on every ordinary go test rather
// than reached by chance.
func addMalformedVarbindSeeds(f *testing.F) {
	for _, pkt := range malformedSeedDatagrams() {
		f.Add(pkt)
	}
}

func FuzzGetPDUType(f *testing.F) {
	f.Add(crasherGetPDUType)
	f.Add([]byte{0x30, 0x05, 0x02, 0x01, 0x00, 0x04})
	addGoldenV2cSeeds(f)
	addAgreementSeeds(f)
	f.Fuzz(func(t *testing.T, data []byte) {
		s := robustnessTestServer()
		s.getPDUType(data)
		assertV2cParserAgreement(t, s, data)
	})
}

func FuzzParseIncomingRequest(f *testing.F) {
	f.Add(crasherGetPDUType)
	addGoldenV2cSeeds(f)
	addAgreementSeeds(f)
	f.Fuzz(func(t *testing.T, data []byte) {
		s := robustnessTestServer()
		s.parseIncomingRequest(data)
		assertV2cParserAgreement(t, s, data)
	})
}

func FuzzParseAllOIDsFromRequest(f *testing.F) {
	f.Add(crasherGetPDUType)
	addGoldenV2cSeeds(f)
	addMalformedVarbindSeeds(f)
	addAgreementSeeds(f)
	f.Fuzz(func(t *testing.T, data []byte) {
		s := robustnessTestServer()
		_, _ = s.parseAllOIDsFromRequest(data)
		assertV2cParserAgreement(t, s, data)
		// This target owns addMalformedVarbindSeeds, so it is where the
		// discard claim's guard is actually reached by committed seeds
		// (nl6#534 review R14).
		assertMalformedListIsDiscarded(t, s, data)
	})
}

func FuzzIsSNMPv3Request(f *testing.F) {
	f.Add(crasherIsSNMPv3)
	addAgreementSeeds(f)
	f.Fuzz(func(t *testing.T, data []byte) {
		isSNMPv3Request(data)
		// This target's own subject is the v3 discriminator, so most of what
		// it generates is not a v1/v2c request at all — the agreement helper
		// self-skips those. It is wired anyway because its input IS a raw
		// datagram and the claims cost nothing on a skip (nl6#534 review R5).
		assertV2cParserAgreement(t, robustnessTestServer(), data)
	})
}

func FuzzParseSNMPv3Message(f *testing.F) {
	f.Add(crasherParseV3)
	f.Fuzz(func(_ *testing.T, data []byte) { _, _ = robustnessTestServer().parseSNMPv3Message(data) })
}

func FuzzExtractOIDAndTypeFromScopedPDU(f *testing.F) {
	f.Add(crasherScopedPDU)
	f.Add(validScopedPDU(".1.3.6.1.2.1.1.1.0"))
	f.Fuzz(func(_ *testing.T, data []byte) {
		_, _, _ = robustnessTestServer().extractOIDAndTypeFromScopedPDU(data)
	})
}

// ── nl6#513: Tier 0 — leaf parsers, no fixture ───────────────────────────────
//
// Added by the parser-family measurement spike. nl6#512 fuzzed six parsers,
// which is a small share of the package's 57 parseLength/skipLength call
// sites, and nobody knew whether the panic class it fixed recurs elsewhere.
// These targets exist to produce that number, not to fix anything: a crasher
// found here is recorded and filed, and the fuzzing continues.
//
// Tier 0 targets take a zero-value receiver or are free functions, so they run
// at full speed with no device fixture.

// FuzzParseAck drives the INFORM acknowledgement parser. It is the issue's
// "start here": six parseLength sites, never fuzzed, and reachable by anyone
// who can send nl6 a UDP datagram from a spoofed collector address. nl6#501
// hand-fixed A panic here and nothing established it was the only one.
func FuzzParseAck(f *testing.F) {
	f.Add([]byte{})
	f.Add([]byte{0xA2})
	f.Add([]byte{0x30, 0x08, 0x02, 0x84, 0x00, 0x00, 0x00, 0x00, 0x00, 0x04}) // crasherGetPDUType shape
	// A well-formed GetResponse ack, so mutation starts from something the
	// parser accepts rather than from bytes rejected at offset 0.
	f.Add(validInformAck(42))
	f.Fuzz(func(_ *testing.T, pkt []byte) {
		enc := &SNMPv2cEncoder{}
		_, _, _ = enc.ParseAck(pkt)
	})
}

// validInformAck builds a minimal GetResponse-PDU acknowledgement.
func validInformAck(reqID int) []byte {
	var pduBody []byte
	pduBody = append(pduBody, encodeInteger(reqID)...)
	pduBody = append(pduBody, encodeInteger(0)...) // error-status
	pduBody = append(pduBody, encodeInteger(0)...) // error-index
	pduBody = append(pduBody, encodeSequence(nil)...)
	pdu := append([]byte{SNMP_GET_RESPONSE}, append(encodeLength(len(pduBody)), pduBody...)...)
	var msg []byte
	msg = append(msg, encodeInteger(snmpVersion2c)...)
	msg = append(msg, encodeOctetString("public")...)
	msg = append(msg, pdu...)
	return encodeSequence(msg)
}

// FuzzParseGetBulkParams drives the non-repeaters / max-repetitions parser.
// It has the `pos = newPos + verLen` shape with no `< 0` guard, twice, which
// is the exact shape nl6#512 found crashing elsewhere. Its only s.device
// reference sits inside a commented-out log line, so no fixture is needed.
func FuzzParseGetBulkParams(f *testing.F) {
	f.Add(crasherGetPDUType)
	f.Add(buildGetBulkPDUForFuzz(0, 10, ".1.3.6.1.2.1.1.1.0"))
	addGoldenV2cSeeds(f)
	addAgreementSeeds(f)
	f.Fuzz(func(t *testing.T, data []byte) {
		// A zero-value receiver is enough: every parser the agreement helper
		// drives reaches only s.skipLength, which touches no field.
		s := &SNMPServer{}
		_, _ = s.parseGetBulkParams(data)
		assertV2cParserAgreement(t, s, data)
	})
}

func buildGetBulkPDUForFuzz(nonRepeaters, maxRepetitions int, oid string) []byte {
	vb := encodeSequence(append(encodeOID(oid), encodeNull()...))
	var pduContents []byte
	pduContents = append(pduContents, encodeInteger(42)...)
	pduContents = append(pduContents, encodeInteger(nonRepeaters)...)
	pduContents = append(pduContents, encodeInteger(maxRepetitions)...)
	pduContents = append(pduContents, encodeSequence(vb)...)
	pdu := append([]byte{ASN1_GET_BULK}, append(encodeLength(len(pduContents)), pduContents...)...)
	var msg []byte
	msg = append(msg, encodeInteger(snmpVersion2c)...)
	msg = append(msg, encodeOctetString("public")...)
	msg = append(msg, pdu...)
	return encodeSequence(msg)
}

// FuzzParseUSMSecurityParameters makes no use of its receiver at all.
func FuzzParseUSMSecurityParameters(f *testing.F) {
	f.Add(crasherParseV3)
	f.Add([]byte{0x30, 0x00})
	f.Fuzz(func(_ *testing.T, data []byte) {
		_ = (&SNMPServer{}).parseUSMSecurityParameters(data, &SNMPv3SecurityParams{})
	})
}

// FuzzParseIntegerAndOctetString drives the two SNMPv3 primitives directly.
// nl6#512 reached them incidentally through its own targets; nothing has ever
// driven them with a position that is already out of range, which is how a
// caller reaches them after a length has gone wrong upstream.
func FuzzParseIntegerAndOctetString(f *testing.F) {
	f.Add([]byte{0x02, 0x01, 0x00}, 0)
	f.Add([]byte{0x04, 0x03, 'a', 'b', 'c'}, 0)
	f.Add([]byte{0x02, 0x84, 0x00, 0x00, 0x00, 0x00}, 0)
	f.Add([]byte{}, 5)
	f.Add([]byte{0x04, 0xff}, 0)
	f.Fuzz(func(_ *testing.T, data []byte, pos int) {
		// A negative position is not a parser input any caller produces; it
		// would only mask the out-of-range cases that matter. Bitwise NOT
		// rather than negation: -math.MinInt overflows and stays negative,
		// which would make the harness itself report a crasher.
		if pos < 0 {
			pos = ^pos
		}
		_, _, _ = parseInteger(data, pos)
		_, _, _ = parseOctetString(data, pos)
	})
}

// FuzzParseLengthInvariants fuzzes parseLength for an INVARIANT rather than a
// panic, because parseLength is total by inspection and the interesting
// question is the contract its 57 call sites rely on:
//
//	length >= -1              -1 is the only sentinel
//	newPos >= pos             a caller that advances never moves backwards
//	success => newPos in range the returned position is safe to slice from
//
// The middle one is the whole nl6#512 bug class: -1 passes an upper-bound
// check (`pos+n > len(buf)` is false for n == -1), so every call site needs an
// explicit `< 0` arm. If parseLength could return any other negative value,
// that guidance would be incomplete.
func FuzzParseLengthInvariants(f *testing.F) {
	f.Add([]byte{0x05}, 0)
	f.Add([]byte{0x84, 0x00, 0x00, 0x00, 0x00}, 0)
	f.Add([]byte{0xff}, 0)
	f.Add([]byte{}, 0)
	f.Add([]byte{0x81}, 0)
	f.Fuzz(func(t *testing.T, data []byte, pos int) {
		if pos < 0 {
			pos = ^pos // not -pos: see FuzzParseIntegerAndOctetString
		}
		length, newPos := parseLength(data, pos)

		if length < -1 {
			t.Fatalf("parseLength(% x, %d) = length %d: -1 is the only negative sentinel, "+
				"so a caller's `< 0` guard is the documented contract", data, pos, length)
		}
		if newPos < pos {
			t.Fatalf("parseLength(% x, %d) moved the position backwards to %d", data, pos, newPos)
		}
		// NOT asserted: that newPos+length fits the buffer. parseLength reports
		// the length the BER header DECLARES; checking it against the buffer is
		// the caller's job, and every call site does exactly that. Asserting it
		// here would be asserting a contract parseLength does not have.
		//
		// What IS its contract: if it reports success, the position it returns
		// must be inside the buffer, or a caller slicing from newPos panics
		// even with the `< 0` guard nl6#512 added everywhere.
		if length >= 0 && newPos > len(data) {
			t.Fatalf("parseLength(% x, %d) succeeded with length %d but returned position %d, "+
				"past the %d-byte buffer: a caller slicing from there panics even with a `< 0` guard",
				data, pos, length, newPos, len(data))
		}
	})
}

// ── nl6#513: Tier 1 — device fixture ─────────────────────────────────────────
//
// These need a device with a resource index. The fixture is built PER
// EXECUTION, deliberately: lldpServedCache persists on SNMPServer, so a
// hoisted fixture makes run n cheaper than run 1 and the rate measurement
// would be measuring the cache rather than the parser. len(oidValues) is the
// cost knob the spike varies.

// fuzzFixtureOIDs returns an OID set of roughly the requested size.
func fuzzFixtureOIDs(n int) map[string]string {
	vals := make(map[string]string, n)
	if n == 0 {
		return vals
	}
	vals[".1.3.6.1.2.1.1.1.0"] = "fuzz device"
	for i := 1; len(vals) < n; i++ {
		vals[fmt.Sprintf(".1.3.6.1.2.1.2.2.1.2.%d", i)] = fmt.Sprintf("Gi0/%d", i)
		vals[fmt.Sprintf(".1.3.6.1.2.1.2.2.1.5.%d", i)] = "1000000000"
		vals[fmt.Sprintf(".1.3.6.1.2.1.31.1.1.1.6.%d", i)] = "123456789"
	}
	return vals
}

// fuzzFixtureSize lets the nl6#513 rate measurement vary the fixture without
// committing several near-identical targets. It defaults to the size the
// committed targets use, so an ordinary `go test` and CI are unaffected.
func fuzzFixtureSize(dflt int) int {
	if v := os.Getenv("NL6_FUZZ_FIXTURE_OIDS"); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n >= 0 {
			return n
		}
	}
	return dflt
}

// fuzzTestServer is the Tier 1 fixture: n OIDs plus a noAuthNoPriv v3 user.
// Auth is NONE deliberately, so a fuzz input that reaches the scoped PDU is
// not first discarded by an HMAC it cannot forge. The cost is stated plainly:
// the auth and priv branches of validateSNMPv3Credentials and the decrypt
// path are NOT exercised by any target driven from this server, and the
// pinned-scoped targets (FuzzHandleSNMPv3GetBulkScoped,
// FuzzCreateSNMPv3Response) bypass credential validation altogether. The
// decrypt path has its own target, FuzzHandleSNMPv3RequestPriv, on a
// privacy-enabled server.
func fuzzTestServer(n int) *SNMPServer {
	n = fuzzFixtureSize(n)
	s := newTestServer(fuzzFixtureOIDs(n))
	s.v3Config = &SNMPv3Config{
		Enabled:      true,
		EngineID:     "0x80001234",
		Username:     "fuzzuser",
		Password:     "s3cretpassword",
		AuthProtocol: SNMPV3_AUTH_NONE,
		PrivProtocol: SNMPV3_PRIV_NONE,
	}
	return s
}

// addValidV3Seeds adds the v3 datagrams nl6#513 requires as Tier 2 seeds: a
// discovery message (empty engine ID and user, RFC 3414 §4), a noAuthNoPriv
// GET the fixture's user accepts, and the discovery probe with its scoped PDU
// wrapped as an OCTET STRING, which is the shape an encrypted (authPriv)
// message has on the wire. Every crasher seed is rejected by
// parseSNMPv3Message before it reaches the USM or scoped-PDU length reads, so
// without these the v3 targets gated on a successful parse never call the
// function they are named after on an ordinary `go test`, and the encrypted
// branch's length read is never executed at all.
func addValidV3Seeds(f *testing.F) {
	s := fuzzTestServer(0)
	f.Add(v3DiscoveryRequest(f, s, false))
	f.Add(v3RequestAt(f, s, ASN1_GET_REQUEST, 7, ".1.3.6.1.2.1.1.1.0"))
	f.Add(v3DiscoveryRequest(f, s, true))
}

// v3DiscoveryRequest builds the engine-ID discovery probe a manager sends
// first: USM parameters with empty engine ID and user name, and a scoped PDU
// carrying an empty GET. With encryptedShape the scoped PDU goes out as an
// OCTET STRING instead of a SEQUENCE; the content is still plaintext, which
// is enough to drive the parser's encrypted branch and nothing past it.
func v3DiscoveryRequest(tb testing.TB, s *SNMPServer, encryptedShape bool) []byte {
	tb.Helper()
	var pduBody []byte
	pduBody = append(pduBody, encodeInteger(1)...)
	pduBody = append(pduBody, encodeInteger(0)...)
	pduBody = append(pduBody, encodeInteger(0)...)
	pduBody = append(pduBody, encodeSequence(nil)...)
	pdu := append([]byte{ASN1_GET_REQUEST}, append(encodeLength(len(pduBody)), pduBody...)...)
	var scoped []byte
	scoped = append(scoped, encodeOctetString("")...)
	scoped = append(scoped, encodeOctetString("")...)
	scoped = append(scoped, pdu...)
	scopedPDU := encodeSequence(scoped)
	if encryptedShape {
		scopedPDU = encodeOctetString(string(scopedPDU))
	}
	usm, err := s.encodeUSMSecurityParameters(&SNMPv3SecurityParams{})
	if err != nil {
		tb.Fatalf("encodeUSMSecurityParameters: %v", err)
	}
	req, err := s.encodeSNMPv3Message(&SNMPv3Message{
		Version: SNMPV3_VERSION,
		GlobalData: SNMPv3GlobalData{
			MsgID:            1,
			MsgMaxSize:       65507,
			MsgFlags:         SNMPV3_MSG_FLAG_REPORT,
			MsgSecurityModel: SNMPV3_SECURITY_MODEL_USM,
		},
		ScopedPDU: scopedPDU,
	}, usm)
	if err != nil {
		tb.Fatalf("encodeSNMPv3Message: %v", err)
	}
	return req
}

func FuzzHandleGetBulk(f *testing.F) {
	f.Add(crasherGetPDUType)
	f.Add(buildGetBulkPDUForFuzz(0, 10, ".1.3.6.1.2.1.1.1.0"))
	addGoldenV2cSeeds(f)
	addAgreementSeeds(f)
	// WIRED to assertV2cParserAgreement as of nl6#560. It was the one
	// raw-datagram target left out, and the reason was measured rather than
	// assumed: 21 of its 205 COMMITTED corpus entries violated CLAIM 1, every
	// one of them the negative community length that walked
	// parseGetBulkParams' cursor backwards onto a 0xa5 byte. That a panic-only
	// fuzzer had been replaying the defect on every CI run without noticing is
	// the sharpest available statement of what nl6#513 could not see.
	// TestGetBulkCorpusAgrees now pins the whole corpus as agreeing.
	f.Fuzz(func(t *testing.T, data []byte) {
		s := fuzzTestServer(50)
		_ = s.handleGetBulk(".1.3.6.1.2.1.1.1.0", data)
		assertV2cParserAgreement(t, s, data)
	})
}

func FuzzHandleGetRequestVarbinds(f *testing.F) {
	f.Add(crasherGetPDUType)
	addGoldenV2cSeeds(f)
	addAgreementSeeds(f)
	f.Fuzz(func(t *testing.T, data []byte) {
		s := fuzzTestServer(50)
		// The oids argument is what the server itself parsed out of the same
		// datagram, so deriving it here keeps the pair consistent the way the
		// real dispatcher does.
		oids, _ := s.parseAllOIDsFromRequest(data)
		if len(oids) == 0 {
			oids = []string{".1.3.6.1.2.1.1.1.0"}
		}
		_ = s.handleGetRequestVarbinds(oids, data)
		assertV2cParserAgreement(t, s, data)
	})
}

// FuzzHandleSNMPv3GetBulkDerived derives the whole v3 message from the fuzz
// input. FuzzHandleSNMPv3GetBulkScoped pins a valid message and fuzzes only
// the scoped PDU. The issue asks for BOTH because they explore different
// territory: the first spends most of its budget failing to build a message,
// the second reaches the scoped-PDU parser on every execution.
func FuzzHandleSNMPv3GetBulkDerived(f *testing.F) {
	f.Add(crasherParseV3)
	addValidV3Seeds(f)
	f.Fuzz(func(_ *testing.T, data []byte) {
		s := fuzzTestServer(50)
		msg, err := s.parseSNMPv3Message(data)
		if err != nil || msg == nil {
			return
		}
		// Same reasoning as FuzzHandleSNMPv3GetBulkScoped: the start OID is
		// echoed as the end-of-MIB binding's name, so it must come from the
		// fuzzed input rather than a literal.
		startOID, _, err := s.extractOIDAndTypeFromScopedPDU(msg.ScopedPDU)
		if err != nil || startOID == "" {
			startOID = ".1.3.6.1.2.1.1.1.0"
		}
		_ = s.handleSNMPv3GetBulk(startOID, msg, msg.ScopedPDU)
	})
}

func FuzzHandleSNMPv3GetBulkScoped(f *testing.F) {
	f.Add(crasherScopedPDU)
	f.Add(validScopedPDU(".1.3.6.1.2.1.1.1.0"))
	// GETBULK-shaped seeds. Neither seed above carries the 0xA5 tag, so
	// without these parseSNMPv3GetBulkParams' reads past the tag (nl6#535)
	// were reached by live fuzzing only, never by an ordinary `go test`.
	engineID := fuzzTestServer(1).v3Config.EngineID
	f.Add(v3BulkScopedPDUBytes(engineID, ".1.3.6.1.2.1.1.1.0", 0, 5))
	f.Add(v3BulkScopedPDUBytes(engineID, ".1.3.6.1.2.1.1.1.0", 1, 200))
	// MULTI-COLUMN seeds. Every GETBULK seed above names ONE column, so the
	// list walk nl6#535 added — the loop over VarBinds after the first, and
	// the padding it drives — was reached by live fuzzing only, which is the
	// exact omission recorded two comments up. These make CI replay it on
	// every ordinary `go test` (nl6#535 review R8).
	f.Add(v3BulkScopedPDUCols(engineID, 0, 4,
		[]string{".1.3.6.1.2.1.2.2.1.2", ".1.3.6.1.2.1.31.1.1.1.1", ".1.3.6.1.2.1.1.9.1.3"}))
	f.Add(v3BulkScopedPDUCols(engineID, 2, 3,
		[]string{".1.3.6.1.2.1.1.1.0", ".1.3.6.1.2.1.2.2.1.2", ".1.3.6.1.9.9.9.1"}))
	for _, seed := range brokenMultiColumnScopedPDUs(engineID) {
		f.Add(seed)
	}
	for _, seed := range brokenBulkScopedPDUs(engineID) {
		f.Add(seed)
	}
	f.Fuzz(func(_ *testing.T, scopedPDU []byte) {
		s := fuzzTestServer(50)
		msg := &SNMPv3Message{GlobalData: SNMPv3GlobalData{MsgID: 1}, ScopedPDU: scopedPDU}
		// Take the start OID from the fuzzed scoped PDU rather than pinning a
		// literal. Since nl6#526 that OID is echoed back as the name of the
		// end-of-MIB binding, so it reaches encodeOID: an OID the encoder
		// refuses would become a zero-length name, which sorts before
		// everything and recreates the very defect nl6#526 removed.
		startOID, _, err := s.extractOIDAndTypeFromScopedPDU(scopedPDU)
		if err != nil || startOID == "" {
			startOID = ".1.3.6.1.2.1.1.1.0"
		}
		_ = s.handleSNMPv3GetBulk(startOID, msg, scopedPDU)
	})
}

func FuzzCreateSNMPv3Response(f *testing.F) {
	f.Add(crasherScopedPDU)
	f.Add(validScopedPDU(".1.3.6.1.2.1.1.1.0"))
	f.Fuzz(func(_ *testing.T, scopedPDU []byte) {
		s := fuzzTestServer(20)
		msg := &SNMPv3Message{GlobalData: SNMPv3GlobalData{MsgID: 1}, ScopedPDU: scopedPDU}
		_, _ = s.createSNMPv3Response(".1.3.6.1.2.1.1.1.0", "value", msg)
	})
}

func FuzzCreateSNMPv3DiscoveryResponse(f *testing.F) {
	f.Add(crasherParseV3)
	addValidV3Seeds(f)
	f.Fuzz(func(_ *testing.T, data []byte) {
		s := fuzzTestServer(20)
		msg, err := s.parseSNMPv3Message(data)
		if err != nil || msg == nil {
			return
		}
		_ = s.createSNMPv3DiscoveryResponse(msg)
	})
}

func FuzzValidateSNMPv3Credentials(f *testing.F) {
	f.Add(crasherParseV3)
	addValidV3Seeds(f)
	f.Fuzz(func(_ *testing.T, data []byte) {
		s := fuzzTestServer(20)
		msg, err := s.parseSNMPv3Message(data)
		if err != nil || msg == nil {
			return
		}
		_ = s.validateSNMPv3Credentials(msg)
	})
}

// ── nl6#513: Tier 2 — end to end ─────────────────────────────────────────────

// FuzzHandleSingleRequest is the only target whose totality actually matters
// operationally: it is the function the listener goroutine calls, and a panic
// here takes the whole fleet down rather than one device.
//
// listener and clientAddr are both nil-guarded, so it can be driven without a
// socket. Seeding matters more here than anywhere else: an unseeded end-to-end
// fuzzer spends nearly its whole budget on inputs rejected at byte 0, and the
// number it produces answers a question nobody is asking.
func FuzzHandleSingleRequest(f *testing.F) {
	// The four nl6#512 crashers.
	f.Add(crasherGetPDUType)
	f.Add(crasherIsSNMPv3)
	f.Add(crasherParseV3)
	f.Add(crasherScopedPDU)
	// Valid datagrams of each shape the dispatcher branches on.
	f.Add(snmpRequestAt(ASN1_GET_REQUEST, snmpVersion2c, []string{".1.3.6.1.2.1.1.1.0"}))
	f.Add(snmpRequestAt(ASN1_GET_NEXT, snmpVersion1, []string{".1.3.6.1.2.1.1.1.0"}))
	f.Add(buildGetBulkPDUForFuzz(0, 10, ".1.3.6.1.2.1.1.1.0"))
	addValidV3Seeds(f)
	addGoldenV2cSeeds(f)
	addMalformedVarbindSeeds(f)
	addAgreementSeeds(f)
	f.Fuzz(func(t *testing.T, data []byte) {
		s := fuzzTestServer(50)
		s.handleSingleRequest(data, nil)
		// The agreement assertions belong here above all: this is the target
		// nl6#513 measured as 6-8x more productive than the leaf ones, so it
		// is where a disagreement is most likely to be reached first.
		assertV2cParserAgreement(t, s, data)
		assertMalformedListIsDiscarded(t, s, data)
	})
}

// ── nl6#527: the decrypt branch ──────────────────────────────────────────────

// FuzzHandleSNMPv3RequestPriv covers the one parseLength call site none of the
// targets above can reach: the unwrap of a DECRYPTED scoped PDU in
// handleSNMPv3Request (nl6#527), which runs only when the server has privacy
// configured and the message carries the PRIV flag. A mutated ciphertext
// decrypts to arbitrary bytes, so this is also where the unwrap's length guard
// (a SEQUENCE tag followed by a bad length) is exercised rather than argued.
//
// Seeded with a genuinely encrypted GET for each privacy protocol and with a
// ciphertext whose plaintext is a SEQUENCE carrying an over-long length, so an
// ordinary `go test` executes both arms of the guard.
func FuzzHandleSNMPv3RequestPriv(f *testing.F) {
	f.Add(crasherParseV3)
	for _, proto := range []int{SNMPV3_PRIV_DES, SNMPV3_PRIV_AES128} {
		s := fuzzPrivTestServer(20, proto)
		plainMsg, err := s.parseSNMPv3Message(buildV3RequestAt(f, s, ASN1_GET_REQUEST, ".1.3.6.1.2.1.1.1.0", 7))
		if err != nil {
			f.Fatalf("parse plaintext seed: %v", err)
		}
		cipherText, privParams, err := s.encryptScopedPDU(encodeSequence(plainMsg.ScopedPDU), v3PrivSeed(s))
		if err != nil {
			f.Fatalf("encrypt seed: %v", err)
		}
		f.Add(buildV3EncryptedRequest(f, s, cipherText, privParams))

		// SEQUENCE tag, length 0x84 00 00 00 40 (64) over a 16-byte body: the
		// tag test passes, the bound test must fail.
		badLen := append([]byte{ASN1_SEQUENCE, 0x84, 0x00, 0x00, 0x00, 0x40}, make([]byte, 10)...)
		cipherText, privParams, err = s.encryptScopedPDU(badLen, v3PrivSeed(s))
		if err != nil {
			f.Fatalf("encrypt bad-length seed: %v", err)
		}
		f.Add(buildV3EncryptedRequest(f, s, cipherText, privParams))
	}
	f.Fuzz(func(_ *testing.T, data []byte) {
		_ = fuzzPrivTestServer(20, SNMPV3_PRIV_DES).handleSNMPv3Request(data)
		_ = fuzzPrivTestServer(20, SNMPV3_PRIV_AES128).handleSNMPv3Request(data)
	})
}

// fuzzPrivTestServer is fuzzTestServer with authPriv configured, so a message
// carrying the PRIV flag reaches decryptScopedPDU and the unwrap after it.
func fuzzPrivTestServer(n, privProto int) *SNMPServer {
	s := fuzzTestServer(n)
	s.v3Config.AuthProtocol = SNMPV3_AUTH_MD5
	s.v3Config.PrivProtocol = privProto
	s.v3Config.PrivPassword = "s3cretpassword"
	return s
}

// ── nl6#534: self-differential parser agreement ──────────────────────────────
//
// nl6#513 established that the SNMP parsers are TOTAL — no input panics. That
// says nothing about a silent MIS-parse, which is the nl6#514 class: a
// zero-length community read as absent, answered with a community the caller
// never sent. A panic has an oracle (the process died); a wrong answer does
// not.
//
// Several parsers read the SAME v1/v2c datagram independently — getPDUType,
// parseIncomingRequest, parseAllOIDsFromRequest and parseGetBulkParams each
// walk the outer SEQUENCE / version / community / PDU envelope with their own
// code. When two of them disagree about the same datagram, at least one is
// wrong, and no oracle is needed to say so. That is what the assertions below
// check, on every execution of every target that sees a raw datagram.
//
// The trap this file must not fall into: an assertion that CANNOT fail. Two
// parsers with legitimately different contracts do not satisfy naive equality,
// and an assertion relaxed until it stops firing pins nothing while making the
// suite look stronger. So each claim below is written as the RELATIONSHIP the
// contracts actually establish, is one-directional where the contracts are
// one-directional, and is demonstrated by mutating the parser it constrains.
//
// The first cut of this change shipped that very failure and it is worth
// naming: roundTripOIDs[0] was byte-identical to parseIncomingRequest's own
// fallback OID, so the first-name round-trip compared the parser's default
// against itself and could not fire for any input — a total loss of the
// request OID left the whole suite green. Hence roundTripOIDs deliberately
// EXCLUDES that OID, TestParserDefaultsMatchTheTestConstants pins the
// constants to the parsers they came from, and
// TestAgreementSeedsReachEveryGuard pins that a committed seed actually
// satisfies each claim's guard.
//
// What these assertions still cannot see: a fault both parsers share. Two
// readers that walk the envelope the same wrong way agree perfectly. The
// round-trip target below covers part of that gap, and states its own bound.

const (
	// The values parseIncomingRequest returns when a field is absent or
	// unreadable, and parseGetBulkParams' two defaults. They are values, not
	// sentinels, so a parser that reads them off the wire is indistinguishable
	// from one that never got there — which is why the guards below SKIP on a
	// default rather than assert against it.
	//
	// Hand-copied literals are a coupling with no signal when it breaks, so
	// TestParserDefaultsMatchTheTestConstants asks the parsers themselves.
	defaultParsedOID       = ".1.3.6.1.2.1.1.1.0"
	defaultParsedRequestID = 123
	defaultParsedCommunity = "public"
	defaultParsedVersion   = snmpVersion2c
	defaultBulkNonRepeat   = 0
	defaultBulkMaxRepeat   = 10
)

// fatalfTB is the sink assertV2cParserAgreement writes to.
//
// It is a local interface rather than testing.TB because testing.TB cannot be
// implemented outside the testing package (it carries an unexported method),
// and the helper's OWN logic has to be a subject: every line of it runs only
// as an assertion, so an inverted guard would produce a green suite forever.
// TestAgreementHelperCatchesADisagreement drives it through a recorder that
// satisfies this interface.
//
// *testing.T satisfies it, so the fuzz callbacks pass theirs unchanged.
type fatalfTB interface {
	Helper()
	Fatalf(format string, args ...any)
}

// parseIncomingRequestReadsPDU reports whether parseIncomingRequest will walk
// INTO a PDU carrying this tag. It recognises exactly GET, GETNEXT and GETBULK
// and leaves request-id and OID at their defaults for anything else —
// GetResponse and SetRequest included, where parseAllOIDsFromRequest (which
// accepts any tag) still reads the names. That divergence is a documented
// contract difference, so it is asserted as the CONTRAPOSITIVE rather than
// skipped.
func parseIncomingRequestReadsPDU(tag byte) bool {
	return tag == ASN1_GET_REQUEST || tag == ASN1_GET_NEXT || tag == ASN1_GET_BULK
}

// assertV2cParserAgreement is the self-differential core: it drives every
// parser that reads a v1/v2c request envelope over the same bytes and fails
// when two of them disagree in a way their contracts forbid.
//
// It is called from the entry-point target AND from every leaf target that
// sees a raw datagram, so a regression confined to one parser is caught by the
// leaf target that names it as well as by the end-to-end one.
//
// SNMPv3 datagrams are excluded, and that is a contract statement rather than
// a convenience: these four parsers describe the v1/v2c envelope, which a v3
// message does not have (RFC 3412 §6 puts msgGlobalData where v2c puts the
// community). Running them over v3 bytes compares four parsers' behaviour on a
// structure none of them claims to read.
//
// Each claim's message begins with a stable phrase
// ("PDU-offset disagreement", "varbind-name disagreement",
// "PDU-tag disagreement") so TestAgreementHelperCatchesADisagreement can
// assert WHICH claim fired rather than merely that something did.
func assertV2cParserAgreement(t fatalfTB, s *SNMPServer, data []byte) {
	t.Helper()
	if isSNMPv3Request(data) {
		return
	}

	oids, listOK := s.parseAllOIDsFromRequest(data)
	nonRep, maxRep := s.parseGetBulkParams(data)
	checkV2cParserAgreement(t, v2cParseResults{
		req:    s.parseIncomingRequest(data),
		pduTag: s.getPDUType(data),
		oids:   oids,
		listOK: listOK,
		nonRep: nonRep,
		maxRep: maxRep,
	}, data)
}

// v2cParseResults is what the four envelope readers made of one datagram.
//
// It exists so the CLAIMS can be driven over results the parsers did not
// produce. Every line of checkV2cParserAgreement runs only as an assertion, so
// its ability to FIRE has to be demonstrated by something — and until nl6#559
// and nl6#560 were fixed that something was the defects themselves, which are
// now gone. Feeding the pre-fix results in directly keeps each claim's
// firing half under test without keeping a defect in the parsers to supply it.
type v2cParseResults struct {
	req    SNMPRequest
	pduTag byte
	oids   []string
	listOK bool
	nonRep int
	maxRep int
}

// checkV2cParserAgreement holds the claims themselves. See
// assertV2cParserAgreement above for what they mean; this split is a
// testability seam and nothing else.
func checkV2cParserAgreement(t fatalfTB, r v2cParseResults, data []byte) {
	t.Helper()
	req, pduTag, oids, listOK, nonRep, maxRep := r.req, r.pduTag, r.oids, r.listOK, r.nonRep, r.maxRep

	// CLAIM 1 — getPDUType and parseGetBulkParams agree on where the PDU
	// starts.
	//
	// One-directional, deliberately. parseGetBulkParams returns (0, 10) both
	// when it never found a GETBULK PDU and when it found one carrying exactly
	// those values, so "getPDUType says GETBULK => parseGetBulkParams read
	// something" is not a claim the return values can support. The other
	// direction is: parseGetBulkParams cannot report a non-default pair unless
	// it walked the envelope and found ASN1_GET_BULK at the end of it, so
	// getPDUType — which walks the same envelope for the same purpose — must
	// find that same tag byte.
	//
	// Writing this as an equality in both directions is exactly the assertion
	// that has to be relaxed until it is silent.
	//
	// This claim FOUND nl6#560 (parseGetBulkParams read three declared lengths
	// with no `< 0` arm, so parseLength's -1 walked its cursor backward and it
	// parsed a GETBULK out of bytes that were not one) and, with CLAIM 3,
	// nl6#559 (getPDUType assumed a one-octet version). Both are fixed, and
	// their reproducers are committed as fuzz seeds by addAgreementSeeds — an
	// ordinary `go test` replays them, so a regression fails the suite.
	if (nonRep != defaultBulkNonRepeat || maxRep != defaultBulkMaxRepeat) && pduTag != ASN1_GET_BULK {
		t.Fatalf("PDU-offset disagreement: parseGetBulkParams read a GETBULK PDU "+
			"(non-repeaters=%d, max-repetitions=%d, defaults are %d/%d) but getPDUType reports tag 0x%02X, "+
			"not GETBULK (0x%02X). The two disagree about where the PDU begins.\ndatagram: % x",
			nonRep, maxRep, defaultBulkNonRepeat, defaultBulkMaxRepeat, pduTag, ASN1_GET_BULK, data)
	}

	// CLAIM 2 — the two name readers agree on the first varbind name.
	//
	// Guarded on BOTH parsers having actually read a name:
	//
	//   listOK == false      the list is malformed and the datagram is
	//                        discarded (nl6#537). No agreement claim is made:
	//                        parseIncomingRequest is documented to keep going
	//                        and return its default, so the two are SUPPOSED
	//                        to differ. The dispatcher-side claim for this
	//                        case is assertMalformedListIsDiscarded.
	//   len(oids) == 0       (nil, true): the walk never reached a list, or
	//                        the list is empty.
	//   req.OID == default   parseIncomingRequest never decoded a name — or
	//                        decoded one that happens to equal the default,
	//                        which its return value cannot distinguish. This
	//                        guard is why roundTripOIDs must never offer the
	//                        default as a first name: it would put the
	//                        round-trip's own first-name check and this claim
	//                        in the same blind spot.
	//
	// The guard deliberately does NOT involve getPDUType. Routing it through a
	// third parser would let a getPDUType defect silence this claim, which is
	// how an agreement assertion quietly stops being able to fail.
	if listOK && len(oids) > 0 && req.OID != defaultParsedOID && req.OID != oids[0] {
		t.Fatalf("varbind-name disagreement: parseAllOIDsFromRequest reads the first name as %q "+
			"but parseIncomingRequest reads it as %q (list: %q)\ndatagram: % x",
			oids[0], req.OID, oids, data)
	}

	// CLAIM 3 — getPDUType and parseIncomingRequest agree on the PDU TAG.
	//
	// This is the version-agreement claim the I/O matrix asks for, made
	// through the only channel the return values offer. parseIncomingRequest
	// reaches a varbind name ONLY along a path that first found one of
	// GET/GETNEXT/GETBULK at its computed PDU offset. So a decoded name is
	// proof that it saw a tag parseIncomingRequestReadsPDU accepts, and
	// getPDUType — walking the same envelope, past the same version and
	// community — must report a tag from that same set.
	//
	// One-directional again: getPDUType answers ASN1_GET_REQUEST when it
	// cannot read the envelope at all, which is IN the set, so a getPDUType
	// bail is not a fire. What fires is getPDUType landing on a byte that is
	// neither a bail nor a PDU tag — a genuine offset disagreement. It does
	// not catch getPDUType confusing one valid tag for another.
	//
	// Why this matters and the round-trip does not cover it: the version is
	// READ by getPDUType, parseGetBulkParams and parseAllOIDsFromRequest and
	// REPORTED by none of them, so there is no second reader to compare
	// parseIncomingRequest's Version against directly. This claim compares
	// the CONSEQUENCE of reading it — the offset that follows — and it names
	// nl6#559 on every datagram carrying a non-minimal version, rather than
	// only on the narrow slice where parseGetBulkParams reports non-defaults.
	//
	// NOT ASSERTED, and this is the honest bound: the PDU TYPE itself. The
	// matrix asks for `getPDUType` and `parseIncomingRequest` to agree on it,
	// and SNMPRequest carries no PDU-type field, so the strongest claim
	// available is set membership, not equality. Adding such a field is a
	// production change and out of scope here.
	if req.OID != defaultParsedOID && !parseIncomingRequestReadsPDU(pduTag) {
		t.Fatalf("PDU-tag disagreement: parseIncomingRequest decoded the varbind name %q, "+
			"which it only reaches after finding a GET/GETNEXT/GETBULK tag, but getPDUType "+
			"reports tag 0x%02X — neither a PDU tag nor its ASN1_GET_REQUEST bail. "+
			"The two disagree about where the PDU begins (nl6#559 is one cause).\ndatagram: % x",
			req.OID, pduTag, data)
	}

	// NOT ASSERTED — the absent-list case, (nil, true) => req.OID is the
	// default.
	//
	// It does not hold, and the divergence is legitimate rather than a bug.
	// parseAllOIDsFromRequest returns early on any envelope field it cannot
	// read; parseIncomingRequest is lenient and SKIPS such a field without
	// advancing, so a PDU carrying no request-id INTEGER but a well-formed
	// variable-bindings list gives (nil, true) from one and a real decoded OID
	// from the other. Both behave as documented. Per the nl6#534 rule an
	// assertion that fires there would be a finding about the contract, not a
	// test — so the contract is recorded here and the assertion is not made.
	//
	// Two further shapes in the same category, recorded rather than asserted
	// because each is outside a parser's stated bound rather than a defect in
	// it: a request-id INTEGER with five or more content octets (legal padded
	// BER, but parseIncomingRequest documents a 1..4 range and does not
	// advance past a wider one), and a request-id whose content parseBERInt
	// reads but parseIncomingRequest's unsigned assembly cannot represent.
	// A zero-length version INTEGER (`02 00`) is NOT in this category: it
	// desynchronises getPDUType's bare `pos++` and is a second instance of
	// nl6#559, pinned as repro559ZeroLengthVersion.
	//
	// NOT ASSERTED, and this is the suite's sharpest remaining blind spot: a
	// getPDUType BAIL that should have been a tag.
	//
	// ASN1_GET_REQUEST (0xA0) does double duty — it is a PDU tag AND the value
	// getPDUType returns when it cannot read the envelope at all — so CLAIM 3
	// exempts it, and CLAIM 1 cannot reach it either (parseGetBulkParams
	// declines the same unreadable envelope and returns its defaults, which is
	// CLAIM 1's own skip). A datagram on which getPDUType bails while
	// parseIncomingRequest walks in and decodes a GETNEXT is therefore INVISIBLE
	// to all three claims, and the dispatcher answers the walk step from the GET
	// branch. That is not hypothetical: it is exactly what the first cut of the
	// nl6#559 fix left standing at the community field, where getPDUType bailed
	// on an unreadable length and parseIncomingRequest carried on
	// (repro559CommunityLengthUnreadable).
	//
	// Closing it needs a PDU-TYPE field on SNMPRequest — a production change
	// this file has already declined once, for the same reason, in CLAIM 3's
	// own note. Until then the shape is pinned BEHAVIOURALLY rather than by an
	// agreement claim, by TestUnreadableCommunityLengthIsWalkedAsAGetNext, and
	// the production rule is that the four readers walk each envelope field
	// the same way. Every instance of this bug found so far has been a
	// violation of that rule rather than of a claim here.
}

// assertMalformedListIsDiscarded is the dispatcher-side half of CLAIM 2's
// skipped case: where the agreement helper makes no claim about a malformed
// list, this one asserts what nl6#537 requires the SERVER to do about it.
//
// Contract: parseAllOIDsFromRequest reporting false means the variable-bindings
// list is not a valid ASN.1 encoding, which RFC 1157 §4.1 step 1 and RFC 3412
// §7.2 answer by discarding the datagram. All three v1/v2c dispatch sites gate
// on it, so the claim needs no PDU-type guard: whatever branch is taken, a
// false verdict must produce no response bytes at all.
//
// Server requirement: a NON-NIL s.device, because the discard logs once per
// device. It does NOT need a populated OID fixture — every dispatch site gates
// before it reaches the resource index — so robustnessTestServer() is enough
// and the claim is cheap to wire anywhere a raw datagram is in hand.
func assertMalformedListIsDiscarded(t fatalfTB, s *SNMPServer, data []byte) {
	t.Helper()
	if isSNMPv3Request(data) {
		return
	}
	if _, ok := s.parseAllOIDsFromRequest(data); ok {
		return
	}
	if resp := s.handleSNMPv2cRequest(data); len(resp) != 0 {
		t.Fatalf("discard disagreement: parseAllOIDsFromRequest reports the variable-bindings list "+
			"malformed, but the dispatcher answered with %d bytes instead of discarding (nl6#537)"+
			"\ndatagram: % x\nresponse: % x", len(resp), data, resp)
	}
}

// ── nl6#559 / nl6#560: the two disagreements nl6#534 FOUND, now fixed ────────
//
// nl6#534 recorded these as named variables and deliberately kept them OUT of
// the seed corpus: a seed would have failed an ordinary `go test` for a defect
// that change was not permitted to repair. Both parsers are fixed here, so all
// four are now committed seeds through addAgreementSeeds and an ordinary
// `go test` replays them — a regression in either envelope reader fails the
// suite rather than waiting for a fuzz campaign to rediscover it.

// repro560NegativeLengthWalksBackwards is nl6#560, found by FuzzGetPDUType
// after 445,685 executions and fixed by the `< 0` arms parseGetBulkParams now
// carries on all seven of its declared-length reads.
//
// parseGetBulkParams read the community length with parseLength and then did
// `pos = newPos + commLen` with NO `commLen < 0` test. parseLength signals
// failure with -1, so the cursor moved BACKWARD onto the community length byte
// 0xa5 — which is also ASN1_GET_BULK — and it parsed a GETBULK PDU out of
// bytes that are not one, reporting non-repeaters 12336. getPDUType, which did
// guard, answered its ASN1_GET_REQUEST bail.
var repro560NegativeLengthWalksBackwards = []byte{
	0x30, 0x30, 0x02, 0x01, 0x30, 0x04, 0xa5, 0x30, 0x02, 0x04,
	0x30, 0x30, 0x30, 0x30, 0x02, 0x02, 0x30, 0x30,
}

// nonMinimalVersionRequest builds a v2c request whose version INTEGER is
// encoded in TWO content octets (`02 02 00 01`). BER — which SNMP uses, not
// DER — permits it, and every parser in the package read it correctly except
// getPDUType, which skipped the version as skipLength plus a bare `pos++` and
// so reported the version's own second content octet (0x01) as the PDU tag.
func nonMinimalVersionRequest(pduTag byte, oids []string) []byte {
	var varbinds []byte
	for _, oid := range oids {
		varbinds = append(varbinds, encodeVarBind(oid, encodeNull())...)
	}
	var pduBody []byte
	pduBody = append(pduBody, encodeInteger(42)...)
	pduBody = append(pduBody, encodeInteger(0)...)
	pduBody = append(pduBody, encodeInteger(7)...)
	pduBody = append(pduBody, encodeSequence(varbinds)...)
	pdu := append([]byte{pduTag}, append(encodeLength(len(pduBody)), pduBody...)...)

	var msg []byte
	msg = append(msg, 0x02, 0x02, 0x00, 0x01) // version = 1, non-minimally encoded
	msg = append(msg, encodeOctetString("public")...)
	msg = append(msg, pdu...)
	return encodeSequence(msg)
}

// unreadableCommunityLengthRequest builds a v1/v2c request whose community
// OCTET STRING declares an INDEFINITE length (`04 80`), which parseLength
// refuses. Everything after it is a well-formed PDU.
//
// This is nl6#559 ONE FIELD LATER, and it is what the first cut of the nl6#559
// fix left standing: getPDUType bailed to ASN1_GET_REQUEST on an unreadable
// community length while parseIncomingRequest leaves the cursor on the length
// octet and carries on, decoding a GETNEXT with real varbind names. The
// dispatcher runs on getPDUType's answer, so the walk step was served from the
// GET branch.
//
// No agreement claim can see it, which is why it also needs
// TestUnreadableCommunityLengthIsWalkedAsAGetNext: CLAIM 3 exempts
// ASN1_GET_REQUEST because that is also getPDUType's bail value, and CLAIM 1
// cannot fire because parseGetBulkParams declines the same datagram. See the
// NOT ASSERTED entry at the end of checkV2cParserAgreement.
func unreadableCommunityLengthRequest(pduTag byte, oids []string) []byte {
	var varbinds []byte
	for _, oid := range oids {
		varbinds = append(varbinds, encodeVarBind(oid, encodeNull())...)
	}
	var pduBody []byte
	pduBody = append(pduBody, encodeInteger(42)...)
	pduBody = append(pduBody, encodeInteger(0)...)
	pduBody = append(pduBody, encodeInteger(0)...)
	pduBody = append(pduBody, encodeSequence(varbinds)...)
	pdu := append([]byte{pduTag}, append(encodeLength(len(pduBody)), pduBody...)...)

	var msg []byte
	msg = append(msg, encodeInteger(snmpVersion2c)...)
	msg = append(msg, 0x04, 0x80) // community, indefinite length: parseLength refuses it
	msg = append(msg, pdu...)
	return encodeSequence(msg)
}

// zeroLengthVersionRequest builds a v1/v2c request whose version INTEGER has
// ZERO content octets (`02 00`). The same getPDUType defect as nl6#559 in the
// other direction: its bare `pos++` stepped one octet too FAR, landing on the
// community string's length octet and reporting 0x06 as the PDU tag.
func zeroLengthVersionRequest(pduTag byte, oids []string) []byte {
	var varbinds []byte
	for _, oid := range oids {
		varbinds = append(varbinds, encodeVarBind(oid, encodeNull())...)
	}
	var pduBody []byte
	pduBody = append(pduBody, encodeInteger(42)...)
	pduBody = append(pduBody, encodeInteger(0)...)
	pduBody = append(pduBody, encodeInteger(0)...)
	pduBody = append(pduBody, encodeSequence(varbinds)...)
	pdu := append([]byte{pduTag}, append(encodeLength(len(pduBody)), pduBody...)...)

	var msg []byte
	msg = append(msg, 0x02, 0x00) // version, zero content octets
	msg = append(msg, encodeOctetString("public")...)
	msg = append(msg, pdu...)
	return encodeSequence(msg)
}

var (
	// nl6#559 as a GETBULK: CLAIM 1 and CLAIM 3 both fire.
	repro559NonMinimalVersion = nonMinimalVersionRequest(ASN1_GET_BULK, []string{".1.3.6.1.2.1.2.2.1.2.1"})
	// nl6#559 as a GETNEXT: getPDUType reports 0x01, so the dispatcher answers
	// a walk step as a GET. CLAIM 3 fires; CLAIM 1 cannot, because
	// parseGetBulkParams correctly declines a non-GETBULK PDU.
	repro559NonMinimalVersionGetNext = nonMinimalVersionRequest(ASN1_GET_NEXT, []string{".1.3.6.1.2.1.2.2.1.2.1"})
	// The zero-content-octet instance of nl6#559.
	repro559ZeroLengthVersion = zeroLengthVersionRequest(ASN1_GET_NEXT, []string{".1.3.6.1.2.1.2.2.1.2.1"})
	// nl6#559 one field later: an unreadable COMMUNITY length. Every claim is
	// silent on it in both directions, so its pin is a dispatcher test.
	repro559CommunityLengthUnreadable = unreadableCommunityLengthRequest(ASN1_GET_NEXT, []string{repro559WalkStart})
)

// repro559WalkStart is the OID repro559CommunityLengthUnreadable walks FROM.
// It is a name the fuzz fixture serves and is deliberately not the last one,
// so a GETNEXT of it has a successor to return and the walk step is
// distinguishable from a GET.
const repro559WalkStart = ".1.3.6.1.2.1.2.2.1.2.1"

// brokenGetBulkEnvelopes is one row per declared-length read in
// parseGetBulkParams, each a datagram whose length is unreadable AT THAT FIELD
// and nowhere else. Shared by the guard test and the fuzz seeds, the same
// shape as brokenVarbindLists and brokenBulkScopedPDUs.
//
// Which of these rows WITNESSES its guard — fails when that one guard is
// removed and no other — is measured and recorded in
// TestParseGetBulkParamsBailsOnEveryUnreadableLength's comment, not in a field
// here: nothing inside a test can observe its own mutant, so a `witness: true`
// column would be prose with a compiler's blessing and no enforcement.
var brokenGetBulkEnvelopes = []struct {
	name string
	data []byte
	// wantNonRep/wantMaxRep are the documented defaults on every row but the
	// last. The fields are read in order and each is committed as it is read,
	// so a length that fails at max-repetitions keeps the non-repeaters value
	// that was already read correctly: the guard's job is to stop the walk,
	// not to unwind a field the parser did read. Stating the expectation per
	// row rather than assuming 0/10 everywhere is what keeps that visible.
	wantNonRep int
	wantMaxRep int
}{
	{
		// Indefinite-length outer SEQUENCE. parseLength refuses it (X.690's
		// indefinite form is not admitted here), and skipLength — which the
		// two sibling readers used to use — answers 1 for the same byte.
		name:       "outer SEQUENCE length",
		wantNonRep: defaultBulkNonRepeat, wantMaxRep: defaultBulkMaxRepeat,
		data: []byte{
			0x30, 0x80, 0x02, 0x01, 0x01, 0x04, 0x00, 0xa5, 0x0c,
			0x02, 0x01, 0x01, 0x02, 0x01, 0x05, 0x02, 0x01, 0x07,
		},
	},
	{
		// The outer SEQUENCE declares more content than the datagram carries.
		// Bounding rather than sign-checking is what catches this one.
		name:       "outer SEQUENCE length over-declares",
		wantNonRep: defaultBulkNonRepeat, wantMaxRep: defaultBulkMaxRepeat,
		data: []byte{
			0x30, 0x7f, 0x02, 0x01, 0x01, 0x04, 0x00, 0xa5, 0x0c,
			0x02, 0x01, 0x01, 0x02, 0x01, 0x05, 0x02, 0x01, 0x07,
		},
	},
	{
		name:       "version length",
		wantNonRep: defaultBulkNonRepeat, wantMaxRep: defaultBulkMaxRepeat,
		data: gbEnvelope([]byte{0x02, 0x80}, encodeOctetString(""), gbParamPDU(gbGoodParams)),
	},
	{
		// The one nl6#560 named, and the only FIELD guard with a witness: the
		// cursor lands back on the 0xa5 length octet, which is ALSO the GETBULK
		// tag the next branch tests for.
		//
		// The bytes after it are laid out so the walk-back SUCCEEDS all the way
		// to the parameters: 0x09 is a readable PDU length covering exactly the
		// three INTEGERs. An earlier version of this row put a second 0xa5
		// there and was masked — the mutant reached the PDU-length read, failed
		// it, and bailed on the SIBLING guard, so the row passed with the guard
		// it was written for removed. A witness has to survive every other
		// guard on the path or it is not a witness for its own.
		name:       "community length",
		wantNonRep: defaultBulkNonRepeat, wantMaxRep: defaultBulkMaxRepeat,
		data: gbEnvelope(encodeInteger(snmpVersion2c), []byte{0x04, 0xa5},
			append([]byte{byte(len(gbGoodParams))}, gbGoodParams...)),
	},
	{
		// This row cannot witness the PDU-length SIGN guard, and the reason is
		// worth knowing: the reslice below it, `data[:newPos+pduLen]`, truncates
		// the buffer to one octet BEFORE the cursor when pduLen is -1, so the
		// walk stops on the bounds check whether the sign guard is there or
		// not. The sign guard is pinned by TestGetBulkCorpusAgrees instead
		// (measured), and the reslice by the under-declare row.
		name:       "PDU length",
		wantNonRep: defaultBulkNonRepeat, wantMaxRep: defaultBulkMaxRepeat,
		data: gbEnvelope(encodeInteger(snmpVersion2c), encodeOctetString(""),
			append(append([]byte{ASN1_GET_BULK, 0x80}, gbGoodParams...), 0x00)),
	},
	{
		// The two CONTAINER lengths do more than pass a sign test: they reslice
		// the buffer, so a read cannot leave the container it belongs to. These
		// two rows are the witnesses for that, and they are the only ones a
		// sign check alone does not cover — here the length is perfectly
		// READABLE and simply smaller than what follows, which is how a
		// parameter gets read from outside the PDU that is supposed to own it
		// (the nl6#537 rule).
		name:       "outer SEQUENCE length under-declares",
		wantNonRep: defaultBulkNonRepeat, wantMaxRep: defaultBulkMaxRepeat,
		data: []byte{
			0x30, 0x05, 0x02, 0x01, 0x01, 0x04, 0x00, // the SEQUENCE ends here
			0xa5, 0x09, 0x02, 0x01, 0x01, 0x02, 0x01, 0x05, 0x02, 0x01, 0x07, // outside it
		},
	},
	{
		name:       "PDU length under-declares",
		wantNonRep: defaultBulkNonRepeat, wantMaxRep: defaultBulkMaxRepeat,
		data: gbEnvelope(encodeInteger(snmpVersion2c), encodeOctetString(""),
			append([]byte{ASN1_GET_BULK, 0x03, 0x02, 0x01, 0x01}, // PDU holds the request-id only
				0x02, 0x01, 0x05, 0x02, 0x01, 0x07)), // the parameters sit outside it
	},
	{
		name:       "PDU length over-declares",
		wantNonRep: defaultBulkNonRepeat, wantMaxRep: defaultBulkMaxRepeat,
		data: []byte{
			0x30, 0x14, 0x02, 0x01, 0x01, 0x04, 0x00, 0xa5, 0x7f,
			0x02, 0x01, 0x01, 0x02, 0x01, 0x05, 0x02, 0x01, 0x07,
		},
	},
	{
		name:       "request-id length",
		wantNonRep: defaultBulkNonRepeat, wantMaxRep: defaultBulkMaxRepeat,
		data: gbEnvelope(encodeInteger(snmpVersion2c), encodeOctetString(""),
			gbParamPDU(append([]byte{0x02, 0x80}, 0x02, 0x01, 0x05, 0x02, 0x01, 0x07))),
	},
	{
		name:       "non-repeaters length",
		wantNonRep: defaultBulkNonRepeat, wantMaxRep: defaultBulkMaxRepeat,
		data: gbEnvelope(encodeInteger(snmpVersion2c), encodeOctetString(""),
			gbParamPDU([]byte{0x02, 0x01, 0x01, 0x02, 0x80, 0x02, 0x01, 0x07})),
	},
	{
		name: "max-repetitions length",
		// Non-repeaters was already read, and correctly: 5.
		wantNonRep: 5, wantMaxRep: defaultBulkMaxRepeat,
		data: gbEnvelope(encodeInteger(snmpVersion2c), encodeOctetString(""),
			gbParamPDU([]byte{0x02, 0x01, 0x01, 0x02, 0x01, 0x05, 0x02, 0x80})),
	},
}

// gbGoodParams is request-id 1, non-repeaters 5, max-repetitions 7 — both
// parameters deliberately NON-default, so a row that wrongly parses reports
// 5/7 and is distinguishable from the 0/10 the guards must produce.
var gbGoodParams = []byte{0x02, 0x01, 0x01, 0x02, 0x01, 0x05, 0x02, 0x01, 0x07}

func gbParamPDU(body []byte) []byte {
	return append([]byte{ASN1_GET_BULK}, append(encodeLength(len(body)), body...)...)
}

func gbEnvelope(version, community, pdu []byte) []byte {
	var msg []byte
	msg = append(msg, version...)
	msg = append(msg, community...)
	msg = append(msg, pdu...)
	return encodeSequence(msg)
}

// TestParseGetBulkParamsBailsOnEveryUnreadableLength pins the nl6#560 guards
// one field at a time.
//
// Removing the seven guards TOGETHER fails a great deal; removing them one at
// a time was measured to fail nothing for six of them, which is the state this
// table ends. Every row must answer the documented defaults: a length the
// parser could not read means it does not know where the PDU is, and reporting
// parameters from that position is the nl6#560 failure class whatever byte
// pattern reached it.
//
// Which guard each row witnesses was MEASURED, by removing one guard at a time
// and running the package suite. The result, and it is the honest half of this
// test:
//
//	outer SEQUENCE length   sign  witnessed by the over-declares row
//	                        bound witnessed by the under-declares row
//	version length          sign  NO witness (structural, see below)
//	community length        sign  witnessed by the community row, and by
//	                              FuzzGetPDUType / FuzzParseIncomingRequest on
//	                              the seeds this table supplies
//	PDU length              sign  witnessed by TestGetBulkCorpusAgrees only
//	                        bound witnessed by the under-declares row
//	request-id length       sign  NO witness (structural)
//	non-repeaters length    sign  NO witness (structural)
//	max-repetitions length  sign  NO witness (structural)
//
// The four unwitnessed guards cannot be witnessed, and that is a property of
// the encoding rather than a gap here. On a failed read parseLength returns
// newPos pointing AT the offending length octet, so an unguarded
// `pos = newPos + (-1)` lands the cursor exactly there. For the next branch to
// then misfire, that octet would have to both FAIL parseLength (0x80, or a long
// form declaring 0 or more than 4 length octets) and EQUAL the tag the branch
// tests for. That is possible only at the community field, whose next branch
// tests for 0xA5 — a byte that declares 37 length octets and is also
// ASN1_GET_BULK, which is precisely why nl6#560 was found there. The version,
// request-id and non-repeaters branches test for 0x04 and 0x02, both valid
// short-form lengths parseLength never rejects, and the max-repetitions read is
// the last thing the function does. Those four are therefore defence-in-depth:
// they hold only while their siblings do, and they are kept so the rule "every
// length read tests its sign" needs no exceptions — which is cheaper than
// a reader having to re-derive this argument at each site.
func TestParseGetBulkParamsBailsOnEveryUnreadableLength(t *testing.T) {
	s := robustnessTestServer()

	for _, tc := range brokenGetBulkEnvelopes {
		t.Run(tc.name, func(t *testing.T) {
			nonRep, maxRep := s.parseGetBulkParams(tc.data)
			if nonRep != tc.wantNonRep || maxRep != tc.wantMaxRep {
				t.Errorf("parseGetBulkParams = (%d, %d), want (%d, %d): the %s is unreadable, so "+
					"the parser must stop rather than report parameters from a position it "+
					"guessed (nl6#560)\ndatagram: % x",
					nonRep, maxRep, tc.wantNonRep, tc.wantMaxRep, tc.name, tc.data)
			}
		})
	}

	// The positive control: the same envelope with every length readable must
	// report 5/7, or the table above would pass on a function that returned
	// the defaults unconditionally.
	good := gbEnvelope(encodeInteger(snmpVersion2c), encodeOctetString(""), gbParamPDU(gbGoodParams))
	if nonRep, maxRep := s.parseGetBulkParams(good); nonRep != 5 || maxRep != 7 {
		t.Errorf("positive control: parseGetBulkParams = (%d, %d), want (5, 7)\ndatagram: % x",
			nonRep, maxRep, good)
	}
}

// TestExtractRequestIDGuardsNegativeLengths is nl6#560's second site, one
// message layer up, with one row per declared-length read in the function.
//
// extractRequestIDFromScopedPDU skipped contextEngineID and contextName with
// `pos = newPos + n` and no `n < 0` arm, so parseLength's -1 walked the cursor
// BACKWARD onto the offending length octet. That octet is then re-read as a
// tag, and 0xA0 is both a length byte parseLength refuses (32 length octets,
// past its 4-octet ceiling) and ASN1_GET_REQUEST — so the function walked into
// a PDU that is not there and returned a request id nobody sent. A v3 response
// carrying it is answered to a request the manager cannot match.
//
// Each row is a witness for ONE guard: the first returns at the
// contextEngineID skip, the second walks past a well-formed contextEngineID so
// that removing only the contextName guard is caught, and the last two cover
// the PDU length, which reads a request id out of a PDU whose own extent is
// unknown rather than walking backward. The witness value is exact — 12345
// unguarded against the documented fallback of 1 — because "not 12345" also
// passes for a function that fails some other way.
//
// No agreement assertion covers this function: the four self-differential
// readers describe the v1/v2c envelope, and a scoped PDU has no second reader
// here, so the guards need their own subject or reverting one is silent.
func TestExtractRequestIDGuardsNegativeLengths(t *testing.T) {
	s := robustnessTestServer()

	tests := []struct {
		name      string
		scopedPDU []byte
	}{
		{
			name: "contextEngineID length",
			scopedPDU: []byte{
				0x04, 0xa0, // contextEngineID OCTET STRING, unreadable length 0xA0
				0x06,                   // what the unguarded walk re-reads as a PDU length
				0x02, 0x02, 0x30, 0x39, // INTEGER 12345 — the invented request id
				0x05, 0x00, 0x00, 0x00, // padding to clear the 10-byte floor
			},
		},
		{
			name: "contextName length",
			scopedPDU: []byte{
				0x04, 0x00, // a well-formed empty contextEngineID, so the walk gets past it
				0x04, 0xa0, // contextName OCTET STRING, unreadable length 0xA0
				0x06,
				0x02, 0x02, 0x30, 0x39,
				0x05, 0x00, 0x00,
			},
		},
		{
			name: "PDU length",
			scopedPDU: []byte{
				0x04, 0x00, 0x04, 0x00,
				0xa0, 0x80, // GetRequest whose length is the indefinite form
				0x02, 0x02, 0x30, 0x39,
				0x05, 0x00,
			},
		},
		{
			name: "PDU length over-declares",
			scopedPDU: []byte{
				0x04, 0x00, 0x04, 0x00,
				0xa0, 0x7f, // declares 127 content octets; six are present
				0x02, 0x02, 0x30, 0x39,
				0x05, 0x00,
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := s.extractRequestIDFromScopedPDU(tc.scopedPDU); got != 1 {
				t.Errorf("extractRequestIDFromScopedPDU = %d, want the fallback 1: the %s is "+
					"unreadable, so the request id was read out of bytes that are not a PDU "+
					"(nl6#560)\nscoped PDU: % x", got, tc.name, tc.scopedPDU)
			}
		})
	}

	// Positive control: the same shape with every length readable must return
	// the request id, or the rows above would pass on a function that returned
	// 1 unconditionally.
	good := []byte{0x04, 0x00, 0x04, 0x00, 0xa0, 0x04, 0x02, 0x02, 0x30, 0x39, 0x05, 0x00}
	if got := s.extractRequestIDFromScopedPDU(good); got != 12345 {
		t.Errorf("positive control: extractRequestIDFromScopedPDU = %d, want 12345\nscoped PDU: % x",
			got, good)
	}
}

// syntheticResultsMarker stands where a datagram would be in the synthetic
// rows of TestAgreementHelperCatchesADisagreement. The claims print the
// datagram, and passing nil there produces a message ending in "datagram: "
// with nothing after it, which reads like a real failure on empty input.
// TestUnreadableCommunityLengthIsWalkedAsAGetNext pins nl6#559's community
// instance, which no agreement claim can see (see the NOT ASSERTED entry at
// the end of checkV2cParserAgreement).
//
// The datagram is a GETNEXT whose community declares an indefinite length.
// parseIncomingRequest has always read it as a GETNEXT of a real name; the
// question is whether getPDUType agrees, and the only oracle-free way to ask
// is the DISPATCHER, which runs on getPDUType's answer. A GETNEXT returns the
// SUCCESSOR of the requested name; a GET returns the requested name itself, so
// the two branches are distinguishable from the response alone without this
// test needing to know which OID the successor is.
//
// Asserting the tag as well is deliberate: the response check alone would pass
// if the walk were served for some other reason, and the tag check alone is the
// kind of assertion that keeps passing while the dispatcher changes under it.
func TestUnreadableCommunityLengthIsWalkedAsAGetNext(t *testing.T) {
	s := newTestServer(fuzzFixtureOIDs(20))
	data := repro559CommunityLengthUnreadable

	if tag := s.getPDUType(data); tag != ASN1_GET_NEXT {
		t.Errorf("getPDUType = 0x%02X, want GETNEXT (0x%02X): it bailed on the community "+
			"length while parseIncomingRequest walked past it (nl6#559, community instance)"+
			"\ndatagram: % x", tag, ASN1_GET_NEXT, data)
	}
	if req := s.parseIncomingRequest(data); req.OID != repro559WalkStart {
		t.Fatalf("premise broken: parseIncomingRequest reads %q, want %q — this datagram is "+
			"only a witness while that parser reads the name\ndatagram: % x",
			req.OID, repro559WalkStart, data)
	}

	resp := s.handleSNMPv2cRequest(data)
	if len(resp) == 0 {
		t.Fatalf("the dispatcher discarded the datagram\ndatagram: % x", data)
	}
	names, ok := s.parseAllOIDsFromRequest(resp)
	if !ok || len(names) == 0 {
		t.Fatalf("the response carries no readable varbind name (ok=%v, names=%q)\nresponse: % x",
			ok, names, resp)
	}
	if names[0] == repro559WalkStart {
		t.Errorf("the walk step was answered from the GET branch: the response names the "+
			"REQUESTED oid %q instead of its successor\ndatagram: % x\nresponse: % x",
			repro559WalkStart, data, resp)
	}
}

// TestAllThreeEnvelopeReadersStopAtAnUnreadableOuterLength pins the outer
// SEQUENCE length, which nl6#560 left read three different ways.
//
// parseGetBulkParams bailed, while getPDUType and parseIncomingRequest stepped
// over it with skipLength — a function with no failure signal, which answers a
// malformed long-form length with a plausible `1 + lengthBytes` skip. On the
// datagram below that lenient walk lands exactly on a GETNEXT tag, so the two
// readers disagreed about a datagram whose outer length neither of them could
// read.
//
// The claim is agreement, not any particular answer: all three stop. That is
// also what parseAllOIDsFromRequest does (it reports the list malformed and the
// dispatcher discards, nl6#537), so the datagram is answered by nobody rather
// than by a GET branch that guessed.
func TestAllThreeEnvelopeReadersStopAtAnUnreadableOuterLength(t *testing.T) {
	s := newTestServer(fuzzFixtureOIDs(20))

	// 30 80 is the indefinite form: parseLength refuses it, skipLength answers
	// 1. Everything after it is a well-formed GETNEXT of a served name, so a
	// lenient reader finds 0xA1 and a strict one finds nothing.
	data := []byte{0x30, 0x80, 0x02, 0x01, 0x01, 0x04, 0x00, 0xa1, 0x11,
		0x02, 0x01, 0x2a, 0x02, 0x01, 0x00, 0x02, 0x01, 0x00,
		0x30, 0x06, 0x30, 0x04, 0x06, 0x00, 0x05, 0x00}

	if tag := s.getPDUType(data); tag != ASN1_GET_REQUEST {
		t.Errorf("getPDUType = 0x%02X, want its ASN1_GET_REQUEST bail (0x%02X): the outer "+
			"SEQUENCE length is unreadable, so it must not walk on with a skip computed "+
			"from a length it could not read\ndatagram: % x", tag, ASN1_GET_REQUEST, data)
	}
	if req := s.parseIncomingRequest(data); req.OID != defaultParsedOID || req.RequestID != defaultParsedRequestID {
		t.Errorf("parseIncomingRequest read OID %q / request-id %d past an unreadable outer "+
			"length, want its defaults %q / %d\ndatagram: % x",
			req.OID, req.RequestID, defaultParsedOID, defaultParsedRequestID, data)
	}
	if nonRep, maxRep := s.parseGetBulkParams(data); nonRep != defaultBulkNonRepeat || maxRep != defaultBulkMaxRepeat {
		t.Errorf("parseGetBulkParams = (%d, %d), want the defaults (%d, %d)",
			nonRep, maxRep, defaultBulkNonRepeat, defaultBulkMaxRepeat)
	}

	// The positive control: the SAME datagram with a readable outer length is
	// served as a walk, so the assertions above are about the length byte and
	// not about the rest of the datagram being unusable.
	good := append([]byte{}, data...)
	good[1] = byte(len(data) - 2)
	if tag := s.getPDUType(good); tag != ASN1_GET_NEXT {
		t.Errorf("positive control: getPDUType = 0x%02X, want GETNEXT (0x%02X)\ndatagram: % x",
			tag, ASN1_GET_NEXT, good)
	}
}

var syntheticResultsMarker = []byte("SYNTHETIC-RESULTS-NO-DATAGRAM")

// recordingTB is a fatalfTB that records instead of aborting.
//
// It does NOT call runtime.Goexit the way testing.T.Fatalf does, deliberately:
// the claims in assertV2cParserAgreement are independent of one another, so
// letting the helper run to the end reports EVERY claim a datagram violates
// rather than only the first. That is what lets a test assert which claims
// fired and, just as importantly, which did not.
type recordingTB struct{ msgs []string }

func (r *recordingTB) Helper() {}
func (r *recordingTB) Fatalf(format string, args ...any) {
	r.msgs = append(r.msgs, fmt.Sprintf(format, args...))
}

func (r *recordingTB) fired(phrase string) bool {
	for _, m := range r.msgs {
		if strings.Contains(m, phrase) {
			return true
		}
	}
	return false
}

// TestAgreementHelperCatchesADisagreement makes the helper's own logic a
// subject.
//
// Every line of assertV2cParserAgreement runs only as an assertion, so an
// inverted guard, a swapped operand or a claim deleted outright produces a
// green suite forever — the fuzz targets cannot notice an assertion that
// stopped asserting. This drives it over datagrams whose verdict is known
// independently (the two defects nl6#534 found) and over the well-formed
// agreement seeds, and asserts which claims fire and which stay silent.
//
// Until nl6#559 and nl6#560 were fixed, the FIRING half of that subject came
// from the defects themselves: four reproducers whose verdict was known
// independently. Fixing the parsers removed every datagram that can make a
// correct parser set disagree — by construction, since agreement is now the
// property — so the firing half is driven through checkV2cParserAgreement with
// the results the PRE-FIX parsers actually returned. The reproducer datagrams
// stay, as the silent regression rows that pin the fixes.
//
// CLAIM 2 had no witness of either kind before: two correct name readers
// cannot be made to disagree by choosing bytes. Synthetic results give it its
// firing half, and it keeps its silent half over the real datagrams.
func TestAgreementHelperCatchesADisagreement(t *testing.T) {
	s := newTestServer(fuzzFixtureOIDs(20))

	const (
		claim1 = "PDU-offset disagreement"
		claim2 = "varbind-name disagreement"
		claim3 = "PDU-tag disagreement"
	)

	// The firing half: parse results no correct parser set produces any more.
	//
	// The first three are MEASURED, not modelled. They were captured by
	// checking the pre-change production files out over the current test file
	// and printing all four readers' output for each reproducer datagram:
	//
	//	git show HEAD~1:go/nl6/snmp_server.go > snmp_server.go   (and _handlers, _response)
	//	go test ./nl6/ -run TestZZPrefixCapture -v                (a throwaway logging test)
	//
	//	repro560NegativeLengthWalksBackwards  getPDUType=0xA0 params=(12336,10) req.OID=default
	//	repro559NonMinimalVersion (GETBULK)   getPDUType=0x01 params=(0,7)      req.OID=name
	//	repro559NonMinimalVersionGetNext      getPDUType=0x01 params=(0,10)     req.OID=name
	//	repro559ZeroLengthVersion             getPDUType=0x06 params=(0,10)     req.OID=name
	//	repro559CommunityLengthUnreadable     getPDUType=0xA0 params=(0,10)     req.OID=name
	//
	// Hand-authoring them would make a guard look reachable when it is not,
	// which is the failure the nl6#534 review already paid for once. The rows
	// below are those lines transcribed.
	//
	// data is a MARKER rather than nil: a synthetic row's failure message ends
	// in the datagram, and an empty one there is indistinguishable from a real
	// datagram that happened to be empty.
	synthetic := []struct {
		name   string
		res    v2cParseResults
		fires  []string
		silent []string
	}{
		{
			name: "pre-fix nl6#560: parseGetBulkParams invents a GETBULK, getPDUType bails",
			res: v2cParseResults{
				req:    SNMPRequest{OID: defaultParsedOID},
				pduTag: ASN1_GET_REQUEST,
				nonRep: 12336,
				maxRep: defaultBulkMaxRepeat,
			},
			fires:  []string{claim1},
			silent: []string{claim2, claim3},
		},
		{
			name: "pre-fix nl6#559: getPDUType reports the version content octet 0x01",
			res: v2cParseResults{
				req:    SNMPRequest{OID: roundTripOIDs[0]},
				pduTag: 0x01,
				oids:   []string{roundTripOIDs[0]},
				listOK: true,
				nonRep: defaultBulkNonRepeat,
				maxRep: 7,
			},
			fires:  []string{claim1, claim3},
			silent: []string{claim2},
		},
		{
			name: "pre-fix nl6#559: zero-length version, getPDUType reports 0x06",
			res: v2cParseResults{
				req:    SNMPRequest{OID: roundTripOIDs[0]},
				pduTag: 0x06,
				oids:   []string{roundTripOIDs[0]},
				listOK: true,
				nonRep: defaultBulkNonRepeat,
				maxRep: defaultBulkMaxRepeat,
			},
			fires:  []string{claim3},
			silent: []string{claim1, claim2},
		},
		{
			// The BLIND SPOT, asserted as such. This is what the pre-fix
			// parsers returned for repro559CommunityLengthUnreadable: a
			// getPDUType bail where parseIncomingRequest read a GETNEXT with
			// a real name. Every claim is silent, because ASN1_GET_REQUEST is
			// both a PDU tag and getPDUType's bail value (CLAIM 3's exemption)
			// and parseGetBulkParams declines the same envelope (CLAIM 1's
			// skip). It is pinned behaviourally instead, by
			// TestUnreadableCommunityLengthIsWalkedAsAGetNext; this row exists
			// so that a future claim which CAN see it fails here first and is
			// noticed rather than silently widening the suite.
			name: "pre-fix nl6#559 community instance: no claim can see it",
			res: v2cParseResults{
				req:    SNMPRequest{OID: roundTripOIDs[0]},
				pduTag: ASN1_GET_REQUEST,
				listOK: true,
				nonRep: defaultBulkNonRepeat,
				maxRep: defaultBulkMaxRepeat,
			},
			silent: []string{claim1, claim2, claim3},
		},
		{
			name: "two name readers disagree about the first varbind name",
			res: v2cParseResults{
				req:    SNMPRequest{OID: roundTripOIDs[0]},
				pduTag: ASN1_GET_REQUEST,
				oids:   []string{roundTripOIDs[1]},
				listOK: true,
				nonRep: defaultBulkNonRepeat,
				maxRep: defaultBulkMaxRepeat,
			},
			fires:  []string{claim2},
			silent: []string{claim1, claim3},
		},
	}
	for _, tt := range synthetic {
		t.Run("synthetic: "+tt.name, func(t *testing.T) {
			var rec recordingTB
			checkV2cParserAgreement(&rec, tt.res, syntheticResultsMarker)
			for _, want := range tt.fires {
				if !rec.fired(want) {
					t.Errorf("%q did not fire; the helper reported %d message(s): %q",
						want, len(rec.msgs), rec.msgs)
				}
			}
			for _, notWant := range tt.silent {
				if rec.fired(notWant) {
					t.Errorf("%q fired but must not; messages: %q", notWant, rec.msgs)
				}
			}
		})
	}

	tests := []struct {
		name   string
		data   []byte
		fires  []string
		silent []string
	}{}
	// The silent half: the four reproducers, which the two envelope fixes
	// turned from disagreements into ordinary datagrams, plus the well-formed
	// controls.
	for _, d := range envelopeReproDatagrams() {
		tests = append(tests, struct {
			name   string
			data   []byte
			fires  []string
			silent []string
		}{
			name:   "regression: " + d.name,
			data:   d.data,
			silent: []string{claim1, claim2, claim3},
		})
	}
	for _, d := range agreementSeedDatagrams() {
		tests = append(tests, struct {
			name   string
			data   []byte
			fires  []string
			silent []string
		}{
			name:   "well-formed control: " + d.name,
			data:   d.data,
			silent: []string{claim1, claim2, claim3},
		})
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var rec recordingTB
			assertV2cParserAgreement(&rec, s, tt.data)
			for _, want := range tt.fires {
				if !rec.fired(want) {
					t.Errorf("%q did not fire; the helper reported %d message(s): %q",
						want, len(rec.msgs), rec.msgs)
				}
			}
			for _, notWant := range tt.silent {
				if rec.fired(notWant) {
					t.Errorf("%q fired but must not; messages: %q", notWant, rec.msgs)
				}
			}
		})
	}
}

// TestParserDefaultsMatchTheTestConstants pins the hand-copied literals above
// to the parsers they were copied from.
//
// Every guard in assertV2cParserAgreement is written against one of these. If
// a production default moves, the guards silently start skipping real reads or
// firing on absent ones, with no signal anywhere — the cheapest possible
// coupling to break loudly, so it is broken loudly here. A nil datagram is the
// shortest input that reaches every default.
func TestParserDefaultsMatchTheTestConstants(t *testing.T) {
	s := robustnessTestServer()

	req := s.parseIncomingRequest(nil)
	if req.OID != defaultParsedOID {
		t.Errorf("parseIncomingRequest default OID = %q, test constant is %q", req.OID, defaultParsedOID)
	}
	if req.RequestID != defaultParsedRequestID {
		t.Errorf("parseIncomingRequest default request-id = %d, test constant is %d",
			req.RequestID, defaultParsedRequestID)
	}
	if req.Community != defaultParsedCommunity {
		t.Errorf("parseIncomingRequest default community = %q, test constant is %q",
			req.Community, defaultParsedCommunity)
	}
	if req.Version != defaultParsedVersion {
		t.Errorf("parseIncomingRequest default version = %d, test constant is %d",
			req.Version, defaultParsedVersion)
	}

	nonRep, maxRep := s.parseGetBulkParams(nil)
	if nonRep != defaultBulkNonRepeat || maxRep != defaultBulkMaxRepeat {
		t.Errorf("parseGetBulkParams defaults = (%d, %d), test constants are (%d, %d)",
			nonRep, maxRep, defaultBulkNonRepeat, defaultBulkMaxRepeat)
	}

	// parseIncomingRequestReadsPDU is the same kind of hand-copied coupling as
	// the constants above: a test-local mirror of which PDU tags the parser
	// walks into. Ask the parser instead, over every tag the round-trip target
	// builds. A request whose name is decoded is proof the parser walked in;
	// one left at the default OID and the default request-id is proof it did
	// not.
	for _, tag := range roundTripPDUTags {
		data := buildV2cRequestForRoundTrip(tag, snmpVersion2c, "public", 4242,
			[]string{roundTripOIDs[0]}, 0, 0, 0)
		req := s.parseIncomingRequest(data)
		walkedIn := req.OID == roundTripOIDs[0] && req.RequestID == 4242
		if walkedIn != parseIncomingRequestReadsPDU(tag) {
			t.Errorf("parseIncomingRequestReadsPDU(0x%02X) = %v but the parser %s: "+
				"OID %q, request-id %d", tag, parseIncomingRequestReadsPDU(tag),
				map[bool]string{true: "walked into the PDU", false: "kept its defaults"}[walkedIn],
				req.OID, req.RequestID)
		}
	}

	// The blind spot the first cut of nl6#534 shipped: a round-trip corpus
	// whose first name equals the parser's fallback compares the default with
	// itself, and CLAIM 2 is guarded off on exactly that case, so a total loss
	// of the request OID goes unnoticed by every assertion in the file.
	for i, oid := range roundTripOIDs {
		if oid == defaultParsedOID {
			t.Errorf("roundTripOIDs[%d] is parseIncomingRequest's own fallback %q: "+
				"a first-name round-trip over it cannot fail", i, defaultParsedOID)
		}
	}
}

// envelopeReproDatagrams is the nl6#559 / nl6#560 half of what
// addAgreementSeeds registers: the five datagrams whose parse the envelope
// fixes CHANGED.
//
// They are kept apart from agreementSeedDatagrams because the two lists answer
// different questions. Those are well-formed datagrams chosen so each claim's
// GUARD is satisfied by a committed seed; these are the mis-parsed shapes, and
// their property is that every claim is now SILENT on them. Mixing them would
// make TestAgreementSeedsReachEveryGuard's "seed satisfies the guard but
// violates the claim" check read as a contradiction on a malformed input it
// was never about.
func envelopeReproDatagrams() []struct {
	name string
	data []byte
} {
	return []struct {
		name string
		data []byte
	}{
		{"nl6#560 negative community length", repro560NegativeLengthWalksBackwards},
		{"nl6#559 non-minimal version, GETBULK", repro559NonMinimalVersion},
		{"nl6#559 non-minimal version, GETNEXT", repro559NonMinimalVersionGetNext},
		{"nl6#559 zero-length version INTEGER", repro559ZeroLengthVersion},
		{"nl6#559 unreadable community length", repro559CommunityLengthUnreadable},
	}
}

// agreementSeedDatagrams is the single definition of the WELL-FORMED
// datagrams addAgreementSeeds registers, so the seeds and the reachability
// test cannot drift apart. addAgreementSeeds registers three lists in all —
// this one, envelopeReproDatagrams and brokenGetBulkEnvelopes — and each is
// defined once, for the same reason.
func agreementSeedDatagrams() []struct {
	name string
	data []byte
} {
	return []struct {
		name string
		data []byte
	}{
		{"GETBULK non-repeaters=2 max-repetitions=200", buildGetBulkPDUForFuzz(2, 200, ".1.3.6.1.2.1.2.2.1.2")},
		{"GETBULK max-repetitions=60000", buildGetBulkPDUForFuzz(0, 60000, ".1.3.6.1.2.1.31.1.1.1.6.7")},
		{"three-binding GET", snmpRequestAt(ASN1_GET_REQUEST, snmpVersion2c,
			[]string{".1.3.6.1.2.1.2.2.1.2.1", ".1.3.6.1.2.1.31.1.1.1.6.7", ".1.3.6.1.4.1.9.9.999.1.2.3"})},
	}
}

// addAgreementSeeds registers datagrams the nl6#534 agreement assertions need
// in order to be REACHABLE by an ordinary `go test` seed replay.
//
// Every GETBULK seed this file had before nl6#534 carries non-repeaters=0 and
// max-repetitions=10 — which are exactly parseGetBulkParams' defaults, so its
// return value cannot distinguish "read the PDU" from "never found it" and
// CLAIM 1 is guarded off on every one of them. An assertion no committed seed
// can reach is an assertion CI does not run, which is the failure mode this
// change exists to avoid.
//
// Reachability is not left to inspection: TestAgreementSeedsReachEveryGuard
// asserts each guard predicate directly over these datagrams, so reverting a
// seed to the defaults fails a named test instead of silently disarming a
// claim.
func addAgreementSeeds(f *testing.F) {
	for _, d := range agreementSeedDatagrams() {
		f.Add(d.data)
	}
	// The nl6#559 / nl6#560 reproducers, committed as seeds now that the
	// parsers they mis-parsed are fixed. Every target that calls
	// assertV2cParserAgreement therefore replays both defects on an ordinary
	// `go test` run.
	for _, d := range envelopeReproDatagrams() {
		f.Add(d.data)
	}
	// One datagram per declared-length read in parseGetBulkParams. Four of
	// those guards have no behavioural witness (see
	// TestParseGetBulkParamsBailsOnEveryUnreadableLength), so seeding the
	// shapes is what puts them in front of the agreement claims at all.
	for _, d := range brokenGetBulkEnvelopes {
		f.Add(d.data)
	}
}

// TestAgreementSeedsReachEveryGuard is the positive control for the agreement
// claims: it asserts that a committed seed actually SATISFIES each claim's
// guard, so the claim runs in CI rather than being skipped on every input.
//
// Without it, reverting buildGetBulkPDUForFuzz(2, 200, …) to (0, 10) and
// dropping the 60000 seed leaves the suite green, the test count unchanged,
// and CLAIM 1 unreachable on every committed seed — a verified-failing
// mutation would start passing with no signal. Same shape as
// TestWellFormedMultiVarbindStillAnswered, which exists for the same reason on
// the nl6#537 discard path.
func TestAgreementSeedsReachEveryGuard(t *testing.T) {
	s := newTestServer(fuzzFixtureOIDs(20))

	var claim1, claim2, claim3 int
	for _, d := range agreementSeedDatagrams() {
		req := s.parseIncomingRequest(d.data)
		pduTag := s.getPDUType(d.data)
		oids, listOK := s.parseAllOIDsFromRequest(d.data)
		nonRep, maxRep := s.parseGetBulkParams(d.data)

		if nonRep != defaultBulkNonRepeat || maxRep != defaultBulkMaxRepeat {
			claim1++
			if pduTag != ASN1_GET_BULK {
				t.Errorf("%s: seed satisfies CLAIM 1's guard but violates the claim "+
					"(getPDUType 0x%02X) — the seeds must be well formed", d.name, pduTag)
			}
		}
		if listOK && len(oids) > 0 && req.OID != defaultParsedOID {
			claim2++
		}
		if req.OID != defaultParsedOID {
			claim3++
		}
	}

	if claim1 == 0 {
		t.Error("no committed agreement seed makes parseGetBulkParams report a non-default " +
			"(non-repeaters, max-repetitions): CLAIM 1 is skipped on every seed and CI never runs it")
	}
	if claim2 == 0 {
		t.Error("no committed agreement seed makes BOTH name readers decode a name: " +
			"CLAIM 2 is skipped on every seed")
	}
	if claim3 == 0 {
		t.Error("no committed agreement seed makes parseIncomingRequest decode a name: " +
			"CLAIM 3 is skipped on every seed")
	}

	// The discard claim's guard is `ok == false`, which only the malformed
	// shapes reach. addMalformedVarbindSeeds is the corpus that supplies it.
	malformed := 0
	for _, pkt := range malformedSeedDatagrams() {
		if _, ok := s.parseAllOIDsFromRequest(pkt); !ok {
			malformed++
		}
	}
	if malformed == 0 {
		t.Error("no committed malformed seed makes parseAllOIDsFromRequest report false: " +
			"assertMalformedListIsDiscarded is skipped on every seed")
	}
}

// malformedSeedDatagrams is the single definition of the datagrams
// addMalformedVarbindSeeds registers, for the same reason
// agreementSeedDatagrams exists.
func malformedSeedDatagrams() [][]byte {
	out := [][]byte{
		malformedNameRequest(ASN1_GET_REQUEST, snmpVersion2c, 3, 1),
		malformedNameRequest(ASN1_GET_NEXT, snmpVersion2c, 1, 0),
		malformedNameRequest(ASN1_GET_BULK, snmpVersion2c, 2, 1),
	}
	for _, tc := range brokenVarbindLists {
		out = append(out, requestWithRawList(ASN1_GET_REQUEST, snmpVersion2c, tc.list))
	}
	return out
}

// roundTripOIDs are the names the round-trip target draws from. They are fixed
// rather than fuzzed because encodeOID/decodeOID agreement is already pinned by
// FuzzOIDRoundTrip (nl6#529); what varies here is the SHAPE of the request
// around them — how many bindings, which PDU tag, how the lengths are encoded.
//
// defaultParsedOID (.1.3.6.1.2.1.1.1.0) is DELIBERATELY ABSENT, and
// TestParserDefaultsMatchTheTestConstants enforces that. With it present at
// index 0 the first-name round-trip compared parseIncomingRequest's fallback
// against itself and could not fail for any input, while CLAIM 2 was guarded
// off on precisely that value — so neutering the name decode outright left the
// entire suite green. That is the failure the change's own spec warned about,
// shipped.
var roundTripOIDs = []string{
	".1.3.6.1.2.1.2.2.1.2.1",
	".1.3.6.1.2.1.31.1.1.1.6.7",
	".1.3.6.1.4.1.9.9.999.1.2.3",
	".1.0.8802.1.1.2.1.3.7.1.3.1",
	".1.3.6.1.2.1.1.4.0",
}

// roundTripPDUTags are the PDU tags the round-trip target builds.
//
// GetResponse (0xA2) and SetRequest (0xA3) are included on purpose: they are
// where parseAllOIDsFromRequest (which accepts ANY tag) reads names and
// parseIncomingRequest (which recognises three) does not, so they are the
// divergence most worth exercising. The round-trip asserts the CONTRAPOSITIVE
// for them — request-id and OID must stay at their defaults — rather than
// skipping.
var roundTripPDUTags = []byte{ASN1_GET_REQUEST, ASN1_GET_NEXT, ASN1_GET_BULK, ASN1_GET_RESPONSE, 0xA3}

// Encoding-style bits for buildV2cRequestForRoundTrip. BER admits encodings a
// minimal encoder never emits, and nl6#559 is exactly such a shape, so the
// builder has to be able to express them or the target cannot rediscover its
// own headline defect.
const (
	rtStyleVersionPadded   = 1 << iota // version INTEGER with a leading 0x00 octet
	rtStyleCommunityLong               // community length in long form on a short body
	rtStyleRequestIDPadded             // request-id INTEGER with a leading 0x00 octet
	rtStyleMask            = rtStyleVersionPadded | rtStyleCommunityLong | rtStyleRequestIDPadded
)

// encodeIntegerPadded encodes v with one extra leading 0x00 content octet: a
// legal, non-minimal BER INTEGER.
func encodeIntegerPadded(v int) []byte {
	body := encodeInteger(v)
	if len(body) < 2 {
		return body
	}
	content := append([]byte{0x00}, body[2:]...)
	return append([]byte{ASN1_INTEGER}, append(encodeLength(len(content)), content...)...)
}

// encodeOctetStringLongForm encodes s with a 1-octet long-form length
// (0x81 nn), which is legal BER for any length and what parseLength's long-form
// arm exists to read.
func encodeOctetStringLongForm(s string) []byte {
	if len(s) > 0xff {
		return encodeOctetString(s)
	}
	out := []byte{ASN1_OCTET_STRING, 0x81, byte(len(s))}
	return append(out, s...)
}

// buildV2cRequestForRoundTrip encodes a v1/v2c request from field values using
// only the package's own encoders, plus the two legal non-minimal spellings
// above when style asks for them. Returns the datagram.
func buildV2cRequestForRoundTrip(pduTag byte, version int, community string, reqID int,
	oids []string, int1, int2 int, style int) []byte {
	var varbinds []byte
	for _, oid := range oids {
		varbinds = append(varbinds, encodeVarBind(oid, encodeNull())...)
	}

	reqIDBytes := encodeInteger(reqID)
	if style&rtStyleRequestIDPadded != 0 {
		reqIDBytes = encodeIntegerPadded(reqID)
	}

	var pduBody []byte
	pduBody = append(pduBody, reqIDBytes...)
	// For GETBULK these are non-repeaters and max-repetitions (RFC 3416
	// §4.2.3); for GET/GETNEXT they are error-status and error-index.
	pduBody = append(pduBody, encodeInteger(int1)...)
	pduBody = append(pduBody, encodeInteger(int2)...)
	pduBody = append(pduBody, encodeSequence(varbinds)...)

	pdu := append([]byte{pduTag}, append(encodeLength(len(pduBody)), pduBody...)...)

	versionBytes := encodeInteger(version)
	if style&rtStyleVersionPadded != 0 {
		versionBytes = encodeIntegerPadded(version)
	}
	communityBytes := encodeOctetString(community)
	if style&rtStyleCommunityLong != 0 {
		communityBytes = encodeOctetStringLongForm(community)
	}

	var msg []byte
	msg = append(msg, versionBytes...)
	msg = append(msg, communityBytes...)
	msg = append(msg, pdu...)
	return encodeSequence(msg)
}

// FuzzV2cRequestRoundTrip is the encoder half of nl6#534.
//
// The claim is `parser ≡ encoder⁻¹` and NOT `parser ≡ spec`: the ground truth
// is what this package's own encoders were handed, so a convention the encoder
// and the parser share — a wrong one included — round-trips perfectly and is
// invisible here. What it does catch is a parser that loses or corrupts a field
// the encoder wrote, which is the nl6#514 shape (a zero-length community
// written as `04 00` and read back as absent).
//
// It is where the version, community and request-id claims are made, because
// those fields are READ by several parsers and REPORTED by only
// parseIncomingRequest, so there is no second reader to differ from.
// (CLAIM 3 in the agreement helper makes the version claim a second way, by
// comparing the OFFSET that follows the version rather than its value.)
// Asserting the server's ECHO of a field against the parser that produced the
// echo would be an assertion that cannot fail; driving the echo from the value
// the ENCODER was given, as the last block does, is what restores it.
//
// The fuzzed inputs are constrained to what the encoders can express, and each
// constraint is a documented parser bound rather than a convenience:
//   - version 0..127, because parseIncomingRequest reads the version only when
//     it encodes in a single content octet — so the version VALUE claim is
//     additionally skipped under rtStyleVersionPadded, which is outside that
//     bound by construction;
//   - request-id 0..2^31-1, and the request-id VALUE claim is skipped when a
//     padding octet pushes the content past the 4-octet range the parser
//     documents.
//
// Nothing else is skipped under a non-minimal style. That is the point of
// having the styles: a padded version is legal BER that desynchronises
// getPDUType, so this target can rediscover nl6#559 on its own. Committed
// seeds all use style 0, so ordinary seed replay stays green.
func FuzzV2cRequestRoundTrip(f *testing.F) {
	f.Add([]byte("public"), uint8(1), uint32(42), uint8(0), uint8(1), uint32(0), uint32(10), uint8(0))
	// nl6#514: a zero-length community must come back present-and-empty.
	f.Add([]byte(""), uint8(1), uint32(0), uint8(1), uint8(3), uint32(2), uint32(200), uint8(0))
	// A community past the 127-byte short-form boundary, plus a GETBULK whose
	// max-repetitions needs two content octets (the nl6#489 ceiling).
	f.Add(bytes.Repeat([]byte("c"), 200), uint8(0), uint32(2147483647), uint8(2), uint8(4), uint32(3), uint32(60000), uint8(0))
	f.Add([]byte{0x00, 0xff, 0x0a}, uint8(1), uint32(65536), uint8(2), uint8(0), uint32(0), uint32(0), uint8(0))
	// A GETBULK whose max-repetitions needs three and four content octets:
	// parseBERInt is documented to read at ANY width and nl6#535's clamp work
	// lives up there.
	f.Add([]byte("public"), uint8(1), uint32(7), uint8(2), uint8(2), uint32(1), uint32(1<<20), uint8(0))
	f.Add([]byte("public"), uint8(1), uint32(7), uint8(2), uint8(2), uint32(1), uint32(1<<28), uint8(0))
	// GetResponse and SetRequest: parseAllOIDsFromRequest reads the names,
	// parseIncomingRequest keeps its defaults.
	f.Add([]byte("public"), uint8(1), uint32(9), uint8(3), uint8(2), uint32(0), uint32(0), uint8(0))
	f.Add([]byte("public"), uint8(1), uint32(9), uint8(4), uint8(2), uint32(0), uint32(0), uint8(0))
	// Long-form community length on a short community: legal BER, and the only
	// non-minimal style that no parser mishandles today, so it is safe to seed.
	f.Add([]byte("public"), uint8(1), uint32(11), uint8(0), uint8(2), uint32(0), uint32(0), uint8(rtStyleCommunityLong))
	// A request-id whose padded spelling needs FIVE content octets: legal BER,
	// what an encoder emits for any value at or above 2^31, and the shape
	// live fuzzing found within a second of nl6#559/#560 unblocking this
	// target. Before nl6#562 the parser stopped at it and read the `06 01 30`
	// inside the PDU as the first varbind name; now every claim above is made
	// on it unconditionally.
	f.Add([]byte("public"), uint8(1), uint32(0x7ffffffd), uint8(2), uint8(4), uint32(0), uint32(10), uint8(rtStyleRequestIDPadded))

	f.Fuzz(func(t *testing.T, community []byte, version uint8, reqID uint32, pduSel uint8,
		nVarbinds uint8, int1, int2 uint32, style uint8) {
		pduTag := roundTripPDUTags[int(pduSel)%len(roundTripPDUTags)]
		ver := int(version & 0x7f)
		rid := int(reqID & 0x7fffffff)
		comm := string(community)
		st := int(style) & rtStyleMask

		// %9 over a 5-element table, so a name REPEATS in a long list. A list
		// naming the same column twice is ordinary manager behaviour and was
		// unreachable while the modulus matched the table length.
		oids := make([]string, 0, 9)
		for i := 0; i < int(nVarbinds)%9; i++ {
			oids = append(oids, roundTripOIDs[i%len(roundTripOIDs)])
		}

		data := buildV2cRequestForRoundTrip(pduTag, ver, comm, rid, oids, int(int1), int(int2), st)
		s := fuzzTestServer(50)
		readsPDU := parseIncomingRequestReadsPDU(pduTag)

		req := s.parseIncomingRequest(data)
		if req.Community != comm {
			t.Fatalf("community round-trip: encoded %q (%d bytes), parsed %q — "+
				"a zero-length community read as absent is nl6#514\ndatagram: % x",
				comm, len(comm), req.Community, data)
		}
		// The version VALUE is only in parseIncomingRequest's stated range when
		// it occupies exactly one content octet; a padded spelling is outside
		// it by construction, so the claim is skipped rather than weakened.
		// The version's EFFECT on the following offset is still asserted, by
		// CLAIM 3 at the end of this callback.
		if st&rtStyleVersionPadded == 0 && req.Version != ver {
			t.Fatalf("version round-trip: encoded %d, parsed %d\ndatagram: % x", ver, req.Version, data)
		}

		// The request-id claim is made at EVERY width the encoder can emit,
		// including the padded five-octet spelling. It used to be skipped
		// past four content octets, because parseIncomingRequest documented a
		// 1..4 bound and did not advance past a wider field — nl6#562, fixed
		// in this change, so the skip is gone rather than merely narrowed.
		// Two guards were removed here, not one: the same bound also silenced
		// the first-name claim below, and a skip on both sides of a defect is
		// how a target stops being able to see it.
		if readsPDU {
			if req.RequestID != rid {
				t.Fatalf("request-id round-trip: encoded %d, parsed %d\ndatagram: % x",
					rid, req.RequestID, data)
			}
		} else if req.RequestID != defaultParsedRequestID || req.OID != defaultParsedOID {
			// The contrapositive of parseIncomingRequestReadsPDU: a PDU tag it
			// does not recognise must leave both fields at their defaults. A
			// parser that walked into a GetResponse or SetRequest would answer
			// a request nobody made.
			t.Fatalf("PDU-tag gate: parseIncomingRequest walked into a 0x%02X PDU and reported "+
				"request-id %d / OID %q instead of its defaults %d / %q\ndatagram: % x",
				pduTag, req.RequestID, req.OID, defaultParsedRequestID, defaultParsedOID, data)
		}

		gotOIDs, ok := s.parseAllOIDsFromRequest(data)
		if !ok {
			t.Fatalf("parseAllOIDsFromRequest calls this package's own encoding malformed\ndatagram: % x", data)
		}
		if len(gotOIDs) != len(oids) {
			t.Fatalf("varbind-count round-trip: encoded %d names %q, parsed %d %q\ndatagram: % x",
				len(oids), oids, len(gotOIDs), gotOIDs, data)
		}
		for i := range oids {
			if gotOIDs[i] != oids[i] {
				t.Fatalf("varbind-name round-trip at %d: encoded %q, parsed %q (full list %q)\ndatagram: % x",
					i, oids[i], gotOIDs[i], gotOIDs, data)
			}
		}
		if readsPDU {
			wantFirst := defaultParsedOID
			if len(oids) > 0 {
				wantFirst = oids[0]
			}
			if req.OID != wantFirst {
				t.Fatalf("first-name round-trip: encoded %q, parseIncomingRequest reports %q\ndatagram: % x",
					wantFirst, req.OID, data)
			}
		}

		// GETBULK parameters. For every other tag the same two integers are
		// error-status and error-index, and parseGetBulkParams must NOT read
		// them: it is gated on the PDU tag, and a parser that ignored the gate
		// would report a manager's error-index as a repetition count.
		//
		// Checked BEFORE the PDU-type round-trip below, deliberately: the two
		// are demonstrated by different mutations, and with the order reversed
		// the PDU-type claim absorbs the mutation that belongs to this one.
		gotNonRep, gotMaxRep := s.parseGetBulkParams(data)
		if pduTag == ASN1_GET_BULK {
			if gotNonRep != int(int1) || gotMaxRep != int(int2) {
				t.Fatalf("GETBULK params round-trip: encoded non-repeaters=%d max-repetitions=%d, "+
					"parsed %d/%d (BER width is the nl6#489 defect: anything >= 128 used to become 10)"+
					"\ndatagram: % x", int1, int2, gotNonRep, gotMaxRep, data)
			}
		} else if gotNonRep != defaultBulkNonRepeat || gotMaxRep != defaultBulkMaxRepeat {
			t.Fatalf("parseGetBulkParams read the error-status/error-index of a 0x%02X PDU as "+
				"non-repeaters=%d max-repetitions=%d instead of keeping its defaults %d/%d"+
				"\ndatagram: % x", pduTag, gotNonRep, gotMaxRep, defaultBulkNonRepeat, defaultBulkMaxRepeat, data)
		}

		if got := s.getPDUType(data); got != pduTag {
			t.Fatalf("PDU-type round-trip: encoded 0x%02X, getPDUType reports 0x%02X\ndatagram: % x",
				pduTag, got, data)
		}

		// End-to-end: the request-id the server echoes, read back by a
		// DIFFERENT parser (parseV2cAck, the INFORM-ack reader — a GetResponse
		// is a GetResponse whichever subsystem produced it) and compared
		// against the value the ENCODER was given. Comparing it against
		// parseIncomingRequest's output instead would compare the parser with
		// itself, since the echo is built from exactly that value.
		//
		// v2c only: parseV2cAck requires version == 1 (RFC 3416 informs are
		// v2c), so a v1 or v3-numbered request is out of its stated range.
		if ver == snmpVersion2c {
			resp := s.handleSNMPv2cRequest(data)
			// An EMPTY response is itself the failure, not a reason to skip:
			// parseAllOIDsFromRequest accepted this datagram above, so a
			// discard here is the nl6#537 OVER-discard direction — a server
			// that answered nothing at all would otherwise pass silently.
			if len(resp) == 0 {
				t.Fatalf("the server discarded a datagram this package built and "+
					"parseAllOIDsFromRequest accepted (nl6#537 over-discard)\ndatagram: % x", data)
			}
			gotID, _, err := parseV2cAck(resp)
			if err != nil {
				t.Fatalf("the server's own GetResponse does not parse as one: %v\nresponse: % x", err, resp)
			}
			wantID := rid
			// A PDU tag the parser does not walk into is the only case left
			// where the echo is the default: since nl6#562 the request-id is
			// read at any width the encoder emits, so a padded one is echoed
			// as itself rather than as 123 to a manager that sent something
			// else.
			if !readsPDU {
				wantID = defaultParsedRequestID
			}
			if int(gotID) != wantID {
				t.Fatalf("request-id echo: encoded %d, the response carries %d\ndatagram: % x\nresponse: % x",
					wantID, gotID, data, resp)
			}
		}

		// Every self-differential claim must also hold on a datagram this
		// package built. A disagreement here is strictly worse than one on
		// mutated bytes: it means the parsers cannot agree about nl6's own
		// output. Run LAST so its Fatalf cannot pre-empt a round-trip claim
		// that a mutation is meant to demonstrate.
		assertV2cParserAgreement(t, s, data)
	})
}

// readFuzzCorpus reads the committed corpus files under testdata/fuzz/<dir>
// and returns the []byte entries they carry.
//
// Go's corpus file format is a version line followed by one Go literal per
// fuzz argument. Every target read here takes a single []byte, so a line that
// is not a []byte literal is skipped rather than fataled — a corpus for a
// multi-argument target would otherwise make this helper look broken.
func readFuzzCorpus(t *testing.T, dir string) [][]byte {
	t.Helper()
	files, err := filepath.Glob(filepath.Join("testdata", "fuzz", dir, "*"))
	if err != nil {
		t.Fatalf("glob corpus for %s: %v", dir, err)
	}
	var out [][]byte
	for _, f := range files {
		b, err := os.ReadFile(f)
		if err != nil {
			t.Fatalf("read %s: %v", f, err)
		}
		for _, line := range strings.Split(string(b), "\n") {
			line = strings.TrimSpace(line)
			if !strings.HasPrefix(line, "[]byte(") || !strings.HasSuffix(line, ")") {
				continue
			}
			v, err := strconv.Unquote(strings.TrimSuffix(strings.TrimPrefix(line, "[]byte("), ")"))
			if err != nil {
				continue
			}
			out = append(out, []byte(v))
		}
	}
	if len(out) == 0 {
		t.Fatalf("no []byte entries found in testdata/fuzz/%s", dir)
	}
	return out
}

// wellFormedMinimalCorpus is a deterministic set of v1/v2c requests in the
// MINIMAL spelling every shipped manager emits: one-octet version, short-form
// lengths, an unpadded request-id inside 1..4 octets, names the fixture serves.
//
// Built from nl6's own encoders rather than from captured bytes, so it stays
// readable, and deliberately NOT fuzz-derived: the acceptance criterion is
// about the datagrams real managers send, and a corpus of mutated bytes would
// bury three deliberate changes on malformed input under noise.
//
// Each entry carries its PDU tag and binding count, because nl6#542 made
// GETNEXT answer every binding: a multi-binding GETNEXT is the one shape in
// this corpus whose response legitimately changed, and the digest below has to
// be able to leave exactly that shape out without hand-listing datagrams.
type wellFormedDatagram struct {
	data  []byte
	tag   byte
	names int
}

func wellFormedMinimalCorpus() []wellFormedDatagram {
	names := []string{
		".1.3.6.1.2.1.1.1.0",
		".1.3.6.1.2.1.2.2.1.2.1",
		".1.3.6.1.2.1.2.2.1.5.3",
		".1.3.6.1.2.1.31.1.1.1.6.7",
	}
	var out []wellFormedDatagram
	for _, tag := range []byte{ASN1_GET_REQUEST, ASN1_GET_NEXT, ASN1_GET_BULK} {
		for _, ver := range []int{snmpVersion1, snmpVersion2c} {
			for _, comm := range []string{"public", "", "a-very-long-community-string-past-the-usual"} {
				for _, rid := range []int{1, 42, 65536, 2147483647} {
					for n := 1; n <= len(names); n++ {
						out = append(out, wellFormedDatagram{
							data: buildV2cRequestForRoundTrip(
								tag, ver, comm, rid, names[:n], 0, 10, 0),
							tag:   tag,
							names: n,
						})
					}
				}
			}
		}
	}
	return out
}

// TestWellFormedResponsesUnchangedOnTheWire is the in-tree evidence for the
// acceptance criterion that a well-formed minimal datagram is answered
// byte-identically to before nl6#559/#560/#562.
//
// Same shape and same reason as TestShippedOIDsUnchangedOnTheWire (nl6#529):
// the digest was computed against the PRE-CHANGE tree, not re-derived from the
// new code, or it would prove only that the code agrees with itself. It was
// captured by checking the pre-change production files out over this test file
// and running this test, which then reported the digest it wanted:
//
//	git show faba13a:go/nl6/snmp_server.go > snmp_server.go   (and _handlers, _response, snmpv3, snmpv3_crypto)
//	go test ./nl6/ -run TestWellFormedResponsesUnchangedOnTheWire -v
//
// What it does NOT cover, stated because a digest test invites the assumption
// that it covers everything: malformed and non-minimally-encoded datagrams,
// where this change deliberately DOES alter the answer (that is the fix), and
// v3, which has no v1/v2c envelope. Those are pinned by the agreement claims
// and the reproducer seeds instead.
//
// %d responses, %s over the corpus. A single changed byte in any response
// moves the digest.
//
// nl6#542 EXCLUDED one shape and re-derived the digest rather than updating it
// in place. A multi-binding GETNEXT now answers every binding, so its response
// changed by design; every other shape in this corpus — GET and GETBULK at any
// binding count, and the SINGLE-binding GETNEXT that is essentially all real
// GETNEXT traffic — must still be byte-identical, and that is the regression
// this test exists for. The digest was re-derived by checking the nl6#542
// baseline (5f3ca99) production files out over this test file and reading back
// the digest it reported, so it is still a PRE-change measurement and not the
// new code agreeing with itself.
func TestWellFormedResponsesUnchangedOnTheWire(t *testing.T) {
	const wantDigest = "adb8350ebaa6965fed21ed868f9fceac9745fc87f92eb390a805b1cee6f24105"

	// Pinned so a corpus that silently shrank — or an exclusion filter that
	// grew — fails here instead of passing over a smaller digest. 288 total,
	// of which 72 are multi-binding GETNEXT (2 versions x 3 communities x
	// 4 request-ids x 3 binding counts above one).
	const wantTotal, wantHashed = 288, 216

	s := newTestServer(fuzzFixtureOIDs(20))
	corpus := wellFormedMinimalCorpus()
	if len(corpus) != wantTotal {
		t.Fatalf("corpus has %d datagrams, want %d", len(corpus), wantTotal)
	}

	// unchangedShape reports whether this datagram's response is one nl6#542
	// promised not to move.
	unchangedShape := func(d wellFormedDatagram) bool {
		return d.tag != ASN1_GET_NEXT || d.names == 1
	}

	digest := func() (string, int) {
		h := sha256.New()
		n := 0
		for _, d := range corpus {
			if !unchangedShape(d) {
				continue
			}
			resp := s.handleSNMPv2cRequest(d.data)
			h.Write(d.data)
			h.Write([]byte{0})
			h.Write(resp)
			h.Write([]byte{0})
			n++
		}
		return hex.EncodeToString(h.Sum(nil)), n
	}

	got, hashed := digest()
	if hashed != wantHashed {
		t.Fatalf("hashed %d datagrams, want %d: the exclusion filter has moved", hashed, wantHashed)
	}

	// Determinism first: a digest over responses that vary run to run would
	// fail for a reason that has nothing to do with the wire format, and the
	// next reader would delete the test rather than the non-determinism.
	if got2, _ := digest(); got2 != got {
		t.Fatalf("the corpus is not deterministic within one run: %s then %s — a response "+
			"carries a live counter or a timestamp and this test cannot pin it", got, got2)
	}

	if got != wantDigest {
		t.Errorf("responses over %d well-formed minimal datagrams digest to %s, want %s.\n"+
			"Only a NON-minimal or malformed encoding, or a multi-binding GETNEXT, may be "+
			"answered differently; a mismatch here means a datagram a real manager sends is "+
			"answered differently.", hashed, got, wantDigest)
	}
}

// TestPaddedVersionSelectsSNMPv1Behaviour pins the VALUE half of nl6#559.
//
// The first cut fixed the version OFFSET and left `versionLen == 1` on the
// value, so `02 02 00 00` — a legal BER encoding of version 1 — parsed as the
// snmpVersion2c DEFAULT. Nothing in the response says "version", so a test on
// req.Version alone would pass over a parser that read it and then ignored it;
// the assertion that matters is a v1-SPECIFIC BEHAVIOUR, and the Counter64
// GET-divert (nl6#524) is the cheapest one to reach: v1 has no Counter64, so a
// GET of an ifHC column must answer noSuchName rather than tag 0x46.
//
// Three rows, because either half alone is weak: the minimal v1 spelling is
// the control that the datagram shape reaches the divert at all, the padded v1
// spelling is the claim, and the v2c row is the contrapositive — a parser that
// diverted everything would pass the first two.
func TestPaddedVersionSelectsSNMPv1Behaviour(t *testing.T) {
	s := newTestServer(fuzzFixtureOIDs(20))
	const hcColumn = ".1.3.6.1.2.1.31.1.1.1.6.7" // ifHCInOctets, a Counter64

	tests := []struct {
		name       string
		version    int
		style      int
		wantVer    int
		wantDivert bool
	}{
		{"minimal v1 (control)", snmpVersion1, 0, snmpVersion1, true},
		{"padded v1 (nl6#559, value half)", snmpVersion1, rtStyleVersionPadded, snmpVersion1, true},
		{"padded v2c (contrapositive)", snmpVersion2c, rtStyleVersionPadded, snmpVersion2c, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			data := buildV2cRequestForRoundTrip(ASN1_GET_REQUEST, tt.version, "public", 42,
				[]string{hcColumn}, 0, 0, tt.style)

			if got := s.parseIncomingRequest(data).Version; got != tt.wantVer {
				t.Errorf("parseIncomingRequest version = %d, want %d\ndatagram: % x",
					got, tt.wantVer, data)
			}

			resp := s.handleSNMPv2cRequest(data)
			if len(resp) == 0 {
				t.Fatalf("the dispatcher discarded the datagram\ndatagram: % x", data)
			}
			hdr := decodeResponseHeader(t, resp)
			diverted := hdr.errStatus == snmpErrNoSuchName
			if diverted != tt.wantDivert {
				t.Errorf("Counter64 GET-divert: error-status=%d (diverted=%v), want diverted=%v — "+
					"the version VALUE decides this, so a v1 request read as v2c gets a "+
					"Counter64 its decoder has no type for (nl6#524)\ndatagram: % x\nresponse: % x",
					hdr.errStatus, diverted, tt.wantDivert, data, resp)
			}
		})
	}
}

// TestIsSNMPv3RequestReadsThePaddedVersion pins nl6#559's third site.
//
// isSNMPv3Request is the gate every datagram passes before dispatch, and it
// required a one-octet version, so a BER-legal `02 02 00 03` was classified
// not-v3 and fell to the v2c path, which reads msgGlobalData where it expects
// a community. The classifier and parseSNMPv3Message are asserted TOGETHER: a
// gate that admits what the parser then rejects turns a wrong answer into a
// silent discard, which is better but still wrong, and the two drifting apart
// is the failure this pins.
func TestIsSNMPv3RequestReadsThePaddedVersion(t *testing.T) {
	s := fuzzTestServer(0)
	minimal := v3DiscoveryRequest(t, s, false)
	padded := withPaddedV3Version(t, minimal)

	for _, tt := range []struct {
		name string
		data []byte
	}{
		{"minimal version (control)", minimal},
		{"padded version 02 02 00 03", padded},
	} {
		t.Run(tt.name, func(t *testing.T) {
			if !isSNMPv3Request(tt.data) {
				t.Errorf("isSNMPv3Request = false, want true: a v3 message classified v2c is "+
					"parsed with msgGlobalData where the community belongs\ndatagram: % x", tt.data)
			}
			msg, err := s.parseSNMPv3Message(tt.data)
			if err != nil {
				t.Fatalf("parseSNMPv3Message: %v — the classifier and the parser must agree "+
					"about which datagrams are v3\ndatagram: % x", err, tt.data)
			}
			if msg.Version != SNMPV3_VERSION {
				t.Errorf("parsed version = %d, want %d", msg.Version, SNMPV3_VERSION)
			}
		})
	}
}

// withPaddedV3Version re-spells a v3 message's version INTEGER in two content
// octets and re-encodes the outer SEQUENCE around it, which is legal BER and
// what an encoder padding to a fixed field width emits.
func withPaddedV3Version(t *testing.T, msg []byte) []byte {
	t.Helper()
	const minimalVersion = "\x02\x01\x03"
	body := msg[2:] // strip the outer SEQUENCE tag and its short-form length
	if !strings.HasPrefix(string(body), minimalVersion) {
		t.Fatalf("premise broken: the v3 message does not start with a minimal version "+
			"INTEGER\nmessage: % x", msg)
	}
	padded := append([]byte{0x02, 0x02, 0x00, 0x03}, body[len(minimalVersion):]...)
	return encodeSequence(padded)
}

// TestAgreementHelperIsWiredIntoEveryRawDatagramTarget pins the wiring per
// call site, the way TestGuardIsWiredIntoLoaders does for the resource guard.
//
// Deleting the assertV2cParserAgreement call from a target fails nothing
// otherwise: the corpus tests re-run both committed corpora through the helper
// directly, and the reproducer seeds are replayed by every other wired target,
// so a target that quietly stopped asserting would keep a green suite and lose
// only its LIVE fuzzing — which is the whole reason these targets exist.
// nl6#560 is what that costs: FuzzHandleGetBulk was unwired for one release
// and its committed corpus accumulated 21 instances of a defect nobody saw.
//
// Source inspection rather than behaviour, deliberately: the property is
// "this call appears in this function", and there is no way to observe it from
// outside a live fuzz run.
func TestAgreementHelperIsWiredIntoEveryRawDatagramTarget(t *testing.T) {
	src, err := os.ReadFile("snmp_parser_robustness_test.go")
	if err != nil {
		t.Fatalf("read own source: %v", err)
	}

	// Every target whose fuzz argument IS a v1/v2c datagram (or, for the
	// round-trip target, a datagram it builds from one). Targets that fuzz a
	// scoped PDU, a USM parameter block or a length byte are absent on
	// purpose: the four readers describe the v1/v2c envelope and running them
	// over anything else compares parsers on a structure none of them claims.
	wired := []string{
		"FuzzGetPDUType",
		"FuzzParseIncomingRequest",
		"FuzzParseAllOIDsFromRequest",
		"FuzzParseGetBulkParams",
		"FuzzIsSNMPv3Request",
		"FuzzHandleSingleRequest",
		"FuzzHandleGetRequestVarbinds",
		"FuzzHandleGetBulk",
		"FuzzV2cRequestRoundTrip",
	}

	bodies := map[string]string{}
	parts := strings.Split(string(src), "\nfunc ")
	for _, part := range parts[1:] {
		name := part[:strings.IndexAny(part, "(")]
		end := strings.Index(part, "\n}\n")
		if end < 0 {
			end = len(part)
		}
		bodies[name] = part[:end]
	}

	for _, name := range wired {
		body, ok := bodies[name]
		if !ok {
			t.Errorf("%s: no such fuzz target in this file — renamed or deleted without "+
				"updating this list", name)
			continue
		}
		if !strings.Contains(body, "assertV2cParserAgreement(") {
			t.Errorf("%s: does not call assertV2cParserAgreement. Every target that sees a raw "+
				"v1/v2c datagram must, or its live-fuzz runs measure panics only — which is "+
				"exactly how nl6#560 sat in a committed corpus unnoticed", name)
		}
	}
}

// TestGetBulkCorpusAgrees is the tripwire nl6#534 left here, discharged.
//
// It replaced TestGetBulkCorpusIsBlockedOnNl6560, which asserted that at least
// one committed FuzzHandleGetBulk corpus entry still violated CLAIM 1 and was
// written to FAIL the moment nl6#560 landed. It did fail, exactly here, and
// the prompt it carried is discharged in full: FuzzHandleGetBulk is wired to
// assertV2cParserAgreement, repro560NegativeLengthWalksBackwards is a
// committed seed, and the negative assertion is replaced by this positive one
// rather than deleted. Deleting it outright would have retired the only
// standing check that this corpus — 21 of whose entries were instances of the
// defect — agrees.
func TestGetBulkCorpusAgrees(t *testing.T) {
	s := newTestServer(fuzzFixtureOIDs(20))
	corpus := readFuzzCorpus(t, "FuzzHandleGetBulk")

	for i, data := range corpus {
		var rec recordingTB
		assertV2cParserAgreement(&rec, s, data)
		if len(rec.msgs) != 0 {
			t.Errorf("corpus entry %d disagrees: %q\ndatagram: % x", i, rec.msgs, data)
		}
	}
	t.Logf("%d committed FuzzHandleGetBulk corpus entries, no disagreement", len(corpus))
}

// TestEntryPointCorpusAgrees is the positive control for the target that IS
// wired: every one of FuzzHandleSingleRequest's committed corpus entries must
// satisfy all three claims.
//
// It exists because a corpus test could be read as "the claims fire on
// anything mutated enough". They do not: the same claims over a 248-entry
// corpus of equally-mutated datagrams are silent. Before nl6#560 this was the
// control for TestGetBulkCorpusIsBlockedOnNl6560, which asserted the opposite
// about the other corpus; now both corpora are asserted to agree.
func TestEntryPointCorpusAgrees(t *testing.T) {
	s := newTestServer(fuzzFixtureOIDs(20))
	corpus := readFuzzCorpus(t, "FuzzHandleSingleRequest")

	for i, data := range corpus {
		var rec recordingTB
		assertV2cParserAgreement(&rec, s, data)
		if len(rec.msgs) != 0 {
			t.Errorf("corpus entry %d disagrees: %q", i, rec.msgs)
		}
	}
	t.Logf("%d committed FuzzHandleSingleRequest corpus entries, no disagreement", len(corpus))
}
