/*
 * Copyright 2026 Ronny Trommer <ronny@no42.org>
 * SPDX-License-Identifier: Apache-2.0
 */

package main

import (
	"bytes"
	"fmt"
	"os"
	"strconv"
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
	f.Add(malformedNameRequest(ASN1_GET_REQUEST, snmpVersion2c, 3, 1))
	f.Add(malformedNameRequest(ASN1_GET_NEXT, snmpVersion2c, 1, 0))
	f.Add(malformedNameRequest(ASN1_GET_BULK, snmpVersion2c, 2, 1))
	for _, tc := range brokenVarbindLists {
		f.Add(requestWithRawList(ASN1_GET_REQUEST, snmpVersion2c, tc.list))
	}
}

func FuzzGetPDUType(f *testing.F) {
	f.Add(crasherGetPDUType)
	f.Add([]byte{0x30, 0x05, 0x02, 0x01, 0x00, 0x04})
	addGoldenV2cSeeds(f)
	f.Fuzz(func(_ *testing.T, data []byte) { robustnessTestServer().getPDUType(data) })
}

func FuzzParseIncomingRequest(f *testing.F) {
	f.Add(crasherGetPDUType)
	addGoldenV2cSeeds(f)
	f.Fuzz(func(_ *testing.T, data []byte) { robustnessTestServer().parseIncomingRequest(data) })
}

func FuzzParseAllOIDsFromRequest(f *testing.F) {
	f.Add(crasherGetPDUType)
	addGoldenV2cSeeds(f)
	addMalformedVarbindSeeds(f)
	f.Fuzz(func(_ *testing.T, data []byte) { _, _ = robustnessTestServer().parseAllOIDsFromRequest(data) })
}

func FuzzIsSNMPv3Request(f *testing.F) {
	f.Add(crasherIsSNMPv3)
	f.Fuzz(func(_ *testing.T, data []byte) { isSNMPv3Request(data) })
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
	f.Fuzz(func(_ *testing.T, data []byte) {
		_, _ = (&SNMPServer{}).parseGetBulkParams(data)
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
	f.Fuzz(func(_ *testing.T, data []byte) {
		_ = fuzzTestServer(50).handleGetBulk(".1.3.6.1.2.1.1.1.0", data)
	})
}

func FuzzHandleGetRequestVarbinds(f *testing.F) {
	f.Add(crasherGetPDUType)
	addGoldenV2cSeeds(f)
	f.Fuzz(func(_ *testing.T, data []byte) {
		s := fuzzTestServer(50)
		// The oids argument is what the server itself parsed out of the same
		// datagram, so deriving it here keeps the pair consistent the way the
		// real dispatcher does.
		oids, _ := s.parseAllOIDsFromRequest(data)
		if len(oids) == 0 {
			oids = []string{".1.3.6.1.2.1.1.1.0"}
		}
		_ = s.handleGetRequestVarbinds(oids, data)
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
	f.Fuzz(func(_ *testing.T, data []byte) {
		fuzzTestServer(50).handleSingleRequest(data, nil)
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
