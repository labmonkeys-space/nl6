/*
 * Copyright 2026 Ronny Trommer <ronny@no42.org>
 * SPDX-License-Identifier: Apache-2.0
 */

package main

import (
	"bytes"
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
			s.parseAllOIDsFromRequest(pkt)
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
	f.Fuzz(func(_ *testing.T, data []byte) { robustnessTestServer().parseAllOIDsFromRequest(data) })
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
