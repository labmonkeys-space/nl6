/*
 * Copyright 2026 Ronny Trommer <ronny@no42.org>
 * SPDX-License-Identifier: Apache-2.0
 */

package main

import (
	"bytes"
	"strings"
	"testing"
)

// Golden packets: request bytes captured from real SNMP clients.
//
// Every other SNMP test in this package builds its input with nl6's own
// encoders, which makes those tests self-consistent by construction: encoder
// and parser can share a misconception and still agree. These fixtures are the
// opposite. They are verbatim bytes produced by third-party stacks, so they
// test the parser against the wire rather than against nl6's own habits.
//
// nl6#514 is what that distinction is for. Both clients below emit a
// zero-length community for `-c ""`, which `parseIncomingRequest` treated as
// absent and silently answered with "public". No synthetic test found it,
// because nl6 never generated the input that triggers it.
//
// Captured 2026-08-28 with net-snmp 5.6.2.1 and snmp4j 3.13.1 (the same major
// line OpenNMS ships). Method: `nc -u -l 1161 > out.bin` in one shell, the
// client command below in another, then `xxd -p out.bin`. No tcpdump and no
// root required. The listener receives the datagram directly.
//
// Request IDs differ per capture; that is expected. A fixture records what was
// captured, not a value chosen by this repository.

// snmpget -v2c -c public -r 0 -t 1 127.0.0.1:1161 1.3.6.1.2.1.1.1.0
var goldenNetSNMPPublic = []byte{
	0x30, 0x29, 0x02, 0x01, 0x01, 0x04, 0x06, 0x70, 0x75, 0x62, 0x6c, 0x69,
	0x63, 0xa0, 0x1c, 0x02, 0x04, 0x34, 0x44, 0x2e, 0x1b, 0x02, 0x01, 0x00,
	0x02, 0x01, 0x00, 0x30, 0x0e, 0x30, 0x0c, 0x06, 0x08, 0x2b, 0x06, 0x01,
	0x02, 0x01, 0x01, 0x01, 0x00, 0x05, 0x00,
}

// snmpget -v2c -c "" -r 0 -t 1 127.0.0.1:1161 1.3.6.1.2.1.1.1.0
// Note bytes 5-6: `04 00`, an OCTET STRING of length zero. This is the nl6#514 case.
var goldenNetSNMPEmptyCommunity = []byte{
	0x30, 0x23, 0x02, 0x01, 0x01, 0x04, 0x00, 0xa0, 0x1c, 0x02, 0x04, 0x6d,
	0xd6, 0x08, 0x60, 0x02, 0x01, 0x00, 0x02, 0x01, 0x00, 0x30, 0x0e, 0x30,
	0x0c, 0x06, 0x08, 0x2b, 0x06, 0x01, 0x02, 0x01, 0x01, 0x01, 0x00, 0x05,
	0x00,
}

// SnmpCommand get -v 2c -c public -r 0 -t 800 udp:127.0.0.1/1161 1.3.6.1.2.1.1.1.0
var goldenSNMP4JPublic = []byte{
	0x30, 0x29, 0x02, 0x01, 0x01, 0x04, 0x06, 0x70, 0x75, 0x62, 0x6c, 0x69,
	0x63, 0xa0, 0x1c, 0x02, 0x04, 0x64, 0x9a, 0x06, 0x5a, 0x02, 0x01, 0x00,
	0x02, 0x01, 0x00, 0x30, 0x0e, 0x30, 0x0c, 0x06, 0x08, 0x2b, 0x06, 0x01,
	0x02, 0x01, 0x01, 0x01, 0x00, 0x05, 0x00,
}

// SnmpCommand get -v 2c -c "" -r 0 -t 800 udp:127.0.0.1/1161 1.3.6.1.2.1.1.1.0
// Byte-identical to net-snmp through the community field: `30 23 02 01 01 04 00`.
var goldenSNMP4JEmptyCommunity = []byte{
	0x30, 0x23, 0x02, 0x01, 0x01, 0x04, 0x00, 0xa0, 0x1c, 0x02, 0x04, 0x71,
	0x12, 0xd1, 0xc7, 0x02, 0x01, 0x00, 0x02, 0x01, 0x00, 0x30, 0x0e, 0x30,
	0x0c, 0x06, 0x08, 0x2b, 0x06, 0x01, 0x02, 0x01, 0x01, 0x01, 0x00, 0x05,
	0x00,
}

// snmpget -v2c -c "<200 x 'c'>" -r 0 -t 1 127.0.0.1:1161 1.3.6.1.2.1.1.1.0
//
// A community of 128 octets or more forces a long-form length: `04 81 c8`, and
// the outer SEQUENCE goes long-form too (`30 81 ec`). Reading that length as a
// single raw byte put getPDUType's cursor inside the community and made it
// report a byte of payload as the PDU type. A GETBULK then fell through to the
// GET branch while the varbind parser read the request correctly, so the client
// got a well-formed answer to a question it had not asked (nl6#512).
//
// That fix shipped with a synthetic test. This is a real client producing the
// encoding. Long-form outer lengths are not exotic. Every PDU over 127 bytes
// uses one, so this path is exercised constantly.
var goldenNetSNMPLongCommunity = []byte{
	0x30, 0x81, 0xec, 0x02, 0x01, 0x01, 0x04, 0x81, 0xc8, 0x63, 0x63, 0x63,
	0x63, 0x63, 0x63, 0x63, 0x63, 0x63, 0x63, 0x63, 0x63, 0x63, 0x63, 0x63,
	0x63, 0x63, 0x63, 0x63, 0x63, 0x63, 0x63, 0x63, 0x63, 0x63, 0x63, 0x63,
	0x63, 0x63, 0x63, 0x63, 0x63, 0x63, 0x63, 0x63, 0x63, 0x63, 0x63, 0x63,
	0x63, 0x63, 0x63, 0x63, 0x63, 0x63, 0x63, 0x63, 0x63, 0x63, 0x63, 0x63,
	0x63, 0x63, 0x63, 0x63, 0x63, 0x63, 0x63, 0x63, 0x63, 0x63, 0x63, 0x63,
	0x63, 0x63, 0x63, 0x63, 0x63, 0x63, 0x63, 0x63, 0x63, 0x63, 0x63, 0x63,
	0x63, 0x63, 0x63, 0x63, 0x63, 0x63, 0x63, 0x63, 0x63, 0x63, 0x63, 0x63,
	0x63, 0x63, 0x63, 0x63, 0x63, 0x63, 0x63, 0x63, 0x63, 0x63, 0x63, 0x63,
	0x63, 0x63, 0x63, 0x63, 0x63, 0x63, 0x63, 0x63, 0x63, 0x63, 0x63, 0x63,
	0x63, 0x63, 0x63, 0x63, 0x63, 0x63, 0x63, 0x63, 0x63, 0x63, 0x63, 0x63,
	0x63, 0x63, 0x63, 0x63, 0x63, 0x63, 0x63, 0x63, 0x63, 0x63, 0x63, 0x63,
	0x63, 0x63, 0x63, 0x63, 0x63, 0x63, 0x63, 0x63, 0x63, 0x63, 0x63, 0x63,
	0x63, 0x63, 0x63, 0x63, 0x63, 0x63, 0x63, 0x63, 0x63, 0x63, 0x63, 0x63,
	0x63, 0x63, 0x63, 0x63, 0x63, 0x63, 0x63, 0x63, 0x63, 0x63, 0x63, 0x63,
	0x63, 0x63, 0x63, 0x63, 0x63, 0x63, 0x63, 0x63, 0x63, 0x63, 0x63, 0x63,
	0x63, 0x63, 0x63, 0x63, 0x63, 0x63, 0x63, 0x63, 0x63, 0x63, 0x63, 0x63,
	0x63, 0x63, 0x63, 0x63, 0x63, 0xa0, 0x1c, 0x02, 0x04, 0x26, 0x61, 0x33,
	0x0c, 0x02, 0x01, 0x00, 0x02, 0x01, 0x00, 0x30, 0x0e, 0x30, 0x0c, 0x06,
	0x08, 0x2b, 0x06, 0x01, 0x02, 0x01, 0x01, 0x01, 0x00, 0x05, 0x00,
}

func TestGoldenPackets_ParseIncomingRequest(t *testing.T) {
	const sysDescr = ".1.3.6.1.2.1.1.1.0"

	tests := []struct {
		name          string
		packet        []byte
		wantVersion   int
		wantCommunity string
		wantRequestID int
		wantOID       string
		wantPDUType   byte
	}{
		{
			name:          "net-snmp 5.6.2.1 community=public",
			packet:        goldenNetSNMPPublic,
			wantVersion:   1,
			wantCommunity: "public",
			wantRequestID: 876883483,
			wantOID:       sysDescr,
			wantPDUType:   ASN1_GET_REQUEST,
		},
		{
			// nl6#514: before the fix this returned "public".
			name:          "net-snmp 5.6.2.1 community empty",
			packet:        goldenNetSNMPEmptyCommunity,
			wantVersion:   1,
			wantCommunity: "",
			wantRequestID: 1842743392,
			wantOID:       sysDescr,
			wantPDUType:   ASN1_GET_REQUEST,
		},
		{
			name:          "snmp4j 3.13.1 community=public",
			packet:        goldenSNMP4JPublic,
			wantVersion:   1,
			wantCommunity: "public",
			wantRequestID: 1687815770,
			wantOID:       sysDescr,
			wantPDUType:   ASN1_GET_REQUEST,
		},
		{
			// nl6#514: the defect is not net-snmp-specific.
			name:          "snmp4j 3.13.1 community empty",
			packet:        goldenSNMP4JEmptyCommunity,
			wantVersion:   1,
			wantCommunity: "",
			wantRequestID: 1897058759,
			wantOID:       sysDescr,
			wantPDUType:   ASN1_GET_REQUEST,
		},
		{
			// nl6#512: long-form community length, from a real client.
			name:          "net-snmp 5.6.2.1 community 200 bytes (long-form length)",
			packet:        goldenNetSNMPLongCommunity,
			wantVersion:   1,
			wantCommunity: strings.Repeat("c", 200),
			wantRequestID: 643904268,
			wantOID:       sysDescr,
			wantPDUType:   ASN1_GET_REQUEST,
		},
	}

	s := &SNMPServer{device: &DeviceSimulator{ID: "golden-packets"}}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := s.parseIncomingRequest(tt.packet)

			if req.Version != tt.wantVersion {
				t.Errorf("Version = %d, want %d", req.Version, tt.wantVersion)
			}
			if req.Community != tt.wantCommunity {
				t.Errorf("Community = %q, want %q", req.Community, tt.wantCommunity)
			}
			if req.RequestID != tt.wantRequestID {
				t.Errorf("RequestID = %d, want %d", req.RequestID, tt.wantRequestID)
			}
			if req.OID != tt.wantOID {
				t.Errorf("OID = %q, want %q", req.OID, tt.wantOID)
			}

			// getPDUType parses the same datagram independently. On a well-formed
			// packet the two must agree; nl6#512 was a case where they did not.
			if got := s.getPDUType(tt.packet); got != tt.wantPDUType {
				t.Errorf("getPDUType = 0x%02X, want 0x%02X", got, tt.wantPDUType)
			}

			// The parsed struct is not what the client sees. Each response builder
			// re-parses the request and encodes req.Community itself, so a default
			// substituted on the encode side would leave the assertions above green.
			// Check the community bytes on the wire for every response path.
			wantWire := append([]byte{0x02, 0x01, 0x01}, encodeOctetString(tt.wantCommunity)...)
			responses := map[string][]byte{
				"createSNMPResponse":    s.createSNMPResponse(tt.wantOID, "x", tt.packet),
				"createVarbindResponse": s.createVarbindResponse([]string{tt.wantOID}, []string{"x"}, tt.packet, overflowTooBig),
				"createGetBulkResponse": s.createGetBulkResponse([]string{tt.wantOID}, []string{"x"}, tt.packet),
			}
			for name, resp := range responses {
				got := responseMessageHeader(t, resp)
				if !bytes.HasPrefix(got, wantWire) {
					t.Errorf("%s: message starts % x, want version+community % x", name, got[:min(len(got), len(wantWire))], wantWire)
				}
			}
		})
	}
}

// responseMessageHeader strips the outer SEQUENCE tag and length from an
// encoded SNMP message and returns the contents, which start with the version
// INTEGER followed by the community OCTET STRING.
func responseMessageHeader(t *testing.T, msg []byte) []byte {
	t.Helper()
	if len(msg) == 0 || msg[0] != ASN1_SEQUENCE {
		t.Fatalf("response does not start with SEQUENCE: % x", msg[:min(len(msg), 8)])
	}
	n, pos := parseLength(msg, 1)
	if n < 0 || pos+n > len(msg) {
		t.Fatalf("response SEQUENCE length %d at pos %d does not fit %d bytes", n, pos, len(msg))
	}
	return msg[pos : pos+n]
}

// TestGoldenPackets_CommunityGuardRejectsMalformedLengths pins the lower bound
// that TestGoldenPackets_ParseIncomingRequest's empty-community rows required
// widening. `communityLen >= 0` admits a zero-length community; it must still
// reject parseLength's -1, because pos+(-1) <= len(data) holds and the slice
// expression would then invert.
func TestGoldenPackets_CommunityGuardRejectsMalformedLengths(t *testing.T) {
	// Every packet here is at least 10 bytes. parseIncomingRequest returns its
	// defaults for anything shorter before the community guard is evaluated, so
	// a shorter row would pass with or without the guard and pin nothing.
	tests := []struct {
		name   string
		packet []byte
	}{
		{
			// `04 85`: long form declaring five length octets. parseLength caps
			// long form at four and returns -1.
			name: "community length has too many octets",
			packet: []byte{
				0x30, 0x0a, 0x02, 0x01, 0x01, 0x04, 0x85, 0x00, 0x00, 0x00, 0x00, 0x00,
			},
		},
		{
			// `04 81` as the final two bytes: long form declaring one length octet
			// that is not there, so parseLength returns -1. The 4-byte version
			// INTEGER pads the packet past the 10-byte floor.
			name: "community length truncated",
			packet: []byte{
				0x30, 0x0a, 0x02, 0x04, 0x00, 0x00, 0x00, 0x01, 0x04, 0x81,
			},
		},
		{
			// `04 20`: declares 32 community octets with 4 bytes remaining.
			name: "community length overruns buffer",
			packet: []byte{
				0x30, 0x0a, 0x02, 0x01, 0x01, 0x04, 0x20, 0x61, 0x62, 0x63, 0x64,
			},
		},
	}

	s := &SNMPServer{device: &DeviceSimulator{ID: "golden-packets"}}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// A panic here fails the test rather than being recovered: the parsers
			// are required to be total, and there is no recover() on the serve path.
			req := s.parseIncomingRequest(tt.packet)

			// The community is not extractable, so the default stands. This asserts
			// the guard rejected the length rather than slicing on it.
			if req.Community != "public" {
				t.Errorf("Community = %q, want the untouched default %q", req.Community, "public")
			}
		})
	}
}
