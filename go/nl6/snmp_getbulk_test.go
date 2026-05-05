//go:build linux

/*
 * © 2025 Sharon Aicler (saichler@gmail.com)
 *
 * Layer 8 Ecosystem is licensed under the Apache License, Version 2.0.
 * You may obtain a copy of the License at:
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

// Note: the simulator package uses Linux-only syscalls (TUN/netns) so tests
// must be run on Linux. The //go:build linux constraint above ensures this file
// is skipped on macOS/Windows during local development.

package main

import (
	"fmt"
	"testing"
)

// ── Test helpers ─────────────────────────────────────────────────────────────

// newTestServer returns an SNMPServer backed by the supplied OID→value map.
// Indexes are built via buildResourceIndexes so findNextOID works correctly.
func newTestServer(oidValues map[string]string) *SNMPServer {
	res := &DeviceResources{
		SNMP: make([]SNMPResource, 0, len(oidValues)),
	}
	for oid, val := range oidValues {
		res.SNMP = append(res.SNMP, SNMPResource{OID: oid, Response: val})
	}
	sm := &SimulatorManager{}
	sm.buildResourceIndexes(res)

	device := &DeviceSimulator{resources: res}
	return &SNMPServer{device: device}
}

// buildGetBulkPDU constructs a minimal SNMPv2c GETBULK packet for the given
// OIDs, non-repeaters, and max-repetitions values.
func buildGetBulkPDU(nonRepeaters, maxRepetitions int, oids []string) []byte {
	var varBindList []byte
	for _, oid := range oids {
		vb := encodeSequence(append(encodeOID(oid), encodeNull()...))
		varBindList = append(varBindList, vb...)
	}

	pduContents := encodeInteger(42) // request-id
	pduContents = append(pduContents, encodeInteger(nonRepeaters)...)
	pduContents = append(pduContents, encodeInteger(maxRepetitions)...)
	pduContents = append(pduContents, encodeSequence(varBindList)...)

	pdu := []byte{ASN1_GET_BULK}
	pdu = append(pdu, encodeLength(len(pduContents))...)
	pdu = append(pdu, pduContents...)

	msgContents := encodeInteger(1) // SNMPv2c
	msgContents = append(msgContents, encodeOctetString("public")...)
	msgContents = append(msgContents, pdu...)

	return encodeSequence(msgContents)
}

// parseGetBulkResponse parses an SNMP GetResponse packet and returns parallel
// slices of OID strings and their string values (integers returned as decimal).
func parseGetBulkResponse(data []byte) ([]string, []string, error) {
	var oids, values []string
	pos := 0

	// Outer SEQUENCE
	if pos >= len(data) || data[pos] != ASN1_SEQUENCE {
		return nil, nil, fmt.Errorf("expected SEQUENCE at pos 0, got 0x%02x", safeAt(data, pos))
	}
	pos++
	_, pos = parseLength(data, pos)

	// Skip version (INTEGER)
	if pos >= len(data) || data[pos] != ASN1_INTEGER {
		return nil, nil, fmt.Errorf("expected INTEGER (version)")
	}
	pos++
	vLen, pos2 := parseLength(data, pos)
	pos = pos2 + vLen

	// Skip community (OCTET STRING)
	if pos >= len(data) || data[pos] != ASN1_OCTET_STRING {
		return nil, nil, fmt.Errorf("expected OCTET STRING (community)")
	}
	pos++
	cLen, pos2 := parseLength(data, pos)
	pos = pos2 + cLen

	// GetResponse PDU (0xa2)
	if pos >= len(data) || data[pos] != ASN1_GET_RESPONSE {
		return nil, nil, fmt.Errorf("expected GetResponse (0xa2), got 0x%02x", safeAt(data, pos))
	}
	pos++
	_, pos = parseLength(data, pos)

	// Skip request-id, error-status, error-index (3 INTEGERs)
	for i := 0; i < 3; i++ {
		if pos >= len(data) || data[pos] != ASN1_INTEGER {
			return nil, nil, fmt.Errorf("expected INTEGER (PDU header field %d)", i)
		}
		pos++
		fLen, pos2 := parseLength(data, pos)
		pos = pos2 + fLen
	}

	// VarBindList SEQUENCE
	if pos >= len(data) || data[pos] != ASN1_SEQUENCE {
		return nil, nil, fmt.Errorf("expected SEQUENCE (VarBindList)")
	}
	pos++
	vbListLen, pos := parseLength(data, pos)
	end := pos + vbListLen

	for pos < end {
		if data[pos] != ASN1_SEQUENCE {
			break
		}
		pos++
		vbLen, pos2 := parseLength(data, pos)
		pos = pos2
		nextVB := pos + vbLen

		// OID
		if pos >= len(data) || data[pos] != ASN1_OID {
			return nil, nil, fmt.Errorf("expected OID tag in VarBind")
		}
		pos++
		oidLen, pos2 := parseLength(data, pos)
		pos = pos2
		oid := decodeOID(data[pos : pos+oidLen])
		oids = append(oids, oid)
		pos += oidLen

		// Value — we only need to distinguish endOfMibView from real values.
		val := extractVarBindValue(data, pos)
		values = append(values, val)

		pos = nextVB
	}

	return oids, values, nil
}

// extractVarBindValue returns a string representation of the next ASN.1 value.
// Handles INTEGER, OCTET STRING, and SNMPv2c application types (Gauge32,
// Counter32, TimeTicks, Counter64) so that test assertions can compare
// numeric values regardless of which application tag was used.
func extractVarBindValue(data []byte, pos int) string {
	if pos >= len(data) {
		return ""
	}
	tag := data[pos]
	pos++
	vLen, pos2 := parseLength(data, pos)
	pos = pos2

	switch tag {
	case 0x82: // endOfMibView exception (SNMPv2c)
		return "endOfMibView"
	case ASN1_INTEGER:
		v := 0
		for i := 0; i < vLen && pos+i < len(data); i++ {
			v = (v << 8) | int(data[pos+i])
		}
		return fmt.Sprintf("%d", v)
	case ASN1_GAUGE32, ASN1_COUNTER32, ASN1_TIMETICKS:
		// Unsigned 32-bit application types — decode as uint then format.
		var v uint64
		for i := 0; i < vLen && pos+i < len(data); i++ {
			v = (v << 8) | uint64(data[pos+i])
		}
		return fmt.Sprintf("%d", v)
	case ASN1_COUNTER64:
		var v uint64
		for i := 0; i < vLen && pos+i < len(data); i++ {
			v = (v << 8) | uint64(data[pos+i])
		}
		return fmt.Sprintf("%d", v)
	case ASN1_OCTET_STRING:
		if pos+vLen <= len(data) {
			return string(data[pos : pos+vLen])
		}
	}
	return fmt.Sprintf("tag=0x%02x", tag)
}

func safeAt(data []byte, pos int) byte {
	if pos < len(data) {
		return data[pos]
	}
	return 0
}

// ── parseAllOIDsFromRequest tests ────────────────────────────────────────────

func TestParseAllOIDsFromRequest_SingleOID(t *testing.T) {
	s := &SNMPServer{device: &DeviceSimulator{}}
	want := []string{".1.3.6.1.2.1.2.2.1.2"}

	pdu := buildGetBulkPDU(0, 10, want)
	got := s.parseAllOIDsFromRequest(pdu)

	if len(got) != len(want) {
		t.Fatalf("got %d OID(s), want %d", len(got), len(want))
	}
	if got[0] != want[0] {
		t.Errorf("OID[0]: got %q, want %q", got[0], want[0])
	}
}

func TestParseAllOIDsFromRequest_MultipleOIDs(t *testing.T) {
	s := &SNMPServer{device: &DeviceSimulator{}}
	want := []string{
		".1.3.6.1.2.1.2.2.1.2",  // ifDescr column
		".1.3.6.1.2.1.2.2.1.5",  // ifSpeed column
		".1.3.6.1.2.1.2.2.1.7",  // ifAdminStatus column
		".1.3.6.1.2.1.2.2.1.8",  // ifOperStatus column
		".1.3.6.1.2.1.31.1.1.1.1",  // ifName column
		".1.3.6.1.2.1.31.1.1.1.18", // ifAlias column
	}

	pdu := buildGetBulkPDU(0, 10, want)
	got := s.parseAllOIDsFromRequest(pdu)

	if len(got) != len(want) {
		t.Fatalf("got %d OIDs, want %d", len(got), len(want))
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("OID[%d]: got %q, want %q", i, got[i], want[i])
		}
	}
}

func TestParseAllOIDsFromRequest_MalformedPDU(t *testing.T) {
	s := &SNMPServer{device: &DeviceSimulator{}}

	// Should return empty slice without panicking.
	got := s.parseAllOIDsFromRequest([]byte{0x00, 0x01, 0x02})
	if len(got) != 0 {
		t.Errorf("expected empty slice for malformed PDU, got %v", got)
	}

	got = s.parseAllOIDsFromRequest(nil)
	if len(got) != 0 {
		t.Errorf("expected empty slice for nil input, got %v", got)
	}
}

// ── handleGetBulk tests ──────────────────────────────────────────────────────

// TestHandleGetBulkMultiColumn verifies that a two-column GETBULK request
// produces correctly interleaved responses: col1.row1, col2.row1, col1.row2, …
func TestHandleGetBulkMultiColumn(t *testing.T) {
	s := newTestServer(map[string]string{
		".1.3.6.1.2.1.2.2.1.2.1": "eth0",
		".1.3.6.1.2.1.2.2.1.2.2": "eth1",
		".1.3.6.1.2.1.2.2.1.5.1": "1000000000",
		".1.3.6.1.2.1.2.2.1.5.2": "1000000000",
	})

	// Ask for ifDescr column and ifSpeed column, 2 repetitions.
	colOIDs := []string{
		".1.3.6.1.2.1.2.2.1.2", // ifDescr column prefix
		".1.3.6.1.2.1.2.2.1.5", // ifSpeed column prefix
	}
	pdu := buildGetBulkPDU(0, 2, colOIDs)

	resp := s.handleGetBulk(".1.3.6.1.2.1.2.2.1.2", pdu)

	gotOIDs, gotVals, err := parseGetBulkResponse(resp)
	if err != nil {
		t.Fatalf("parseGetBulkResponse: %v", err)
	}

	// Expected interleaved order: ifDescr.1, ifSpeed.1, ifDescr.2, ifSpeed.2
	wantOIDs := []string{
		".1.3.6.1.2.1.2.2.1.2.1",
		".1.3.6.1.2.1.2.2.1.5.1",
		".1.3.6.1.2.1.2.2.1.2.2",
		".1.3.6.1.2.1.2.2.1.5.2",
	}
	wantVals := []string{"eth0", "1000000000", "eth1", "1000000000"}

	if len(gotOIDs) != len(wantOIDs) {
		t.Fatalf("varbind count: got %d, want %d\nOIDs: %v", len(gotOIDs), len(wantOIDs), gotOIDs)
	}
	for i := range wantOIDs {
		if gotOIDs[i] != wantOIDs[i] {
			t.Errorf("varbind[%d] OID: got %q, want %q", i, gotOIDs[i], wantOIDs[i])
		}
		if gotVals[i] != wantVals[i] {
			t.Errorf("varbind[%d] value: got %q, want %q", i, gotVals[i], wantVals[i])
		}
	}
}

// TestHandleGetBulkNonRepeaters verifies that non-repeater OIDs are handled
// with GETNEXT semantics and repeater OIDs are iterated max-repetitions times.
func TestHandleGetBulkNonRepeaters(t *testing.T) {
	s := newTestServer(map[string]string{
		".1.3.6.1.2.1.1.1.0":     "Cisco IOS",     // sysDescr (non-repeater target)
		".1.3.6.1.2.1.2.2.1.2.1": "eth0",
		".1.3.6.1.2.1.2.2.1.2.2": "eth1",
	})

	// non-repeaters=1 (sysDescr column), repeater=ifDescr column, maxRep=2
	colOIDs := []string{
		".1.3.6.1.2.1.1.1", // non-repeater: next after sysDescr prefix → sysDescr.0
		".1.3.6.1.2.1.2.2.1.2", // repeater: ifDescr column
	}
	pdu := buildGetBulkPDU(1, 2, colOIDs)

	resp := s.handleGetBulk(colOIDs[0], pdu)

	gotOIDs, _, err := parseGetBulkResponse(resp)
	if err != nil {
		t.Fatalf("parseGetBulkResponse: %v", err)
	}

	// Expect: 1 non-repeater result + 2 repeater results = 3 varbinds total.
	if len(gotOIDs) != 3 {
		t.Fatalf("varbind count: got %d, want 3 (1 non-repeater + 2 repeater)\nOIDs: %v", len(gotOIDs), gotOIDs)
	}

	// First entry is the non-repeater GETNEXT result.
	if gotOIDs[0] != ".1.3.6.1.2.1.1.1.0" {
		t.Errorf("non-repeater OID: got %q, want %q", gotOIDs[0], ".1.3.6.1.2.1.1.1.0")
	}
	// Next two are the repeater column.
	if gotOIDs[1] != ".1.3.6.1.2.1.2.2.1.2.1" {
		t.Errorf("repeater[0] OID: got %q, want %q", gotOIDs[1], ".1.3.6.1.2.1.2.2.1.2.1")
	}
	if gotOIDs[2] != ".1.3.6.1.2.1.2.2.1.2.2" {
		t.Errorf("repeater[1] OID: got %q, want %q", gotOIDs[2], ".1.3.6.1.2.1.2.2.1.2.2")
	}
}

// TestHandleGetBulkEndOfMib verifies RFC 3416 §4.2.3 endOfMibView padding.
//
// SNMP agents do not know about column boundaries — findNextOID always returns
// the lexicographically next OID in the MIB regardless of column prefix.
// endOfMibView is only emitted when the MIB is fully exhausted (no more OIDs).
// Once a column hits end-of-MIB, handleGetBulk must pad all remaining
// repetitions for that column with the original requested OID + endOfMibView.
func TestHandleGetBulkEndOfMib(t *testing.T) {
	// Single OID in the MIB. After one repetition the MIB is exhausted and
	// the remaining 2 repetitions must be padded with endOfMibView.
	s := newTestServer(map[string]string{
		".1.3.6.1.2.1.2.2.1.2.1": "eth0",
	})

	colOIDs := []string{".1.3.6.1.2.1.2.2.1.2"} // ifDescr column prefix
	pdu := buildGetBulkPDU(0, 3, colOIDs)

	resp := s.handleGetBulk(colOIDs[0], pdu)

	gotOIDs, gotVals, err := parseGetBulkResponse(resp)
	if err != nil {
		t.Fatalf("parseGetBulkResponse: %v", err)
	}

	// 3 reps × 1 col = 3 varbinds.
	if len(gotVals) != 3 {
		t.Fatalf("varbind count: got %d, want 3\nOIDs: %v\nVals: %v", len(gotVals), gotOIDs, gotVals)
	}

	// rep 0: the real entry
	if gotVals[0] == "endOfMibView" {
		t.Errorf("rep0: expected real value, got endOfMibView")
	}

	// rep 1 and rep 2: endOfMibView padding (MIB fully exhausted)
	if gotVals[1] != "endOfMibView" {
		t.Errorf("rep1: expected endOfMibView (MIB exhausted), got %q", gotVals[1])
	}
	if gotVals[2] != "endOfMibView" {
		t.Errorf("rep2: expected endOfMibView (MIB exhausted), got %q", gotVals[2])
	}
}

// TestParseIncomingRequest_RequestID verifies that parseIncomingRequest
// correctly extracts the request-id from GET, GETNEXT, and GETBULK PDUs.
// Before the 0xa5 fix, GETBULK fell through and always returned the default
// request-id of 123, causing all GETBULK responses to be dropped by clients.
func TestParseIncomingRequest_RequestID(t *testing.T) {
	s := &SNMPServer{device: &DeviceSimulator{}}

	tests := []struct {
		name      string
		pdu       []byte
		wantReqID int
	}{
		{
			name:      "GETBULK request-id 42",
			pdu:       buildGetBulkPDU(0, 10, []string{".1.3.6.1.2.1.2.2.1.2"}),
			wantReqID: 42,
		},
		{
			name: "GETBULK request-id 12345678 (multi-byte)",
			pdu: func() []byte {
				// Build a GETBULK PDU with a 3-byte request-id.
				varBindList := encodeSequence(append(encodeOID(".1.3.6.1.2.1.2.2.1.2"), encodeNull()...))
				pduContents := encodeInteger(12345678)
				pduContents = append(pduContents, encodeInteger(0)...)   // nonRepeaters
				pduContents = append(pduContents, encodeInteger(10)...)  // maxRepetitions
				pduContents = append(pduContents, encodeSequence(varBindList)...)
				pdu := []byte{ASN1_GET_BULK}
				pdu = append(pdu, encodeLength(len(pduContents))...)
				pdu = append(pdu, pduContents...)
				msg := encodeInteger(1)
				msg = append(msg, encodeOctetString("public")...)
				msg = append(msg, pdu...)
				return encodeSequence(msg)
			}(),
			wantReqID: 12345678,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			req := s.parseIncomingRequest(tc.pdu)
			if req.RequestID != tc.wantReqID {
				t.Errorf("RequestID = %d, want %d", req.RequestID, tc.wantReqID)
			}
		})
	}
}

// TestHandleGetBulkFallback verifies backward compatibility: when the PDU
// cannot be parsed for OIDs, the single startOID fallback still works.
func TestHandleGetBulkFallback(t *testing.T) {
	s := newTestServer(map[string]string{
		".1.3.6.1.2.1.1.1.0": "Cisco IOS",
		".1.3.6.1.2.1.1.2.0": ".1.3.6.1.4.1.9",
	})

	// Pass a garbage PDU — parseAllOIDsFromRequest returns empty, fallback activates.
	// handleGetBulk falls back to startOID=".1.3.6.1.2.1.1.1", so GETNEXT produces
	// the first OID in the MIB: 1.3.6.1.2.1.1.1.0 (sysDescr).
	garblePDU := []byte{0x00, 0x01, 0x02, 0x03}

	resp := s.handleGetBulk(".1.3.6.1.2.1.1.1", garblePDU)

	gotOIDs, gotVals, err := parseGetBulkResponse(resp)
	if err != nil {
		t.Fatalf("parseGetBulkResponse: %v", err)
	}
	if len(gotOIDs) == 0 {
		t.Fatal("fallback produced no varbinds")
	}
	// The fallback must return 1.3.6.1.2.1.1.1.0 (the first — and only — OID
	// lexicographically greater than the start prefix ".1.3.6.1.2.1.1.1").
	wantOID := ".1.3.6.1.2.1.1.1.0"
	wantVal := "Cisco IOS"
	if gotOIDs[0] != wantOID {
		t.Errorf("fallback OID: got %q, want %q", gotOIDs[0], wantOID)
	}
	if gotVals[0] != wantVal {
		t.Errorf("fallback value: got %q, want %q", gotVals[0], wantVal)
	}
}
