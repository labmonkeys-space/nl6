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

// Tests for RFC 1902 SNMP type encoding. No Linux syscalls — runs on any OS.

package main

import (
	"testing"
)

// ── snmpTypeTag ───────────────────────────────────────────────────────────────

func TestSnmpTypeTag(t *testing.T) {
	tests := []struct {
		oid  string
		want byte
	}{
		// sysObjectID → OBJECT IDENTIFIER
		{".1.3.6.1.2.1.1.2.0", ASN1_OBJECT_ID},

		// sysUpTime → TimeTicks
		{".1.3.6.1.2.1.1.3.0", ASN1_TIMETICKS},

		// ifSpeed → Gauge32
		{".1.3.6.1.2.1.2.2.1.5.1", ASN1_GAUGE32},
		{".1.3.6.1.2.1.2.2.1.5.24", ASN1_GAUGE32},

		// ifLastChange → TimeTicks
		{".1.3.6.1.2.1.2.2.1.9.1", ASN1_TIMETICKS},

		// ifInOctets → Counter32
		{".1.3.6.1.2.1.2.2.1.10.1", ASN1_COUNTER32},

		// ifHighSpeed → Gauge32
		{".1.3.6.1.2.1.31.1.1.1.15.1", ASN1_GAUGE32},

		// ifHCInOctets → Counter64
		{".1.3.6.1.2.1.31.1.1.1.6.1", ASN1_COUNTER64},

		// ifHCOutOctets → Counter64
		{".1.3.6.1.2.1.31.1.1.1.10.1", ASN1_COUNTER64},

		// ipRouteDest → IpAddress
		{".1.3.6.1.2.1.4.21.1.1.192.168.1.0", ASN1_IPADDRESS},

		// ipRouteNextHop → IpAddress
		{".1.3.6.1.2.1.4.21.1.7.0.0.0.0", ASN1_IPADDRESS},

		// ifIndex → INTEGER (not in table → 0)
		{".1.3.6.1.2.1.2.2.1.1.1", 0},

		// ifAdminStatus → INTEGER (not in table → 0)
		{".1.3.6.1.2.1.2.2.1.7.1", 0},

		// sysDescr → OCTET STRING (not in table → 0)
		{".1.3.6.1.2.1.1.1.0", 0},

		// Unrecognised → 0
		{".1.2.3.4.5", 0},
	}

	for _, tc := range tests {
		got := snmpTypeTag(tc.oid)
		if got != tc.want {
			t.Errorf("snmpTypeTag(%q) = 0x%02x, want 0x%02x", tc.oid, got, tc.want)
		}
	}
}

// Verify that a partial prefix does not match a longer column.
// e.g. prefix "1.3.6.1.2.1.2.2.1.1" (ifIndex) must NOT match
// "1.3.6.1.2.1.2.2.1.10.1" (ifInOctets), which would give the wrong type.
func TestSnmpTypeTag_NoPrefixFalseMatch(t *testing.T) {
	// ifInOctets (column 10) must not match ifIndex (column 1)
	if got := snmpTypeTag(".1.3.6.1.2.1.2.2.1.10.1"); got != ASN1_COUNTER32 {
		t.Errorf("ifInOctets OID: got 0x%02x, want ASN1_COUNTER32 (0x%02x)", got, ASN1_COUNTER32)
	}
	// ifHCOutOctets (column 10 in ifXTable) must not match ifInMulticastPkts (column 2)
	if got := snmpTypeTag(".1.3.6.1.2.1.31.1.1.1.10.1"); got != ASN1_COUNTER64 {
		t.Errorf("ifHCOutOctets OID: got 0x%02x, want ASN1_COUNTER64 (0x%02x)", got, ASN1_COUNTER64)
	}
}

// ── encodeUnsigned32 ──────────────────────────────────────────────────────────

func TestEncodeUnsigned32(t *testing.T) {
	tests := []struct {
		tag   byte
		value uint32
		want  []byte
	}{
		{ASN1_GAUGE32, 0, []byte{0x42, 0x01, 0x00}},
		{ASN1_GAUGE32, 1000, []byte{0x42, 0x02, 0x03, 0xE8}},
		{ASN1_GAUGE32, 1000000000, []byte{0x42, 0x04, 0x3B, 0x9A, 0xCA, 0x00}},
		{ASN1_COUNTER32, 4294967295, []byte{0x41, 0x04, 0xFF, 0xFF, 0xFF, 0xFF}}, // max uint32
		{ASN1_TIMETICKS, 123456789, []byte{0x43, 0x04, 0x07, 0x5B, 0xCD, 0x15}},
	}

	for _, tc := range tests {
		got := encodeUnsigned32(tc.tag, tc.value)
		if !bytesEqual(got, tc.want) {
			t.Errorf("encodeUnsigned32(0x%02x, %d) = %x, want %x", tc.tag, tc.value, got, tc.want)
		}
	}
}

// ── encodeCounter64 ───────────────────────────────────────────────────────────

func TestEncodeCounter64(t *testing.T) {
	tests := []struct {
		value uint64
		want  []byte
	}{
		{0, []byte{0x46, 0x01, 0x00}},
		{1, []byte{0x46, 0x01, 0x01}},
		// 13897247566 = 0x33C572B4E (value from cisco_ios_snmp_hcif.json ifHCInOctets)
		{13897247566, []byte{0x46, 0x05, 0x03, 0x3C, 0x57, 0x2B, 0x4E}},
		// max uint64
		{18446744073709551615, []byte{0x46, 0x08, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF}},
	}

	for _, tc := range tests {
		got := encodeCounter64(tc.value)
		if !bytesEqual(got, tc.want) {
			t.Errorf("encodeCounter64(%d) = %x, want %x", tc.value, got, tc.want)
		}
	}
}

// ── encodeIPAddress ───────────────────────────────────────────────────────────

func TestEncodeIPAddress(t *testing.T) {
	tests := []struct {
		ipStr string
		want  []byte
	}{
		{"192.168.1.0", []byte{0x40, 0x04, 192, 168, 1, 0}},
		{"0.0.0.0", []byte{0x40, 0x04, 0, 0, 0, 0}},
		{"255.255.255.255", []byte{0x40, 0x04, 255, 255, 255, 255}},
		{"10.0.0.1", []byte{0x40, 0x04, 10, 0, 0, 1}},
	}

	for _, tc := range tests {
		got := encodeIPAddress(tc.ipStr)
		if !bytesEqual(got, tc.want) {
			t.Errorf("encodeIPAddress(%q) = %x, want %x", tc.ipStr, got, tc.want)
		}
	}

	// Non-IP string should fall back to OCTET STRING (tag 0x04).
	got := encodeIPAddress("not-an-ip")
	if len(got) == 0 || got[0] != ASN1_OCTET_STRING {
		t.Errorf("encodeIPAddress(invalid) tag = 0x%02x, want OCTET STRING (0x04)", got[0])
	}
}

// ── encodeTypedValue ─────────────────────────────────────────────────────────

func TestEncodeTypedValue_SysObjectID(t *testing.T) {
	// sysObjectID value must be encoded as OBJECT IDENTIFIER (0x06), not OCTET STRING.
	// The value may arrive with or without a leading dot from JSON resource files.
	for _, val := range []string{"1.3.6.1.4.1.9.1.1", ".1.3.6.1.4.1.9.1.1"} {
		got := encodeTypedValue(".1.3.6.1.2.1.1.2.0", val)
		if len(got) == 0 || got[0] != ASN1_OBJECT_ID {
			t.Errorf("sysObjectID value %q: tag = 0x%02x, want OBJECT IDENTIFIER (0x%02x)", val, got[0], ASN1_OBJECT_ID)
		}
	}

	// Both forms must produce identical wire bytes (encodeOID strips the dot).
	a := encodeTypedValue(".1.3.6.1.2.1.1.2.0", "1.3.6.1.4.1.9.1.1")
	b := encodeTypedValue(".1.3.6.1.2.1.1.2.0", ".1.3.6.1.4.1.9.1.1")
	if !bytesEqual(a, b) {
		t.Errorf("sysObjectID with/without dot produce different bytes: %x vs %x", a, b)
	}

	// Round-trip: encoded payload must decode back to the canonical dotted form.
	const canonical = ".1.3.6.1.4.1.9.1.1"
	encoded := encodeTypedValue(".1.3.6.1.2.1.1.2.0", canonical)
	if len(encoded) < 2 {
		t.Fatalf("encoded sysObjectID too short (%d bytes)", len(encoded))
	}
	_, payloadStart := parseLength(encoded, 1)
	decoded := decodeOID(encoded[payloadStart:])
	if decoded != canonical {
		t.Errorf("sysObjectID round-trip: got %q, want %q", decoded, canonical)
	}
}

func TestEncodeTypedValue_EndOfMibView(t *testing.T) {
	got := encodeTypedValue(".1.3.6.1.2.1.2.2.1.5.1", "endOfMibView")
	want := []byte{0x82, 0x00}
	if !bytesEqual(got, want) {
		t.Errorf("endOfMibView: got %x, want %x", got, want)
	}
}

func TestEncodeTypedValue_Gauge32(t *testing.T) {
	// ifSpeed = 1000 Mbps expressed in bps = 1000000000
	got := encodeTypedValue(".1.3.6.1.2.1.2.2.1.5.1", "1000000000")
	if len(got) == 0 || got[0] != ASN1_GAUGE32 {
		t.Errorf("ifSpeed tag: got 0x%02x, want Gauge32 (0x%02x)", got[0], ASN1_GAUGE32)
	}
}

func TestEncodeTypedValue_Counter32(t *testing.T) {
	got := encodeTypedValue(".1.3.6.1.2.1.2.2.1.10.1", "123456") // ifInOctets
	if len(got) == 0 || got[0] != ASN1_COUNTER32 {
		t.Errorf("ifInOctets tag: got 0x%02x, want Counter32 (0x%02x)", got[0], ASN1_COUNTER32)
	}
}

func TestEncodeTypedValue_Counter64(t *testing.T) {
	got := encodeTypedValue(".1.3.6.1.2.1.31.1.1.1.6.1", "13897247566") // ifHCInOctets
	if len(got) == 0 || got[0] != ASN1_COUNTER64 {
		t.Errorf("ifHCInOctets tag: got 0x%02x, want Counter64 (0x%02x)", got[0], ASN1_COUNTER64)
	}
}

func TestEncodeTypedValue_TimeTicks(t *testing.T) {
	got := encodeTypedValue(".1.3.6.1.2.1.1.3.0", "123456789") // sysUpTime
	if len(got) == 0 || got[0] != ASN1_TIMETICKS {
		t.Errorf("sysUpTime tag: got 0x%02x, want TimeTicks (0x%02x)", got[0], ASN1_TIMETICKS)
	}
}

func TestEncodeTypedValue_IpAddress(t *testing.T) {
	got := encodeTypedValue(".1.3.6.1.2.1.4.21.1.1.192.168.1.0", "192.168.1.0") // ipRouteDest
	if len(got) == 0 || got[0] != ASN1_IPADDRESS {
		t.Errorf("ipRouteDest tag: got 0x%02x, want IpAddress (0x%02x)", got[0], ASN1_IPADDRESS)
	}
}

func TestEncodeTypedValue_Integer(t *testing.T) {
	// ifAdminStatus is not in the type table → should be INTEGER
	got := encodeTypedValue(".1.3.6.1.2.1.2.2.1.7.1", "1")
	if len(got) == 0 || got[0] != ASN1_INTEGER {
		t.Errorf("ifAdminStatus tag: got 0x%02x, want INTEGER (0x%02x)", got[0], ASN1_INTEGER)
	}
}

func TestEncodeTypedValue_OctetString(t *testing.T) {
	// sysDescr → OCTET STRING (non-integer string, not in type table)
	got := encodeTypedValue(".1.3.6.1.2.1.1.1.0", "Cisco IOS")
	if len(got) == 0 || got[0] != ASN1_OCTET_STRING {
		t.Errorf("sysDescr tag: got 0x%02x, want OCTET STRING (0x%02x)", got[0], ASN1_OCTET_STRING)
	}
}

// ── helper ────────────────────────────────────────────────────────────────────

func bytesEqual(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
