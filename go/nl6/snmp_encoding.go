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

package main

import (
	"net"
	"strconv"
	"strings"
)

// parseLength parses ASN.1 BER/DER length encoding
func parseLength(data []byte, pos int) (int, int) {
	if pos >= len(data) {
		return -1, pos
	}

	length := int(data[pos])
	pos++

	// Short form (length < 128)
	if length < 0x80 {
		return length, pos
	}

	// Long form
	lengthBytes := length & 0x7F
	if lengthBytes == 0 || lengthBytes > 4 || pos+lengthBytes > len(data) {
		return -1, pos
	}

	length = 0
	for i := 0; i < lengthBytes; i++ {
		length = (length << 8) | int(data[pos])
		pos++
	}

	return length, pos
}

// legalOIDArcPair reports whether (first, second) is a pair X.690 §8.19.4 can
// represent. The first arc is 0, 1 or 2; when it is 0 or 1 the second arc is
// limited to 0..39, because 40*first+second is what actually goes on the wire
// and a wider second arc would ALIAS a higher first arc: 1.40 and 2.0 both
// compute 80 and could not be told apart on decode.
//
// Only the first arc 2 may carry an unbounded second arc, which is how
// legitimate OIDs such as the ITU test arc 2.999 exist. Encoding a pair
// outside this set would produce a valid-looking OID that is not the one the
// caller named, which is the fabrication class nl6#529 exists to remove.
func legalOIDArcPair(first, second int) bool {
	if first < 0 || second < 0 || first > 2 {
		return false
	}
	if first < 2 && second > 39 {
		return false
	}
	// The COMBINED value is what goes on the wire, so it is what must fit an
	// SMI sub-identifier. Bounding the raw second arc instead is not the same
	// test, and having the two encoders bound different things is precisely
	// how they diverged on "2.7000000000" (found by FuzzOIDRoundTrip).
	// Computed in uint64 so the sum cannot overflow a 32-bit int.
	return uint64(40)*uint64(first)+uint64(second) <= maxOIDSubIdentifier
}

// maxOIDSubIdentifier bounds a decoded sub-identifier. SMI caps an arc at
// 2^32-1, and without a bound the accumulator below wraps: ten continuation
// bytes used to decode to the arc -1, which then flowed into a response and
// back out through the encoder (nl6#529).
//
// Untyped, and compared against int in both encoders, so this package
// assumes a 64-bit int: on a 32-bit GOARCH the comparison is a constant
// overflow at compile time. nl6 only builds for amd64 and arm64.
const maxOIDSubIdentifier = 0xFFFFFFFF

// maxOIDBodyBytes is the largest OID content field both encoders can express
// identically: appendOID writes a two-octet long-form length at most.
const maxOIDBodyBytes = 0xFFFF

// decodeOID decodes a BER OBJECT IDENTIFIER body into dotted form, or returns
// "" if the bytes are not a well-formed OID.
//
// The first sub-identifier is a base-128 varint carrying 40*first + second
// (X.690 §8.19.4), NOT a single byte. Reading it as one byte was symmetric
// with the old encodeOID and both were wrong: the round-trip held only while
// the second arc stayed under 40, and fabricated silently above it.
//
// This is on the request-parse path (snmp_handlers.go, snmp.go,
// snmp_response.go all decode attacker-supplied bytes), so it refuses
// malformed input rather than inventing a value for it.
func decodeOID(oidBytes []byte) string {
	if len(oidBytes) == 0 {
		return ""
	}

	subIDs, pos := make([]uint64, 0, len(oidBytes)), 0
	for pos < len(oidBytes) {
		// X.690 §8.19.2: a sub-identifier is encoded minimally, so its leading
		// octet is never 0x80. Without this an attacker can pad any OID with
		// arbitrarily many 0x80 bytes and produce unbounded distinct byte
		// strings that all decode to the same OID, which defeats any
		// dedup, cache key or equality check keyed on the wire form.
		if oidBytes[pos] == 0x80 {
			return ""
		}

		var value uint64
		terminated := false
		for pos < len(oidBytes) {
			b := oidBytes[pos]
			pos++

			// Guard BEFORE shifting: 2^32-1 needs at most five 7-bit groups,
			// so anything wider is out of range whatever the remaining bytes
			// hold, and shifting first is what produced a negative arc. This
			// is the ONLY range check; a post-shift one cannot fire, since the
			// largest value reachable through this guard is exactly 2^32-1.
			if value > (maxOIDSubIdentifier >> 7) {
				return ""
			}
			value = (value << 7) | uint64(b&0x7F)

			if (b & 0x80) == 0 {
				terminated = true
				break
			}
		}
		// A sub-identifier whose last byte still sets the continuation bit is
		// truncated, not complete. It used to be accepted at face value.
		if !terminated {
			return ""
		}
		subIDs = append(subIDs, value)
	}

	// Split the first sub-identifier back into two arcs. X.690 §8.19.4: the
	// first arc is 0, 1 or 2, and only 0 and 1 are limited to a second arc
	// under 40, which is why the first arc is clamped rather than divided out.
	first := subIDs[0] / 40
	if first > 2 {
		first = 2
	}
	second := subIDs[0] - 40*first

	oid := make([]string, 0, len(subIDs)+1)
	oid = append(oid, strconv.FormatUint(first, 10), strconv.FormatUint(second, 10))
	for _, v := range subIDs[1:] {
		oid = append(oid, strconv.FormatUint(v, 10))
	}

	return "." + strings.Join(oid, ".")
}

// ASN.1 encoding helper functions
func encodeLength(length int) []byte {
	if length < 0x80 {
		return []byte{byte(length)}
	}

	// Long form
	var bytes []byte
	temp := length
	for temp > 0 {
		bytes = append([]byte{byte(temp & 0xff)}, bytes...)
		temp >>= 8
	}

	result := make([]byte, len(bytes)+1)
	result[0] = byte(0x80 | len(bytes))
	copy(result[1:], bytes)
	return result
}

func encodeInteger(value int) []byte {
	var bytes []byte
	if value == 0 {
		bytes = []byte{0x00}
	} else if value > 0 {
		// Positive integer
		temp := value
		for temp > 0 {
			bytes = append([]byte{byte(temp & 0xff)}, bytes...)
			temp >>= 8
		}
		// Add leading zero if high bit is set (to keep it positive)
		if len(bytes) > 0 && bytes[0]&0x80 != 0 {
			bytes = append([]byte{0x00}, bytes...)
		}
	} else {
		// Negative integer - use two's complement representation
		temp := uint64(value) // Convert to unsigned for bit manipulation
		// For negative numbers, we need to ensure proper two's complement encoding
		if value >= -128 && value < 0 {
			bytes = []byte{byte(temp)}
		} else if value >= -32768 && value < 0 {
			bytes = []byte{byte(temp >> 8), byte(temp)}
		} else if value >= -8388608 && value < 0 {
			bytes = []byte{byte(temp >> 16), byte(temp >> 8), byte(temp)}
		} else {
			// For larger negative numbers, use full 32-bit representation
			bytes = []byte{byte(temp >> 24), byte(temp >> 16), byte(temp >> 8), byte(temp)}
		}

		// Ensure we have the minimum number of bytes for negative representation
		// If the high bit is not set, we need to add 0xFF prefix to maintain negative value
		if len(bytes) > 0 && bytes[0]&0x80 == 0 {
			bytes = append([]byte{0xFF}, bytes...)
		}
	}

	result := []byte{ASN1_INTEGER}
	result = append(result, encodeLength(len(bytes))...)
	result = append(result, bytes...)
	return result
}

func encodeOctetString(value string) []byte {
	data := []byte(value)
	result := []byte{ASN1_OCTET_STRING}
	result = append(result, encodeLength(len(data))...)
	result = append(result, data...)
	return result
}

func encodeOID(oid string) []byte {
	oid = strings.TrimPrefix(oid, ".")
	parts := strings.Split(oid, ".")
	if len(parts) < 2 {
		return []byte{ASN1_OID, 0x00}
	}

	var encoded []byte

	// X.690 §8.19.4: the first two arcs share ONE sub-identifier valued
	// 40*first + second, and every sub-identifier is a base-128 varint. This
	// used to emit that byte directly, which silently fabricated any OID whose
	// combined value exceeded what one byte can carry: 3.40.1 went out as
	// .4.0.1, 2.999 (the legal ITU arc) as .1.15. Valid-looking BER carrying
	// data nobody wrote, which a collector cannot detect (nl6#529).
	//
	// encodeOIDComponent already emits a correct varint, so this is the same
	// treatment every other arc has always had. decodeOID reads it back as a
	// varint; the two must move together or the round-trip breaks.
	// strconv errors are NOT swallowed. Discarding them was the second route
	// into the same fabrication: "1.3.x.7" became the perfectly valid-looking
	// OID .1.3.0.7, and "1." became .1.0, because a component that failed to
	// parse silently contributed the arc 0. An OID this function cannot
	// represent faithfully takes the degenerate path instead of becoming a
	// different OID (nl6#529).
	first, err1 := strconv.Atoi(parts[0])
	second, err2 := strconv.Atoi(parts[1])
	if err1 != nil || err2 != nil || !legalOIDArcPair(first, second) {
		return []byte{ASN1_OID, 0x00}
	}
	encoded = append(encoded, encodeOIDComponent(40*first+second)...)

	// Encode remaining components
	for i := 2; i < len(parts); i++ {
		val, err := strconv.Atoi(parts[i])
		if err != nil || val < 0 || val > maxOIDSubIdentifier {
			return []byte{ASN1_OID, 0x00}
		}
		encoded = append(encoded, encodeOIDComponent(val)...)
	}

	// Both encoders must agree byte for byte, and appendOID writes at most a
	// two-octet long-form length. A body at or past 0x10000 would take three
	// octets here and be truncated there, so it is refused in both rather than
	// silently diverging. No SNMP datagram could carry an OID this size in any
	// case: the bound is about keeping the two implementations identical, not
	// about the wire.
	if len(encoded) > maxOIDBodyBytes {
		return []byte{ASN1_OID, 0x00}
	}

	result := []byte{ASN1_OID}
	result = append(result, encodeLength(len(encoded))...)
	result = append(result, encoded...)
	return result
}

func encodeOIDComponent(value int) []byte {
	if value < 0x80 {
		return []byte{byte(value)}
	}

	var result []byte
	temp := value

	// First, collect all the 7-bit chunks in reverse order
	var chunks []byte
	for temp > 0 {
		chunks = append(chunks, byte(temp&0x7f))
		temp >>= 7
	}

	// Now build the result with proper bit flags
	// All bytes except the last should have the high bit set
	for i := len(chunks) - 1; i >= 0; i-- {
		if i > 0 {
			result = append(result, chunks[i]|0x80) // Set high bit for continuation
		} else {
			result = append(result, chunks[i]) // Last byte, no high bit
		}
	}

	return result
}

func encodeSequence(contents []byte) []byte {
	result := []byte{ASN1_SEQUENCE}
	result = append(result, encodeLength(len(contents))...)
	result = append(result, contents...)
	return result
}

// encodeVarBind wraps an OID and an already-encoded value in the VarBind
// SEQUENCE of RFC 3416. Used where the value is not derived from resource data
// — an SNMPv1 noSuchName response echoes the requested names with NULL values.
func encodeVarBind(oid string, valueBytes []byte) []byte {
	return encodeSequence(append(encodeOID(oid), valueBytes...))
}

func encodeNull() []byte {
	return []byte{ASN1_NULL, 0x00}
}

// encodeUnsigned32 encodes a uint32 with the given application tag.
// Used for Counter32 (0x41), Gauge32 (0x42), and TimeTicks (0x43).
func encodeUnsigned32(tag byte, value uint32) []byte {
	var b [4]byte
	b[0] = byte(value >> 24)
	b[1] = byte(value >> 16)
	b[2] = byte(value >> 8)
	b[3] = byte(value)
	// Strip leading zero bytes (minimum-length encoding).
	start := 0
	for start < 3 && b[start] == 0 {
		start++
	}
	result := []byte{tag}
	result = append(result, encodeLength(4-start)...)
	result = append(result, b[start:]...)
	return result
}

// encodeCounter64 encodes a uint64 with tag ASN1_COUNTER64 (0x46).
func encodeCounter64(value uint64) []byte {
	var b [8]byte
	for i := 7; i >= 0; i-- {
		b[i] = byte(value & 0xff) // explicit low-byte extraction (CodeQL go/incorrect-integer-conversion)
		value >>= 8
	}
	start := 0
	for start < 7 && b[start] == 0 {
		start++
	}
	result := []byte{ASN1_COUNTER64}
	result = append(result, encodeLength(8-start)...)
	result = append(result, b[start:]...)
	return result
}

// encodeIPAddress encodes a dotted-decimal IPv4 string as an SNMP IpAddress (0x40).
// Falls back to OCTET STRING if the string is not a valid IPv4 address.
func encodeIPAddress(ipStr string) []byte {
	ip := net.ParseIP(ipStr)
	if ip4 := ip.To4(); ip4 != nil {
		result := []byte{ASN1_IPADDRESS, 0x04}
		result = append(result, ip4...)
		return result
	}
	return encodeOctetString(ipStr)
}

// oidTypeEntry maps an OID column prefix to the SNMP application type tag
// that must be used when encoding values for that column.
type oidTypeEntry struct {
	prefix string
	tag    byte
}

// oidTypeTable maps standard MIB OID column prefixes to their RFC-mandated
// ASN.1 application type tags. snmpTypeTag() matches a leaf OID against each
// entry using HasPrefix(oid, prefix+".") OR exact equality (oid == prefix),
// so both ".1.3.6.1.2.1.1.2.0" and the bare ".1.3.6.1.2.1.1.2" match the
// sysObjectID entry. The trailing "." in the HasPrefix check prevents
// digit-extension false matches (e.g. prefix "...1" cannot match "...10.*"),
// so ordering within the table is irrelevant for correctness.
var oidTypeTable = []oidTypeEntry{
	// MIB-II system group
	{".1.3.6.1.2.1.1.2", ASN1_OBJECT_ID}, // sysObjectID
	{".1.3.6.1.2.1.1.3", ASN1_TIMETICKS}, // sysUpTime

	// ifTable — RFC 2863
	{".1.3.6.1.2.1.2.2.1.5", ASN1_GAUGE32},    // ifSpeed
	{".1.3.6.1.2.1.2.2.1.9", ASN1_TIMETICKS},  // ifLastChange
	{".1.3.6.1.2.1.2.2.1.10", ASN1_COUNTER32}, // ifInOctets
	{".1.3.6.1.2.1.2.2.1.11", ASN1_COUNTER32}, // ifInUcastPkts
	{".1.3.6.1.2.1.2.2.1.12", ASN1_COUNTER32}, // ifInNUcastPkts
	{".1.3.6.1.2.1.2.2.1.13", ASN1_COUNTER32}, // ifInDiscards
	{".1.3.6.1.2.1.2.2.1.14", ASN1_COUNTER32}, // ifInErrors
	{".1.3.6.1.2.1.2.2.1.15", ASN1_COUNTER32}, // ifInUnknownProtos
	{".1.3.6.1.2.1.2.2.1.16", ASN1_COUNTER32}, // ifOutOctets
	{".1.3.6.1.2.1.2.2.1.17", ASN1_COUNTER32}, // ifOutUcastPkts
	{".1.3.6.1.2.1.2.2.1.18", ASN1_COUNTER32}, // ifOutNUcastPkts
	{".1.3.6.1.2.1.2.2.1.19", ASN1_COUNTER32}, // ifOutDiscards
	{".1.3.6.1.2.1.2.2.1.20", ASN1_COUNTER32}, // ifOutErrors
	{".1.3.6.1.2.1.2.2.1.21", ASN1_GAUGE32},   // ifOutQLen

	// ifXTable — RFC 2863
	{".1.3.6.1.2.1.31.1.1.1.2", ASN1_COUNTER32},  // ifInMulticastPkts
	{".1.3.6.1.2.1.31.1.1.1.3", ASN1_COUNTER32},  // ifInBroadcastPkts
	{".1.3.6.1.2.1.31.1.1.1.4", ASN1_COUNTER32},  // ifOutMulticastPkts
	{".1.3.6.1.2.1.31.1.1.1.5", ASN1_COUNTER32},  // ifOutBroadcastPkts
	{".1.3.6.1.2.1.31.1.1.1.6", ASN1_COUNTER64},  // ifHCInOctets
	{".1.3.6.1.2.1.31.1.1.1.7", ASN1_COUNTER64},  // ifHCInUcastPkts
	{".1.3.6.1.2.1.31.1.1.1.8", ASN1_COUNTER64},  // ifHCInMulticastPkts
	{".1.3.6.1.2.1.31.1.1.1.9", ASN1_COUNTER64},  // ifHCInBroadcastPkts
	{".1.3.6.1.2.1.31.1.1.1.10", ASN1_COUNTER64}, // ifHCOutOctets
	{".1.3.6.1.2.1.31.1.1.1.11", ASN1_COUNTER64}, // ifHCOutUcastPkts
	{".1.3.6.1.2.1.31.1.1.1.12", ASN1_COUNTER64}, // ifHCOutMulticastPkts
	{".1.3.6.1.2.1.31.1.1.1.13", ASN1_COUNTER64}, // ifHCOutBroadcastPkts
	{".1.3.6.1.2.1.31.1.1.1.15", ASN1_GAUGE32},   // ifHighSpeed
	{".1.3.6.1.2.1.31.1.1.1.19", ASN1_TIMETICKS}, // ifCounterDiscontinuityTime

	// ipAddrTable — RFC 4293
	{".1.3.6.1.2.1.4.20.1.1", ASN1_IPADDRESS}, // ipAdEntAddr
	{".1.3.6.1.2.1.4.20.1.3", ASN1_IPADDRESS}, // ipAdEntNetMask

	// ipRouteTable (deprecated but still walked by many NMSes)
	{".1.3.6.1.2.1.4.21.1.1", ASN1_IPADDRESS},  // ipRouteDest
	{".1.3.6.1.2.1.4.21.1.7", ASN1_IPADDRESS},  // ipRouteNextHop
	{".1.3.6.1.2.1.4.21.1.11", ASN1_IPADDRESS}, // ipRouteMask

	// ipNetToMediaTable
	{".1.3.6.1.2.1.4.22.1.3", ASN1_IPADDRESS}, // ipNetToMediaNetAddress

	// ifAlias (ifXTable .18) — DisplayString. Forced so a numeric link
	// label or static alias is never emitted as INTEGER.
	{".1.3.6.1.2.1.31.1.1.1.18", ASN1_OCTET_STRING}, // ifAlias

	// OLD-CISCO-MEMORY-MIB freeMem — SYNTAX Gauge. Without this entry a
	// numeric value takes the default INTEGER branch, which is the wrong type
	// and caps the value at 2^31-1 (nl6#515).
	{".1.3.6.1.4.1.9.2.1.8", ASN1_GAUGE32}, // freeMem

	// LLDP-MIB (IEEE 802.1AB) string-typed columns. The chassis-id is a
	// binary OCTET STRING (macAddress subtype); the sys/port name and
	// description leaves are SnmpAdminString. Subtype columns (.3.1, .3.7.1.2,
	// .4.1.1.4, .4.1.1.6) are intentionally absent — they are INTEGER enums.
	{".1.0.8802.1.1.2.1.3.2", ASN1_OCTET_STRING},      // lldpLocChassisId
	{".1.0.8802.1.1.2.1.3.3", ASN1_OCTET_STRING},      // lldpLocSysName
	{".1.0.8802.1.1.2.1.3.4", ASN1_OCTET_STRING},      // lldpLocSysDesc
	{".1.0.8802.1.1.2.1.3.7.1.3", ASN1_OCTET_STRING},  // lldpLocPortId
	{".1.0.8802.1.1.2.1.3.7.1.4", ASN1_OCTET_STRING},  // lldpLocPortDesc
	{".1.0.8802.1.1.2.1.4.1.1.5", ASN1_OCTET_STRING},  // lldpRemChassisId
	{".1.0.8802.1.1.2.1.4.1.1.7", ASN1_OCTET_STRING},  // lldpRemPortId
	{".1.0.8802.1.1.2.1.4.1.1.8", ASN1_OCTET_STRING},  // lldpRemPortDesc
	{".1.0.8802.1.1.2.1.4.1.1.9", ASN1_OCTET_STRING},  // lldpRemSysName
	{".1.0.8802.1.1.2.1.4.1.1.10", ASN1_OCTET_STRING}, // lldpRemSysDesc
}

// snmpTypeTag returns the SNMP application type tag for the given OID, or 0
// if the OID is not in the well-known type table (use INTEGER / OCTET_STRING).
func snmpTypeTag(oid string) byte {
	for _, e := range oidTypeTable {
		if strings.HasPrefix(oid, e.prefix+".") || oid == e.prefix {
			return e.tag
		}
	}
	return 0
}

// encodeTypedValue encodes an SNMP value using the correct ASN.1 type tag for
// the given OID. This replaces the old pattern of encoding every numeric value
// as INTEGER (0x02) regardless of the OID's MIB definition.
//
// Type resolution priority:
//  1. RFC 3416 exception sentinel (valueNoSuchObject, valueEndOfMibView)
//  2. OID-derived application type (Counter32, Gauge32, TimeTicks, Counter64, IpAddress)
//  3. Integer-parseable value → INTEGER
//  4. Everything else → OCTET STRING
func encodeTypedValue(oid, value string) []byte {
	// RFC 3416 exceptions occupy the varbind's value position as
	// context-specific, primitive, zero-length tags. The response is otherwise
	// a success: error-status stays noError.
	//
	// Only noSuchObject is emitted, never noSuchInstance. §4.2.1 separates them
	// by OID prefix registration — noSuchObject when no accessible variable
	// shares the prefix, noSuchInstance when the object exists but the instance
	// does not. A profile is a flat OID→value map with no MIB registry, so nl6
	// cannot evaluate that test and noSuchObject is the only defensible answer.
	//
	// Callers on the SNMPv1 path must not reach here with a sentinel: v1 has no
	// exceptions and needs the noSuchName error-status instead (RFC 3584
	// §4.2.2.2). The response builders divert it.
	//
	// Every SNMPv3 path reaches here: createScopedPDU is the third caller
	// (nl6#518), and since nl6#526 the GETBULK handler answers end-of-MIB with
	// the sentinel too, so a v3 GET, GETNEXT or GETBULK that reaches this
	// encoder terminates a walk on the exception rather than on a placeholder.
	// A GETBULK whose scoped PDU fails to decrypt does not reach it: that
	// fallback rewrites the request to a GET of sysDescr.0.
	switch value {
	case valueEndOfMibView:
		return []byte{0x82, 0x00} // endOfMibView   [2] IMPLICIT NULL
	case valueNoSuchObject:
		return []byte{0x80, 0x00} // noSuchObject   [0] IMPLICIT NULL
	}

	tag := snmpTypeTag(oid)
	switch tag {
	case ASN1_OCTET_STRING:
		// Force OCTET STRING even when the value parses as an integer
		// (e.g. a purely-numeric lldp*SysName). Without this the default
		// branch would emit INTEGER, violating the MIB's string type.
		return encodeOctetString(value)

	case ASN1_OBJECT_ID:
		return encodeOID(value)

	case ASN1_IPADDRESS:
		return encodeIPAddress(value)

	case ASN1_COUNTER32, ASN1_GAUGE32, ASN1_TIMETICKS:
		if u, err := strconv.ParseUint(value, 10, 32); err == nil {
			return encodeUnsigned32(tag, uint32(u))
		}
		// Negative values are theoretically invalid for unsigned types, but
		// some resource files use -1 as a placeholder. Parse at 32-bit width
		// (out-of-range values fall through to the octet-string encoding
		// instead of silently truncating) and wrap-cast so -1 stays
		// 0xFFFFFFFF on the wire.
		if i, err := strconv.ParseInt(value, 10, 32); err == nil {
			return encodeUnsigned32(tag, uint32(int32(i)))
		}
		return encodeOctetString(value)

	case ASN1_COUNTER64:
		if u, err := strconv.ParseUint(value, 10, 64); err == nil {
			return encodeCounter64(u)
		}
		return encodeOctetString(value)

	default:
		// No special type: integer values → INTEGER, everything else → OCTET STRING.
		if i, err := strconv.Atoi(value); err == nil {
			return encodeInteger(i)
		}
		return encodeOctetString(value)
	}
}
