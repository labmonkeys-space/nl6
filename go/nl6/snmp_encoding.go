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

// decodeOID converts ASN.1 encoded OID bytes to dot notation string
func decodeOID(oidBytes []byte) string {
	if len(oidBytes) == 0 {
		return ""
	}

	var oid []string

	// First byte encodes first two sub-identifiers
	// first = byte / 40, second = byte % 40
	firstByte := oidBytes[0]
	first := firstByte / 40
	second := firstByte % 40
	oid = append(oid, strconv.Itoa(int(first)))
	oid = append(oid, strconv.Itoa(int(second)))

	// Process remaining bytes
	pos := 1
	for pos < len(oidBytes) {
		value := 0

		// Parse variable length encoding (base 128)
		for pos < len(oidBytes) {
			b := oidBytes[pos]
			pos++

			value = (value << 7) | int(b&0x7F)

			// If high bit is 0, this is the last byte of this sub-identifier
			if (b & 0x80) == 0 {
				break
			}
		}

		oid = append(oid, strconv.Itoa(value))
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

	// First two components are encoded as 40*first + second
	first, _ := strconv.Atoi(parts[0])
	second, _ := strconv.Atoi(parts[1])
	encoded = append(encoded, byte(40*first+second))

	// Encode remaining components
	for i := 2; i < len(parts); i++ {
		val, _ := strconv.Atoi(parts[i])
		encoded = append(encoded, encodeOIDComponent(val)...)
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
//  1. "endOfMibView" exception (SNMPv2c)
//  2. OID-derived application type (Counter32, Gauge32, TimeTicks, Counter64, IpAddress)
//  3. Integer-parseable value → INTEGER
//  4. Everything else → OCTET STRING
func encodeTypedValue(oid, value string) []byte {
	if value == "endOfMibView" {
		return []byte{0x82, 0x00}
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
