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

// SNMP ASN.1 BER/DER type tags (shared constants defined here)
const (
	ASN1_SEQUENCE     = 0x30
	ASN1_INTEGER      = 0x02
	ASN1_OCTET_STRING = 0x04
	ASN1_NULL         = 0x05
	ASN1_OBJECT_ID    = 0x06
	ASN1_GET_REQUEST  = 0xA0
	ASN1_GET_NEXT     = 0xA1
	ASN1_GET_RESPONSE = 0xA2
	ASN1_SET_REQUEST  = 0xA3
	ASN1_GET_BULK     = 0xA5
	ASN1_OID          = 0x06
	SNMP_GET_RESPONSE = 0xa2

	// SNMPv2c trap/inform PDU tags (RFC 3416).
	// Used by trap_v2c.go for outbound notifications and trap_exporter.go
	// for matching inbound INFORM acknowledgements (which arrive as GetResponse-PDU).
	ASN1_INFORM_REQUEST = 0xA6 // InformRequest-PDU
	ASN1_TRAP_V2C       = 0xA7 // SNMPv2-Trap-PDU

	// SNMPv2c application type tags (RFC 1902 §7.1)
	ASN1_IPADDRESS = 0x40 // IpAddress  – 4-byte IPv4 address
	ASN1_COUNTER32 = 0x41 // Counter32  – 32-bit monotonically increasing counter
	ASN1_GAUGE32   = 0x42 // Gauge32    – 32-bit gauge (also used for Unsigned32)
	ASN1_TIMETICKS = 0x43 // TimeTicks  – hundredths of a second since epoch
	ASN1_COUNTER64 = 0x46 // Counter64  – 64-bit monotonically increasing counter
)

// SNMPv3 specific constants
const (
	SNMPV3_VERSION            = 3
	SNMPV3_MSG_FLAG_AUTH      = 0x01
	SNMPV3_MSG_FLAG_PRIV      = 0x02
	SNMPV3_MSG_FLAG_REPORT    = 0x04
	SNMPV3_SECURITY_MODEL_USM = 3
	SNMPV3_AUTH_NONE          = 0
	SNMPV3_AUTH_MD5           = 1
	SNMPV3_AUTH_SHA1          = 2
	SNMPV3_PRIV_NONE          = 0
	SNMPV3_PRIV_DES           = 1
	SNMPV3_PRIV_AES128        = 2
)

// Configuration constants
const (
	DEFAULT_SNMP_PORT = 161
	DEFAULT_SSH_PORT  = 22
	DEFAULT_API_PORT  = 8443 // HTTPS API port for storage devices
	USERNAME          = "simadmin"
	PASSWORD          = "simadmin"
	TUN_DEVICE_PREFIX = "sim"
)

// Global manager instance
var manager *SimulatorManager
