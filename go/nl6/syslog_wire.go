/*
 * © 2025 Labmonkeys Space
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

// Syslog wire encoders. Two RFC-defined formats, one interface.
//
// Decision log:
//   - No trailing LF on UDP datagrams (design.md §OQ#1). Some legacy
//     syslog-ng configurations expect a terminator; operators hitting that
//     should file an issue and a -syslog-trailing-lf flag can be added.
//   - RFC 5424 BOM is OMITTED from the emitted MSG. RFC 5424 §6.4 makes it
//     optional; omitting keeps the wire bytes ASCII-clean and avoids the
//     "is this UTF-8 or Latin-1?" adventure downstream parsers have with
//     lone BOMs. Enable with a future flag if required.
//   - Timestamps are rendered in UTC. RFC 5424 §6.2.3 allows local offset
//     but UTC produces comparable timestamps across a 30k-device fleet.

package main

import (
	"bytes"
	"fmt"
	"strings"
	"time"
)

// SyslogFormat identifies which wire encoder to use.
type SyslogFormat string

const (
	SyslogFormat5424 SyslogFormat = "5424"
	SyslogFormat3164 SyslogFormat = "3164"
)

// ParseSyslogFormat validates the operator-supplied -syslog-format value.
// Leading/trailing whitespace and case are normalised, matching the
// tolerance of the equivalent `ParseTrapMode` — operators occasionally
// quote flag arguments with stray whitespace and that shouldn't be a
// startup error.
func ParseSyslogFormat(s string) (SyslogFormat, error) {
	normalised := strings.ToLower(strings.TrimSpace(s))
	switch normalised {
	case string(SyslogFormat5424):
		return SyslogFormat5424, nil
	case string(SyslogFormat3164):
		return SyslogFormat3164, nil
	default:
		return "", fmt.Errorf("invalid -syslog-format %q (valid: 5424, 3164)", s)
	}
}

// SyslogEncoder encodes one resolved catalog entry into its wire datagram.
// Implementations are stateless and safe for concurrent use.
type SyslogEncoder interface {
	// Encode appends the complete syslog datagram to buf. `now` is the
	// wall-clock time for the TIMESTAMP field. For RFC 3164, msg.Hostname
	// MUST be non-empty (the caller resolves the sysName / DeviceIP fallback
	// before calling); empty Hostname in RFC 5424 renders as NILVALUE `-`.
	Encode(buf *bytes.Buffer, msg SyslogResolved, now time.Time) error

	// MaxMessageSize returns the recommended upper bound on encoded
	// datagram bytes. Exporter write-buffers are sized against this.
	MaxMessageSize() int
}

// NewSyslogEncoder returns the encoder for the given format.
func NewSyslogEncoder(f SyslogFormat) (SyslogEncoder, error) {
	switch f {
	case SyslogFormat5424:
		return &RFC5424Encoder{}, nil
	case SyslogFormat3164:
		return &RFC3164Encoder{}, nil
	default:
		return nil, fmt.Errorf("unknown syslog format %q", f)
	}
}

// calculatePRI computes the RFC 5424 §6.2.1 PRI value as `<N>` with no
// leading zeros, where N = facility*8 + severity. Range: 0..191.
func calculatePRI(facility SyslogFacility, severity SyslogSeverity) string {
	// Bounds are already checked at catalog load; this is belt-and-braces.
	f := uint16(facility) & 0x1F
	s := uint16(severity) & 0x07
	return fmt.Sprintf("<%d>", f*8+s)
}

// sanitiseHostname normalises HOSTNAME for both RFC formats. Spaces and
// tabs become hyphens (spec Requirement "HOSTNAME derivation" — spaces
// replaced to preserve the single-token structure); any other byte that
// would break the header-token grammar (<, >, [, ], ", control chars)
// becomes `_`. Empty input returns empty so the encoder's NILVALUE branch
// can fire.
func sanitiseHostname(s string) string {
	if s == "" {
		return ""
	}
	b := make([]byte, 0, len(s))
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case c == ' ' || c == '\t':
			b = append(b, '-')
		case c < 33 || c > 126 || c == '<' || c == '>' || c == '[' || c == ']' || c == '"':
			b = append(b, '_')
		default:
			b = append(b, c)
		}
	}
	return string(b)
}

// sanitiseHeaderField normalises APP-NAME, MSGID, and TAG values. Any byte
// that breaks the header-token grammar (non-printable ASCII, or PRI / SD
// framing delimiters) becomes `_`. Unlike HOSTNAME, spaces are *not*
// converted to hyphens — the surrounding format already disallows spaces,
// so they collapse to `_` along with other disallowed bytes.
func sanitiseHeaderField(s string) string {
	if s == "" {
		return ""
	}
	b := make([]byte, 0, len(s))
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c < 33 || c > 126 || c == '<' || c == '>' || c == '[' || c == ']' || c == '"' {
			b = append(b, '_')
		} else {
			b = append(b, c)
		}
	}
	return string(b)
}

// sanitiseMessageBody strips injection-enabling control bytes from MSG and
// STRUCTURED-DATA param values. Newlines / carriage returns / NULs get
// replaced with spaces so a crafted catalog or HTTP-override cannot inject
// a fake `<PRI>` line into the collector's stream after a newline.
// Everything else — punctuation, whitespace other than CR/LF, high-bit
// bytes — passes through. The 5424 SD-value path does its own
// `" \ ]` backslash-escape on top of this.
func sanitiseMessageBody(s string) string {
	if s == "" {
		return ""
	}
	// Fast path — if no control bytes, no allocation.
	clean := true
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c == 0x00 || c == '\r' || c == '\n' {
			clean = false
			break
		}
	}
	if clean {
		return s
	}
	b := make([]byte, len(s))
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch c {
		case 0x00, '\r', '\n':
			b[i] = ' '
		default:
			b[i] = c
		}
	}
	return string(b)
}

// -----------------------------------------------------------------------------
// RFC 5424 encoder
// -----------------------------------------------------------------------------

// RFC5424Encoder emits structured syslog messages per RFC 5424 §6:
//
//	<PRI>1 TIMESTAMP HOSTNAME APP-NAME PROCID MSGID STRUCTURED-DATA [BOM-MSG]
//
// Empty fields are rendered as the NILVALUE `-`. TIMESTAMP is ISO 8601 UTC
// with millisecond precision.
type RFC5424Encoder struct{}

// StructuredDataEnterpriseID is the IANA-assigned private enterprise number
// used in the SD-ID (e.g. `meta@32473`). 32473 is the reserved value from
// RFC 5612 for documentation / example use. Operators who want a real
// enterprise number should fork the encoder; this is a simulator, the SD-ID
// is cosmetic for downstream parsers.
const syslogSDEnterpriseID = 32473

// syslogSDID is the SD-ID used in emitted STRUCTURED-DATA elements. Kept as
// a single element because the v1 catalog schema ships a flat key/value map
// without per-key SD-ID partitioning.
const syslogSDID = "meta@32473"

// MaxMessageSize returns the MTU-safe encoding ceiling. Catalog entries are
// validated at load time against this bound (design.md §D12).
func (*RFC5424Encoder) MaxMessageSize() int { return maxSyslogMessageBytes }

func (*RFC5424Encoder) Encode(buf *bytes.Buffer, msg SyslogResolved, now time.Time) error {
	if buf == nil {
		return fmt.Errorf("syslog 5424: buf is nil")
	}
	startLen := buf.Len()

	// PRI + VERSION
	buf.WriteString(calculatePRI(msg.Facility, msg.Severity))
	buf.WriteByte('1')
	buf.WriteByte(' ')

	// TIMESTAMP: RFC 3339 with millisecond precision, UTC ('Z').
	// `time.RFC3339Nano` is too precise; build manually for ms.
	ts := now.UTC()
	fmt.Fprintf(buf, "%04d-%02d-%02dT%02d:%02d:%02d.%03dZ",
		ts.Year(), ts.Month(), ts.Day(),
		ts.Hour(), ts.Minute(), ts.Second(),
		ts.Nanosecond()/1_000_000,
	)
	buf.WriteByte(' ')

	// HOSTNAME / APP-NAME / PROCID / MSGID (NILVALUE `-` when empty).
	writeSyslog5424Field(buf, sanitiseHostname(msg.Hostname))
	buf.WriteByte(' ')
	writeSyslog5424Field(buf, sanitiseHeaderField(msg.AppName))
	buf.WriteByte(' ')
	// PROCID not yet in scope (design §D4); always NILVALUE.
	buf.WriteByte('-')
	buf.WriteByte(' ')
	writeSyslog5424Field(buf, sanitiseHeaderField(msg.MsgID))
	buf.WriteByte(' ')

	// STRUCTURED-DATA.
	if len(msg.StructuredData) == 0 {
		buf.WriteByte('-')
	} else {
		buf.WriteByte('[')
		buf.WriteString(syslogSDID)
		for _, kv := range msg.StructuredData {
			buf.WriteByte(' ')
			// Keys are validated at catalog load against RFC 5424 SD-NAME.
			buf.WriteString(kv.Key)
			buf.WriteString(`="`)
			// Strip injection-enabling control bytes first, then escape the
			// RFC 5424 §6.3.3 reserved characters.
			writeSyslog5424SDParamValue(buf, sanitiseMessageBody(kv.Value))
			buf.WriteByte('"')
		}
		buf.WriteByte(']')
	}

	// MSG (no BOM — decision at top of file).
	if msg.Message != "" {
		buf.WriteByte(' ')
		buf.WriteString(sanitiseMessageBody(msg.Message))
	}

	// MTU safety: the catalog MTU guard uses this same encoder, but HTTP
	// overrides or future exporter paths can still produce oversize content.
	// Fail loudly rather than sending a truncated or fragmented datagram.
	if encoded := buf.Len() - startLen; encoded > maxSyslogMessageBytes {
		return fmt.Errorf("syslog 5424: encoded size %d exceeds MaxMessageSize %d",
			encoded, maxSyslogMessageBytes)
	}
	return nil
}

// writeSyslog5424Field emits a single syslog 5424 header field value,
// substituting NILVALUE `-` for empty input. Callers are responsible for
// passing a value that has already been run through sanitiseHeaderField /
// sanitiseHostname — this function trusts its input.
func writeSyslog5424Field(buf *bytes.Buffer, v string) {
	if v == "" {
		buf.WriteByte('-')
		return
	}
	buf.WriteString(v)
}

// writeSyslog5424SDParamValue escapes reserved characters per RFC 5424
// §6.3.3. Inside PARAM-VALUE the characters `"`, `\`, and `]` must be
// backslash-escaped; all others pass through verbatim.
func writeSyslog5424SDParamValue(buf *bytes.Buffer, v string) {
	for i := 0; i < len(v); i++ {
		c := v[i]
		if c == '"' || c == '\\' || c == ']' {
			buf.WriteByte('\\')
		}
		buf.WriteByte(c)
	}
}

// -----------------------------------------------------------------------------
// RFC 3164 encoder
// -----------------------------------------------------------------------------

// RFC3164Encoder emits BSD-style syslog messages per RFC 3164 §4:
//
//	<PRI>TIMESTAMP HOSTNAME TAG: MSG
//
// TIMESTAMP uses `Mmm DD HH:MM:SS` with a double-space pad between the
// month abbreviation and single-digit day-of-month values.
type RFC3164Encoder struct{}

// syslogTagMaxLen is the maximum TAG field length per RFC 3164 §5.3.
const syslogTagMaxLen = 32

// MaxMessageSize returns the MTU-safe encoding ceiling. 3164 is always
// smaller than 5424 for the same inputs, so the shared ceiling applies.
func (*RFC3164Encoder) MaxMessageSize() int { return maxSyslogMessageBytes }

func (*RFC3164Encoder) Encode(buf *bytes.Buffer, msg SyslogResolved, now time.Time) error {
	if buf == nil {
		return fmt.Errorf("syslog 3164: buf is nil")
	}
	if msg.Hostname == "" {
		return fmt.Errorf("syslog 3164: hostname is required")
	}
	startLen := buf.Len()

	// PRI
	buf.WriteString(calculatePRI(msg.Facility, msg.Severity))

	// TIMESTAMP — `Mmm DD HH:MM:SS` with two-space pad for single-digit DD.
	ts := now.UTC()
	day := ts.Day()
	if day < 10 {
		fmt.Fprintf(buf, "%s  %d %02d:%02d:%02d",
			ts.Month().String()[:3], day,
			ts.Hour(), ts.Minute(), ts.Second())
	} else {
		fmt.Fprintf(buf, "%s %d %02d:%02d:%02d",
			ts.Month().String()[:3], day,
			ts.Hour(), ts.Minute(), ts.Second())
	}
	buf.WriteByte(' ')

	// HOSTNAME
	buf.WriteString(sanitiseHostname(msg.Hostname))
	buf.WriteByte(' ')

	// TAG — sanitised to ASCII-token form and truncated to 32 characters.
	// RFC 5424-only fields (msgId, structuredData) are silently ignored
	// (design.md Requirement "RFC 3164 wire format").
	tag := sanitiseHeaderField(msg.AppName)
	if tag == "" {
		// 3164 has no NILVALUE; the catalog loader rejects empty AppName
		// so this path is defensive only.
		tag = "unknown"
	}
	if len(tag) > syslogTagMaxLen {
		tag = tag[:syslogTagMaxLen]
	}
	buf.WriteString(tag)
	buf.WriteByte(':')
	if msg.Message != "" {
		buf.WriteByte(' ')
		buf.WriteString(sanitiseMessageBody(msg.Message))
	}

	if encoded := buf.Len() - startLen; encoded > maxSyslogMessageBytes {
		return fmt.Errorf("syslog 3164: encoded size %d exceeds MaxMessageSize %d",
			encoded, maxSyslogMessageBytes)
	}
	return nil
}
