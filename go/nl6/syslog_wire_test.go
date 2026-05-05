/*
 * © 2025 Labmonkeys Space
 * Apache-2.0 — see LICENSE.
 */

package main

import (
	"bytes"
	"crypto/md5"
	"encoding/hex"
	"fmt"
	"regexp"
	"strings"
	"testing"
	"time"
)

// fixedNow is the canonical timestamp used by byte-pinned and round-trip
// tests. Chosen to include single-digit day and non-zero milliseconds so
// the 3164 double-space-pad and 5424 millisecond precision are exercised.
func fixedNow() time.Time {
	return time.Date(2026, time.April, 5, 12, 34, 56, 789_000_000, time.UTC)
}

// Small helpers to build a resolved message for test isolation.
func makeResolved(msg string) SyslogResolved {
	return SyslogResolved{
		Facility: 23, // local7
		Severity: 3,  // error
		AppName:  "IFMGR",
		MsgID:    "LINKDOWN",
		Hostname: "rtr-edge-01",
		Message:  msg,
	}
}

// -----------------------------------------------------------------------------
// PRI calculation
// -----------------------------------------------------------------------------

func TestSyslogPRITable(t *testing.T) {
	cases := []struct {
		facility SyslogFacility
		severity SyslogSeverity
		want     string
	}{
		{23, 3, "<187>"}, // local7.error
		{10, 6, "<86>"},  // authpriv.info
		{0, 0, "<0>"},    // kern.emerg
		{4, 7, "<39>"},   // auth.debug
		{16, 5, "<133>"}, // local0.notice
	}
	for _, c := range cases {
		got := calculatePRI(c.facility, c.severity)
		if got != c.want {
			t.Errorf("facility=%d severity=%d: got %q, want %q", c.facility, c.severity, got, c.want)
		}
	}
}

// -----------------------------------------------------------------------------
// RFC 5424
// -----------------------------------------------------------------------------

// rfc5424Fields is a minimal RFC 5424 header splitter used for round-trip
// testing. It extracts the first seven header tokens (PRI+VERSION, TIMESTAMP,
// HOSTNAME, APP-NAME, PROCID, MSGID, STRUCTURED-DATA) and the trailing MSG.
// Not a full parser; good enough to assert field equality in tests.
func rfc5424Fields(s string) (pri, version, ts, host, app, procid, msgid, sd, msg string, err error) {
	re := regexp.MustCompile(`^(<\d+>)(\d+) (\S+) (\S+) (\S+) (\S+) (\S+) (\[[^\]]*\]|-)(?: (.*))?$`)
	m := re.FindStringSubmatch(s)
	if m == nil {
		return "", "", "", "", "", "", "", "", "", fmt.Errorf("rfc5424Fields: no match on %q", s)
	}
	return m[1], m[2], m[3], m[4], m[5], m[6], m[7], m[8], m[9], nil
}

func TestRFC5424RoundTrip(t *testing.T) {
	var buf bytes.Buffer
	enc := &RFC5424Encoder{}
	resolved := makeResolved("Interface GigabitEthernet0/3 (ifIndex=3) changed state to down")
	resolved.StructuredData = []SyslogSDPair{
		{Key: "ifIndex", Value: "3"},
		{Key: "ifName", Value: "GigabitEthernet0/3"},
	}
	if err := enc.Encode(&buf, resolved, fixedNow()); err != nil {
		t.Fatal(err)
	}
	got := buf.String()
	pri, ver, ts, host, app, procid, msgid, sd, msg, err := rfc5424Fields(got)
	if err != nil {
		t.Fatalf("parse: %v\nwire: %q", err, got)
	}
	checks := []struct{ name, got, want string }{
		{"PRI", pri, "<187>"},
		{"VERSION", ver, "1"},
		{"TIMESTAMP", ts, "2026-04-05T12:34:56.789Z"},
		{"HOSTNAME", host, "rtr-edge-01"},
		{"APP-NAME", app, "IFMGR"},
		{"PROCID", procid, "-"},
		{"MSGID", msgid, "LINKDOWN"},
		{"MSG", msg, resolved.Message},
	}
	for _, c := range checks {
		if c.got != c.want {
			t.Errorf("%s: got %q, want %q", c.name, c.got, c.want)
		}
	}
	if !strings.HasPrefix(sd, "[meta@32473 ") {
		t.Errorf("STRUCTURED-DATA: %q does not start with [meta@32473", sd)
	}
	if !strings.Contains(sd, `ifIndex="3"`) {
		t.Errorf("STRUCTURED-DATA: %q missing ifIndex", sd)
	}
	if !strings.Contains(sd, `ifName="GigabitEthernet0/3"`) {
		t.Errorf("STRUCTURED-DATA: %q missing ifName", sd)
	}
}

func TestRFC5424EmptyFieldsRenderNILVALUE(t *testing.T) {
	var buf bytes.Buffer
	enc := &RFC5424Encoder{}
	// Deliberately empty AppName, MsgID, Hostname, and SD.
	msg := SyslogResolved{Facility: 1, Severity: 6}
	if err := enc.Encode(&buf, msg, fixedNow()); err != nil {
		t.Fatal(err)
	}
	got := buf.String()
	pri, _, _, host, app, procid, msgid, sd, _, err := rfc5424Fields(got)
	if err != nil {
		t.Fatalf("parse: %v\nwire: %q", err, got)
	}
	if pri != "<14>" {
		t.Errorf("PRI: got %q, want <14>", pri)
	}
	for name, v := range map[string]string{"HOSTNAME": host, "APP-NAME": app, "PROCID": procid, "MSGID": msgid, "STRUCTURED-DATA": sd} {
		if v != "-" {
			t.Errorf("%s: got %q, want NILVALUE -", name, v)
		}
	}
}

func TestRFC5424HostnameSpacesReplaced(t *testing.T) {
	var buf bytes.Buffer
	enc := &RFC5424Encoder{}
	msg := makeResolved("body")
	msg.Hostname = "some host with spaces"
	if err := enc.Encode(&buf, msg, fixedNow()); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(buf.String(), "some-host-with-spaces") {
		t.Errorf("wire: %q missing hyphenated hostname", buf.String())
	}
}

func TestRFC5424SDValueEscaping(t *testing.T) {
	var buf bytes.Buffer
	enc := &RFC5424Encoder{}
	msg := makeResolved("body")
	msg.StructuredData = []SyslogSDPair{
		{Key: "note", Value: `has "quote" and \ backslash and ] bracket`},
	}
	if err := enc.Encode(&buf, msg, fixedNow()); err != nil {
		t.Fatal(err)
	}
	want := `note="has \"quote\" and \\ backslash and \] bracket"`
	if !strings.Contains(buf.String(), want) {
		t.Errorf("SD escaping: wire=%q, want substring %q", buf.String(), want)
	}
}

// -----------------------------------------------------------------------------
// RFC 3164
// -----------------------------------------------------------------------------

func TestRFC3164RoundTrip(t *testing.T) {
	var buf bytes.Buffer
	enc := &RFC3164Encoder{}
	msg := makeResolved("Interface GigabitEthernet0/3 changed state to down")
	if err := enc.Encode(&buf, msg, fixedNow()); err != nil {
		t.Fatal(err)
	}
	got := buf.String()
	// Expected exact form; double-space before the day-of-month since 5 is
	// single-digit.
	want := "<187>Apr  5 12:34:56 rtr-edge-01 IFMGR: Interface GigabitEthernet0/3 changed state to down"
	if got != want {
		t.Errorf("\n got: %q\nwant: %q", got, want)
	}
}

func TestRFC3164DoubleDigitDayUsesSingleSpace(t *testing.T) {
	var buf bytes.Buffer
	enc := &RFC3164Encoder{}
	msg := makeResolved("body")
	ts := time.Date(2026, time.April, 20, 12, 34, 56, 0, time.UTC)
	if err := enc.Encode(&buf, msg, ts); err != nil {
		t.Fatal(err)
	}
	want := "<187>Apr 20 12:34:56 rtr-edge-01 IFMGR: body"
	if got := buf.String(); got != want {
		t.Errorf("\n got: %q\nwant: %q", got, want)
	}
}

func TestRFC3164TagTruncation(t *testing.T) {
	var buf bytes.Buffer
	enc := &RFC3164Encoder{}
	msg := makeResolved("body")
	msg.AppName = strings.Repeat("X", 40) // 40 > 32
	if err := enc.Encode(&buf, msg, fixedNow()); err != nil {
		t.Fatal(err)
	}
	// Expect exactly 32 Xs followed by `:`.
	want := strings.Repeat("X", 32) + ":"
	if !strings.Contains(buf.String(), want) {
		t.Errorf("wire: %q missing %q", buf.String(), want)
	}
	// Ensure the 33rd X is not present.
	if strings.Contains(buf.String(), strings.Repeat("X", 33)) {
		t.Errorf("TAG not truncated — 33 Xs present in %q", buf.String())
	}
}

func TestRFC3164MissingHostnameIsError(t *testing.T) {
	var buf bytes.Buffer
	enc := &RFC3164Encoder{}
	msg := makeResolved("body")
	msg.Hostname = ""
	if err := enc.Encode(&buf, msg, fixedNow()); err == nil {
		t.Fatal("expected error for empty hostname in 3164")
	}
}

func TestRFC3164Ignores5424OnlyFields(t *testing.T) {
	// RFC 3164 has no slot for MSGID or STRUCTURED-DATA; the encoder must
	// silently drop them even if the catalog populated them.
	var buf bytes.Buffer
	enc := &RFC3164Encoder{}
	msg := makeResolved("body")
	msg.MsgID = "SHOULD-NOT-APPEAR"
	msg.StructuredData = []SyslogSDPair{{Key: "k", Value: "v"}}
	if err := enc.Encode(&buf, msg, fixedNow()); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(buf.String(), "SHOULD-NOT-APPEAR") {
		t.Errorf("3164 leaked MSGID: %q", buf.String())
	}
	if strings.Contains(buf.String(), `k="v"`) || strings.Contains(buf.String(), "[meta@") {
		t.Errorf("3164 leaked STRUCTURED-DATA: %q", buf.String())
	}
}

// -----------------------------------------------------------------------------
// Format factory and parser helpers
// -----------------------------------------------------------------------------

func TestParseSyslogFormat(t *testing.T) {
	if f, err := ParseSyslogFormat("5424"); err != nil || f != SyslogFormat5424 {
		t.Errorf("ParseSyslogFormat(5424): (%v, %v)", f, err)
	}
	if f, err := ParseSyslogFormat("3164"); err != nil || f != SyslogFormat3164 {
		t.Errorf("ParseSyslogFormat(3164): (%v, %v)", f, err)
	}
	if _, err := ParseSyslogFormat("notAFormat"); err == nil {
		t.Error("ParseSyslogFormat(notAFormat): expected error, got nil")
	}
}

// -----------------------------------------------------------------------------
// Byte-pinned regression tests
// -----------------------------------------------------------------------------

// TestByteIdentity5424 pins the MD5 of a canonical RFC 5424 encode. Any
// change to the encoder that affects wire bytes will flip the hash and
// force a review.
func TestByteIdentity5424(t *testing.T) {
	var buf bytes.Buffer
	enc := &RFC5424Encoder{}
	msg := SyslogResolved{
		Facility: 23,
		Severity: 3,
		AppName:  "IFMGR",
		MsgID:    "LINKDOWN",
		Hostname: "rtr-edge-01",
		StructuredData: []SyslogSDPair{
			{Key: "ifIndex", Value: "3"},
			{Key: "ifName", Value: "GigabitEthernet0/3"},
		},
		Message: "Interface GigabitEthernet0/3 (ifIndex=3) changed state to down",
	}
	if err := enc.Encode(&buf, msg, fixedNow()); err != nil {
		t.Fatal(err)
	}
	sum := md5.Sum(buf.Bytes())
	const want = "6aed253d55e20c3e1134d033574b7855"
	if got := hex.EncodeToString(sum[:]); got != want {
		t.Errorf("byte-identity MD5 changed — review wire format\n"+
			"  got:  %s\n"+
			"  want: %s\n"+
			"  wire: %q",
			got, want, buf.String())
	}
}

// TestEncoderMaxMessageSizeEnforced — oversize messages must fail at
// encode time rather than being sent as truncated/fragmented datagrams.
// Exercises both 5424 and 3164.
func TestEncoderMaxMessageSizeEnforced(t *testing.T) {
	oversize := strings.Repeat("A", maxSyslogMessageBytes+50)

	t.Run("5424", func(t *testing.T) {
		var buf bytes.Buffer
		enc := &RFC5424Encoder{}
		msg := makeResolved(oversize)
		if err := enc.Encode(&buf, msg, fixedNow()); err == nil {
			t.Fatal("expected size-exceeded error, got nil")
		}
	})
	t.Run("3164", func(t *testing.T) {
		var buf bytes.Buffer
		enc := &RFC3164Encoder{}
		msg := makeResolved(oversize)
		if err := enc.Encode(&buf, msg, fixedNow()); err == nil {
			t.Fatal("expected size-exceeded error, got nil")
		}
	})
}

// TestEncoderMSGInjectionSanitised — CR / LF / NUL in MSG or SD values
// MUST NOT pass through verbatim; otherwise an attacker or catalog author
// could inject a fake `<PRI>` line into the collector's stream.
func TestEncoderMSGInjectionSanitised(t *testing.T) {
	t.Run("5424 MSG strips newline", func(t *testing.T) {
		var buf bytes.Buffer
		enc := &RFC5424Encoder{}
		msg := makeResolved("real msg\n<0>fake injection")
		if err := enc.Encode(&buf, msg, fixedNow()); err != nil {
			t.Fatal(err)
		}
		wire := buf.String()
		if strings.Contains(wire, "\n") {
			t.Errorf("literal newline leaked to wire: %q", wire)
		}
		// The fake PRI characters are still in the message but no longer on
		// a new line — downstream parsers see one contiguous message.
		if !strings.Contains(wire, "real msg <0>fake injection") {
			t.Errorf("expected newline -> space replacement, got: %q", wire)
		}
	})
	t.Run("5424 SD value strips CRLF/NUL", func(t *testing.T) {
		var buf bytes.Buffer
		enc := &RFC5424Encoder{}
		msg := makeResolved("body")
		msg.StructuredData = []SyslogSDPair{{Key: "k", Value: "v1\r\nv2\x00v3"}}
		if err := enc.Encode(&buf, msg, fixedNow()); err != nil {
			t.Fatal(err)
		}
		wire := buf.String()
		if strings.ContainsAny(wire, "\r\n\x00") {
			t.Errorf("control bytes leaked to SD wire: %q", wire)
		}
	})
	t.Run("3164 MSG strips newline", func(t *testing.T) {
		var buf bytes.Buffer
		enc := &RFC3164Encoder{}
		msg := makeResolved("real\n<0>fake")
		if err := enc.Encode(&buf, msg, fixedNow()); err != nil {
			t.Fatal(err)
		}
		if strings.Contains(buf.String(), "\n") {
			t.Errorf("literal newline leaked to wire: %q", buf.String())
		}
	})
}

// TestEncoderHeaderFramingCharsSanitised — `<`, `>`, `[`, `]`, `"` in
// HOSTNAME / APP-NAME / MSGID must not pass through verbatim; those
// characters carry framing meaning in RFC 5424 and can desync parsers.
func TestEncoderHeaderFramingCharsSanitised(t *testing.T) {
	var buf bytes.Buffer
	enc := &RFC5424Encoder{}
	msg := makeResolved("body")
	msg.AppName = "IF<MGR>"
	msg.MsgID = "LINK[DOWN]"
	msg.Hostname = "host[fake]"
	if err := enc.Encode(&buf, msg, fixedNow()); err != nil {
		t.Fatal(err)
	}
	wire := buf.String()
	for _, bad := range []string{"<MGR>", "[DOWN]", "[fake]"} {
		if strings.Contains(wire, bad) {
			t.Errorf("framing char leaked to wire: %q contains %q", wire, bad)
		}
	}
	// Each disallowed char should have been replaced with `_`.
	for _, good := range []string{"IF_MGR_", "LINK_DOWN_", "host_fake_"} {
		if !strings.Contains(wire, good) {
			t.Errorf("wire %q missing expected sanitised token %q", wire, good)
		}
	}
}

// TestByteIdentity3164 pins the MD5 of a canonical RFC 3164 encode.
func TestByteIdentity3164(t *testing.T) {
	var buf bytes.Buffer
	enc := &RFC3164Encoder{}
	msg := SyslogResolved{
		Facility: 23,
		Severity: 3,
		AppName:  "IFMGR",
		Hostname: "rtr-edge-01",
		Message:  "Interface GigabitEthernet0/3 changed state to down",
	}
	if err := enc.Encode(&buf, msg, fixedNow()); err != nil {
		t.Fatal(err)
	}
	sum := md5.Sum(buf.Bytes())
	const want = "390c2315542cdcbf1e95d5068b04631e"
	if got := hex.EncodeToString(sum[:]); got != want {
		t.Errorf("byte-identity MD5 changed — review wire format\n"+
			"  got:  %s\n"+
			"  want: %s\n"+
			"  wire: %q",
			got, want, buf.String())
	}
}
