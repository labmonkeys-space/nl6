/*
 * Copyright 2026 Ronny Trommer <ronny@no42.org>
 * SPDX-License-Identifier: Apache-2.0
 */

package main

import (
	"encoding/json"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// parseStartIP is THE start_ip predicate for both creation paths, so its
// three refusals and its acceptance are pinned here by kind, not by message
// text (nl6#942). Every row goes through the same assertions: a row with a
// kind must be refused with that kind, a row with a wantIP must be accepted
// as that 4-byte address.
func TestParseStartIP(t *testing.T) {
	for _, tc := range []struct {
		in     string
		kind   error
		wantIP net.IP
	}{
		{in: "10.42.0.3", wantIP: net.IPv4(10, 42, 0, 3)},
		{in: "192.168.100.1", wantIP: net.IPv4(192, 168, 100, 1)},
		{in: "", kind: errStartIPRequired},
		{in: "not-an-ip", kind: errStartIPInvalid},
		{in: "10.42.0.256", kind: errStartIPInvalid},
		{in: "10.42.0.", kind: errStartIPInvalid},
		{in: "10.42.0.3 cisco_ios.json", kind: errStartIPInvalid},
		{in: "2001:db8::1", kind: errStartIPNotIPv4},
		// An IPv4-mapped IPv6 literal is an IPv6 literal: net.IP.To4 would
		// accept it, netip.Addr.Is4 does not, and the docs promise that every
		// IPv6 address is refused.
		{in: "::ffff:10.42.0.3", kind: errStartIPNotIPv4},
		{in: "fe80::1%eth0", kind: errStartIPNotIPv4},
	} {
		t.Run(tc.in, func(t *testing.T) {
			ip, err := parseStartIP(tc.in)
			if tc.kind == nil {
				if err != nil {
					t.Fatalf("parseStartIP(%q): %v", tc.in, err)
				}
				if len(ip) != net.IPv4len || !ip.Equal(tc.wantIP) {
					t.Fatalf("parseStartIP(%q) = %v (len %d), want %v in the 4-byte form", tc.in, ip, len(ip), tc.wantIP)
				}
				return
			}
			if ip != nil {
				t.Errorf("parseStartIP(%q) returned %v alongside an error", tc.in, ip)
			}
			if !errors.Is(err, tc.kind) {
				t.Fatalf("parseStartIP(%q) = %v, want kind %v", tc.in, err, tc.kind)
			}
			var sierr *startIPError
			if !errors.As(err, &sierr) {
				t.Fatalf("parseStartIP(%q) = %T, want *startIPError", tc.in, err)
			}
		})
	}
}

// The one rendering quotes the value so whitespace is visible, escapes control
// and bidi runes, and is length-capped like the resource_file 400 class. The
// cap applies to the LOG rendering too: Error() and PublicMessage() are equal.
func TestStartIPError_PublicMessage(t *testing.T) {
	const rlo = "\u202e" // U+202E RIGHT-TO-LEFT OVERRIDE
	for _, tc := range []struct {
		in   string
		want string
	}{
		{"", "start_ip is required"},
		{"not-an-ip", `invalid start IP address: "not-an-ip"`},
		{"10.42.0.3\t", `invalid start IP address: "10.42.0.3\t"`},
		{"10.42.0.3 ", `invalid start IP address: "10.42.0.3 "`},
		{"2001:db8::1", `start IP address must be IPv4: "2001:db8::1"`},
		// Quote escapes the newline and the override to ASCII.
		{"a\nFATAL: fine" + rlo, `invalid start IP address: "a\nFATAL: fine\u202e"`},
	} {
		_, err := parseStartIP(tc.in)
		var sierr *startIPError
		if !errors.As(err, &sierr) {
			t.Fatalf("parseStartIP(%q) = %T, want *startIPError", tc.in, err)
		}
		if got := sierr.PublicMessage(); got != tc.want {
			t.Errorf("PublicMessage(%q) = %q, want %q", tc.in, got, tc.want)
		}
		if sierr.Error() != sierr.PublicMessage() {
			t.Errorf("Error(%q) = %q differs from PublicMessage %q; the type has one rendering", tc.in, sierr.Error(), sierr.PublicMessage())
		}
		if strings.ContainsAny(sierr.Error(), "\n\r\t"+rlo) {
			t.Errorf("Error(%q) = %q carries a raw control or bidi rune", tc.in, sierr.Error())
		}
	}

	// A 60 KiB value of U+202E expands about sixfold under Quote. Both
	// renderings are capped, so the log line is bounded too.
	_, err := parseStartIP(strings.Repeat(rlo, 20*1024))
	var sierr *startIPError
	if !errors.As(err, &sierr) {
		t.Fatalf("long value: %T, want *startIPError", err)
	}
	for name, got := range map[string]string{"Error": sierr.Error(), "PublicMessage": sierr.PublicMessage()} {
		if len(got) > maxResourceMessageBytes+len("… (truncated)") || !strings.HasSuffix(got, "(truncated)") {
			t.Errorf("%s of a 60 KiB value is %d bytes and ends %q; want capped and marked", name, len(got), got[len(got)-12:])
		}
	}
}

// postCreateDevices drives the router against sm with the euid faked to a
// non-root user, so a request that gets past every caller-data check stops at
// the privilege check instead of creating TUN interfaces on a root CI
// container. The manager comes from newCreateGateRESTManager, so the
// resource_file resolves to a fixture in a temp dir and not to resources/.
func postCreateDevices(t *testing.T, sm *SimulatorManager, body string) *httptest.ResponseRecorder {
	t.Helper()
	silenceCreateGateLogs(t)
	withFakeEuid(t, 1000)
	withManager(t, sm)

	r := httptest.NewRequest(http.MethodPost, "/api/v1/devices", strings.NewReader(body))
	r.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	setupRoutes().ServeHTTP(w, r)
	return w
}

func createBody(t *testing.T, startIP string) string {
	t.Helper()
	body, err := json.Marshal(CreateDevicesRequest{StartIP: startIP, DeviceCount: 1, ResourceFile: "gategood.json"})
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	return string(body)
}

func decodeAPIResponse(t *testing.T, w *httptest.ResponseRecorder) APIResponse {
	t.Helper()
	var resp APIResponse
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode response %q: %v", w.Body.String(), err)
	}
	return resp
}

// A bad start_ip is caller data and gets 400 through the handler (nl6#940),
// from the ONE check inside the batch via the typed error that
// createDevicesErrorResponse maps (nl6#942). An IPv6 address is a bad start_ip:
// before this it was accepted and the batch walked a single address.
func TestCreateDevicesHandler_RejectsBadStartIPWith400(t *testing.T) {
	for _, tc := range []struct {
		startIP string
		want    string
	}{
		{"not-an-ip", `invalid start IP address: "not-an-ip"`},
		{"10.42.0.256", `invalid start IP address: "10.42.0.256"`},
		{"10.42.0.3 cisco_ios.json", `invalid start IP address: "10.42.0.3 cisco_ios.json"`},
		{"10.42.0.3\t", `invalid start IP address: "10.42.0.3\t"`},
		{"2001:db8::1", `start IP address must be IPv4: "2001:db8::1"`},
		{"::ffff:10.42.0.3", `start IP address must be IPv4: "::ffff:10.42.0.3"`},
		{"", "start_ip is required"},
	} {
		t.Run(tc.startIP, func(t *testing.T) {
			sm := newCreateGateRESTManager(t)
			w := postCreateDevices(t, sm, createBody(t, tc.startIP))

			if w.Code != http.StatusBadRequest {
				t.Fatalf("status = %d, want 400 (body %s)", w.Code, w.Body.String())
			}
			resp := decodeAPIResponse(t, w)
			if resp.Success || resp.Message != tc.want {
				t.Errorf("response = {success:%v message:%q}, want {success:false message:%q}", resp.Success, resp.Message, tc.want)
			}
			if n := len(sm.ListDevices()); n != 0 {
				t.Errorf("%d devices exist after a refused start_ip, want 0", n)
			}
			// The refusal is judged before the batch publishes itself, so a
			// malformed request never shows as a batch of `count` devices on
			// GET /api/v1/status or refuses a concurrent freeze.
			if got := sm.deviceCreateTotal.Load(); got != 0 {
				t.Errorf("deviceCreateTotal = %v after a refused start_ip, want 0: the batch published itself before validating", got)
			}
		})
	}
}

// Positive control: a valid start_ip passes the check and the batch runs on to
// the privilege check, so the check refuses the bad addresses and not every
// address. Asserted on the ANSWER, not on deviceCreateTotal, which the batch
// stores before it validates anything else (nl6#944).
func TestCreateDevicesHandler_ValidStartIPReachesTheBatch(t *testing.T) {
	sm := newCreateGateRESTManager(t)
	w := postCreateDevices(t, sm, createBody(t, "10.42.0.3"))

	if w.Code == http.StatusBadRequest {
		t.Fatalf("status = 400, body %s: a valid start_ip was refused", w.Body.String())
	}
	if resp := decodeAPIResponse(t, w); !strings.Contains(resp.Message, "root privileges") {
		t.Errorf("message = %q, want the privilege requirement: the batch did not run to it (status %d)", resp.Message, w.Code)
	}
}

// The gate is judged before start_ip (nl6#943): with a batch in flight a bad
// start_ip is a 409 with Retry-After, as every other request is, because a
// concurrency verdict must not depend on caller data.
func TestCreateDevicesHandler_GateIsJudgedBeforeStartIP(t *testing.T) {
	sm := newCreateGateRESTManager(t)
	hold, err := sm.tryEnterCreateBatch(2000)
	if err != nil {
		t.Fatalf("tryEnterCreateBatch: %v", err)
	}
	defer hold()

	w := postCreateDevices(t, sm, createBody(t, "not-an-ip"))
	if w.Code != http.StatusConflict {
		t.Fatalf("status = %d, want 409 (body %s)", w.Code, w.Body.String())
	}
	if got := w.Header().Get("Retry-After"); got != createConflictRetryAfterSeconds {
		t.Errorf("Retry-After = %q, want %q", got, createConflictRetryAfterSeconds)
	}
}
