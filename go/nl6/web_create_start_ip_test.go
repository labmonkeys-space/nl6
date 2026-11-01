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
// three refusals and its one acceptance are pinned here by kind, not by
// message text (nl6#942).
func TestParseStartIP(t *testing.T) {
	ip, err := parseStartIP("10.42.0.3")
	if err != nil {
		t.Fatalf("parseStartIP(10.42.0.3): %v", err)
	}
	if len(ip) != net.IPv4len || !ip.Equal(net.IPv4(10, 42, 0, 3)) {
		t.Errorf("parseStartIP(10.42.0.3) = %v (len %d), want the 4-byte form", ip, len(ip))
	}

	for _, tc := range []struct {
		in   string
		kind error
	}{
		{"", errStartIPRequired},
		{"not-an-ip", errStartIPInvalid},
		{"10.42.0.256", errStartIPInvalid},
		{"10.42.0.3 cisco_ios.json", errStartIPInvalid},
		{"2001:db8::1", errStartIPNotIPv4},
		{"::ffff:10.42.0.3", errStartIPInvalid}, // IPv4-mapped parses and To4() succeeds; see below
	} {
		t.Run(tc.in, func(t *testing.T) {
			if tc.in == "::ffff:10.42.0.3" {
				// An IPv4-mapped IPv6 address IS an IPv4 address to net.IP.To4,
				// so it is accepted and normalised. Pinned so the behaviour is
				// a decision and not a surprise.
				ip, err := parseStartIP(tc.in)
				if err != nil || !ip.Equal(net.IPv4(10, 42, 0, 3)) {
					t.Fatalf("parseStartIP(%q) = %v, %v; want 10.42.0.3, nil", tc.in, ip, err)
				}
				return
			}
			_, err := parseStartIP(tc.in)
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

// The HTTP rendering quotes the value so whitespace is visible, escapes control
// and bidi runes, and is length-capped like the resource_file 400 class.
func TestStartIPError_PublicMessage(t *testing.T) {
	for _, tc := range []struct {
		in   string
		want string
	}{
		{"", "start_ip is required"},
		{"not-an-ip", `invalid start IP address: "not-an-ip"`},
		{"10.42.0.3\t", `invalid start IP address: "10.42.0.3\t"`},
		{"10.42.0.3 ", `invalid start IP address: "10.42.0.3 "`},
		{"2001:db8::1", `start IP address must be IPv4: "2001:db8::1"`},
		// %q escapes the newline and U+202E RIGHT-TO-LEFT OVERRIDE to ASCII.
		{"a\nFATAL: fine\u202e", "invalid start IP address: \"a\\nFATAL: fine\\u202e\""},
	} {
		_, err := parseStartIP(tc.in)
		var sierr *startIPError
		if !errors.As(err, &sierr) {
			t.Fatalf("parseStartIP(%q) = %T, want *startIPError", tc.in, err)
		}
		if got := sierr.PublicMessage(); got != tc.want {
			t.Errorf("PublicMessage(%q) = %q, want %q", tc.in, got, tc.want)
		}
		if strings.ContainsAny(sierr.Error(), "\n\r\t\u202e") {
			t.Errorf("Error(%q) = %q carries a raw control or bidi rune", tc.in, sierr.Error())
		}
	}

	_, err := parseStartIP(strings.Repeat("x", 3*maxResourceMessageBytes))
	var sierr *startIPError
	if !errors.As(err, &sierr) {
		t.Fatalf("long value: %T, want *startIPError", err)
	}
	if got := sierr.PublicMessage(); len(got) > maxResourceMessageBytes+len("… (truncated)") || !strings.HasSuffix(got, "(truncated)") {
		t.Errorf("PublicMessage of a %d-byte value is %d bytes and ends %q; want capped and marked", 3*maxResourceMessageBytes, len(got), got[len(got)-12:])
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
		})
	}
}

// Positive control: a valid start_ip passes the check and the batch runs on to
// the privilege check, so the check refuses the bad addresses and not every
// address. Asserted on the ANSWER, not on deviceCreateTotal, which the batch
// stores before it validates anything (nl6#944).
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
