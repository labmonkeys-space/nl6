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
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// TestValidatePrivateIPv4_AcceptsRFC1918Ranges verifies that all RFC 1918
// private address ranges are accepted by the validation function.
func TestValidatePrivateIPv4_AcceptsRFC1918Ranges(t *testing.T) {
	validIPs := []string{
		// 10.0.0.0/8
		"10.0.0.1",
		"10.42.0.1",
		"10.255.255.254",
		// 172.16.0.0/12
		"172.16.0.1",
		"172.20.0.1",
		"172.31.255.254",
		// 192.168.0.0/16
		"192.168.0.1",
		"192.168.100.1",
		"192.168.255.254",
	}

	for _, ip := range validIPs {
		t.Run(ip, func(t *testing.T) {
			if err := validatePrivateIPv4(ip); err != nil {
				t.Errorf("validatePrivateIPv4(%q) returned error: %v, want nil", ip, err)
			}
		})
	}
}

// TestValidatePrivateIPv4_RejectsPublicAndReservedRanges verifies that
// public IP addresses, reserved ranges, and other non-RFC1918 addresses
// are rejected.
func TestValidatePrivateIPv4_RejectsPublicAndReservedRanges(t *testing.T) {
	invalidIPs := []struct {
		ip     string
		reason string
	}{
		// Public addresses
		{"8.8.8.8", "public DNS"},
		{"1.1.1.1", "public DNS"},
		{"93.184.216.34", "public address"},
		{"203.0.113.1", "TEST-NET-3"},
		// Reserved/special ranges
		{"127.0.0.1", "loopback"},
		{"0.0.0.0", "unspecified"},
		{"255.255.255.255", "broadcast"},
		{"169.254.1.1", "link-local"},
		{"224.0.0.1", "multicast"},
		// Near-miss RFC 1918 ranges
		{"9.255.255.255", "just before 10.0.0.0/8"},
		{"11.0.0.1", "just after 10.0.0.0/8"},
		{"172.15.255.255", "just before 172.16.0.0/12"},
		{"172.32.0.1", "just after 172.16.0.0/12"},
		{"192.167.255.255", "just before 192.168.0.0/16"},
		{"192.169.0.1", "just after 192.168.0.0/16"},
	}

	for _, tc := range invalidIPs {
		t.Run(tc.ip+"_"+tc.reason, func(t *testing.T) {
			err := validatePrivateIPv4(tc.ip)
			if err == nil {
				t.Errorf("validatePrivateIPv4(%q) returned nil, want error for %s", tc.ip, tc.reason)
			}
			if !strings.Contains(err.Error(), "RFC 1918") {
				t.Errorf("error message %q should mention RFC 1918", err.Error())
			}
		})
	}
}

// TestValidatePrivateIPv4_RejectsInvalidFormats verifies that malformed
// IP addresses and IPv6 addresses are rejected.
func TestValidatePrivateIPv4_RejectsInvalidFormats(t *testing.T) {
	invalidFormats := []struct {
		input  string
		reason string
	}{
		{"", "empty string"},
		{"not-an-ip", "non-IP string"},
		{"10.0.0", "incomplete IPv4"},
		{"10.0.0.1.1", "too many octets"},
		{"10.0.0.256", "octet out of range"},
		{"::1", "IPv6 loopback"},
		{"2001:db8::1", "IPv6 address"},
		{"::ffff:10.0.0.1", "IPv4-mapped IPv6"},
	}

	for _, tc := range invalidFormats {
		t.Run(tc.reason, func(t *testing.T) {
			err := validatePrivateIPv4(tc.input)
			if err == nil {
				t.Errorf("validatePrivateIPv4(%q) returned nil, want error for %s", tc.input, tc.reason)
			}
		})
	}
}

// TestCreateDevicesHandler_RejectsPublicIPAddress verifies that the
// POST /api/v1/devices endpoint rejects requests with public IP addresses
// before any privileged operations occur.
func TestCreateDevicesHandler_RejectsPublicIPAddress(t *testing.T) {
	publicIPs := []string{
		"8.8.8.8",
		"1.1.1.1",
		"93.184.216.34",
	}

	for _, ip := range publicIPs {
		t.Run(ip, func(t *testing.T) {
			body, _ := json.Marshal(CreateDevicesRequest{
				StartIP:     ip,
				DeviceCount: 1,
				Netmask:     "24",
			})
			r := httptest.NewRequest(http.MethodPost, "/api/v1/devices", bytes.NewReader(body))
			w := httptest.NewRecorder()

			createDevicesHandler(w, r)

			if w.Code != http.StatusBadRequest {
				t.Errorf("status = %d, want 400 for public IP %s", w.Code, ip)
			}
			if !strings.Contains(w.Body.String(), "RFC 1918") {
				t.Errorf("response body should mention RFC 1918, got: %s", w.Body.String())
			}
		})
	}
}

// TestCreateDevicesHandler_AcceptsPrivateIPAddress verifies that the
// POST /api/v1/devices endpoint accepts requests with RFC 1918 private
// IP addresses. This test does not create actual devices (no manager),
// but verifies the IP validation passes.
func TestCreateDevicesHandler_AcceptsPrivateIPAddress(t *testing.T) {
	privateIPs := []string{
		"10.0.0.1",
		"172.16.0.1",
		"192.168.1.1",
	}

	for _, ip := range privateIPs {
		t.Run(ip, func(t *testing.T) {
			body, _ := json.Marshal(CreateDevicesRequest{
				StartIP:     ip,
				DeviceCount: 1,
				Netmask:     "24",
			})
			r := httptest.NewRequest(http.MethodPost, "/api/v1/devices", bytes.NewReader(body))
			w := httptest.NewRecorder()

			createDevicesHandler(w, r)

			// The handler will fail later (no manager, no root), but it should
			// NOT fail with a 400 about RFC 1918 ranges.
			if w.Code == http.StatusBadRequest && strings.Contains(w.Body.String(), "RFC 1918") {
				t.Errorf("private IP %s was rejected as non-RFC1918: %s", ip, w.Body.String())
			}
		})
	}
}
