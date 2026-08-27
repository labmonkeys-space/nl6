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
	"testing"
)

func TestValidateIPRange(t *testing.T) {
	tests := []struct {
		name      string
		ip        string
		netmask   string
		wantError bool
		errorMsg  string
	}{
		// Valid private IPs
		{
			name:      "Valid 10.x.x.x address",
			ip:        "10.42.0.1",
			netmask:   "16",
			wantError: false,
		},
		{
			name:      "Valid 172.16.x.x address",
			ip:        "172.16.0.1",
			netmask:   "16",
			wantError: false,
		},
		{
			name:      "Valid 192.168.x.x address",
			ip:        "192.168.1.1",
			netmask:   "24",
			wantError: false,
		},
		// Invalid public IPs
		{
			name:      "Public IP 8.8.8.8",
			ip:        "8.8.8.8",
			netmask:   "24",
			wantError: true,
			errorMsg:  "outside allowed simulator ranges",
		},
		{
			name:      "Public IP 1.1.1.1",
			ip:        "1.1.1.1",
			netmask:   "24",
			wantError: true,
			errorMsg:  "outside allowed simulator ranges",
		},
		// Localhost
		{
			name:      "Localhost 127.0.0.1",
			ip:        "127.0.0.1",
			netmask:   "24",
			wantError: true,
			errorMsg:  "localhost range",
		},
		// Link-local
		{
			name:      "Link-local 169.254.1.1",
			ip:        "169.254.1.1",
			netmask:   "16",
			wantError: true,
			errorMsg:  "link-local range",
		},
		// Multicast
		{
			name:      "Multicast 224.0.0.1",
			ip:        "224.0.0.1",
			netmask:   "24",
			wantError: true,
			errorMsg:  "multicast range",
		},
		{
			name:      "Multicast 239.255.255.255",
			ip:        "239.255.255.255",
			netmask:   "24",
			wantError: true,
			errorMsg:  "multicast range",
		},
		// Network/broadcast addresses for /24
		{
			name:      "Network address x.x.x.0 with /24",
			ip:        "10.42.0.0",
			netmask:   "24",
			wantError: true,
			errorMsg:  "network address",
		},
		{
			name:      "Broadcast address x.x.x.255 with /24",
			ip:        "10.42.0.255",
			netmask:   "24",
			wantError: true,
			errorMsg:  "broadcast address",
		},
		// Network/broadcast OK for /16 and /8
		{
			name:      "x.x.x.0 with /16 is OK",
			ip:        "10.42.0.0",
			netmask:   "16",
			wantError: false,
		},
		{
			name:      "x.x.x.255 with /16 is OK",
			ip:        "10.42.0.255",
			netmask:   "16",
			wantError: false,
		},
		// Invalid IP format
		{
			name:      "Invalid IP format",
			ip:        "not-an-ip",
			netmask:   "24",
			wantError: true,
			errorMsg:  "invalid IP address",
		},
		{
			name:      "Empty IP",
			ip:        "",
			netmask:   "24",
			wantError: true,
			errorMsg:  "invalid IP address",
		},
		// Edge cases in private ranges
		{
			name:      "Start of 10.0.0.0/8",
			ip:        "10.0.0.1",
			netmask:   "8",
			wantError: false,
		},
		{
			name:      "End of 10.0.0.0/8",
			ip:        "10.255.255.254",
			netmask:   "8",
			wantError: false,
		},
		{
			name:      "Start of 172.16.0.0/12",
			ip:        "172.16.0.1",
			netmask:   "16",
			wantError: false,
		},
		{
			name:      "End of 172.16.0.0/12",
			ip:        "172.31.255.254",
			netmask:   "16",
			wantError: false,
		},
		{
			name:      "Just outside 172.16.0.0/12 (172.15.x.x)",
			ip:        "172.15.0.1",
			netmask:   "16",
			wantError: true,
			errorMsg:  "outside allowed simulator ranges",
		},
		{
			name:      "Just outside 172.16.0.0/12 (172.32.x.x)",
			ip:        "172.32.0.1",
			netmask:   "16",
			wantError: true,
			errorMsg:  "outside allowed simulator ranges",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validateIPRange(tt.ip, tt.netmask)
			if tt.wantError {
				if err == nil {
					t.Errorf("validateIPRange(%q, %q) expected error containing %q, got nil", tt.ip, tt.netmask, tt.errorMsg)
					return
				}
				if tt.errorMsg != "" && !contains(err.Error(), tt.errorMsg) {
					t.Errorf("validateIPRange(%q, %q) error = %q, want error containing %q", tt.ip, tt.netmask, err.Error(), tt.errorMsg)
				}
			} else {
				if err != nil {
					t.Errorf("validateIPRange(%q, %q) unexpected error: %v", tt.ip, tt.netmask, err)
				}
			}
		})
	}
}

func contains(s, substr string) bool {
	return len(s) >= len(substr) && (s == substr || len(substr) == 0 || 
		(len(s) > 0 && len(substr) > 0 && findSubstring(s, substr)))
}

func findSubstring(s, substr string) bool {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}
