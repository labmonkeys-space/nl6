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

//go:build !linux

// Non-Linux stubs for TUN interface management.
// The real implementations require Linux kernel TUN/TAP and ioctl.
package main

import (
	"net"
	"strconv"
	"strings"
)

func createTunInterface(name string, ip net.IP, netmask string) (*TunInterface, error) {
	return nil, errNotLinux
}

func createTunInterfaceInNamespaceViaExec(nsName, tunName string, ip net.IP, netmask string) (*TunInterface, error) {
	return nil, errNotLinux
}

func (tun *TunInterface) destroy() error { return nil }

// compareOIDsLexicographically compares two OID strings numerically component
// by component. Returns -1, 0, or 1. Identical to the Linux implementation in
// tun.go — kept in sync to ensure consistent SNMP GETNEXT ordering on all
// platforms.
func compareOIDsLexicographically(oid1, oid2 string) int {
	var parts1, parts2 []string
	if s := strings.TrimPrefix(oid1, "."); s != "" {
		parts1 = strings.Split(s, ".")
	}
	if s := strings.TrimPrefix(oid2, "."); s != "" {
		parts2 = strings.Split(s, ".")
	}

	maxLen := len(parts1)
	if len(parts2) > maxLen {
		maxLen = len(parts2)
	}

	for i := 0; i < maxLen; i++ {
		var val1, val2 int
		if i < len(parts1) {
			val1, _ = strconv.Atoi(parts1[i])
		}
		if i < len(parts2) {
			val2, _ = strconv.Atoi(parts2[i])
		}
		if val1 < val2 {
			return -1
		} else if val1 > val2 {
			return 1
		}
	}

	if len(parts1) < len(parts2) {
		return -1
	} else if len(parts1) > len(parts2) {
		return 1
	}
	return 0
}
