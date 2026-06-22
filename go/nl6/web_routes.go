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
	"fmt"
	"net"
	"strings"
	"time"
)

func generateRouteScript(devices []DeviceInfo) string {
	if len(devices) == 0 {
		return `#!/bin/bash
# No devices found in simulator
echo "No devices found in simulator"
exit 1
`
	}

	// Collect unique /16 management-plane networks from the device IPs. The
	// fleet is a flat /16 (see ipalloc.go), and the runtime installs a single
	// /16 host route per plane; a /16 route reaches every device in that /16,
	// including an explicit-/24 batch's devices. Grouping here keeps the
	// generated script consistent with the live routes instead of emitting up
	// to 256 per-/24 stanzas.
	subnets := make(map[string]bool)
	for _, device := range devices {
		if cidr := networkCIDR(net.ParseIP(device.IP), defaultPrefixLen); cidr != "" {
			subnets[cidr] = true
		}
	}

	var script strings.Builder

	// Write script header
	script.WriteString(generateScriptHeader(subnets))

	// Write temporary routes function
	script.WriteString(generateTemporaryRoutesSection(subnets))

	// Write permanent routes dispatcher
	script.WriteString(generatePermanentRoutesDispatcher(subnets))

	// Write OS-specific route sections
	script.WriteString(generateDebianRouteSection(subnets))
	script.WriteString(generateRHELRouteSection(subnets))
	script.WriteString(generateSUSERouteSection(subnets))

	// Write utility sections
	script.WriteString(generateShowRoutesSection(subnets))
	script.WriteString(generateRemovalInstructionsSection(subnets))
	script.WriteString(generateVerifyConfigSection())

	// Write main execution
	script.WriteString(generateMainExecutionSection())

	return script.String()
}

// generateScriptHeader generates the header portion of the route script
func generateScriptHeader(subnets map[string]bool) string {
	var header strings.Builder

	header.WriteString(`#!/bin/bash
#
# Enhanced Static Route Configuration Script for nl6
# Generated on: ` + time.Now().Format("2006-01-02 15:04:05") + `
#
# This script creates PERMANENT routes by default (persist after reboot)
# Usage: ./add_simulator_routes.sh <SIMULATOR_HOST_IP> [--temporary]
#
# Examples:
#   ./add_simulator_routes.sh 192.168.1.100              # Permanent routes (DEFAULT)
#   ./add_simulator_routes.sh 192.168.1.100 --temporary  # Temporary routes (until reboot)
#

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
BLUE='\033[0;34m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Function to show usage
show_usage() {
    echo "Usage: $0 <SIMULATOR_HOST_IP> [--temporary]"
    echo ""
    echo "Options:"
    echo "  --temporary    Add routes only until next reboot (optional)"
    echo "                 DEFAULT: Routes are made permanent"
    echo ""
    echo "Examples:"
    echo "  $0 192.168.1.100              # Add PERMANENT routes (default)"
    echo "  $0 192.168.1.100 --temporary  # Add temporary routes"
    echo ""
    echo "This script will configure routes for the following subnets:"
`)

	// Add subnet list to help text
	for subnet := range subnets {
		header.WriteString(fmt.Sprintf(`    echo "  - %s"`, subnet))
		header.WriteString("\n")
	}

	header.WriteString(`    echo ""
    echo "Supported operating systems for persistent routes:"
    echo "  - Ubuntu/Debian (via /etc/systemd/networkd/ or netplan)"
    echo "  - RHEL/CentOS/Fedora (via NetworkManager or network-scripts)"
    echo "  - openSUSE (via wicked)"
    echo ""
}

# Parse arguments
if [ $# -lt 1 ] || [ $# -gt 2 ]; then
    show_usage
    exit 1
fi

SIMULATOR_HOST=$1
PERMANENT=true  # DEFAULT: Always create permanent routes

if [ "$2" = "--temporary" ]; then
    PERMANENT=false
    echo -e "${YELLOW}⚠️  Using temporary mode - routes will be lost after reboot${NC}"
fi

# Detect operating system
detect_os() {
    if [ -f /etc/os-release ]; then
        . /etc/os-release
        OS=$NAME
        VERSION=$VERSION_ID
    else
        OS=$(uname -s)
        VERSION=$(uname -r)
    fi

    # Normalize OS detection
    case "$OS" in
        *Ubuntu*|*Debian*)
            OS_TYPE="debian"
            ;;
        *"Red Hat"*|*CentOS*|*Fedora*|*Rocky*|*AlmaLinux*)
            OS_TYPE="rhel"
            ;;
        *openSUSE*|*SUSE*)
            OS_TYPE="suse"
            ;;
        *)
            OS_TYPE="unknown"
            ;;
    esac
}

`)

	return header.String()
}

// generateTemporaryRoutesSection generates the temporary routes function
func generateTemporaryRoutesSection(subnets map[string]bool) string {
	var section strings.Builder

	section.WriteString(`# Function to add temporary routes
add_temporary_routes() {
    echo -e "${BLUE}📡 Adding temporary static routes to simulator subnets via $SIMULATOR_HOST${NC}"
    echo ""
`)

	// Add temporary route commands for each subnet
	for subnet := range subnets {
		section.WriteString(fmt.Sprintf(`    echo -e "${YELLOW}Adding temporary route: %s via $SIMULATOR_HOST${NC}"
    if sudo ip route add %s via $SIMULATOR_HOST 2>/dev/null; then
        echo -e "${GREEN}✅ Successfully added route for %s${NC}"
    else
        echo -e "${YELLOW}⚠️  Route %s already exists or failed to add${NC}"
    fi
    echo ""
`, subnet, subnet, subnet, subnet))
	}

	section.WriteString(`}

`)

	return section.String()
}

// generatePermanentRoutesDispatcher generates the permanent routes dispatcher function
func generatePermanentRoutesDispatcher(subnets map[string]bool) string {
	var section strings.Builder

	section.WriteString(`# Function to add permanent routes
add_permanent_routes() {
    echo -e "${BLUE}💾 Adding permanent static routes to simulator subnets via $SIMULATOR_HOST${NC}"
    echo -e "${YELLOW}⚠️  This requires root privileges and will modify system configuration files${NC}"
    echo ""

    detect_os

    case "$OS_TYPE" in
        "debian")
            add_permanent_routes_debian
            ;;
        "rhel")
            add_permanent_routes_rhel
            ;;
        "suse")
            add_permanent_routes_suse
            ;;
        *)
            echo -e "${RED}❌ Unsupported OS for permanent routes: $OS${NC}"
            echo -e "${YELLOW}💡 Falling back to temporary routes...${NC}"
            add_temporary_routes
            echo ""
            echo -e "${BLUE}📋 Manual permanent route configuration:${NC}"
            echo -e "${YELLOW}For your OS ($OS), manually add these routes to your system configuration:${NC}"
`)

	for subnet := range subnets {
		section.WriteString(fmt.Sprintf(`            echo "  Route: %s via $SIMULATOR_HOST"`, subnet))
		section.WriteString("\n")
	}

	section.WriteString(`            return
            ;;
    esac
}

`)

	return section.String()
}
