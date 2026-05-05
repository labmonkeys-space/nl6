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
)

// Route script utility functions

// generateShowRoutesSection generates the section that shows current routes
func generateShowRoutesSection(subnets map[string]bool) string {
	var section string

	section = `# Function to show current routes
show_current_routes() {
    echo -e "${BLUE}📋 Current simulator routes:${NC}"
`

	for subnet := range subnets {
		section += fmt.Sprintf(`    if ip route show %s >/dev/null 2>&1; then
        echo -e "${GREEN}✅ %s: $(ip route show %s)${NC}"
    else
        echo -e "${RED}❌ %s: No route found${NC}"
    fi
`, subnet, subnet, subnet, subnet)
	}

	section += `}

`

	return section
}

// generateRemovalInstructionsSection generates the removal instructions section
func generateRemovalInstructionsSection(subnets map[string]bool) string {
	var section string

	section = `# Function to show removal instructions
show_removal_instructions() {
    echo ""
    echo -e "${BLUE}🗑️  Route Removal Instructions:${NC}"
    echo ""

    if [ "$PERMANENT" = true ]; then
        echo -e "${YELLOW}For permanent routes, you need to:${NC}"
        echo -e "${YELLOW}1. Remove the configuration files created by this script${NC}"
        echo -e "${YELLOW}2. Restart the network service${NC}"
        echo ""
        echo -e "${BLUE}Configuration files to remove:${NC}"
        case "$OS_TYPE" in
            "debian")
                echo "  - /etc/netplan/99-simulator-routes.yaml (if using netplan)"
                echo "  - /etc/systemd/network/50-simulator-routes.network (if using systemd-networkd)"
                echo "  - Lines in /etc/network/interfaces (if using traditional interfaces)"
                ;;
            "rhel")
                echo "  - NetworkManager connection routes (use nmcli con modify)"
                echo "  - /etc/sysconfig/network-scripts/route-* files"
                ;;
            "suse")
                echo "  - Lines in /etc/sysconfig/network/routes"
                ;;
        esac
        echo ""
    else
        echo -e "${YELLOW}For temporary routes, run these commands:${NC}"
`

	for subnet := range subnets {
		section += fmt.Sprintf(`        echo "  sudo ip route del %s"`, subnet)
		section += "\n"
	}

	section += `    fi
}

`

	return section
}

// generateVerifyConfigSection generates the verification section
func generateVerifyConfigSection() string {
	return `# Function to verify persistent configuration
verify_persistent_configuration() {
    echo ""
    echo -e "${BLUE}🔍 Verifying persistent configuration...${NC}"

    local config_found=false

    # Check for netplan configuration
    if [ -f "/etc/netplan/99-simulator-routes.yaml" ]; then
        echo -e "${GREEN}✅ Found netplan configuration: /etc/netplan/99-simulator-routes.yaml${NC}"
        config_found=true
        echo -e "${YELLOW}📄 Configuration content:${NC}"
        sudo cat "/etc/netplan/99-simulator-routes.yaml" | head -20
        echo ""
    fi

    # Check for systemd-networkd configuration
    if [ -f "/etc/systemd/network/50-simulator-routes.network" ]; then
        echo -e "${GREEN}✅ Found systemd-networkd configuration: /etc/systemd/network/50-simulator-routes.network${NC}"
        config_found=true
    fi

    # Check for NetworkManager configuration
    if command -v nmcli >/dev/null 2>&1; then
        local connection=$(nmcli -t -f NAME con show --active | head -1)
        if [ -n "$connection" ]; then
            local routes=$(nmcli -g ipv4.routes con show "$connection" 2>/dev/null)
            if [ -n "$routes" ]; then
                echo -e "${GREEN}✅ Found NetworkManager routes in connection: $connection${NC}"
                config_found=true
            fi
        fi
    fi

    # Check for traditional interfaces file
    if grep -q "nl6" /etc/network/interfaces 2>/dev/null; then
        echo -e "${GREEN}✅ Found routes in /etc/network/interfaces${NC}"
        config_found=true
    fi

    if [ "$config_found" = false ]; then
        echo -e "${RED}❌ No persistent configuration found!${NC}"
        echo -e "${YELLOW}💡 Routes may not persist after reboot${NC}"
        return 1
    fi

    return 0
}

`
}

// generateMainExecutionSection generates the main execution section of the script
func generateMainExecutionSection() string {
	return `# Main execution
echo -e "${BLUE}🚀 nl6 Route Configuration${NC}"
echo -e "${BLUE}================================================${NC}"
echo ""

# Check for additional flags (--temporary and --debug can be combined)
DEBUG=false
for arg in "$@"; do
    if [ "$arg" = "--debug" ]; then
        DEBUG=true
        echo -e "${YELLOW}🔧 Debug mode enabled${NC}"
        echo -e "${BLUE}System Information:${NC}"
        echo "  OS: $(cat /etc/os-release | grep PRETTY_NAME | cut -d= -f2)"
        echo "  Kernel: $(uname -r)"
        echo "  Netplan: $(which netplan 2>/dev/null || echo 'not found')"
        echo "  NetworkManager: $(systemctl is-active NetworkManager 2>/dev/null || echo 'inactive')"
        echo "  systemd-networkd: $(systemctl is-active systemd-networkd 2>/dev/null || echo 'inactive')"
        echo ""
    fi
done

if [ "$PERMANENT" = true ]; then
    echo -e "${BLUE}💾 Creating PERMANENT routes that will persist after reboot${NC}"
    echo -e "${YELLOW}📝 Note: To create temporary routes instead, use --temporary flag${NC}"
    echo ""
    add_permanent_routes

    # Verify the persistent configuration was created
    verify_persistent_configuration
else
    add_temporary_routes
fi

echo ""
show_current_routes

if [ "$PERMANENT" = true ]; then
    echo ""
    echo -e "${BLUE}💡 Testing persistence (for Ubuntu 24.04 Server):${NC}"
    echo -e "${YELLOW}1. Verify the configuration file exists:${NC}"
    echo "   ls -la /etc/netplan/99-simulator-routes.yaml"
    echo -e "${YELLOW}2. Test the configuration:${NC}"
    echo "   sudo netplan generate"
    echo "   sudo netplan apply"
    echo -e "${YELLOW}3. Verify routes are active:${NC}"
    echo "   ip route | grep $SIMULATOR_HOST"
    echo -e "${YELLOW}4. After reboot, check if routes persist:${NC}"
    echo "   ip route | grep $SIMULATOR_HOST"
fi

show_removal_instructions

echo ""
echo -e "${GREEN}🎉 Route configuration complete!${NC}"

if [ "$PERMANENT" = true ]; then
    echo -e "${GREEN}✅ Permanent routes are now configured and will persist across reboots${NC}"
    echo -e "${BLUE}💡 On Ubuntu 24.04, systemd-networkd should be enabled (usually is by default)${NC}"
    echo -e "${YELLOW}📝 To remove these routes later, see the removal instructions above${NC}"
else
    echo -e "${YELLOW}⚠️  Temporary routes are active only until next reboot${NC}"
    echo -e "${BLUE}💡 To make routes permanent, run without --temporary flag${NC}"
fi
`
}
