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

// Linux-specific route configuration script sections

// generateDebianRouteSection generates the Debian/Ubuntu route configuration section
func generateDebianRouteSection(subnets map[string]bool) string {
	var section string

	section = `# Function to add permanent routes on Debian/Ubuntu systems
add_permanent_routes_debian() {
    echo -e "${BLUE}🐧 Detected Debian/Ubuntu system${NC}"

    # Detect Ubuntu version if possible
    if [ -f /etc/os-release ]; then
        . /etc/os-release
        echo -e "${BLUE}📋 System: $NAME $VERSION${NC}"
    fi

    # For Ubuntu Server 20.04+ and Ubuntu Desktop 18.04+, netplan is the default
    # Check if netplan is being used (it should be for Ubuntu 24.04)
    if [ -d "/etc/netplan" ] && [ "$(ls -A /etc/netplan/*.yaml /etc/netplan/*.yml 2>/dev/null)" ]; then
        echo -e "${YELLOW}📝 Using netplan configuration (recommended for Ubuntu 18.04+)${NC}"
        add_permanent_routes_netplan
    elif [ -d "/etc/netplan" ] && [ ! "$(ls -A /etc/netplan 2>/dev/null)" ]; then
        # Netplan directory exists but is empty - create a new config
        echo -e "${YELLOW}📝 Netplan directory exists but empty - creating new configuration${NC}"
        add_permanent_routes_netplan
    elif command -v systemctl >/dev/null 2>&1 && systemctl is-enabled systemd-networkd >/dev/null 2>&1; then
        echo -e "${YELLOW}📝 Using systemd-networkd configuration${NC}"
        add_permanent_routes_systemd_networkd
    else
        echo -e "${YELLOW}📝 Using traditional network interfaces${NC}"
        add_permanent_routes_interfaces
    fi
}

# Function for netplan-based systems (Ubuntu 18.04+)
add_permanent_routes_netplan() {
    local netplan_file="/etc/netplan/99-simulator-routes.yaml"

    # First check if there's an existing netplan configuration and detect the renderer
    local renderer="systemd-networkd"  # Default for Ubuntu Server
    local existing_netplan=$(ls /etc/netplan/*.yaml /etc/netplan/*.yml 2>/dev/null | head -1)

    if [ -n "$existing_netplan" ]; then
        # Check if NetworkManager is the renderer
        if grep -q "renderer.*NetworkManager" "$existing_netplan" 2>/dev/null; then
            renderer="NetworkManager"
            echo -e "${YELLOW}📝 Detected NetworkManager as netplan renderer${NC}"
        elif grep -q "renderer.*networkd" "$existing_netplan" 2>/dev/null; then
            renderer="systemd-networkd"
            echo -e "${YELLOW}📝 Detected systemd-networkd as netplan renderer${NC}"
        else
            # No explicit renderer, check what's actually running
            if systemctl is-active NetworkManager >/dev/null 2>&1; then
                renderer="NetworkManager"
                echo -e "${YELLOW}📝 NetworkManager is active, using it as renderer${NC}"
            else
                renderer="systemd-networkd"
                echo -e "${YELLOW}📝 Using systemd-networkd as default renderer${NC}"
            fi
        fi
    fi

    # Detect primary network interface
    local primary_interface=$(ip route show default | head -1 | awk '{print $5}')

    if [ -z "$primary_interface" ]; then
        echo -e "${RED}❌ Could not detect primary network interface${NC}"
        return 1
    fi

    echo -e "${BLUE}📡 Configuring routes for interface: $primary_interface${NC}"

    # Create the netplan file with proper structure
    echo "# Static routes for nl6" | sudo tee "$netplan_file" > /dev/null
    echo "# Generated on $(date)" | sudo tee -a "$netplan_file" > /dev/null
    echo "# Interface: $primary_interface" | sudo tee -a "$netplan_file" > /dev/null
    echo "network:" | sudo tee -a "$netplan_file" > /dev/null
    echo "  version: 2" | sudo tee -a "$netplan_file" > /dev/null

    # Add renderer if needed
    if [ "$renderer" = "NetworkManager" ]; then
        echo "  renderer: NetworkManager" | sudo tee -a "$netplan_file" > /dev/null
    fi
    # systemd-networkd is default, so we don't need to specify it explicitly

    echo "  ethernets:" | sudo tee -a "$netplan_file" > /dev/null
    echo "    $primary_interface:" | sudo tee -a "$netplan_file" > /dev/null
    echo "      routes:" | sudo tee -a "$netplan_file" > /dev/null
`

	for subnet := range subnets {
		section += `    echo "        - to: ` + subnet + `" | sudo tee -a "$netplan_file" > /dev/null
    echo "          via: $SIMULATOR_HOST" | sudo tee -a "$netplan_file" > /dev/null
`
	}

	section += `
    echo -e "${GREEN}✅ Created netplan configuration: $netplan_file${NC}"

    # Test the configuration first
    echo -e "${YELLOW}🔍 Testing netplan configuration...${NC}"
    if sudo netplan generate 2>/dev/null; then
        echo -e "${GREEN}✅ Configuration syntax is valid${NC}"

        echo -e "${YELLOW}🔄 Applying netplan configuration...${NC}"
        if sudo netplan apply 2>&1 | grep -q "error\|Error\|ERROR"; then
            echo -e "${RED}❌ Failed to apply netplan configuration${NC}"
            echo -e "${YELLOW}💡 Trying alternative approach...${NC}"

            # Try to just restart the network service
            if [ "$renderer" = "NetworkManager" ]; then
                sudo systemctl restart NetworkManager
            else
                sudo systemctl restart systemd-networkd
            fi
        else
            echo -e "${GREEN}✅ Netplan configuration applied successfully${NC}"

            # For systemd-networkd, we might need to restart it explicitly
            if [ "$renderer" = "systemd-networkd" ]; then
                echo -e "${YELLOW}🔄 Ensuring systemd-networkd picks up the changes...${NC}"
                sudo systemctl restart systemd-networkd
            fi
        fi
    else
        echo -e "${RED}❌ Configuration syntax check failed${NC}"
        echo -e "${YELLOW}💡 Please check the generated file: $netplan_file${NC}"
        echo -e "${YELLOW}💡 You may need to run 'sudo netplan apply' manually after fixing${NC}"
    fi
}

# Function for systemd-networkd systems
add_permanent_routes_systemd_networkd() {
    local networkd_dir="/etc/systemd/network"
    local route_file="$networkd_dir/50-simulator-routes.network"

    # Create the networkd directory if it doesn't exist
    sudo mkdir -p "$networkd_dir"

    # Detect primary network interface
    local primary_interface=$(ip route show default | head -1 | awk '{print $5}')

    echo "# Static routes for nl6" | sudo tee "$route_file" > /dev/null
    echo "# Generated on $(date)" | sudo tee -a "$route_file" > /dev/null
    echo "[Match]" | sudo tee -a "$route_file" > /dev/null
    echo "Name=$primary_interface" | sudo tee -a "$route_file" > /dev/null
    echo "" | sudo tee -a "$route_file" > /dev/null
    echo "[Network]" | sudo tee -a "$route_file" > /dev/null
`

	for subnet := range subnets {
		section += `    echo "Route=` + subnet + `,$SIMULATOR_HOST" | sudo tee -a "$route_file" > /dev/null
`
	}

	section += `
    echo -e "${GREEN}✅ Created systemd-networkd configuration: $route_file${NC}"
    echo -e "${YELLOW}🔄 Restarting systemd-networkd...${NC}"

    sudo systemctl restart systemd-networkd
    echo -e "${GREEN}✅ systemd-networkd restarted${NC}"
}

# Function for traditional /etc/network/interfaces
add_permanent_routes_interfaces() {
    local interfaces_file="/etc/network/interfaces"
    local backup_file="/etc/network/interfaces.backup.$(date +%Y%m%d_%H%M%S)"

    # Backup original file
    sudo cp "$interfaces_file" "$backup_file"
    echo -e "${GREEN}✅ Backed up interfaces file to $backup_file${NC}"

    # Add routes to interfaces file
    echo "" | sudo tee -a "$interfaces_file" > /dev/null
    echo "# Static routes for nl6 - Added $(date)" | sudo tee -a "$interfaces_file" > /dev/null
`

	for subnet := range subnets {
		section += `    echo "up ip route add ` + subnet + ` via $SIMULATOR_HOST" | sudo tee -a "$interfaces_file" > /dev/null
    echo "down ip route del ` + subnet + ` via $SIMULATOR_HOST" | sudo tee -a "$interfaces_file" > /dev/null
`
	}

	section += `
    echo -e "${GREEN}✅ Added routes to $interfaces_file${NC}"
    echo -e "${YELLOW}💡 Routes will be active after next network restart or reboot${NC}"
}

`

	return section
}

// generateRHELRouteSection generates the RHEL/CentOS/Fedora route configuration section
func generateRHELRouteSection(subnets map[string]bool) string {
	var section string

	section = `# Function to add permanent routes on RHEL/CentOS/Fedora systems
add_permanent_routes_rhel() {
    echo -e "${BLUE}🎩 Detected RHEL/CentOS/Fedora system${NC}"

    # Check if NetworkManager is being used
    if command -v nmcli >/dev/null 2>&1 && systemctl is-active NetworkManager >/dev/null 2>&1; then
        echo -e "${YELLOW}📝 Using NetworkManager configuration${NC}"
        add_permanent_routes_networkmanager
    else
        echo -e "${YELLOW}📝 Using traditional network-scripts${NC}"
        add_permanent_routes_network_scripts
    fi
}

# Function for NetworkManager-based systems
add_permanent_routes_networkmanager() {
    # Get the active connection name
    local connection=$(nmcli -t -f NAME con show --active | head -1)

    if [ -z "$connection" ]; then
        echo -e "${RED}❌ No active NetworkManager connection found${NC}"
        return 1
    fi

    echo -e "${BLUE}📡 Adding routes to NetworkManager connection: $connection${NC}"
`

	for subnet := range subnets {
		section += `    if sudo nmcli con modify "$connection" +ipv4.routes "` + subnet + ` $SIMULATOR_HOST"; then
        echo -e "${GREEN}✅ Added route for ` + subnet + `${NC}"
    else
        echo -e "${RED}❌ Failed to add route for ` + subnet + `${NC}"
    fi
`
	}

	section += `
    echo -e "${YELLOW}🔄 Reactivating NetworkManager connection...${NC}"
    sudo nmcli con up "$connection"
    echo -e "${GREEN}✅ NetworkManager configuration applied${NC}"
}

# Function for traditional network-scripts
add_permanent_routes_network_scripts() {
    local route_file="/etc/sysconfig/network-scripts/route-$(ip route show default | head -1 | awk '{print $5}')"

    echo "# Static routes for nl6" | sudo tee "$route_file" > /dev/null
    echo "# Generated on $(date)" | sudo tee -a "$route_file" > /dev/null
`

	for subnet := range subnets {
		section += `    echo "` + subnet + ` via $SIMULATOR_HOST" | sudo tee -a "$route_file" > /dev/null
`
	}

	section += `
    echo -e "${GREEN}✅ Created route file: $route_file${NC}"
    echo -e "${YELLOW}💡 Routes will be active after next network restart or reboot${NC}"
}

`

	return section
}

// generateSUSERouteSection generates the openSUSE/SUSE route configuration section
func generateSUSERouteSection(subnets map[string]bool) string {
	var section string

	section = `# Function to add permanent routes on openSUSE/SUSE systems
add_permanent_routes_suse() {
    echo -e "${BLUE}🦎 Detected openSUSE/SUSE system${NC}"

    local route_file="/etc/sysconfig/network/routes"
    local backup_file="/etc/sysconfig/network/routes.backup.$(date +%Y%m%d_%H%M%S)"

    # Backup original file if it exists
    if [ -f "$route_file" ]; then
        sudo cp "$route_file" "$backup_file"
        echo -e "${GREEN}✅ Backed up routes file to $backup_file${NC}"
    fi

    # Add routes
    echo "# Static routes for nl6 - Added $(date)" | sudo tee -a "$route_file" > /dev/null
`

	for subnet := range subnets {
		section += `    echo "` + subnet + ` $SIMULATOR_HOST - -" | sudo tee -a "$route_file" > /dev/null
`
	}

	section += `
    echo -e "${GREEN}✅ Added routes to $route_file${NC}"
    echo -e "${YELLOW}🔄 Restarting network service...${NC}"

    if sudo systemctl restart wicked; then
        echo -e "${GREEN}✅ Network service restarted${NC}"
    else
        echo -e "${YELLOW}⚠️  Network service restart failed, routes will be active after reboot${NC}"
    fi
}

`

	return section
}
