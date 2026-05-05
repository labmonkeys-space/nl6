#!/bin/bash
#
# Setup systemd-networkd to ignore sim* interfaces
# This prevents systemd-networkd from consuming excessive CPU/memory
# when running thousands of simulated network devices.
#
# Run this once before starting the simulator with many devices.
#

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

echo "=========================================="
echo "Systemd-networkd Configuration for nl6"
echo "=========================================="
echo ""

# Check if running as root
if [ "$EUID" -ne 0 ]; then
    echo -e "${RED}Error: This script must be run as root (sudo)${NC}"
    echo "Usage: sudo $0"
    exit 1
fi

# Create the network configuration directory if it doesn't exist
NETWORK_DIR="/etc/systemd/network"
CONFIG_FILE="$NETWORK_DIR/99-ignore-sim.network"

echo -e "${YELLOW}Creating systemd-networkd configuration...${NC}"

mkdir -p "$NETWORK_DIR"

# Create the configuration file
cat > "$CONFIG_FILE" << 'EOF'
# Ignore all sim* interfaces (nl6 network device simulator)
# This prevents systemd-networkd from monitoring these interfaces,
# which would cause excessive CPU/memory usage with many devices.

[Match]
Name=sim*

[Link]
Unmanaged=yes
EOF

echo -e "${GREEN}Created: $CONFIG_FILE${NC}"

# Show the configuration
echo ""
echo "Configuration contents:"
echo "------------------------"
cat "$CONFIG_FILE"
echo "------------------------"
echo ""

# Restart systemd-networkd to apply changes
echo -e "${YELLOW}Restarting systemd-networkd...${NC}"
systemctl restart systemd-networkd

# Verify the service is running
if systemctl is-active --quiet systemd-networkd; then
    echo -e "${GREEN}systemd-networkd restarted successfully${NC}"
else
    echo -e "${YELLOW}Note: systemd-networkd may not be active on this system${NC}"
fi

echo ""
echo -e "${GREEN}=========================================="
echo "Setup complete!"
echo "==========================================${NC}"
echo ""
echo "systemd-networkd will now ignore all sim* interfaces."
echo "You can safely run the simulator with thousands of devices."
echo ""
echo "To verify the configuration:"
echo "  cat $CONFIG_FILE"
echo ""
echo "To remove this configuration later:"
echo "  sudo rm $CONFIG_FILE"
echo "  sudo systemctl restart systemd-networkd"
echo ""
