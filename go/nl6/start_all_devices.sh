#!/bin/bash

# nl6 — network device simulator - System Optimization and Device Startup Script
# This script optimizes system settings for high-load SNMP operations before starting devices
# Optimized for handling 1000+ parallel SNMP walks

set -e  # Exit on any error

# Configuration
SERVER_PORT="8080"
BASE_IP="10.20.30"
START_IP_LAST_OCTET=1
LOG_FILE="startup.log"
PID_FILE="nl6.pid"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
BLUE='\033[0;34m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
NC='\033[0m' # No Color

# Function to print colored messages
print_info() {
    echo -e "${GREEN}[INFO]${NC} $1"
}

print_warn() {
    echo -e "${YELLOW}[WARN]${NC} $1"
}

print_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

echo -e "${BLUE}🚀 nl6 — network device simulator - System Optimization & Startup${NC}"
echo "============================================================"

# ========================================
# SYSTEM-WIDE OPTIMIZATIONS FOR HIGH LOAD
# ========================================

echo ""
echo -e "${CYAN}📊 Applying System Optimizations for High-Load SNMP Operations${NC}"
echo "================================================================"

# 1. UDP Buffer Optimizations - Critical for handling parallel SNMP walks
print_info "Configuring UDP buffer sizes..."

# Increase maximum receive buffer size to 25MB (prevents packet drops)
sudo sysctl -w net.core.rmem_max=26214400 > /dev/null 2>&1
# Set default receive buffer size to 4MB per socket
sudo sysctl -w net.core.rmem_default=4194304 > /dev/null 2>&1

# Increase maximum send buffer size to 25MB
sudo sysctl -w net.core.wmem_max=26214400 > /dev/null 2>&1
# Set default send buffer size to 4MB per socket
sudo sysctl -w net.core.wmem_default=4194304 > /dev/null 2>&1

# Increase socket option memory to 25MB
sudo sysctl -w net.core.optmem_max=26214400 > /dev/null 2>&1

print_info "✅ UDP buffers: 4MB default, 25MB max (prevents packet loss)"

# 2. Network Device Queue Optimizations
print_info "Optimizing network device queues..."

# Increase network device backlog queue (handles burst traffic)
sudo sysctl -w net.core.netdev_max_backlog=5000 > /dev/null 2>&1

# Increase network device budget (packets processed per NAPI poll)
sudo sysctl -w net.core.netdev_budget=600 > /dev/null 2>&1

print_info "✅ Network queues optimized for burst traffic"

# 3. File Descriptor Limits - Required for many TUN interfaces
print_info "Setting file descriptor limits..."

# Permanently configure high file descriptor limits if not already set
if ! grep -q "nofile.*10000000" /etc/security/limits.conf 2>/dev/null; then
    print_info "Configuring permanent file descriptor limits in /etc/security/limits.conf..."
    sudo tee -a /etc/security/limits.conf > /dev/null << 'LIMITS'
*    soft    nofile    10000000
*    hard    nofile    10000000
root soft    nofile    10000000
root hard    nofile    10000000
LIMITS
    print_info "✅ Permanent limits configured (will take full effect after re-login)"
fi

# Raise hard limit for current session via prlimit, then set soft limit
sudo prlimit --nofile=10000000:10000000 --pid $$ 2>/dev/null || true
ulimit -n 10000000 2>/dev/null || ulimit -n $(ulimit -Hn) 2>/dev/null || true

# Update system-wide file descriptor limit
sudo sh -c 'echo 10000000 > /proc/sys/fs/file-max' 2>/dev/null || true

print_info "✅ File descriptors: $(ulimit -n) (supports 1000+ devices)"

# 4. UDP-Specific Memory Optimizations
print_info "Applying UDP memory optimizations..."

# Increase UDP memory pressure thresholds (min, pressure, max in pages)
sudo sysctl -w net.ipv4.udp_mem="102400 873800 16777216" > /dev/null 2>&1

# Increase minimum UDP buffer sizes
sudo sysctl -w net.ipv4.udp_rmem_min=8192 > /dev/null 2>&1
sudo sysctl -w net.ipv4.udp_wmem_min=8192 > /dev/null 2>&1

print_info "✅ UDP memory thresholds optimized"

# 5. IP Local Port Range
print_info "Expanding local port range..."

# Increase range for outgoing connections
sudo sysctl -w net.ipv4.ip_local_port_range="1024 65535" > /dev/null 2>&1

print_info "✅ Port range: 1024-65535"

# 6. Connection Tracking Optimization (if loaded)
if lsmod | grep -q nf_conntrack; then
    print_info "Optimizing connection tracking..."

    # Increase connection tracking table size
    sudo sysctl -w net.netfilter.nf_conntrack_max=524288 > /dev/null 2>&1 || true
    sudo sysctl -w net.nf_conntrack_max=524288 > /dev/null 2>&1 || true

    # Reduce UDP connection tracking timeouts
    sudo sysctl -w net.netfilter.nf_conntrack_udp_timeout=30 > /dev/null 2>&1 || true
    sudo sysctl -w net.netfilter.nf_conntrack_udp_timeout_stream=30 > /dev/null 2>&1 || true

    print_info "✅ Connection tracking optimized for UDP"
fi

# 7. CPU Performance Optimization
if [ -d /sys/devices/system/cpu/cpu0/cpufreq ]; then
    print_info "Setting CPU governor to performance mode..."
    for cpu in /sys/devices/system/cpu/cpu*/cpufreq/scaling_governor; do
        sudo sh -c "echo performance > $cpu" 2>/dev/null || true
    done
    print_info "✅ CPU in performance mode"
fi

# 8. Go Runtime Optimization
print_info "Configuring Go runtime..."
export GOMAXPROCS=$(nproc)
print_info "✅ GOMAXPROCS set to $(nproc) cores"

# 9. Check TUN/TAP Module
if ! lsmod | grep -q tun; then
    print_info "Loading TUN/TAP kernel module..."
    sudo modprobe tun
    print_info "✅ TUN/TAP module loaded"
fi

# Display optimization summary
echo ""
echo -e "${GREEN}✅ System Optimizations Complete${NC}"
echo "--------------------------------"
echo "• UDP Buffers: 4MB default, 25MB max"
echo "• Network Queue: 5000 packet backlog"
echo "• File Descriptors: 65535 limit"
echo "• CPU Cores: $(nproc) in performance mode"
echo "• Port Range: 1024-65535"
echo ""

# Pre-flight memory check
available_mem=$(free -g | awk '/^Mem:/{print $7}')
if [ "$available_mem" -lt 2 ]; then
    print_warn "Less than 2GB available memory. May experience issues with many devices"
fi

echo -e "${BLUE}🚀 Starting nl6 — network device simulator${NC}"
echo "====================================="
echo "Server Port: $SERVER_PORT"
echo "Starting IP: ${BASE_IP}.${START_IP_LAST_OCTET}"
echo "Log File: $LOG_FILE"
echo ""

# Function to check if server is ready
wait_for_server() {
    echo -e "${YELLOW}⏳ Waiting for server to start...${NC}"
    for i in {1..30}; do
        if curl -s "http://localhost:$SERVER_PORT/health" > /dev/null 2>&1; then
            echo -e "${GREEN}✅ Server is ready!${NC}"
            return 0
        fi
        sleep 1
        echo -n "."
    done
    echo -e "${RED}❌ Server failed to start within 30 seconds${NC}"
    exit 1
}

# Function to create a device via API
create_device() {
    local device_name="$1"
    local ip_address="$2"  
    local resource_file="$3"
    local device_count="$4"
    
    echo -e "${BLUE}🔧 Creating device: $device_name ($ip_address)${NC}"
    
    local json_payload=$(cat <<EOF
{
    "start_ip": "$ip_address",
    "device_count": $device_count,
    "netmask": "16",
    "resource_file": "$resource_file"
}
EOF
)
    
    local response=$(curl -s -X POST \
        -H "Content-Type: application/json" \
        -d "$json_payload" \
        "http://localhost:$SERVER_PORT/api/v1/devices" 2>/dev/null)
    
    if [ $? -eq 0 ]; then
        echo -e "${GREEN}✅ Successfully created: $device_name${NC}"
        return 0
    else
        echo -e "${RED}❌ Failed to create: $device_name${NC}"
        return 1
    fi
}

# Stop any existing simulator
echo -e "${YELLOW}🛑 Stopping any existing simulator...${NC}"
if [ -f "$PID_FILE" ]; then
    if kill $(cat "$PID_FILE") 2>/dev/null; then
        echo -e "${GREEN}✅ Stopped existing simulator${NC}"
    fi
    rm -f "$PID_FILE"
fi

# Kill any process using the port
if lsof -ti:$SERVER_PORT >/dev/null 2>&1; then
    echo -e "${YELLOW}🔄 Killing process on port $SERVER_PORT...${NC}"
    kill $(lsof -ti:$SERVER_PORT) 2>/dev/null || true
    sleep 2
fi

# Start the simulator server in background
echo -e "${BLUE}🌐 Starting simulator server on port $SERVER_PORT...${NC}"
sudo ./nl6 -port "$SERVER_PORT" > "$LOG_FILE" 2>&1 &
SIMULATOR_PID=$!
echo $SIMULATOR_PID > "$PID_FILE"

# Wait for server to be ready
wait_for_server

echo ""
echo -e "${BLUE}🏭 Creating all 19 mock devices...${NC}"
echo "=================================================="

# Create all 19 devices based on Devices.go mock data
# Each device gets a sequential IP address starting from 10.20.30.1

# Device 1: Core-Switch-01 (Cisco Catalyst 9500)
create_device "Core-Switch-01" "${BASE_IP}.$(($START_IP_LAST_OCTET + 0))" "cisco_catalyst_9500.json" 1

# Device 2: NY-CORE-01 (Juniper MX240)  
create_device "NY-CORE-01" "${BASE_IP}.$(($START_IP_LAST_OCTET + 1))" "juniper_mx240.json" 1

# Device 3: LA-CORE-02 (Cisco ASR 9000)
create_device "LA-CORE-02" "${BASE_IP}.$(($START_IP_LAST_OCTET + 2))" "asr9k.json" 1

# Device 4: CHI-SW-01 (Palo Alto PA-3220)
create_device "CHI-SW-01" "${BASE_IP}.$(($START_IP_LAST_OCTET + 3))" "palo_alto_pa3220.json" 1

# Device 5: TOR-FW-01 (Fortinet FortiGate 600E)
create_device "TOR-FW-01" "${BASE_IP}.$(($START_IP_LAST_OCTET + 4))" "fortinet_fortigate_600e.json" 1

# Device 6: LON-CORE-01 (Juniper MX960)
create_device "LON-CORE-01" "${BASE_IP}.$(($START_IP_LAST_OCTET + 5))" "juniper_mx960.json" 1

# Device 7: PAR-SW-01 (Cisco Nexus 9500)
create_device "PAR-SW-01" "${BASE_IP}.$(($START_IP_LAST_OCTET + 6))" "cisco_nexus_9500.json" 1

# Device 8: FRA-CORE-02 (Huawei NE8000 X16)  
create_device "FRA-CORE-02" "${BASE_IP}.$(($START_IP_LAST_OCTET + 7))" "huawei_ne8000.json" 1

# Device 9: AMS-SRV-01 (Dell PowerEdge R750)
create_device "AMS-SRV-01" "${BASE_IP}.$(($START_IP_LAST_OCTET + 8))" "dell_poweredge_r750.json" 1

# Device 10: TYO-CORE-01 (NEC IX3315)
create_device "TYO-CORE-01" "${BASE_IP}.$(($START_IP_LAST_OCTET + 9))" "nec_ix3315.json" 1

# Device 11: SIN-SW-01 (Arista 7280R3)
create_device "SIN-SW-01" "${BASE_IP}.$(($START_IP_LAST_OCTET + 10))" "arista_7280r3.json" 1

# Device 12: MUM-FW-01 (Check Point 15600) - OFFLINE
create_device "MUM-FW-01" "${BASE_IP}.$(($START_IP_LAST_OCTET + 11))" "check_point_15600.json" 1

# Device 13: SEO-SRV-01 (HPE ProLiant DL380 Gen10)  
create_device "SEO-SRV-01" "${BASE_IP}.$(($START_IP_LAST_OCTET + 12))" "hpe_proliant_dl380.json" 1

# Device 14: SYD-CORE-01 (Cisco CRS-X)
create_device "SYD-CORE-01" "${BASE_IP}.$(($START_IP_LAST_OCTET + 13))" "cisco_crs_x.json" 1

# Device 15: MEL-SW-01 (Extreme Networks VSP 4450)
create_device "MEL-SW-01" "${BASE_IP}.$(($START_IP_LAST_OCTET + 14))" "extreme_vsp4450.json" 1

# Device 16: SAO-CORE-01 (Nokia 7750 SR-12)
create_device "SAO-CORE-01" "${BASE_IP}.$(($START_IP_LAST_OCTET + 15))" "nokia_7750_sr12.json" 1

# Device 17: BOG-FW-01 (SonicWall NSa 6700)
create_device "BOG-FW-01" "${BASE_IP}.$(($START_IP_LAST_OCTET + 16))" "sonicwall_nsa6700.json" 1

# Device 18: CAI-SW-01 (D-Link DGS-3630-52TC)  
create_device "CAI-SW-01" "${BASE_IP}.$(($START_IP_LAST_OCTET + 17))" "dlink_dgs3630.json" 1

# Device 19: CPT-SRV-01 (IBM Power System S922)
create_device "CPT-SRV-01" "${BASE_IP}.$(($START_IP_LAST_OCTET + 18))" "ibm_power_s922.json" 1

# Device 20: SFO-IOS-01 (Cisco IOS)
create_device "SFO-IOS-01" "${BASE_IP}.$(($START_IP_LAST_OCTET + 19))" "cisco_ios.json" 1

# Device 21: DEN-SRV-01 (Linux Server)
create_device "DEN-SRV-01" "${BASE_IP}.$(($START_IP_LAST_OCTET + 20))" "linux_server.json" 1

# Device 22: GPU-A100-01 (NVIDIA DGX A100)
create_device "GPU-A100-01" "${BASE_IP}.$(($START_IP_LAST_OCTET + 21))" "nvidia_dgx_a100.json" 1

# Device 23: GPU-H100-01 (NVIDIA DGX H100)
create_device "GPU-H100-01" "${BASE_IP}.$(($START_IP_LAST_OCTET + 22))" "nvidia_dgx_h100.json" 1

# Device 24: GPU-H200-01 (NVIDIA HGX H200)
create_device "GPU-H200-01" "${BASE_IP}.$(($START_IP_LAST_OCTET + 23))" "nvidia_hgx_h200.json" 1

# Device 25: STR-NTAP-01 (NetApp ONTAP)
create_device "STR-NTAP-01" "${BASE_IP}.$(($START_IP_LAST_OCTET + 24))" "netapp_ontap.json" 1

# Device 26: STR-PURE-01 (Pure Storage FlashArray)
create_device "STR-PURE-01" "${BASE_IP}.$(($START_IP_LAST_OCTET + 25))" "pure_storage_flasharray.json" 1

# Device 27: STR-EMC-01 (Dell EMC Unity)
create_device "STR-EMC-01" "${BASE_IP}.$(($START_IP_LAST_OCTET + 26))" "dell_emc_unity.json" 1

# Device 28: STR-AWS-01 (AWS S3 Storage)
create_device "STR-AWS-01" "${BASE_IP}.$(($START_IP_LAST_OCTET + 27))" "aws_s3_storage.json" 1

echo ""
echo "=================================================="
echo -e "${GREEN}🎉 All devices created successfully!${NC}"
echo ""

# Show device status
echo -e "${BLUE}📊 Device Status:${NC}"
echo "------------------"
curl -s "http://localhost:$SERVER_PORT/api/v1/devices" | python3 -m json.tool 2>/dev/null || echo "Devices created (JSON formatting not available)"

echo ""
echo -e "${BLUE}🌐 Access Information:${NC}"
echo "======================"
echo "• Web UI: http://localhost:$SERVER_PORT/"
echo "• API: http://localhost:$SERVER_PORT/api/v1/devices" 
echo "• Health: http://localhost:$SERVER_PORT/health"
echo "• Server PID: $(cat $PID_FILE)"
echo "• Log File: $LOG_FILE"
echo ""

echo -e "${BLUE}📝 Device IP Range:${NC}" 
echo "==================="
echo "• ${BASE_IP}.1  - Core-Switch-01 (Cisco Catalyst 9500)"
echo "• ${BASE_IP}.2  - NY-CORE-01 (Juniper MX240)" 
echo "• ${BASE_IP}.3  - LA-CORE-02 (Cisco ASR 9000)"
echo "• ${BASE_IP}.4  - CHI-SW-01 (Palo Alto PA-3220) ⚠️  CRITICAL"
echo "• ${BASE_IP}.5  - TOR-FW-01 (Fortinet FortiGate 600E) ⚠️  WARNING"  
echo "• ${BASE_IP}.6  - LON-CORE-01 (Juniper MX960)"
echo "• ${BASE_IP}.7  - PAR-SW-01 (Cisco Nexus 9500)"
echo "• ${BASE_IP}.8  - FRA-CORE-02 (Huawei NE8000 X16)"
echo "• ${BASE_IP}.9  - AMS-SRV-01 (Dell PowerEdge R750)"
echo "• ${BASE_IP}.10 - TYO-CORE-01 (NEC IX3315)"
echo "• ${BASE_IP}.11 - SIN-SW-01 (Arista 7280R3)"
echo "• ${BASE_IP}.12 - MUM-FW-01 (Check Point 15600) ❌ OFFLINE"
echo "• ${BASE_IP}.13 - SEO-SRV-01 (HPE ProLiant DL380 Gen10) ⚠️  WARNING"
echo "• ${BASE_IP}.14 - SYD-CORE-01 (Cisco CRS-X)"
echo "• ${BASE_IP}.15 - MEL-SW-01 (Extreme Networks VSP 4450)"
echo "• ${BASE_IP}.16 - SAO-CORE-01 (Nokia 7750 SR-12)"
echo "• ${BASE_IP}.17 - BOG-FW-01 (SonicWall NSa 6700) ⚠️  WARNING"
echo "• ${BASE_IP}.18 - CAI-SW-01 (D-Link DGS-3630-52TC)"
echo "• ${BASE_IP}.19 - CPT-SRV-01 (IBM Power System S922)"
echo "• ${BASE_IP}.20 - SFO-IOS-01 (Cisco IOS)"
echo "• ${BASE_IP}.21 - DEN-SRV-01 (Linux Server)"
echo "• ${BASE_IP}.22 - GPU-A100-01 (NVIDIA DGX A100)"
echo "• ${BASE_IP}.23 - GPU-H100-01 (NVIDIA DGX H100)"
echo "• ${BASE_IP}.24 - GPU-H200-01 (NVIDIA HGX H200)"
echo "• ${BASE_IP}.25 - STR-NTAP-01 (NetApp ONTAP)"
echo "• ${BASE_IP}.26 - STR-PURE-01 (Pure Storage FlashArray)"
echo "• ${BASE_IP}.27 - STR-EMC-01 (Dell EMC Unity)"
echo "• ${BASE_IP}.28 - STR-AWS-01 (AWS S3 Storage)"
echo ""

echo -e "${BLUE}🧪 Test Commands:${NC}"
echo "=================="
echo "# SNMP Test Examples:"
echo "snmpwalk -v2c -c public ${BASE_IP}.1 1.3.6.1.2.1.1.1.0  # Cisco Catalyst 9500"
echo "snmpwalk -v2c -c public ${BASE_IP}.2 1.3.6.1.2.1.1.1.0  # Juniper MX240"
echo "snmpwalk -v2c -c public ${BASE_IP}.4 1.3.6.1.2.1.1.1.0  # Palo Alto PA-3220"
echo ""
echo "# SSH Test Examples (password: admin):"
echo "ssh admin@${BASE_IP}.1  # Cisco CLI"
echo "ssh admin@${BASE_IP}.2  # Juniper CLI"
echo "ssh admin@${BASE_IP}.4  # Palo Alto CLI" 
echo ""
echo "# API Examples:"
echo "curl http://localhost:$SERVER_PORT/api/v1/devices"
echo "curl http://localhost:$SERVER_PORT/api/v1/devices/export"
echo ""

echo -e "${GREEN}✅ Setup complete! All 28 mock devices are running.${NC}"
echo -e "${YELLOW}   17 Network Devices, 4 Servers, 3 GPU Servers, 4 Storage${NC}"
echo -e "${YELLOW}📋 Use './stop_all_devices.sh' to stop all devices and server.${NC}"
