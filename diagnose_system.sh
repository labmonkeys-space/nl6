#!/bin/bash

# System Diagnostic Script for nl6 — network device simulator
# Run this on the fresh Ubuntu server to identify missing components

echo "🔍 nl6 — network device simulator - System Diagnostics"
echo "================================================="
echo ""

# Function to check command existence
check_command() {
    if command -v "$1" &> /dev/null; then
        echo "✅ $1: $(which $1)"
        if [ "$1" = "go" ]; then
            echo "   Version: $(go version 2>/dev/null || echo 'Version check failed')"
        fi
    else
        echo "❌ $1: NOT FOUND"
        return 1
    fi
}

# Function to check file existence
check_file() {
    if [ -e "$1" ]; then
        echo "✅ $1: EXISTS"
        if [ "$1" = "/dev/net/tun" ]; then
            ls -la "$1"
        fi
    else
        echo "❌ $1: NOT FOUND"
        return 1
    fi
}

# Function to check kernel module (improved TUN detection)
check_module() {
    if [ "$1" = "tun" ]; then
        # Special handling for TUN module
        if [ -c /dev/net/tun ]; then
            echo "✅ TUN support: AVAILABLE (/dev/net/tun exists)"
            
            # Check if it's a module or built-in
            if lsmod | grep -q "^tun "; then
                echo "   └─ TUN loaded as module"
            elif grep -q "CONFIG_TUN=y" /boot/config-$(uname -r) 2>/dev/null; then
                echo "   └─ TUN built into kernel"
            else
                echo "   └─ TUN available (method unknown)"
            fi
        else
            echo "❌ TUN support: NOT AVAILABLE (/dev/net/tun missing)"
            return 1
        fi
    else
        # Standard module check for other modules
        if lsmod | grep -q "^$1 "; then
            echo "✅ $1 module: LOADED"
        else
            echo "❌ $1 module: NOT LOADED"
            return 1
        fi
    fi
}

# Function to check sysctl parameter
check_sysctl() {
    local param="$1"
    local expected="$2"
    local actual=$(sysctl -n "$param" 2>/dev/null)
    if [ "$actual" = "$expected" ]; then
        echo "✅ $param: $actual (correct)"
    else
        echo "⚠️  $param: $actual (expected: $expected)"
        return 1
    fi
}

echo "🔧 Essential Commands:"
missing_commands=0
for cmd in go ip ping ssh snmpget jq curl wget; do
    check_command "$cmd" || ((missing_commands++))
done

echo ""
echo "📁 Critical Files and Devices:"
missing_files=0
check_file "/dev/net/tun" || ((missing_files++))

echo ""
echo "🧩 Kernel Modules:"
missing_modules=0
check_module "tun" || ((missing_modules++))

echo ""
echo "⚙️  System Configuration:"
config_issues=0
check_sysctl "net.ipv4.ip_nonlocal_bind" "1" || ((config_issues++))
check_sysctl "net.ipv4.ip_forward" "1" || ((config_issues++))

echo ""
echo "📊 System Limits:"
echo "Max open files (ulimit -n): $(ulimit -n)"
echo "Max processes (ulimit -u): $(ulimit -u)"

# Check if limits are adequate
if [ "$(ulimit -n)" -lt 65536 ]; then
    echo "⚠️  File descriptor limit too low (need >= 65536)"
    ((config_issues++))
fi

if [ "$(ulimit -u)" -lt 32768 ]; then
    echo "⚠️  Process limit too low (need >= 32768)"
    ((config_issues++))
fi

echo ""
echo "👤 User and Permissions:"
echo "Current user: $(whoami)"
echo "User ID: $(id -u)"
if [ "$(id -u)" -eq 0 ]; then
    echo "✅ Running as root (required for TUN interfaces)"
else
    echo "⚠️  Not running as root - simulator will need sudo"
fi

echo ""
echo "🌐 Network Configuration:"
echo "Available network interfaces:"
ip link show | grep -E "^[0-9]+:" | head -5

echo ""
echo "💾 System Resources:"
echo "Memory: $(free -h | grep '^Mem:' | awk '{print $3 "/" $2}')"
echo "Disk space: $(df -h / | tail -1 | awk '{print $4 " available"}')"
echo "CPU cores: $(nproc)"

echo ""
echo "📦 Ubuntu Version:"
if [ -f /etc/os-release ]; then
    source /etc/os-release
    echo "Distribution: $PRETTY_NAME"
    echo "Version: $VERSION"
else
    echo "⚠️  Unable to determine Ubuntu version"
fi

echo ""
echo "🔍 Diagnostic Summary:"
echo "================================================="

total_issues=0

if [ $missing_commands -gt 0 ]; then
    echo "❌ Missing $missing_commands essential command(s)"
    ((total_issues++))
fi

if [ $missing_files -gt 0 ]; then
    echo "❌ Missing $missing_files critical file(s)/device(s)"
    ((total_issues++))
fi

if [ $missing_modules -gt 0 ]; then
    echo "❌ Missing $missing_modules kernel module(s)"
    ((total_issues++))
fi

if [ $config_issues -gt 0 ]; then
    echo "❌ Found $config_issues configuration issue(s)"
    ((total_issues++))
fi

echo ""
if [ $total_issues -eq 0 ]; then
    echo "🎉 System appears ready for nl6 — network device simulator!"
    echo ""
    echo "✅ Next steps:"
    echo "1. Build: cd go/nl6 && go build -o nl6 ."
    echo "2. Run with root privileges: sudo ./nl6"
else
    echo "⚠️  Found $total_issues issue(s) that need to be addressed"
    echo ""
    echo "🔧 Recommended fixes:"
    
    if [ $missing_commands -gt 0 ]; then
        echo ""
        echo "Install missing packages:"
        echo "sudo apt update"
        echo "sudo apt install -y curl wget git build-essential iproute2 net-tools iputils-ping snmp snmp-mibs-downloader openssh-client jq"
        
        if ! command -v go &> /dev/null; then
            echo ""
            echo "Install Go:"
            echo "cd /tmp"
            echo "wget https://golang.org/dl/go1.21.5.linux-amd64.tar.gz"
            echo "sudo tar -C /usr/local -xzf go1.21.5.linux-amd64.tar.gz"
            echo "echo 'export PATH=\$PATH:/usr/local/go/bin' | sudo tee -a /etc/profile"
            echo "source /etc/profile"
        fi
    fi
    
    if [ $missing_modules -gt 0 ] || [ $missing_files -gt 0 ]; then
        echo ""
        echo "Load TUN module:"
        echo "sudo modprobe tun"
        echo "echo 'tun' | sudo tee -a /etc/modules"
    fi
    
    if [ $config_issues -gt 0 ]; then
        echo ""
        echo "Fix system configuration:"
        echo "sudo sysctl net.ipv4.ip_nonlocal_bind=1"
        echo "sudo sysctl net.ipv4.ip_forward=1"
        echo "echo 'net.ipv4.ip_nonlocal_bind = 1' | sudo tee -a /etc/sysctl.conf"
        echo "echo 'net.ipv4.ip_forward = 1' | sudo tee -a /etc/sysctl.conf"
        
        if [ "$(ulimit -n)" -lt 65536 ] || [ "$(ulimit -u)" -lt 32768 ]; then
            echo ""
            echo "Increase system limits:"
            echo "sudo tee -a /etc/security/limits.conf << EOF"
            echo "* soft nofile 65536"
            echo "* hard nofile 65536"
            echo "* soft nproc 32768"
            echo "* hard nproc 32768"
            echo "EOF"
        fi
    fi
    
    echo ""
    echo "🚀 Or run the automated setup script:"
    echo "sudo ./ubuntu_setup.sh"
fi

echo ""
echo "📋 For more detailed setup instructions, see:"
echo "   UBUNTU_REQUIREMENTS.md"