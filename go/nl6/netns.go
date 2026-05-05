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

//go:build linux

package main

import (
	"context"
	"fmt"
	"log"
	"net"
	"os"
	"os/exec"
	"runtime"
	"strings"
	"syscall"
	"time"

	"golang.org/x/sys/unix"
)

const (
	// Network namespace name for all simulated devices
	NETNS_NAME = "opensim"
	// Veth pair names for host-namespace connectivity
	VETH_HOST = "veth-sim-host"
	VETH_NS   = "veth-sim-ns"
	// Bridge IP for host side (gateway for namespace)
	VETH_HOST_IP = "10.254.0.1"
	// Namespace side IP
	VETH_NS_IP = "10.254.0.2"
	// Network mask for veth pair
	VETH_NETMASK = "30"
)

// NetNamespace manages the network namespace for simulated devices
type NetNamespace struct {
	Name       string
	NsFd       int  // File descriptor to the namespace
	OrigNsFd   int  // Original namespace fd to return to
	Active     bool // Whether namespace is active
	VethSetup  bool // Whether veth pair is configured
}

// CreateNetNamespace creates and configures the opensim network namespace
func CreateNetNamespace() (*NetNamespace, error) {
	ns := &NetNamespace{
		Name:   NETNS_NAME,
		NsFd:   -1,
		OrigNsFd: -1,
	}

	log.Printf("Creating network namespace '%s' for device isolation...", NETNS_NAME)
	startTime := time.Now()

	// Check if namespace already exists and clean it up
	if namespaceExists(NETNS_NAME) {
		log.Printf("Network namespace '%s' already exists, cleaning up...", NETNS_NAME)
		if err := deleteNetNamespace(NETNS_NAME); err != nil {
			log.Printf("Warning: failed to clean up existing namespace: %v", err)
		}
	}

	// Create the network namespace
	cmd := exec.Command("ip", "netns", "add", NETNS_NAME)
	if output, err := cmd.CombinedOutput(); err != nil {
		return nil, fmt.Errorf("failed to create namespace: %v, output: %s", err, string(output))
	}

	// Open the namespace file descriptor for later use
	nsPath := fmt.Sprintf("/var/run/netns/%s", NETNS_NAME)
	fd, err := syscall.Open(nsPath, syscall.O_RDONLY, 0)
	if err != nil {
		deleteNetNamespace(NETNS_NAME)
		return nil, fmt.Errorf("failed to open namespace fd: %v", err)
	}
	ns.NsFd = fd
	ns.Active = true

	// Bring up loopback inside namespace
	if err := ns.execInNs("ip", "link", "set", "lo", "up"); err != nil {
		log.Printf("Warning: failed to bring up loopback: %v", err)
	}

	// Setup veth pair for connectivity
	if err := ns.setupVethPair(); err != nil {
		log.Printf("Warning: veth setup failed: %v (devices may not be reachable from host)", err)
	} else {
		ns.VethSetup = true
	}

	// Enable IP forwarding so remote machines can reach devices in the namespace
	enableIPForwarding()

	elapsed := time.Since(startTime)
	log.Printf("Network namespace '%s' created in %v", NETNS_NAME, elapsed)

	return ns, nil
}

// setupVethPair creates a veth pair connecting host to namespace
func (ns *NetNamespace) setupVethPair() error {
	// Delete existing veth if present
	exec.Command("ip", "link", "delete", VETH_HOST).Run()

	// Create veth pair
	cmd := exec.Command("ip", "link", "add", VETH_HOST, "type", "veth", "peer", "name", VETH_NS)
	if output, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("failed to create veth pair: %v, output: %s", err, string(output))
	}

	// Move one end to namespace
	cmd = exec.Command("ip", "link", "set", VETH_NS, "netns", NETNS_NAME)
	if output, err := cmd.CombinedOutput(); err != nil {
		exec.Command("ip", "link", "delete", VETH_HOST).Run()
		return fmt.Errorf("failed to move veth to namespace: %v, output: %s", err, string(output))
	}

	// Configure host side
	cmd = exec.Command("ip", "addr", "add", fmt.Sprintf("%s/%s", VETH_HOST_IP, VETH_NETMASK), "dev", VETH_HOST)
	if output, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("failed to configure host veth IP: %v, output: %s", err, string(output))
	}

	cmd = exec.Command("ip", "link", "set", VETH_HOST, "up")
	if output, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("failed to bring up host veth: %v, output: %s", err, string(output))
	}

	// Configure namespace side
	if err := ns.execInNs("ip", "addr", "add", fmt.Sprintf("%s/%s", VETH_NS_IP, VETH_NETMASK), "dev", VETH_NS); err != nil {
		return fmt.Errorf("failed to configure ns veth IP: %v", err)
	}

	if err := ns.execInNs("ip", "link", "set", VETH_NS, "up"); err != nil {
		return fmt.Errorf("failed to bring up ns veth: %v", err)
	}

	// Set default route in namespace to go through veth
	if err := ns.execInNs("ip", "route", "add", "default", "via", VETH_HOST_IP); err != nil {
		log.Printf("Warning: failed to add default route in namespace: %v", err)
	}

	// Allow forwarding of traffic originating in the namespace. Hosts with
	// Docker installed (common) default the FORWARD chain policy to drop, so
	// the kernel silently drops packets leaving the ns on their way to any
	// non-local destination — notably the flow collector when per-device
	// source IP mode is enabled. The rule is harmless on ACCEPT-policy hosts.
	ns.addForwardAcceptRule()

	log.Printf("Veth pair configured: %s (%s) <-> %s (%s)", VETH_HOST, VETH_HOST_IP, VETH_NS, VETH_NS_IP)

	return nil
}

// addForwardAcceptRule inserts a FORWARD ACCEPT rule matching traffic arriving
// on the host side of the veth pair. Best-effort: logs on failure but does not
// abort veth setup, since many deployments either don't need the rule (no
// forwarded egress from the ns) or have it managed externally.
func (ns *NetNamespace) addForwardAcceptRule() {
	cmd := exec.Command("iptables", "-I", "FORWARD", "1", "-i", VETH_HOST, "-j", "ACCEPT")
	if output, err := cmd.CombinedOutput(); err != nil {
		log.Printf("Warning: failed to install FORWARD ACCEPT rule for %s (iptables missing?): %v, output: %s",
			VETH_HOST, err, string(output))
		return
	}
	log.Printf("Installed FORWARD ACCEPT rule for %s (enables per-device egress from namespace)", VETH_HOST)
}

// removeForwardAcceptRule deletes the rule installed by addForwardAcceptRule.
// Safe to call when the rule is absent (e.g. if the install failed) — iptables
// simply returns non-zero and we swallow it.
func (ns *NetNamespace) removeForwardAcceptRule() {
	exec.Command("iptables", "-D", "FORWARD", "-i", VETH_HOST, "-j", "ACCEPT").Run()
}

// AddRouteToNamespace adds a route on the host to reach IPs inside the namespace
func (ns *NetNamespace) AddRouteToNamespace(network string, netmask string) error {
	// Add route: traffic to the simulated network goes through the namespace veth
	cidr := fmt.Sprintf("%s/%s", network, netmask)
	cmd := exec.Command("ip", "route", "add", cidr, "via", VETH_NS_IP)
	output, err := cmd.CombinedOutput()
	if err != nil {
		// Check if route already exists
		if strings.Contains(string(output), "File exists") {
			return nil // Route already exists, that's fine
		}
		return fmt.Errorf("failed to add route to %s: %v, output: %s", cidr, err, string(output))
	}
	log.Printf("Added host route: %s via %s", cidr, VETH_NS_IP)
	return nil
}

// execInNs executes a command inside the network namespace
func (ns *NetNamespace) execInNs(name string, args ...string) error {
	fullArgs := append([]string{"netns", "exec", ns.Name, name}, args...)
	cmd := exec.Command("ip", fullArgs...)
	output, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("command failed: %v, output: %s", err, string(output))
	}
	return nil
}

// ExecInNsOutput executes a command inside the namespace and returns output
func (ns *NetNamespace) ExecInNsOutput(name string, args ...string) ([]byte, error) {
	fullArgs := append([]string{"netns", "exec", ns.Name, name}, args...)
	cmd := exec.Command("ip", fullArgs...)
	return cmd.CombinedOutput()
}

// EnterNamespace switches the current goroutine to the network namespace
// IMPORTANT: Must call LeaveNamespace() when done, and goroutine must be locked to OS thread
func (ns *NetNamespace) EnterNamespace() error {
	if ns.NsFd < 0 {
		return fmt.Errorf("namespace not initialized")
	}

	// Lock goroutine to OS thread - required for namespace operations
	runtime.LockOSThread()

	// Save original namespace
	origFd, err := syscall.Open("/proc/self/ns/net", syscall.O_RDONLY, 0)
	if err != nil {
		runtime.UnlockOSThread()
		return fmt.Errorf("failed to open original namespace: %v", err)
	}
	ns.OrigNsFd = origFd

	// Switch to the new namespace
	if err := unix.Setns(ns.NsFd, syscall.CLONE_NEWNET); err != nil {
		syscall.Close(origFd)
		ns.OrigNsFd = -1
		runtime.UnlockOSThread()
		return fmt.Errorf("failed to enter namespace: %v", err)
	}

	return nil
}

// LeaveNamespace returns to the original network namespace
func (ns *NetNamespace) LeaveNamespace() error {
	if ns.OrigNsFd < 0 {
		runtime.UnlockOSThread()
		return nil
	}

	// Switch back to original namespace
	err := unix.Setns(ns.OrigNsFd, syscall.CLONE_NEWNET)
	syscall.Close(ns.OrigNsFd)
	ns.OrigNsFd = -1

	// Unlock from OS thread
	runtime.UnlockOSThread()

	if err != nil {
		return fmt.Errorf("failed to leave namespace: %v", err)
	}
	return nil
}

// Close cleans up the network namespace
func (ns *NetNamespace) Close() error {
	if !ns.Active {
		return nil
	}

	log.Printf("Cleaning up network namespace '%s'...", ns.Name)

	// Close namespace fd
	if ns.NsFd >= 0 {
		syscall.Close(ns.NsFd)
		ns.NsFd = -1
	}

	// Delete veth pair (deleting one end deletes both)
	if ns.VethSetup {
		ns.removeForwardAcceptRule()
		exec.Command("ip", "link", "delete", VETH_HOST).Run()
		ns.VethSetup = false
	}

	// Delete the namespace
	if err := deleteNetNamespace(ns.Name); err != nil {
		return err
	}

	ns.Active = false
	log.Printf("Network namespace '%s' cleaned up", ns.Name)
	return nil
}

// namespaceExists checks if a network namespace exists
func namespaceExists(name string) bool {
	nsPath := fmt.Sprintf("/var/run/netns/%s", name)
	_, err := os.Stat(nsPath)
	return err == nil
}

// deleteNetNamespace deletes a network namespace
func deleteNetNamespace(name string) error {
	cmd := exec.Command("ip", "netns", "delete", name)
	output, err := cmd.CombinedOutput()
	if err != nil {
		// Namespace might already be gone
		if strings.Contains(string(output), "No such file") {
			return nil
		}
		return fmt.Errorf("failed to delete namespace: %v, output: %s", err, string(output))
	}
	return nil
}

// ListNamespaceInterfaces lists all interfaces in the namespace
func (ns *NetNamespace) ListNamespaceInterfaces() ([]string, error) {
	output, err := ns.ExecInNsOutput("ip", "-o", "link", "show")
	if err != nil {
		return nil, err
	}

	var interfaces []string
	lines := strings.Split(string(output), "\n")
	for _, line := range lines {
		if line == "" {
			continue
		}
		// Format: "1: lo: <LOOPBACK,UP,LOWER_UP> ..."
		parts := strings.SplitN(line, ":", 3)
		if len(parts) >= 2 {
			ifName := strings.TrimSpace(parts[1])
			interfaces = append(interfaces, ifName)
		}
	}
	return interfaces, nil
}

// AddRouteForDevices adds host routes to reach simulated device IPs through the namespace
// This is called automatically when devices are created to ensure external reachability
func (ns *NetNamespace) AddRouteForDevices(startIP string, count int, netmask string) error {
	if !ns.VethSetup {
		return fmt.Errorf("veth not configured, cannot add routes")
	}

	// Calculate the network ranges that need routes
	// For simplicity, we add routes for each /24 subnet that contains devices
	networks := calculateNetworkRanges(startIP, count, netmask)

	for _, network := range networks {
		if err := ns.addHostRoute(network); err != nil {
			log.Printf("Warning: failed to add route for %s: %v", network, err)
		}
	}

	return nil
}

// addHostRoute adds a single route on the host to reach a network through the namespace
func (ns *NetNamespace) addHostRoute(cidr string) error {
	cmd := exec.Command("ip", "route", "replace", cidr, "via", VETH_NS_IP)
	output, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("failed to add route: %v, output: %s", err, string(output))
	}
	return nil
}

// calculateNetworkRanges determines which network ranges need routes based on device IPs
func calculateNetworkRanges(startIP string, count int, netmask string) []string {
	ip := net.ParseIP(startIP)
	if ip == nil {
		return nil
	}
	ip = ip.To4()
	if ip == nil {
		return nil
	}

	// Track unique /24 networks (or use provided netmask for smaller ranges)
	networks := make(map[string]bool)

	// For each device, determine its network
	currentIP := make(net.IP, 4)
	copy(currentIP, ip)

	for i := 0; i < count; i++ {
		// Get network address for this IP based on netmask
		var networkAddr string
		switch netmask {
		case "8":
			networkAddr = fmt.Sprintf("%d.0.0.0/8", currentIP[0])
		case "16":
			networkAddr = fmt.Sprintf("%d.%d.0.0/16", currentIP[0], currentIP[1])
		case "24":
			networkAddr = fmt.Sprintf("%d.%d.%d.0/24", currentIP[0], currentIP[1], currentIP[2])
		default:
			// Default to /24 for routing efficiency
			networkAddr = fmt.Sprintf("%d.%d.%d.0/24", currentIP[0], currentIP[1], currentIP[2])
		}
		networks[networkAddr] = true

		// Increment IP
		incrementIP(currentIP)
	}

	// Convert map to slice
	result := make([]string, 0, len(networks))
	for network := range networks {
		result = append(result, network)
	}

	return result
}

// incrementIP increments an IPv4 address in place
func incrementIP(ip net.IP) {
	ip[3]++
	if ip[3] == 0 || ip[3] == 255 {
		ip[2]++
		ip[3] = 1
		if ip[2] == 0 {
			ip[1]++
			if ip[1] == 0 {
				ip[0]++
			}
		}
	}
}

// enableIPForwarding enables IPv4 forwarding and configures the host
// so remote machines can reach devices inside the namespace
func enableIPForwarding() {
	// Enable IP forwarding
	cmd := exec.Command("sysctl", "-w", "net.ipv4.ip_forward=1")
	if output, err := cmd.CombinedOutput(); err != nil {
		log.Printf("Warning: failed to enable IP forwarding: %v, output: %s", err, string(output))
	} else {
		log.Printf("IP forwarding enabled")
	}

	// Disable reverse path filtering on the veth interface and all
	// so the kernel doesn't drop response packets from the namespace
	for _, iface := range []string{"all", VETH_HOST} {
		cmd = exec.Command("sysctl", "-w", fmt.Sprintf("net.ipv4.conf.%s.rp_filter=0", iface))
		if output, err := cmd.CombinedOutput(); err != nil {
			log.Printf("Warning: failed to disable rp_filter on %s: %v, output: %s", iface, err, string(output))
		}
	}

	// Allow forwarding on the veth interface
	cmd = exec.Command("sysctl", "-w", fmt.Sprintf("net.ipv4.conf.%s.forwarding=1", VETH_HOST))
	if output, err := cmd.CombinedOutput(); err != nil {
		log.Printf("Warning: failed to enable forwarding on %s: %v, output: %s", VETH_HOST, err, string(output))
	}
}

// RemoveRouteForDevices removes host routes when devices are deleted
func (ns *NetNamespace) RemoveRouteForDevices(startIP string, count int, netmask string) {
	networks := calculateNetworkRanges(startIP, count, netmask)
	for _, network := range networks {
		cmd := exec.Command("ip", "route", "delete", network)
		cmd.Run() // Ignore errors
	}
}

// ListenUDPInNamespace creates a UDP listener inside the network namespace.
// The returned *net.UDPConn remains valid in the host namespace because
// file descriptors survive namespace switches.
func (ns *NetNamespace) ListenUDPInNamespace(addr *net.UDPAddr) (*net.UDPConn, error) {
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()

	// Save original namespace
	origFd, err := syscall.Open("/proc/self/ns/net", syscall.O_RDONLY, 0)
	if err != nil {
		return nil, fmt.Errorf("failed to save original namespace: %v", err)
	}
	defer syscall.Close(origFd)

	// Enter namespace
	if err := unix.Setns(ns.NsFd, syscall.CLONE_NEWNET); err != nil {
		return nil, fmt.Errorf("failed to enter namespace: %v", err)
	}

	// Create listener inside namespace
	conn, listenErr := net.ListenUDP("udp", addr)

	// Return to original namespace (must happen regardless)
	if err := unix.Setns(origFd, syscall.CLONE_NEWNET); err != nil {
		if conn != nil {
			conn.Close()
		}
		return nil, fmt.Errorf("failed to return to original namespace: %v", err)
	}

	// Shrink kernel socket buffers — callers (e.g. SNMP server) may further
	// override this, but set a sane default here so no UDP socket in the
	// namespace inherits the system-wide rmem_default (often 4MB).
	if conn != nil {
		conn.SetReadBuffer(snmpSocketBufSize)
		conn.SetWriteBuffer(snmpSocketBufSize)
	}

	return conn, listenErr
}

// tcpListenSocketBufSize is the kernel socket buffer size for TCP listeners.
// SSH/API sessions are interactive with small payloads; 32KB is sufficient.
// Without this, each listener inherits net.core.rmem_default (often 4MB),
// and 35K listeners × 4MB = 140GB of potential kernel buffer memory.
const tcpListenSocketBufSize = 32768

// ListenTCPInNamespace creates a TCP listener inside the network namespace.
// The returned net.Listener remains valid in the host namespace.
func (ns *NetNamespace) ListenTCPInNamespace(network, address string) (net.Listener, error) {
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()

	// Save original namespace
	origFd, err := syscall.Open("/proc/self/ns/net", syscall.O_RDONLY, 0)
	if err != nil {
		return nil, fmt.Errorf("failed to save original namespace: %v", err)
	}
	defer syscall.Close(origFd)

	// Enter namespace — use ListenConfig with Control to set socket buffer
	// sizes before the socket enters the listen state
	lc := net.ListenConfig{
		Control: setSocketBufferSize,
	}
	if err := unix.Setns(ns.NsFd, syscall.CLONE_NEWNET); err != nil {
		return nil, fmt.Errorf("failed to enter namespace: %v", err)
	}

	// Create listener inside namespace with reduced buffer sizes
	listener, listenErr := lc.Listen(context.Background(), network, address)

	// Return to original namespace (must happen regardless)
	if err := unix.Setns(origFd, syscall.CLONE_NEWNET); err != nil {
		if listener != nil {
			listener.Close()
		}
		return nil, fmt.Errorf("failed to return to original namespace: %v", err)
	}

	return listener, listenErr
}

// setSocketBufferSize is a Control function for net.ListenConfig that reduces
// kernel send/receive buffers on TCP listener sockets before they start listening.
func setSocketBufferSize(network, address string, c syscall.RawConn) error {
	return c.Control(func(fd uintptr) {
		syscall.SetsockoptInt(int(fd), syscall.SOL_SOCKET, syscall.SO_RCVBUF, tcpListenSocketBufSize)
		syscall.SetsockoptInt(int(fd), syscall.SOL_SOCKET, syscall.SO_SNDBUF, tcpListenSocketBufSize)
	})
}
