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
	"encoding/binary"
	"fmt"
	"net"
	"os/exec"
	"runtime"
	"strconv"
	"strings"
	"syscall"
	"unsafe"

	"golang.org/x/sys/unix"
)

// TUN interface management functions
func createTunInterface(name string, ip net.IP, netmask string) (*TunInterface, error) {
	// Open TUN device
	fd, err := syscall.Open("/dev/net/tun", syscall.O_RDWR, 0)
	if err != nil {
		return nil, fmt.Errorf("failed to open /dev/net/tun: %v", err)
	}

	// Configure interface
	ifr := make([]byte, 40)
	copy(ifr, []byte(name))
	binary.LittleEndian.PutUint16(ifr[16:18], 0x0001) // IFF_TUN

	// TUNSETIFF ioctl
	_, _, errno := syscall.Syscall(syscall.SYS_IOCTL, uintptr(fd), 0x400454ca, uintptr(unsafe.Pointer(&ifr[0])))
	if errno != 0 {
		syscall.Close(fd)
		return nil, fmt.Errorf("TUNSETIFF ioctl failed: %v", errno)
	}

	tun := &TunInterface{
		Name: name,
		IP:   ip,
		fd:   fd,
	}

	// Configure the interface
	if err := tun.configure(netmask); err != nil {
		tun.destroy()
		return nil, err
	}

	return tun, nil
}

// createTunInterfaceInNamespace creates a TUN interface inside a network namespace
// This isolates the interface from systemd-networkd in the root namespace
func createTunInterfaceInNamespace(ns *NetNamespace, name string, ip net.IP, netmask string) (*TunInterface, error) {
	if ns == nil {
		// Fallback to root namespace if no namespace provided
		return createTunInterface(name, ip, netmask)
	}

	// Enter the namespace for this goroutine
	if err := ns.EnterNamespace(); err != nil {
		return nil, fmt.Errorf("failed to enter namespace: %v", err)
	}

	// Create the TUN interface while in the namespace
	fd, err := syscall.Open("/dev/net/tun", syscall.O_RDWR, 0)
	if err != nil {
		ns.LeaveNamespace()
		return nil, fmt.Errorf("failed to open /dev/net/tun in namespace: %v", err)
	}

	// Configure interface
	ifr := make([]byte, 40)
	copy(ifr, []byte(name))
	binary.LittleEndian.PutUint16(ifr[16:18], 0x0001) // IFF_TUN

	// TUNSETIFF ioctl
	_, _, errno := syscall.Syscall(syscall.SYS_IOCTL, uintptr(fd), 0x400454ca, uintptr(unsafe.Pointer(&ifr[0])))
	if errno != 0 {
		syscall.Close(fd)
		ns.LeaveNamespace()
		return nil, fmt.Errorf("TUNSETIFF ioctl failed in namespace: %v", errno)
	}

	tun := &TunInterface{
		Name:        name,
		IP:          ip,
		fd:          fd,
		InNamespace: true,
	}

	// Configure the interface (still in namespace)
	if err := tun.configureInNamespace(netmask); err != nil {
		tun.destroy()
		ns.LeaveNamespace()
		return nil, err
	}

	// Leave namespace - the fd remains valid and bound to the namespace interface
	if err := ns.LeaveNamespace(); err != nil {
		// Log but don't fail - fd is still valid
		fmt.Printf("Warning: failed to leave namespace cleanly: %v\n", err)
	}

	return tun, nil
}

// configureInNamespace configures IP and brings up interface while already in namespace
func (tun *TunInterface) configureInNamespace(netmask string) error {
	// Configure IP address using ip command (we're already in the namespace)
	cmd := exec.Command("ip", "addr", "add", fmt.Sprintf("%s/%s", tun.IP.String(), netmask), "dev", tun.Name)
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("failed to set IP address: %v", err)
	}

	// Bring interface up
	cmd = exec.Command("ip", "link", "set", "dev", tun.Name, "up")
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("failed to bring interface up: %v", err)
	}

	return nil
}

// createTunInterfaceInNamespaceViaExec creates a TUN interface in namespace using ip netns exec
// This is an alternative method that doesn't require entering the namespace
func createTunInterfaceInNamespaceViaExec(nsName string, tunName string, ip net.IP, netmask string) (*TunInterface, error) {
	// Create TUN interface using ip netns exec
	// First, create the interface in the namespace by entering it temporarily

	// Use ip tuntap to create the interface
	cmd := exec.Command("ip", "netns", "exec", nsName, "ip", "tuntap", "add", "dev", tunName, "mode", "tun")
	if output, err := cmd.CombinedOutput(); err != nil {
		return nil, fmt.Errorf("failed to create TUN in namespace: %v, output: %s", err, string(output))
	}

	// Configure IP address
	cmd = exec.Command("ip", "netns", "exec", nsName, "ip", "addr", "add",
		fmt.Sprintf("%s/%s", ip.String(), netmask), "dev", tunName)
	if output, err := cmd.CombinedOutput(); err != nil {
		// Cleanup
		exec.Command("ip", "netns", "exec", nsName, "ip", "link", "delete", tunName).Run()
		return nil, fmt.Errorf("failed to configure IP: %v, output: %s", err, string(output))
	}

	// Bring interface up
	cmd = exec.Command("ip", "netns", "exec", nsName, "ip", "link", "set", "dev", tunName, "up")
	if output, err := cmd.CombinedOutput(); err != nil {
		exec.Command("ip", "netns", "exec", nsName, "ip", "link", "delete", tunName).Run()
		return nil, fmt.Errorf("failed to bring up interface: %v, output: %s", err, string(output))
	}

	// Now open the TUN fd from within the namespace
	// We need to enter the namespace to get the fd
	// IMPORTANT: Lock goroutine to OS thread before namespace switching
	// to prevent Go scheduler from migrating us to a different thread
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()

	nsPath := fmt.Sprintf("/var/run/netns/%s", nsName)
	nsFd, err := syscall.Open(nsPath, syscall.O_RDONLY, 0)
	if err != nil {
		exec.Command("ip", "netns", "exec", nsName, "ip", "link", "delete", tunName).Run()
		return nil, fmt.Errorf("failed to open namespace: %v", err)
	}

	// Save original namespace
	origFd, err := syscall.Open("/proc/self/ns/net", syscall.O_RDONLY, 0)
	if err != nil {
		syscall.Close(nsFd)
		exec.Command("ip", "netns", "exec", nsName, "ip", "link", "delete", tunName).Run()
		return nil, fmt.Errorf("failed to save original namespace: %v", err)
	}

	// Enter namespace
	if err := unix.Setns(nsFd, syscall.CLONE_NEWNET); err != nil {
		syscall.Close(nsFd)
		syscall.Close(origFd)
		exec.Command("ip", "netns", "exec", nsName, "ip", "link", "delete", tunName).Run()
		return nil, fmt.Errorf("failed to enter namespace: %v", err)
	}

	// Open TUN device
	tunFd, err := syscall.Open("/dev/net/tun", syscall.O_RDWR, 0)
	if err != nil {
		unix.Setns(origFd, syscall.CLONE_NEWNET)
		syscall.Close(nsFd)
		syscall.Close(origFd)
		exec.Command("ip", "netns", "exec", nsName, "ip", "link", "delete", tunName).Run()
		return nil, fmt.Errorf("failed to open /dev/net/tun: %v", err)
	}

	// Bind to existing interface
	ifr := make([]byte, 40)
	copy(ifr, []byte(tunName))
	binary.LittleEndian.PutUint16(ifr[16:18], 0x0001) // IFF_TUN

	_, _, errno := syscall.Syscall(syscall.SYS_IOCTL, uintptr(tunFd), 0x400454ca, uintptr(unsafe.Pointer(&ifr[0])))
	if errno != 0 {
		syscall.Close(tunFd)
		unix.Setns(origFd, syscall.CLONE_NEWNET)
		syscall.Close(nsFd)
		syscall.Close(origFd)
		exec.Command("ip", "netns", "exec", nsName, "ip", "link", "delete", tunName).Run()
		return nil, fmt.Errorf("TUNSETIFF failed: %v", errno)
	}

	// Return to original namespace
	unix.Setns(origFd, syscall.CLONE_NEWNET)
	syscall.Close(nsFd)
	syscall.Close(origFd)

	return &TunInterface{
		Name:        tunName,
		IP:          ip,
		fd:          tunFd,
		InNamespace: true,
	}, nil
}

// bindToTunInterface opens an existing TUN interface for use by a device
func bindToTunInterface(name string, ip net.IP) (*TunInterface, error) {
	// Open TUN device
	fd, err := syscall.Open("/dev/net/tun", syscall.O_RDWR, 0)
	if err != nil {
		return nil, fmt.Errorf("failed to open /dev/net/tun: %v", err)
	}

	// Bind to existing interface
	ifr := make([]byte, 40)
	copy(ifr, []byte(name))
	binary.LittleEndian.PutUint16(ifr[16:18], 0x0001) // IFF_TUN

	// TUNSETIFF ioctl to bind to existing interface
	_, _, errno := syscall.Syscall(syscall.SYS_IOCTL, uintptr(fd), 0x400454ca, uintptr(unsafe.Pointer(&ifr[0])))
	if errno != 0 {
		syscall.Close(fd)
		return nil, fmt.Errorf("TUNSETIFF ioctl failed: %v", errno)
	}

	return &TunInterface{
		Name: name,
		IP:   ip,
		fd:   fd,
	}, nil
}

func (tun *TunInterface) configure(netmask string) error {
	// Configure IP address using ip command
	cmd := exec.Command("ip", "addr", "add", fmt.Sprintf("%s/%s", tun.IP.String(), netmask), "dev", tun.Name)
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("failed to set IP address: %v", err)
	}

	// Bring interface up
	cmd = exec.Command("ip", "link", "set", "dev", tun.Name, "up")
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("failed to bring interface up: %v", err)
	}

	// log.Printf("Created TUN interface %s with IP %s", tun.Name, tun.IP.String())
	return nil
}

func (tun *TunInterface) destroy() error {
	if tun.fd > 0 {
		return syscall.Close(tun.fd)
	}
	return nil
}

// reconfigure updates the IP address of an existing TUN interface
func (tun *TunInterface) reconfigure(newIP net.IP, netmask string) error {
	// Remove old IP address
	cmd := exec.Command("ip", "addr", "del", fmt.Sprintf("%s/%s", tun.IP.String(), netmask), "dev", tun.Name)
	cmd.Run() // Ignore errors in case the IP wasn't set

	// Set new IP address
	cmd = exec.Command("ip", "addr", "add", fmt.Sprintf("%s/%s", newIP.String(), netmask), "dev", tun.Name)
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("failed to set new IP address %s: %v", newIP.String(), err)
	}

	// Update the interface IP
	tun.IP = make(net.IP, len(newIP))
	copy(tun.IP, newIP)

	return nil
}

// compareOIDsLexicographically compares two OID strings lexicographically
// Returns -1 if oid1 < oid2, 0 if equal, 1 if oid1 > oid2
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
