//go:build linux

/*
 * Copyright 2026 Ronny Trommer <ronny@no42.org>
 * SPDX-License-Identifier: Apache-2.0
 */

// Linux only because netns.go is. The tests replace the ip and iptables
// commands, so they need neither root nor a real namespace.

package main

import (
	"errors"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

// fakeNetnsCommands points namespace setup at a scratch directory and replaces
// its commands. `ip netns add` and `ip netns delete` create and remove the
// namespace file, and a command that starts with failOn fails. It returns the
// commands in the order they ran.
func fakeNetnsCommands(t *testing.T, failOn string) *[]string {
	t.Helper()
	originalDir, originalRun := netnsDir, runCommand
	t.Cleanup(func() { netnsDir, runCommand = originalDir, originalRun })

	netnsDir = t.TempDir()
	nsFile := filepath.Join(netnsDir, NETNS_NAME)
	var ran []string
	runCommand = func(name string, args ...string) ([]byte, error) {
		command := name + " " + strings.Join(args, " ")
		ran = append(ran, command)
		if strings.HasPrefix(command, failOn) {
			return []byte("refused"), errors.New("exit status 1")
		}
		switch command {
		case "ip netns add " + NETNS_NAME:
			return nil, os.WriteFile(nsFile, nil, 0o600)
		case "ip netns delete " + NETNS_NAME:
			return nil, os.Remove(nsFile)
		}
		return nil, nil
	}
	return &ran
}

// A veth pair that cannot be completed must fail namespace setup and leave
// neither the veth nor the namespace behind. The default route is one of the
// steps: without it nothing leaves the namespace for an off-host collector.
func TestCreateNetNamespaceCleansUpWhenVethSetupFails(t *testing.T) {
	for _, failOn := range []string{
		"ip link add " + VETH_HOST,
		"ip link set " + VETH_NS + " netns " + NETNS_NAME,
		"ip addr add " + VETH_HOST_IP,
		"ip link set " + VETH_HOST + " up",
		"ip netns exec " + NETNS_NAME + " ip addr add " + VETH_NS_IP,
		"ip netns exec " + NETNS_NAME + " ip link set " + VETH_NS + " up",
		"ip netns exec " + NETNS_NAME + " ip route add default",
	} {
		t.Run(failOn, func(t *testing.T) {
			ran := fakeNetnsCommands(t, failOn)

			ns, err := CreateNetNamespace()
			if err == nil {
				t.Fatal("expected an error when veth setup fails")
			}
			if ns != nil {
				t.Fatalf("expected no namespace, got %+v", ns)
			}

			failedAt := slices.IndexFunc(*ran, func(c string) bool { return strings.HasPrefix(c, failOn) })
			if failedAt < 0 {
				t.Fatalf("%q never ran: %q", failOn, *ran)
			}
			cleanup := (*ran)[failedAt+1:]
			for _, want := range []string{"ip link delete " + VETH_HOST, "ip netns delete " + NETNS_NAME} {
				if !slices.Contains(cleanup, want) {
					t.Errorf("cleanup did not run %q: %q", want, cleanup)
				}
			}
			if namespaceExists(NETNS_NAME) {
				t.Error("the namespace is still present after the failure")
			}
		})
	}
}

// A leftover namespace that cannot be removed is the cause to report. Going on
// to `ip netns add` would hide it behind "File exists".
func TestCreateNetNamespaceReportsLeftoverNamespaceItCannotRemove(t *testing.T) {
	ran := fakeNetnsCommands(t, "ip netns delete "+NETNS_NAME)
	if err := os.WriteFile(filepath.Join(netnsDir, NETNS_NAME), nil, 0o600); err != nil {
		t.Fatal(err)
	}

	_, err := CreateNetNamespace()
	if err == nil {
		t.Fatal("expected an error when the leftover namespace cannot be removed")
	}
	if !strings.Contains(err.Error(), "remove leftover namespace") {
		t.Fatalf("error %q does not name the leftover namespace", err)
	}
	if slices.Contains(*ran, "ip netns add "+NETNS_NAME) {
		t.Fatalf("namespace creation was still attempted: %q", *ran)
	}
}
