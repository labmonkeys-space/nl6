/*
 * Copyright 2026 Ronny Trommer <ronny@no42.org>
 * SPDX-License-Identifier: Apache-2.0
 */

//go:build !linux

// Non-Linux stubs for network namespace machinery.
// These allow the package to compile on non-Linux hosts so that unit tests for
// platform-independent code (NetFlow encoders, flow cache, etc.) can run via
// `go test` without a Linux host. All methods return errNotLinux at runtime.
package main

import (
	"errors"
	"net"
	"syscall"
)

var errNotLinux = errors.New("network namespaces require Linux")

const (
	NETNS_NAME   = "opensim"
	VETH_HOST    = "veth-sim-host"
	VETH_NS      = "veth-sim-ns"
	VETH_HOST_IP = "10.254.0.1"
	VETH_NS_IP   = "10.254.0.2"
	VETH_NETMASK = "30"
)

// NetNamespace is a stub type; all methods return errNotLinux on non-Linux.
type NetNamespace struct {
	Name      string
	NsFd      int
	OrigNsFd  int
	Active    bool
	VethSetup bool
}

func CreateNetNamespace() (*NetNamespace, error) { return nil, errNotLinux }

func (ns *NetNamespace) Close() error { return nil }

func (ns *NetNamespace) AddRouteForDevices(startIP string, count int, netmask string) error {
	return errNotLinux
}

func (ns *NetNamespace) addHostRoute(_ string) error { return errNotLinux }

func (ns *NetNamespace) RemoveRouteForDevices(startIP string, count int, netmask string) {}

func (ns *NetNamespace) ListenUDPInNamespace(addr *net.UDPAddr) (*net.UDPConn, error) {
	return nil, errNotLinux
}

func (ns *NetNamespace) ListenTCPInNamespace(network, address string) (net.Listener, error) {
	return nil, errNotLinux
}

func setSocketBufferSize(network, address string, c syscall.RawConn) error { return nil }

func incrementIP(_ net.IP) {}
