/*
 * Copyright 2026 Ronny Trommer <ronny@no42.org>
 * SPDX-License-Identifier: Apache-2.0
 */

package main

import (
	"context"
	"net"
	"time"
)

const (
	// deviceDialMaxConcurrent bounds concurrent in-namespace dials across
	// every outbound subsystem (gNMI dial-out, NETCONF call home).
	// DialContextInNamespace pins an OS thread for the connect duration, so
	// this cap, not the device count, sets the worst-case pinned-thread count
	// when a peer is unreachable. Without it 30k devices re-dialing a
	// blackholed peer would hit Go's 10k-thread limit and crash.
	deviceDialMaxConcurrent = 64
	// deviceDialTimeout hard-bounds a single dial, so a blackholed peer
	// releases the thread promptly.
	deviceDialTimeout = 10 * time.Second
)

// deviceDialSem throttles concurrent in-namespace dials. Excess dials wait on
// it as parked goroutines, not pinned threads.
var deviceDialSem = make(chan struct{}, deviceDialMaxConcurrent)

// dialFromDevice opens a TCP connection to addr from inside ns with the
// device IP as source, under deviceDialSem and deviceDialTimeout.
func dialFromDevice(ctx context.Context, ns *NetNamespace, localIP net.IP, addr string) (net.Conn, error) {
	release, err := acquireDeviceDialSlot(ctx)
	if err != nil {
		return nil, err
	}
	defer release()
	dctx, cancel := context.WithTimeout(ctx, deviceDialTimeout)
	defer cancel()
	return ns.DialContextInNamespace(dctx, "tcp", addr, &net.TCPAddr{IP: localIP})
}

// acquireDeviceDialSlot waits for a free dial slot or for ctx to end.
func acquireDeviceDialSlot(ctx context.Context) (release func(), err error) {
	select {
	case deviceDialSem <- struct{}{}:
		return func() { <-deviceDialSem }, nil
	case <-ctx.Done():
		return nil, ctx.Err()
	}
}
