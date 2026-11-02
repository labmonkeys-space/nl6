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
	// deviceDialMaxConcurrent bounds concurrent in-namespace dials per
	// outbound subsystem. DialContextInNamespace pins an OS thread for the
	// connect duration, so these caps, not the device count, set the
	// worst-case pinned-thread count when a peer is unreachable. Without
	// them 30k devices re-dialing a blackholed peer would hit Go's 10k-thread
	// limit and crash.
	deviceDialMaxConcurrent = 64
	// deviceDialTimeout hard-bounds a single dial, so a blackholed peer
	// releases the thread promptly.
	deviceDialTimeout = 10 * time.Second
)

// deviceDialSem is one subsystem's dial slots. Excess dials wait on it as
// parked goroutines, not pinned threads.
type deviceDialSem chan struct{}

// Each subsystem has its own slots, so a blackholed peer of one cannot
// starve the dials of the other. Together they pin at most
// 2 * deviceDialMaxConcurrent threads.
var (
	gnmiDialoutDialSem     = make(deviceDialSem, deviceDialMaxConcurrent)
	netconfCallHomeDialSem = make(deviceDialSem, deviceDialMaxConcurrent)
)

// dialFromDevice opens a TCP connection to addr from inside ns with the
// device IP as source, under sem and deviceDialTimeout. With no namespace
// (tests, -no-namespace) it dials from the default namespace without a
// source binding, as gNMI dial-out always has.
func dialFromDevice(ctx context.Context, sem deviceDialSem, ns *NetNamespace, localIP net.IP, addr string) (net.Conn, error) {
	release, err := sem.acquire(ctx)
	if err != nil {
		return nil, err
	}
	defer release()
	dctx, cancel := context.WithTimeout(ctx, deviceDialTimeout)
	defer cancel()
	if ns == nil {
		var dl net.Dialer
		return dl.DialContext(dctx, "tcp", addr)
	}
	return ns.DialContextInNamespace(dctx, "tcp", addr, &net.TCPAddr{IP: localIP})
}

// acquire waits for a free dial slot or for ctx to end.
func (sem deviceDialSem) acquire(ctx context.Context) (release func(), err error) {
	select {
	case sem <- struct{}{}:
		return func() { <-sem }, nil
	case <-ctx.Done():
		return nil, ctx.Err()
	}
}
