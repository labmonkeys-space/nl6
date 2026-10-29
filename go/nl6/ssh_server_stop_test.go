/*
 * Copyright 2026 Ronny Trommer <ronny@no42.org>
 * SPDX-License-Identifier: Apache-2.0
 */

package main

import (
	"bytes"
	"net"
	"runtime"
	"testing"
	"time"
)

// sshAcceptLoopRunning reports whether any goroutine is inside
// (*SSHServer).handleConnections.
func sshAcceptLoopRunning() bool {
	buf := make([]byte, 1<<20)
	n := runtime.Stack(buf, true)
	return bytes.Contains(buf[:n], []byte("(*SSHServer).handleConnections("))
}

// TestSSHServerStopExitsAcceptLoop stops a listening SSH server after the
// accept loop has handed off one connection, and checks that the loop exits.
// Stop writes the running flag on the test goroutine while the accept loop
// reads it on its own, so under -race a plain bool there was a reported data
// race. Stop does not close live sessions; only the listener and the loop are
// pinned here.
func TestSSHServerStopExitsAcceptLoop(t *testing.T) {
	if sshAcceptLoopRunning() {
		t.Skip("another SSH accept loop is live in this process; the exit check would be ambiguous")
	}
	dev := &DeviceSimulator{ID: "dev-stop", IP: net.IPv4(127, 0, 0, 1)}
	srv := &SSHServer{device: dev, signer: newNetconfTestSigner(t)}
	if err := srv.Start(); err != nil {
		t.Fatal(err)
	}
	dialNetconfTestSSH(t, srv.listener.Addr().String())

	if err := srv.Stop(); err != nil {
		t.Fatalf("stop: %v", err)
	}
	if srv.running.Load() {
		t.Fatal("running still true after Stop")
	}
	deadline := time.Now().Add(5 * time.Second)
	for sshAcceptLoopRunning() {
		if time.Now().After(deadline) {
			t.Fatal("accept loop still running 5s after Stop")
		}
		time.Sleep(10 * time.Millisecond)
	}
	// Idempotent: a second Stop on a stopped server is a no-op.
	if err := srv.Stop(); err != nil {
		t.Fatalf("second stop: %v", err)
	}
}

func TestSSHServerStopBeforeStart(t *testing.T) {
	if err := (&SSHServer{}).Stop(); err != nil {
		t.Fatalf("stop before start: %v", err)
	}
}
