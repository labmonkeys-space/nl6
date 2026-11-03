/*
 * Copyright 2026 Ronny Trommer <ronny@no42.org>
 * SPDX-License-Identifier: Apache-2.0
 */

package main

import (
	"context"
	"errors"
	"testing"
	"time"
)

// TestDeviceDialSlotsCapped holds every slot of one subsystem and checks
// that one more dial waits until a slot frees, while the other subsystem's
// slots stay free.
func TestDeviceDialSlotsCapped(t *testing.T) {
	sem := make(deviceDialSem, deviceDialMaxConcurrent)
	releases := make([]func(), 0, deviceDialMaxConcurrent)
	for i := 0; i < deviceDialMaxConcurrent; i++ {
		r, err := sem.acquire(context.Background())
		if err != nil {
			t.Fatalf("slot %d: %v", i, err)
		}
		releases = append(releases, r)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	if _, err := sem.acquire(ctx); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("dial %d got a slot: %v", deviceDialMaxConcurrent+1, err)
	}
	other := make(deviceDialSem, deviceDialMaxConcurrent)
	r, err := other.acquire(context.Background())
	if err != nil {
		t.Fatalf("a full subsystem blocked another: %v", err)
	}
	r()
	releases[0]()
	r, err = sem.acquire(context.Background())
	if err != nil {
		t.Fatalf("slot after release: %v", err)
	}
	r()
	for _, r := range releases[1:] {
		r()
	}
	if gnmiDialoutDialSem == netconfCallHomeDialSem {
		t.Fatal("gNMI dial-out and NETCONF call home share dial slots")
	}
}
