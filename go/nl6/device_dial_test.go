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

// TestDeviceDialSlotsCapped holds every slot and checks that one more dial
// waits until a slot frees. gNMI dial-out and NETCONF call home both dial
// through dialFromDevice, so this one cap bounds their combined dials.
func TestDeviceDialSlotsCapped(t *testing.T) {
	releases := make([]func(), 0, deviceDialMaxConcurrent)
	for i := 0; i < deviceDialMaxConcurrent; i++ {
		r, err := acquireDeviceDialSlot(context.Background())
		if err != nil {
			t.Fatalf("slot %d: %v", i, err)
		}
		releases = append(releases, r)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	if _, err := acquireDeviceDialSlot(ctx); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("dial %d got a slot: %v", deviceDialMaxConcurrent+1, err)
	}
	releases[0]()
	r, err := acquireDeviceDialSlot(context.Background())
	if err != nil {
		t.Fatalf("slot after release: %v", err)
	}
	r()
	for _, r := range releases[1:] {
		r()
	}
}
