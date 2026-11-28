/*
 * Copyright 2026 Ronny Trommer <ronny@no42.org>
 * SPDX-License-Identifier: Apache-2.0
 */

package main

import (
	"strconv"
	"testing"
	"time"
)

// hrUptimeRows is a resource map with a static hrSystemUptime.0 row between
// two static neighbours, and no metric engine or interface rows, so a GETNEXT
// from ifNumber.0 takes the fast path onto the row's precomputed successor.
func hrUptimeRows() map[string]string {
	return map[string]string{
		".1.3.6.1.2.1.1.1.0":    "descr",
		".1.3.6.1.2.1.2.1.0":    "4",
		hrSystemUptimeOID:       "999",
		".1.3.6.1.2.1.25.1.5.0": "3",
	}
}

// TestHrSystemUptimeCountsFromTheBootInstant: hrSystemUptime.0 is the time
// since the device booted, in TimeTicks, read at serve time, with no offset,
// and the same number as sysUpTime.0 at the same instant (nl6#1087). The row
// only marks that the profile serves the object; its value is never served.
func TestHrSystemUptimeCountsFromTheBootInstant(t *testing.T) {
	boot := time.Date(2026, 11, 28, 12, 0, 0, 0, time.UTC)
	now := boot.Add(42 * time.Second)
	s := newTestServer(hrUptimeRows())
	s.device.bootTime = boot
	s.device.now = fixedClock(&now)

	if got := s.findResponse(hrSystemUptimeOID); got != "4200" {
		t.Errorf("hrSystemUptime.0 42 s after boot = %q, want %q", got, "4200")
	}
	now = now.Add(3 * time.Second)
	if got := s.findResponse(hrSystemUptimeOID); got != "4500" {
		t.Errorf("hrSystemUptime.0 3 s later = %q, want %q", got, "4500")
	}
	if up, hr := s.findResponse(sysUpTimeOID), s.findResponse(hrSystemUptimeOID); up != hr {
		t.Errorf("at one instant sysUpTime.0 = %q and hrSystemUptime.0 = %q, want equal", up, hr)
	}
}

// TestHrSystemUptimeWrapsLikeSysUpTime: both go through uptimeTicks, so both
// wrap at 2^32 ticks.
func TestHrSystemUptimeWrapsLikeSysUpTime(t *testing.T) {
	boot := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	now := boot.Add(time.Duration(1<<32+7) * 10 * time.Millisecond)
	s := newTestServer(hrUptimeRows())
	s.device.bootTime = boot
	s.device.now = fixedClock(&now)

	if got := s.findResponse(hrSystemUptimeOID); got != "7" {
		t.Errorf("hrSystemUptime.0 2^32+7 ticks after boot = %q, want %q", got, "7")
	}
	now = boot.Add(time.Duration(1<<32-1) * 10 * time.Millisecond)
	if got := s.findResponse(hrSystemUptimeOID); got != strconv.FormatUint(1<<32-1, 10) {
		t.Errorf("hrSystemUptime.0 one tick before the wrap = %q, want %d", got, uint64(1<<32-1))
	}
}

// TestHrSystemUptimeWalkFastPathServesTheLiveValue: on a device with no metric
// engine and no interface rows, the GETNEXT fast path returns the precomputed
// static successor. When that successor is hrSystemUptime.0, the live value
// goes out, not the row.
func TestHrSystemUptimeWalkFastPathServesTheLiveValue(t *testing.T) {
	boot := time.Date(2026, 11, 28, 12, 0, 0, 0, time.UTC)
	now := boot.Add(42 * time.Second)
	s := newTestServer(hrUptimeRows())
	s.device.bootTime = boot
	s.device.now = fixedClock(&now)

	oid, val := s.findNextOID(".1.3.6.1.2.1.2.1.0")
	if oid != hrSystemUptimeOID || val != "4200" {
		t.Errorf("GETNEXT(ifNumber.0) = (%s, %q), want (%s, %q)", oid, val, hrSystemUptimeOID, "4200")
	}
	if oid, _ := s.findNextOID(hrSystemUptimeOID); oid != ".1.3.6.1.2.1.25.1.5.0" {
		t.Errorf("GETNEXT(hrSystemUptime.0) = %s, want hrSystemNumUsers.0", oid)
	}
}

// TestHrSystemUptimeWithoutBootInstantServesTheRow: a device built without a
// boot instant answers from its resources, as sysUpTime.0 does.
func TestHrSystemUptimeWithoutBootInstantServesTheRow(t *testing.T) {
	s := newTestServer(hrUptimeRows())
	if got := s.findResponse(hrSystemUptimeOID); got != "999" {
		t.Errorf("unbooted device: GET hrSystemUptime.0 = %q, want the row's %q", got, "999")
	}
	if oid, val := s.findNextOID(".1.3.6.1.2.1.2.1.0"); oid != hrSystemUptimeOID || val != "999" {
		t.Errorf("unbooted device: GETNEXT(ifNumber.0) = (%s, %q), want (%s, %q)", oid, val, hrSystemUptimeOID, "999")
	}
}

// TestHrSystemUptimeWithoutTheRowServesNothing: the row is the marker. A
// booted device whose profile has no row serves noSuchObject and a walk steps
// over the OID, so the object does not appear on profiles that never had it.
func TestHrSystemUptimeWithoutTheRowServesNothing(t *testing.T) {
	boot := time.Date(2026, 11, 28, 12, 0, 0, 0, time.UTC)
	now := boot.Add(42 * time.Second)
	rows := hrUptimeRows()
	delete(rows, hrSystemUptimeOID)
	s := newTestServer(rows)
	s.device.bootTime = boot
	s.device.now = fixedClock(&now)

	if got := s.findResponse(hrSystemUptimeOID); got != valueNoSuchObject {
		t.Errorf("GET hrSystemUptime.0 without a row = %q, want noSuchObject", got)
	}
	if oid, _ := s.findNextOID(".1.3.6.1.2.1.2.1.0"); oid != ".1.3.6.1.2.1.25.1.5.0" {
		t.Errorf("GETNEXT(ifNumber.0) without a row = %s, want hrSystemNumUsers.0", oid)
	}
}

// TestHrSystemUptimeGetAndWalkAgreeOnEveryShippedProfile: on every shipped
// profile that carries the row, a GET and a walk serve the live value at a
// pinned instant. On the three NVIDIA profiles the step into the row takes the
// slow path, because the interface counter span covers all of .25, so this is
// the slow-path half of the walk.
func TestHrSystemUptimeGetAndWalkAgreeOnEveryShippedProfile(t *testing.T) {
	boot := time.Now().Add(-time.Hour)
	now := boot.Add(time.Hour + 3*time.Second)
	want := strconv.FormatUint(uint64(uptimeTicks(boot, now)), 10)
	checked := 0
	for _, profile := range shippedProfileNames(t) {
		s := bootedShippedDevice(t, profile, boot, &now)
		if _, ok := s.device.resources.oidIndex.Load(hrSystemUptimeOID); !ok {
			continue
		}
		checked++
		if got := s.findResponse(hrSystemUptimeOID); got != want {
			t.Errorf("%s: GET hrSystemUptime.0 = %q, want %q", profile, got, want)
		}
		walked, cur := "", ".1.3.6.1.2.1.25"
		for i := 0; i < 1000; i++ {
			next, v := s.findNextOID(cur)
			if next == "" || compareOIDs(next, hrSystemUptimeOID) > 0 {
				break
			}
			if next == hrSystemUptimeOID {
				walked = v
				break
			}
			cur = next
		}
		if walked != want {
			t.Errorf("%s: walked hrSystemUptime.0 = %q, want %q", profile, walked, want)
		}
	}
	if checked != 3 {
		t.Errorf("checked %d shipped profiles that carry hrSystemUptime.0, want 3", checked)
	}
}
