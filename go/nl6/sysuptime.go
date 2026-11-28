/*
 * Copyright 2026 Ronny Trommer <ronny@no42.org>
 * SPDX-License-Identifier: Apache-2.0
 */

package main

import (
	"sort"
	"time"
)

// The system-group objects served live rather than from the resources.
//
// sysUpTimeOID is sysUpTime.0 (SNMPv2-MIB): "The time (in hundredths of a
// second) since the network management portion of the system was last
// re-initialized." It is served from the device's boot instant on every device
// that has one (nl6#1031). sysName.0 and sysLocation.0 are served from the
// device's own fields, and buildResourceIndexes leaves their rows out of the
// index.
const (
	sysUpTimeOID   = ".1.3.6.1.2.1.1.3.0"
	sysNameOID     = ".1.3.6.1.2.1.1.5.0"
	sysLocationOID = ".1.3.6.1.2.1.1.6.0"
)

// hrSystemUptimeOID is hrSystemUptime.0 (HOST-RESOURCES-MIB).
const hrSystemUptimeOID = ".1.3.6.1.2.1.25.1.1.0"

// liveSystemOIDs is the three in walk order.
var liveSystemOIDs = [...]string{sysUpTimeOID, sysNameOID, sysLocationOID}

// bootInstant is the instant a device's clocks count from: its boot instant,
// or now for a device built without one (hand-built test fixtures). Callers
// that construct a clock-bearing engine read it once.
func (d *DeviceSimulator) bootInstant() time.Time {
	if d != nil && !d.bootTime.IsZero() {
		return d.bootTime
	}
	return time.Now()
}

// bootOrNow is boot, or now when boot is zero: the start of an exporter's
// uptime clock, given the boot instant its options carry.
func bootOrNow(boot time.Time) time.Time {
	if boot.IsZero() {
		return time.Now()
	}
	return boot
}

// uptimeTicks is the uptime at now of a device booted at boot, in TimeTicks:
// hundredths of a second, wrapping every 2^32 (about 497 days) as an agent's
// does, since a value at or above 2^32 would not encode as TimeTicks at all
// (nl6#541). It is the ONE formula behind the polled sysUpTime.0, the trap
// varbind and the syslog {{.Uptime}}, so the three agree at one instant.
//
// boot and now both carry Go's monotonic reading in production, so elapsed is
// never negative there; only an injected clock can read before the boot
// instant, and that answers 0.
func uptimeTicks(boot, now time.Time) uint32 {
	elapsed := now.Sub(boot)
	if elapsed < 0 {
		return 0
	}
	return uint32(elapsed / (10 * time.Millisecond))
}

// uptimeNow is the sysUpTime.0 reading now, in TimeTicks, and false on a
// device with no boot instant, which answers from its resources like any
// static OID. readRequest reads it once per request.
func (d *DeviceSimulator) uptimeNow() (uint32, bool) {
	if d == nil || d.bootTime.IsZero() {
		return 0, false
	}
	now := time.Now
	if d.now != nil {
		now = d.now
	}
	return uptimeTicks(d.bootTime, now()), true
}

// servesHrSystemUptime reports whether the device's profile carries the
// hrSystemUptime.0 row. On a device with a boot instant the object then serves
// the reading sysUpTime.0 serves, with no offset (nl6#1087): the row only marks
// that the profile serves the object, and its value is never served there.
// Without the row the object is not served, and without a boot instant the row
// answers like any static OID.
func (d *DeviceSimulator) servesHrSystemUptime() bool {
	if d == nil || d.resources == nil || d.resources.oidIndex == nil {
		return false
	}
	_, ok := d.resources.oidIndex.Load(hrSystemUptimeOID)
	return ok
}

// systemGapPredecessors returns the static OIDs whose successor in sorted
// steps over a live system object: for each of liveSystemOIDs, the last static
// OID sorting before it, when a static OID follows. The GETNEXT fast path
// checks a request against these by string equality instead of comparing OIDs
// on every walk step. A static sysUpTime.0 row (an operator profile may carry
// one) makes its predecessor a gap predecessor too, which sends the walk to
// the slow path, where the live value wins.
func systemGapPredecessors(sorted []string) []string {
	var preds []string
	for _, oid := range liveSystemOIDs {
		i := sort.Search(len(sorted), func(i int) bool { return compareOIDs(sorted[i], oid) >= 0 })
		if i == 0 || i == len(sorted) {
			continue // nothing before it, or nothing after it to step to
		}
		if p := sorted[i-1]; len(preds) == 0 || preds[len(preds)-1] != p {
			preds = append(preds, p)
		}
	}
	return preds
}

// stepsOverLiveSystemOID reports whether the precomputed successor of cur, a
// static OID, steps over a live system object.
func stepsOverLiveSystemOID(cur string, preds []string) bool {
	for _, p := range preds {
		if p == cur {
			return true
		}
	}
	return false
}
