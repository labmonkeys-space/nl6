/*
 * Copyright 2026 Ronny Trommer <ronny@no42.org>
 * SPDX-License-Identifier: Apache-2.0
 */

package main

import "time"

// operTwins remembers, per interface, the instant of an admin event whose
// oper twin is still expected. An admin change that also moves oper-status
// broadcasts two events with the same ifIndex and instant. A consumer that
// renders the whole interface on the first one drops the second.
//
// The entry is per interface because producers broadcast after the mutator
// returns, so two admin changes on different interfaces can interleave their
// events. A twin that never arrives leaves its entry behind until the next
// admin change on that interface overwrites it.
//
// Not safe for concurrent use. Each owner calls it from one goroutine.
type operTwins map[int]time.Time

// twin reports whether evt is the oper event that follows an admin event
// already seen. Call it once per event, in order.
func (t operTwins) twin(evt StateChange) bool {
	if evt.Changed == LeafOperStatus {
		if at, ok := t[evt.IfIndex]; ok && at.Equal(evt.At) {
			delete(t, evt.IfIndex)
			return true
		}
	}
	if evt.Changed&LeafAdminStatus != 0 && evt.PrevOper != evt.Oper {
		t[evt.IfIndex] = evt.At
	}
	return false
}
