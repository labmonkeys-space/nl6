/*
 * Copyright 2026 Ronny Trommer <ronny@no42.org>
 * SPDX-License-Identifier: Apache-2.0
 */

package main

import (
	"slices"
	"time"
)

// operTwinsPerInterface bounds the instants kept per interface.
const operTwinsPerInterface = 4

// operTwins remembers, per interface, the instants of the admin events whose
// oper twins are still expected. An admin change that also moves oper-status
// broadcasts two events with the same ifIndex and instant. A consumer that
// renders the whole interface on the first one drops the second.
//
// Every pending instant is kept, because producers broadcast after the
// mutator returns. Two admin changes can interleave their events, on
// different interfaces or on the same one. A consumer that renders from the
// event would otherwise send the older change once more, after the newer.
//
// A twin that never arrives leaves its instant behind, so the list is capped.
// An append beyond the cap forgets the oldest instant. If its twin still
// arrives, it is rendered once more. A change is never lost.
//
// Not safe for concurrent use. Each owner calls it from one goroutine.
type operTwins map[int][]time.Time

// twin reports whether evt is the oper event that follows an admin event
// already seen. Call it once per event, in order.
func (t operTwins) twin(evt StateChange) bool {
	ats := t[evt.IfIndex]
	if evt.Changed == LeafOperStatus {
		if i := slices.IndexFunc(ats, evt.At.Equal); i >= 0 {
			if len(ats) == 1 {
				delete(t, evt.IfIndex)
			} else {
				t[evt.IfIndex] = slices.Delete(ats, i, i+1)
			}
			return true
		}
	}
	if evt.Changed&LeafAdminStatus != 0 && evt.PrevOper != evt.Oper {
		if len(ats) == operTwinsPerInterface {
			ats = slices.Delete(ats, 0, 1)
		}
		t[evt.IfIndex] = append(ats, evt.At)
	}
	return false
}
