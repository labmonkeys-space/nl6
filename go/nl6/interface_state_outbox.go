/*
 * Copyright 2026 Ronny Trommer <ronny@no42.org>
 * SPDX-License-Identifier: Apache-2.0
 */

package main

// The outbox of the interface state engine: mutators queue their events in
// mutation order, Deliver broadcasts them. The fields and the lock order are
// described on InterfaceState.

// lockOutbox takes outMu and returns the function a mutator defers: it
// appends the events the mutator is returning (*queued, read at return time)
// to the outbox and releases the lock. Deferred before lockFamily, so it runs
// after the family lock is released and outMu stays the outer lock.
func (s *InterfaceState) lockOutbox(queued *[]StateChange) func() {
	s.outMu.Lock()
	return func() {
		s.outbox = append(s.outbox, *queued...)
		s.outMu.Unlock()
	}
}

// Deliver broadcasts every queued event in mutation order. One goroutine
// drains at a time; a caller that finds a drain running returns at once and
// that drain picks its events up. A caller can therefore return before its
// own events are out, but only while another caller is delivering.
//
// Broadcast runs outside outMu because it runs the notify hook, which takes a
// device lock: a device in teardown blocks its own drain and nobody else.
//
// One event is taken per turn, so a panic in the notify hook loses nothing
// behind the event that caused it. The panic reaches the caller, as it did
// when callers broadcast themselves, and the next Deliver carries on.
func (s *InterfaceState) Deliver() {
	s.outMu.Lock()
	if s.draining {
		s.outMu.Unlock()
		return
	}
	s.draining = true
	s.outMu.Unlock()

	// Cleared here only on a panic. The normal exit clears it under the same
	// lock hold that saw the queue empty, and by the time this runs another
	// drain may own the flag.
	done := false
	defer func() {
		if !done {
			s.outMu.Lock()
			s.draining = false
			s.outMu.Unlock()
		}
	}()

	for {
		s.outMu.Lock()
		if len(s.outbox) == 0 {
			s.outbox = nil // a burst must not pin its backing array
			s.draining = false
			done = true
			s.outMu.Unlock()
			return
		}
		evt := s.outbox[0]
		s.outbox = s.outbox[1:]
		s.outMu.Unlock()
		s.Broadcast(evt)
	}
}
