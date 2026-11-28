/*
 * Copyright 2026 Ronny Trommer <ronny@no42.org>
 * SPDX-License-Identifier: Apache-2.0
 */

package main

import "log"

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

// Deliver broadcasts the queued events in mutation order. One drain runs per
// engine at a time; a caller that finds one running returns at once and that
// drain picks its events up. A caller can therefore return before its own
// events are out, but only while another drain is running.
//
// A caller sends at most the events that were queued when it started. Events
// queued behind those go to a goroutine of the engine, which takes the drain
// over without a gap. A caller that is shared, such as the flap scheduler's
// one goroutine, therefore never keeps draining for producers that keep
// mutating, and a reply never waits for more than its own backlog.
//
// Broadcast runs outside outMu because it runs the notify hook, which takes a
// device lock: a device in teardown blocks its own drain and nobody else.
//
// A panic in Broadcast does not stop the drain. The events behind it are
// sent first, by this caller up to its limit and by the engine's goroutine
// after that, so no producer's events wait for the next mutation. The caller
// then panics with the first value, as it did when callers broadcast
// themselves. The value can come from an event another producer queued. A
// panic on the engine's goroutine has no caller and is logged.
func (s *InterfaceState) Deliver() {
	s.outMu.Lock()
	if s.draining || len(s.outbox) == 0 {
		s.outMu.Unlock()
		return
	}
	s.draining = true
	limit := len(s.outbox)
	s.outMu.Unlock()

	if p := s.drain(limit); p != nil {
		panic(p)
	}
}

// drain sends up to limit events, or every event when limit is negative, and
// returns the first panic value of a Broadcast. Later ones are logged. The caller has set draining.
// drain clears it under the lock hold that sees the queue empty, or leaves it
// set and hands the rest to a goroutine when the limit is reached first.
func (s *InterfaceState) drain(limit int) (panicked any) {
	for {
		s.outMu.Lock()
		if len(s.outbox) == 0 {
			s.outbox = nil // a burst must not pin its backing array
			s.draining = false
			s.outMu.Unlock()
			return panicked
		}
		if limit == 0 {
			s.outMu.Unlock()
			go func() {
				if p := s.drain(-1); p != nil {
					log.Printf("interface_state: delivery panicked with no caller to reach: %v", p)
				}
			}()
			return panicked
		}
		evt := s.outbox[0]
		s.outbox = s.outbox[1:]
		s.outMu.Unlock()
		if limit > 0 {
			limit--
		}
		if p := s.broadcastRecovered(evt); p != nil {
			if panicked == nil {
				panicked = p
			} else {
				log.Printf("interface_state: delivery panicked again: %v", p)
			}
		}
	}
}

// broadcastRecovered runs Broadcast and returns the value it panicked with.
func (s *InterfaceState) broadcastRecovered(evt StateChange) (panicked any) {
	defer func() { panicked = recover() }()
	s.Broadcast(evt)
	return nil
}
