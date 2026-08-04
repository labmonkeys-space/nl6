/*
 * Copyright 2026 Ronny Trommer <ronny@no42.org>
 * SPDX-License-Identifier: Apache-2.0
 */

// Awaited-Stop contract tests (#410 / await-syslog-emission-stop). Ports of
// the trap drain suite, adapted to inline firing: Run's exit is itself the
// fire barrier, so Stop() blocking on runDone means "no scheduler-driven fire
// in flight". All ordering synchronisation is via channels; timers appear
// only as positive-hold checks or generous failsafe deadlines.

package main

import (
	"context"
	"net"
	"sync/atomic"
	"testing"
	"time"
)

// blockingSyslogFirer blocks every Fire until release is closed, signalling
// entry so the test can observe a fire provably in flight.
type blockingSyslogFirer struct {
	deviceIP net.IP
	entered  chan struct{} // one non-blocking send per Fire entry
	release  chan struct{}
	count    atomic.Uint64
}

func (f *blockingSyslogFirer) Fire(entry *SyslogCatalogEntry, overrides map[string]string) error {
	select {
	case f.entered <- struct{}{}:
	default:
	}
	<-f.release
	f.count.Add(1)
	return nil
}

// TestSyslogSchedulerStop_BlocksUntilFireCompletes pins the core #410
// contract: Stop() must not return while an inline fire is executing in Run,
// and the fire count is final once it returns.
func TestSyslogSchedulerStop_BlocksUntilFireCompletes(t *testing.T) {
	s := NewSyslogScheduler(SyslogSchedulerOptions{
		Catalog:      testSyslogCatalog(t),
		MeanInterval: time.Millisecond,
		Seed:         1,
	})
	f := &blockingSyslogFirer{
		deviceIP: net.IPv4(10, 0, 0, 1),
		entered:  make(chan struct{}, 1),
		release:  make(chan struct{}),
	}
	s.Register(f.deviceIP, f)

	go s.Run(context.Background())

	select {
	case <-f.entered:
	case <-time.After(5 * time.Second):
		t.Fatal("no fire entered within 5s — scheduler not firing")
	}

	stopReturned := make(chan struct{})
	go func() {
		s.Stop()
		close(stopReturned)
	}()

	// Positive-hold check: with the fire blocked inside Run, Stop must not
	// have returned.
	select {
	case <-stopReturned:
		t.Fatal("Stop returned while a fire was still executing in Run")
	case <-time.After(100 * time.Millisecond):
	}

	close(f.release)

	select {
	case <-stopReturned:
	case <-time.After(5 * time.Second):
		t.Fatal("Stop did not return after the fire was released")
	}

	final := f.count.Load()
	if final == 0 {
		t.Fatal("no fire completed")
	}
	time.Sleep(50 * time.Millisecond) // grace to catch a straggler increment
	if again := f.count.Load(); again != final {
		t.Fatalf("fire count moved after Stop returned: %d -> %d", final, again)
	}
}

// TestSyslogSchedulerStop_NeverRunReturnsImmediately guards the started-flag:
// schedulers constructed but never run (plenty of tests do this) must not
// hang Stop.
func TestSyslogSchedulerStop_NeverRunReturnsImmediately(t *testing.T) {
	s := NewSyslogScheduler(SyslogSchedulerOptions{
		Catalog:      testSyslogCatalog(t),
		MeanInterval: time.Second,
	})
	done := make(chan struct{})
	go func() {
		s.Stop()
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("Stop blocked on a scheduler that was never Run")
	}
}

// TestSyslogSchedulerStop_BoundedUnderGlobalCap pins the derived limiter
// context that syslog has carried since phase 5 — with an awaited Stop it is
// now load-bearing (an un-derived ctx would make Stop inherit up to a full
// token interval), and no test previously failed if it was removed.
func TestSyslogSchedulerStop_BoundedUnderGlobalCap(t *testing.T) {
	s := NewSyslogScheduler(SyslogSchedulerOptions{
		Catalog:            testSyslogCatalog(t),
		MeanInterval:       time.Millisecond, // demand far above the cap
		GlobalCapPerSecond: 1,
		Seed:               1,
	})
	f := &countingSyslogFirer{deviceIP: net.IPv4(10, 0, 0, 1)}
	s.Register(f.deviceIP, f)

	go s.Run(context.Background())

	// Wait for the burst token to be consumed so Run parks in limiter.Wait.
	deadline := time.After(3 * time.Second)
	for f.count.Load() == 0 {
		select {
		case <-deadline:
			t.Fatal("first fire never happened")
		case <-time.After(time.Millisecond):
		}
	}

	start := time.Now()
	s.Stop()
	if el := time.Since(start); el > 500*time.Millisecond {
		t.Fatalf("Stop took %v under cap=1/s — limiter wait not cancelled on stop", el)
	}
}
