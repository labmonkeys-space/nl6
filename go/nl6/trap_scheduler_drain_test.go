/*
 * Copyright 2026 Ronny Trommer <ronny@no42.org>
 * SPDX-License-Identifier: Apache-2.0
 */

// Shutdown-drain contract tests (#408 / await-trap-emission-drain).
//
// The contract under test: Stop() on a running scheduler blocks until the
// emission pool has fully drained — every dispatched fire completed, queue
// empty — and is bounded-time under a global rate cap. All synchronisation is
// via channels; no sleeps stand in for ordering.

package main

import (
	"context"
	"net"
	"sync/atomic"
	"testing"
	"time"
)

// blockingFirer blocks every Fire on release until released is closed,
// signalling entry on a channel so the test can observe a fire in flight.
type blockingFirer struct {
	deviceIP net.IP
	entered  chan struct{} // one send per Fire entry (buffered by test)
	release  chan struct{} // closed by the test to let fires finish
	count    atomic.Uint64
}

func (f *blockingFirer) Fire(entry *CatalogEntry, overrides map[string]string) uint32 {
	select {
	case f.entered <- struct{}{}:
	default:
	}
	<-f.release
	return uint32(f.count.Add(1))
}

// TestTrapSchedulerStop_BlocksUntilDrained pins the core #408 contract:
// Stop() must not return while a dispatched fire is still executing, and once
// it returns, every fire that was dispatched is visible in the firer's count.
func TestTrapSchedulerStop_BlocksUntilDrained(t *testing.T) {
	s := NewTrapScheduler(SchedulerOptions{
		Catalog:      testCatalog(t),
		MeanInterval: time.Microsecond, // saturate: dispatch as fast as possible
		Seed:         1,
		Workers:      2,
	})
	f := &blockingFirer{
		deviceIP: net.IPv4(10, 0, 0, 1),
		entered:  make(chan struct{}, 1),
		release:  make(chan struct{}),
	}
	s.Register(f.deviceIP, f)

	go s.Run(context.Background())

	// Wait until at least one fire is provably in flight (blocked in Fire).
	select {
	case <-f.entered:
	case <-time.After(5 * time.Second):
		t.Fatal("no fire entered within 5s — scheduler not dispatching")
	}

	stopReturned := make(chan struct{})
	go func() {
		s.Stop()
		close(stopReturned)
	}()

	// With a fire held in Fire, Stop must NOT have returned. A short timer
	// here is a positive-hold check, not ordering synchronisation.
	select {
	case <-stopReturned:
		t.Fatal("Stop returned while a dispatched fire was still blocked in Fire")
	case <-time.After(100 * time.Millisecond):
	}

	close(f.release)

	select {
	case <-stopReturned:
	case <-time.After(5 * time.Second):
		t.Fatal("Stop did not return after fires were released")
	}

	// After Stop returns the pool is drained: the count is final. Any late
	// increment would race the read below and trip -race.
	final := f.count.Load()
	if final == 0 {
		t.Fatal("no fires completed — the drain delivered nothing")
	}
	time.Sleep(50 * time.Millisecond) // grace to catch a straggler increment
	if again := f.count.Load(); again != final {
		t.Fatalf("fire count moved after Stop returned: %d -> %d — pool not drained", final, again)
	}
}

// TestTrapSchedulerStop_NeverRunReturnsImmediately guards the started-flag:
// a constructed-but-never-run scheduler must not hang Stop (design D1).
func TestTrapSchedulerStop_NeverRunReturnsImmediately(t *testing.T) {
	s := NewTrapScheduler(SchedulerOptions{
		Catalog:      testCatalog(t),
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

// TestStopTrapExport_DrainsTailToWire is the end-to-end #408 test: a fleet
// firing under load through the real manager teardown. When StopTrapExport
// returns, (a) the exporter's Sent counter is final — no fire lands after the
// drain — and (b) every counted send was actually delivered to the collector,
// i.e. the queued tail drained to a live socket instead of being dropped.
//
// Note deliberately NOT asserted: the post-stop persisted aggregate.
// StopTrapExport zeroes sm.trapAggregates after persisting (review fix P2), so
// the aggregate is unobservable here; persistTrapCounters ordering is instead
// covered by the Close-then-persist flip plus (a).
func TestStopTrapExport_DrainsTailToWire(t *testing.T) {
	mc := newMockCollector(t, false)
	defer mc.Close()

	sm := newTestSimulatorManager()
	if err := sm.StartTrapSubsystem(TrapSubsystemConfig{
		SourcePerDevice:       false,
		MeanSchedulerInterval: 2 * time.Millisecond, // ~500 fires/s of load
	}); err != nil {
		t.Fatal(err)
	}

	device := &DeviceSimulator{ID: "drain-device", IP: net.IPv4(127, 0, 0, 1)}
	exp := NewTrapExporter(TrapExporterOptions{
		DeviceIP:     device.IP,
		Community:    "public",
		Encoder:      sm.trapEncoder,
		Mode:         TrapModeTrap,
		Collector:    mc.addr,
		CollectorStr: mc.addr.String(),
	})
	exp.SetConn(openTestUDPConn(t))
	device.trapExporter = exp
	sm.devices[device.ID] = device
	sm.deviceIPs[device.IP.String()] = struct{}{}
	sm.indexDeviceByIP(device)
	// Production shape: the fleet scheduler fires with the background source.
	getTrapScheduler(sm).Register(device.IP, backgroundTrapFirer{exp})

	// Let real load build up.
	deadline := time.After(5 * time.Second)
	for exp.Stats().Sent.Load() < 50 {
		select {
		case <-deadline:
			t.Fatalf("only %d fires in 5s — scheduler not driving load", exp.Stats().Sent.Load())
		case <-time.After(5 * time.Millisecond):
		}
	}

	sm.StopTrapExport()
	sentFinal := exp.Stats().Sent.Load()

	// (a) Sent is final: any post-stop fire would move it (and trip -race).
	time.Sleep(100 * time.Millisecond)
	if again := exp.Stats().Sent.Load(); again != sentFinal {
		t.Fatalf("Sent moved after StopTrapExport: %d -> %d — fires escaped the drain", sentFinal, again)
	}

	// (b) Every counted send reached the collector (loopback UDP at ~500/s is
	// lossless; allow a short delivery grace before comparing).
	gotDeadline := time.After(2 * time.Second)
	for mc.received.Load() < sentFinal {
		select {
		case <-gotDeadline:
			t.Fatalf("collector received %d of %d sent — drained tail was dropped, not delivered",
				mc.received.Load(), sentFinal)
		case <-time.After(10 * time.Millisecond):
		}
	}
	if got := mc.received.Load(); got != sentFinal {
		t.Fatalf("collector received %d != sent %d", got, sentFinal)
	}
}

// TestTrapSchedulerStop_BoundedUnderGlobalCap guards the derived limiter
// context (design D3): a Stop during a token wait must cancel the wait, not
// ride it out. Cap 1/s with an exhausted burst means Run parks in
// limiter.Wait for up to ~1s per token; an unbounded Stop would inherit that.
func TestTrapSchedulerStop_BoundedUnderGlobalCap(t *testing.T) {
	s := NewTrapScheduler(SchedulerOptions{
		Catalog:            testCatalog(t),
		MeanInterval:       time.Microsecond, // demand far above the cap
		GlobalCapPerSecond: 1,
		Seed:               1,
		Workers:            1,
	})
	f := &countingFirer{deviceIP: net.IPv4(10, 0, 0, 1)}
	s.Register(f.deviceIP, f)

	go s.Run(context.Background())

	// Let the burst token be consumed so Run is parked in limiter.Wait.
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
