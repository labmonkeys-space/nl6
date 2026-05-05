package main

import (
	"context"
	"net"
	"os"
	"testing"
	"time"
)

func TestDeviceStopCleansPartiallyStartedResources(t *testing.T) {
	manager = nil

	reader, writer, err := os.Pipe()
	if err != nil {
		t.Fatalf("os.Pipe: %v", err)
	}
	t.Cleanup(func() {
		_ = reader.Close()
		_ = writer.Close()
	})

	// Cancellable ctx so StartBackgroundLoops's reader/retry goroutines
	// shut down deterministically even if the exporter's Close() in
	// device.Stop() doesn't fully cancel them (e.g., blocked on a nil
	// conn in INFORM mode). Guards the test against goroutine leaks.
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)

	flowExporter := &FlowExporter{}
	syslogExporter := NewSyslogExporter(SyslogExporterOptions{
		DeviceIP:     net.IPv4(127, 0, 0, 1),
		Collector:    &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 514},
		CollectorStr: "127.0.0.1:514",
	})
	trapExporter := NewTrapExporter(TrapExporterOptions{
		DeviceIP:      net.IPv4(127, 0, 0, 1),
		Mode:          TrapModeInform,
		Collector:     &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 162},
		CollectorStr:  "127.0.0.1:162",
		InformTimeout: 10 * time.Millisecond,
	})
	trapExporter.StartBackgroundLoops(ctx)

	// PreAllocated: true bypasses TunInterface.destroy() which would run
	// ioctls/netlink on what is actually a pipe FD (and t.Cleanup already
	// closes `reader`, so we'd also risk a double-close). This test is
	// about Stop's cleanup bookkeeping, not the TUN syscall path.
	device := &DeviceSimulator{
		IP:             net.IPv4(127, 0, 0, 1),
		tunIface:       &TunInterface{Name: "sim999", fd: int(reader.Fd()), PreAllocated: true},
		flowExporter:   flowExporter,
		trapExporter:   trapExporter,
		syslogExporter: syslogExporter,
	}

	if err := device.Stop(); err != nil {
		t.Fatalf("Stop() error = %v", err)
	}

	if device.flowExporter != nil {
		t.Fatal("flow exporter was not cleared")
	}
	if device.trapExporter != nil {
		t.Fatal("trap exporter was not cleared")
	}
	if device.syslogExporter != nil {
		t.Fatal("syslog exporter was not cleared")
	}
	// tunIface is intentionally left non-nil for PreAllocated interfaces
	// (they remain in the pool for reuse) — that's by design in Stop.
	// The non-preallocated clear-after-destroy path is covered implicitly
	// by the production TUN integration tests.
}
