/*
 * Copyright 2026 Ronny Trommer <ronny@no42.org>
 * SPDX-License-Identifier: Apache-2.0
 */

package main

import (
	"net"
	"testing"
)

// BenchmarkSyslogExporterFire measures the full syslog fire path — catalog
// resolve → RFC 5424 encode → UDP socket write — end to end. It is the
// scenario subsystem's NFR-P1 reference workload: the committed baseline in
// testdata/scenario-bench-baseline.txt is captured from THIS benchmark on
// the CI runner class (make bench-baseline), and story 1.4's benchstat gate
// compares against it after the scenario gate is wired into Fire (story 1.2).
func BenchmarkSyslogExporterFire(b *testing.B) {
	// Drained loopback listener so writes never back up a socket buffer.
	lis, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 0})
	if err != nil {
		b.Fatalf("ListenUDP: %v", err)
	}
	defer lis.Close()
	go func() {
		buf := make([]byte, 2048)
		for {
			if _, _, err := lis.ReadFromUDP(buf); err != nil {
				return
			}
		}
	}()

	client, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 0})
	if err != nil {
		b.Fatalf("client socket: %v", err)
	}
	defer client.Close()

	cat, err := LoadEmbeddedSyslogCatalog()
	if err != nil {
		b.Fatal(err)
	}
	entry := cat.ByName["interface-down"]
	if entry == nil {
		b.Fatal("interface-down entry missing from embedded catalog")
	}

	e := NewSyslogExporter(SyslogExporterOptions{
		DeviceIP:     net.ParseIP("10.42.0.7").To4(),
		Encoder:      &RFC5424Encoder{},
		Collector:    lis.LocalAddr().(*net.UDPAddr),
		CollectorStr: lis.LocalAddr().String(),
		SysName:      "bench-device",
		Model:        "Bench-9000",
		Serial:       "SN0BENCH",
		ChassisID:    "02:42:0a:2a:00:07",
		IfIndexFn:    func() int { return 3 },
		IfNameFn:     func(int) string { return "GigabitEthernet0/3" },
	})
	e.SetConn(client)

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if err := e.Fire(entry, nil); err != nil {
			b.Fatalf("Fire: %v", err)
		}
	}
}
