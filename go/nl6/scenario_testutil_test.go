/*
 * Copyright 2026 Ronny Trommer <ronny@no42.org>
 * SPDX-License-Identifier: Apache-2.0
 */

package main

import (
	"net"
	"testing"
)

// newSinkExporter builds a SyslogExporter whose writes go to an in-memory
// sink instead of UDP — the one place scenario tests construct exporters, so
// SyslogExporterOptions changes touch a single call site. write is the sink
// (return an error to simulate a write failure; nil to accept).
func newSinkExporter(t *testing.T, ip net.IP, write func(pdu []byte) error) *SyslogExporter {
	t.Helper()
	exp := NewSyslogExporter(SyslogExporterOptions{
		DeviceIP:  ip,
		Encoder:   &RFC5424Encoder{},
		Collector: &net.UDPAddr{IP: net.IPv4(10, 0, 0, 9), Port: 514},
		SysName:   "dev",
		IfIndexFn: func() int { return 3 },
		IfNameFn:  func(int) string { return "GigabitEthernet0/3" },
	})
	exp.writeOverride = write
	t.Cleanup(func() { _ = exp.Close() })
	return exp
}
