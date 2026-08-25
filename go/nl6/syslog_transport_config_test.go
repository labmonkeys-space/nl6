/*
 * Copyright 2026 Ronny Trommer <ronny@no42.org>
 * SPDX-License-Identifier: Apache-2.0
 */

package main

import "testing"

// TestSyslogConfig_TransportDefaultsToUDP: every request body written before
// this field existed must keep its meaning.
func TestSyslogConfig_TransportDefaultsToUDP(t *testing.T) {
	c := &DeviceSyslogConfig{Collector: "127.0.0.1:514"}
	c.ApplyDefaults()
	if c.Transport != string(SyslogTransportUDP) {
		t.Errorf("transport = %q, want %q", c.Transport, SyslogTransportUDP)
	}
	if c.Framing != "" {
		t.Errorf("framing = %q, want empty under udp", c.Framing)
	}
	if err := c.Validate(); err != nil {
		t.Errorf("Validate: %v", err)
	}
}

// TestSyslogConfig_TCPDefaultsToOctetCounting: the framing with no payload
// precondition is the default, so LF framing's dependence on CR/LF stripping is
// never relied on by accident.
func TestSyslogConfig_TCPDefaultsToOctetCounting(t *testing.T) {
	c := &DeviceSyslogConfig{Collector: "127.0.0.1:514", Transport: "tcp"}
	c.ApplyDefaults()
	if c.Framing != string(SyslogFramingOctetCounting) {
		t.Errorf("framing = %q, want %q", c.Framing, SyslogFramingOctetCounting)
	}
	if err := c.Validate(); err != nil {
		t.Errorf("Validate: %v", err)
	}
}

// TestSyslogConfig_RejectsFramingUnderUDP: framing is a stream concept.
// Accepting it silently would let an operator believe a setting applied when
// nothing reads it — the same class of defect as nl6#445's echoed-but-ignored
// interval.
func TestSyslogConfig_RejectsFramingUnderUDP(t *testing.T) {
	c := &DeviceSyslogConfig{Collector: "127.0.0.1:514", Transport: "udp", Framing: "octet-counting"}
	c.ApplyDefaults()
	if err := c.Validate(); err == nil {
		t.Error("framing under udp was accepted; it applies to nothing and must be refused")
	}
}

func TestSyslogConfig_RejectsUnknownTransportAndFraming(t *testing.T) {
	for _, tc := range []struct{ name, transport, framing string }{
		{"unknown transport", "sctp", ""},
		{"unknown framing", "tcp", "line-delimited"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			c := &DeviceSyslogConfig{Collector: "127.0.0.1:514", Transport: tc.transport, Framing: tc.framing}
			c.ApplyDefaults()
			if err := c.Validate(); err == nil {
				t.Errorf("transport=%q framing=%q was accepted", tc.transport, tc.framing)
			}
		})
	}
}
