/*
 * Copyright 2026 Ronny Trommer <ronny@no42.org>
 * SPDX-License-Identifier: Apache-2.0
 */

package main

import "testing"

// TestSyslogSeed_TransportFlagsValidate covers the shape the -syslog-transport
// and -syslog-framing seed flags feed: the auto-start batch builds a
// DeviceSyslogConfig from them and calls Validate, which is where a bad flag
// combination must surface as a startup failure rather than a silent default.
func TestSyslogSeed_TransportFlagsValidate(t *testing.T) {
	for _, tc := range []struct {
		name      string
		transport string
		framing   string
		wantErr   bool
	}{
		{"udp default", "udp", "", false},
		{"tcp default framing", "tcp", "", false},
		{"tcp octet-counting", "tcp", "octet-counting", false},
		{"tcp non-transparent", "tcp", "non-transparent", false},
		{"framing without tcp", "udp", "octet-counting", true},
		{"unknown transport", "quic", "", true},
		{"unknown framing", "tcp", "netstring", true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			c := &DeviceSyslogConfig{
				Collector: "127.0.0.1:514",
				Format:    "5424",
				Transport: tc.transport,
				Framing:   tc.framing,
			}
			c.ApplyDefaults()
			err := c.Validate()
			if tc.wantErr && err == nil {
				t.Errorf("transport=%q framing=%q accepted; the seed must fail startup instead",
					tc.transport, tc.framing)
			}
			if !tc.wantErr && err != nil {
				t.Errorf("transport=%q framing=%q rejected: %v", tc.transport, tc.framing, err)
			}
		})
	}
}
