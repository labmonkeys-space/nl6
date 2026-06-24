/*
 * Copyright 2026 Ronny Trommer <ronny@no42.org>
 * SPDX-License-Identifier: Apache-2.0
 */

package main

import (
	"net"
	"strings"
	"testing"
)

func TestGetDnsStatus_Disabled(t *testing.T) {
	mgr := newTestManager()
	st := mgr.GetDnsStatus()
	if st.SubsystemActive {
		t.Errorf("status active with subsystem off")
	}
	if len(st.Zones) != 0 || st.Domain != "" {
		t.Errorf("disabled status leaked zone detail: %+v", st)
	}
}

func TestGetDnsStatus_Active(t *testing.T) {
	mgr := newTestManager()
	mgr.devices["d1"] = &DeviceSimulator{IP: net.ParseIP("10.42.0.5"), sysName: "core-rtr-01"}
	if err := mgr.StartDnsSubsystem(DnsSubsystemConfig{
		Enabled:      true,
		Domain:       "nl6.local",
		ReverseZones: []string{"42.10.in-addr.arpa"},
		Listen:       "127.0.0.1:0",
	}); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(mgr.StopDnsSubsystem)

	st := mgr.GetDnsStatus()
	if !st.SubsystemActive {
		t.Fatal("status inactive after Start")
	}
	if st.Domain != "nl6.local" {
		t.Errorf("domain=%q", st.Domain)
	}
	if st.DevicesPublished != 1 || st.PTRsEmitted != 1 || st.PTRsOmitted != 0 {
		t.Errorf("counters: pub=%d ptr=%d omit=%d", st.DevicesPublished, st.PTRsEmitted, st.PTRsOmitted)
	}
	// One forward + one reverse zone, both reporting the seeded serial.
	if len(st.Zones) != 2 {
		t.Fatalf("zones=%d want 2", len(st.Zones))
	}
	var fwd, rev bool
	for _, z := range st.Zones {
		switch z.Kind {
		case "forward":
			fwd = z.Origin == "nl6.local."
		case "reverse":
			rev = z.Origin == "42.10.in-addr.arpa."
		}
		if z.Serial == 0 {
			t.Errorf("zone %s has zero serial", z.Origin)
		}
	}
	if !fwd || !rev {
		t.Errorf("missing forward/reverse zone: %+v", st.Zones)
	}
}

func TestGetDnsStatus_OmittedPTRCounted(t *testing.T) {
	mgr := newTestManager()
	// Device IP outside the only configured reverse zone -> counted omission.
	mgr.devices["d1"] = &DeviceSimulator{IP: net.ParseIP("192.168.1.7"), sysName: "srv-01"}
	if err := mgr.StartDnsSubsystem(DnsSubsystemConfig{
		Enabled: true, Domain: "nl6.local", ReverseZones: []string{"42.10.in-addr.arpa"}, Listen: "127.0.0.1:0",
	}); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(mgr.StopDnsSubsystem)

	st := mgr.GetDnsStatus()
	if st.DevicesPublished != 1 || st.PTRsEmitted != 0 || st.PTRsOmitted != 1 {
		t.Errorf("counters: pub=%d ptr=%d omit=%d, want 1/0/1", st.DevicesPublished, st.PTRsEmitted, st.PTRsOmitted)
	}
}

func TestValidateDNSDomain(t *testing.T) {
	// Valid: ordinary domain, trailing-dot form, and a long-but-legal multi-label.
	for _, ok := range []string{"nl6.local", "nl6.local.", strings.Repeat("a", 63) + "." + strings.Repeat("b", 63)} {
		if err := validateDNSDomain(ok); err != nil {
			t.Errorf("validateDNSDomain(%q) rejected: %v", ok, err)
		}
	}
	// Invalid: empty, a label over 63 octets, an empty label, and a domain
	// whose total length exceeds the cap despite each label being legal.
	tooLong := strings.Repeat("a", 63) + "." + strings.Repeat("b", 63) + "." + strings.Repeat("c", 63) // 191 > 181
	for _, bad := range []string{"", strings.Repeat("a", 64), "nl6..local", tooLong} {
		if err := validateDNSDomain(bad); err == nil {
			t.Errorf("validateDNSDomain(%q) accepted, want error", bad)
		}
	}
}

func TestSplitCommaList(t *testing.T) {
	cases := []struct {
		in   string
		want []string
	}{
		{"", nil},
		{"   ", nil},
		{"a", []string{"a"}},
		{"a,b , c", []string{"a", "b", "c"}},
		{"a,,b,", []string{"a", "b"}},
	}
	for _, c := range cases {
		got := splitCommaList(c.in)
		if len(got) != len(c.want) {
			t.Errorf("splitCommaList(%q) = %v, want %v", c.in, got, c.want)
			continue
		}
		for i := range got {
			if got[i] != c.want[i] {
				t.Errorf("splitCommaList(%q)[%d] = %q, want %q", c.in, i, got[i], c.want[i])
			}
		}
	}
}
