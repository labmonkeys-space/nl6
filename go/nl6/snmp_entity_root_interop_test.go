/*
 * Copyright 2026 Ronny Trommer <ronny@no42.org>
 * SPDX-License-Identifier: Apache-2.0
 */

package main

import (
	"os"
	"os/exec"
	"strconv"
	"strings"
	"testing"
)

// entityNoSuchObject is how net-snmp renders the noSuchObject exception.
const entityNoSuchObject = "No Such Object available on this agent at this OID"

// TestEntityRootInterop reads the fixed ENTITY-MIB rows with net-snmp through
// the real dispatcher on a real UDP socket. The in-package guards read resource
// files; this reads the wire. It matters most for zeroDotZero: the value only
// goes out as an OBJECT IDENTIFIER because oidTypeTable types the column, and a
// key the table does not match would send the string "0.0" instead. It also
// reads the inventory columns: the chassis serves no entPhysicalMfgDate,
// entPhysicalUris or entPhysicalUUID, and a port row names no invented vendor.
//
// Opt-in like the other interop tests; `make test-interop` runs it in CI.
func TestEntityRootInterop(t *testing.T) {
	if os.Getenv("NL6_SNMP_INTEROP") != "1" {
		t.Skip("set NL6_SNMP_INTEROP=1 to run the net-snmp interop check")
	}
	snmpget, err := exec.LookPath("snmpget")
	if err != nil {
		t.Fatalf("NL6_SNMP_INTEROP=1 but snmpget is not on PATH: %v", err)
	}

	cases := []struct {
		profile string
		want    map[string]string // OID -> net-snmp's rendering of the value
	}{
		{"cisco_nexus_9500.json", map[string]string{
			".1.3.6.1.2.1.47.1.1.1.1.4.1":    "INTEGER: 0",
			".1.3.6.1.2.1.47.1.1.1.1.5.1":    "INTEGER: 3",
			".1.3.6.1.2.1.47.1.1.1.1.6.1":    "INTEGER: -1",
			".1.3.6.1.2.1.47.1.1.1.1.9.1":    `""`,
			".1.3.6.1.2.1.47.1.1.1.1.3.1001": "OID: .0.0",
			// Control: the chassis vendor type is still a real OID, so the
			// zeroDotZero row above is not every row of the column degrading.
			".1.3.6.1.2.1.47.1.1.1.1.3.1":     "OID: .1.3.6.1.4.1.9.12.3.1.3.1467",
			".1.3.6.1.2.1.47.1.1.1.1.12.1":    `STRING: "Cisco Systems, Inc."`,
			".1.3.6.1.2.1.47.1.1.1.1.17.1":    entityNoSuchObject,
			".1.3.6.1.2.1.47.1.1.1.1.18.1":    entityNoSuchObject,
			".1.3.6.1.2.1.47.1.1.1.1.19.1":    entityNoSuchObject,
			".1.3.6.1.2.1.47.1.1.1.1.11.1001": `""`,
			".1.3.6.1.2.1.47.1.1.1.1.12.1001": `""`,
			".1.3.6.1.2.1.47.1.1.1.1.15.1001": `""`,
			// Control: the port keeps its name.
			".1.3.6.1.2.1.47.1.1.1.1.7.1001": `STRING: "Ethernet1/1"`,
		}},
		{"palo_alto_pa3220.json", map[string]string{
			".1.3.6.1.2.1.47.1.1.1.1.4.1":    "INTEGER: 0",
			".1.3.6.1.2.1.47.1.1.1.1.5.1":    "INTEGER: 3",
			".1.3.6.1.2.1.47.1.1.1.1.6.1":    "INTEGER: -1",
			".1.3.6.1.2.1.47.1.1.1.1.3.1016": "OID: .0.0",
		}},
		{"cisco_ios.json", map[string]string{
			".1.3.6.1.2.1.47.1.1.1.1.13.1": `STRING: "WS-C2960X-24TS-L"`,
			".1.3.6.1.2.1.47.1.1.1.1.13.2": `""`,
			".1.3.6.1.2.1.47.1.1.1.1.12.1": `STRING: "Cisco Systems, Inc."`,
			".1.3.6.1.2.1.47.1.1.1.1.18.1": entityNoSuchObject,
		}},
		{"juniper_mx10004.json", map[string]string{
			".1.3.6.1.2.1.47.1.1.1.1.12.1": `STRING: "Juniper Networks, Inc."`,
			".1.3.6.1.2.1.47.1.1.1.1.19.1": entityNoSuchObject,
		}},
	}
	for _, c := range cases {
		t.Run(c.profile, func(t *testing.T) {
			port, stop, _ := interopListener(t, deviceForProfile(t, c.profile))
			defer stop()
			target := "127.0.0.1:" + strconv.Itoa(port)
			for oid, want := range c.want {
				out, err := runNetSNMP(t, snmpget, "-v2c", "-c", "public", "-On", "-t", "3", "-r", "0", target, oid)
				if err != nil {
					t.Fatalf("snmpget %s failed: %v\n%s", oid, err, out)
				}
				if got := strings.TrimSpace(strings.TrimPrefix(out, oid+" =")); got != want {
					t.Errorf("%s %s: net-snmp read %q, want %q", c.profile, oid, got, want)
				}
			}
		})
	}
}
