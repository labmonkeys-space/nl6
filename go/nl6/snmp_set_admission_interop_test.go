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

// The external check on write ADMISSION (nl6#690). Every other admission test
// in this package drives nl6's dispatcher with nl6's own request builder, so a
// shared misunderstanding of what a manager actually puts on the wire passes
// all of them — which is the failure mode nl6#625 recorded in full.
//
// net-snmp builds the datagrams here. Two things are asserted that the Go tests
// cannot: that a real manager's SET with the wrong community is met with
// SILENCE (which snmpset reports as a timeout, not an SNMP error), and that a
// real manager's noAuthNoPriv v3 SET below the minimum gets a Report net-snmp
// itself recognises as an unsupported security level.
//
// EVERY negative row carries a POSITIVE CONTROL on the same listener. A
// timeout on its own cannot tell a refusal from a dead listener, a closed port
// or a panicking handler, so each refusal is bracketed by a request that must
// succeed against the very same socket. Without that bracket these rows would
// pass against a build in which SET had been deleted entirely.
//
// Gated like its siblings: NL6_SNMP_INTEROP=1, a missing binary FAILS rather
// than skips, run by `make test-interop`.

// setCommunityArgs is netsnmpArgs for v1/v2c with the community as a parameter
// — netsnmpArgs hardcodes "public", which cannot express a mismatch.
func setCommunityArgs(version, community string) []string {
	v := "-v2c"
	if version == "1" {
		v = "-v1"
	}
	// -t 1 -r 0: one second, no retries. A refusal is a timeout here, and the
	// default (5s, 5 retries) would spend 30 seconds per refused row.
	return []string{v, "-c", community, "-t", "1", "-r", "0"}
}

func TestSNMPSetInteropWriteCommunity(t *testing.T) {
	if os.Getenv("NL6_SNMP_INTEROP") != "1" {
		t.Skip("set NL6_SNMP_INTEROP=1 to run the net-snmp interop check")
	}
	snmpset, err := exec.LookPath("snmpset")
	if err != nil {
		t.Fatalf("NL6_SNMP_INTEROP=1 but snmpset is not on PATH: %v", err)
	}
	snmpget, err := exec.LookPath("snmpget")
	if err != nil {
		t.Fatalf("NL6_SNMP_INTEROP=1 but snmpget is not on PATH: %v", err)
	}

	const ifAdmin3 = ".1.3.6.1.2.1.2.2.1.7.3"

	cases := []struct {
		name      string
		configure string
	}{
		{"a configured write community", "writeme"},
		// The shipped default. `snmpset` against a fleet nobody configured for
		// writes must not work, and this is the row that says so from outside.
		{"no write community configured", ""},
	}
	for _, c := range cases {
		for _, version := range []string{"1", "2c"} {
			t.Run(c.name+"/v"+version, func(t *testing.T) {
				s, state := newSetTestServer(t, 3)
				s.setAdmission = setAdmissionConfig{WriteCommunity: c.configure}
				port, stop, _ := interopListener(t, s)
				defer stop()
				target := "127.0.0.1:" + strconv.Itoa(port)

				set := func(community, val string) (string, error) {
					return runNetSNMP(t, snmpset,
						append(append(setCommunityArgs(version, community), target), ifAdmin3, "i", val)...)
				}
				get := func(community string) (string, error) {
					return runNetSNMP(t, snmpget,
						append(append(setCommunityArgs(version, community), target), ifAdmin3)...)
				}

				before := state.Snapshot(3)

				// POSITIVE CONTROL FIRST: the listener answers reads, with a
				// community that is not the write community. Everything below
				// is meaningless without this.
				out, err := get("definitely-not-the-write-community")
				if err != nil {
					t.Fatalf("the control snmpget failed, so no refusal below means anything: %v\n%s", err, out)
				}
				if !strings.Contains(out, "INTEGER:") {
					t.Fatalf("the control snmpget did not read a value: %s", out)
				}

				// The refusal: silence, which net-snmp reports as a timeout
				// rather than as an SNMP error-status.
				out, err = set("wrong-community", "2")
				if err == nil {
					t.Fatalf("snmpset with the wrong community SUCCEEDED\n%s", out)
				}
				if !strings.Contains(strings.ToLower(out), "timeout") {
					t.Errorf("snmpset with the wrong community was ANSWERED rather than ignored; "+
						"a community mismatch must be met with silence, as real hardware does:\n%s", out)
				}
				if state.Snapshot(3) != before {
					t.Fatal("a refused SET moved interface 3")
				}

				if c.configure == "" {
					// Nothing can be admitted, so the closing control is
					// another read rather than a write.
					if out, err := get("anything"); err != nil {
						t.Fatalf("the closing control snmpget failed: %v\n%s", err, out)
					}
					return
				}

				// CLOSING CONTROL: the same listener, the right community,
				// succeeds — so the timeout above was a refusal and not a dead
				// socket.
				if out, err := set(c.configure, "2"); err != nil {
					t.Fatalf("snmpset with the CONFIGURED write community failed: %v\n%s", err, out)
				}
				if got := state.Snapshot(3).Admin; got != 2 {
					t.Errorf("ifAdminStatus.3 = %d after an admitted snmpset, want 2", got)
				}
			})
		}
	}
}

// A real manager's noAuthNoPriv SET against an authPriv device is refused by
// the minimum security level, and net-snmp recognises the Report.
func TestSNMPSetInteropMinimumSecurityLevel(t *testing.T) {
	if os.Getenv("NL6_SNMP_INTEROP") != "1" {
		t.Skip("set NL6_SNMP_INTEROP=1 to run the net-snmp interop check")
	}
	snmpset, err := exec.LookPath("snmpset")
	if err != nil {
		t.Fatalf("NL6_SNMP_INTEROP=1 but snmpset is not on PATH: %v", err)
	}
	snmpget, err := exec.LookPath("snmpget")
	if err != nil {
		t.Fatalf("NL6_SNMP_INTEROP=1 but snmpget is not on PATH: %v", err)
	}

	const ifAdmin3 = ".1.3.6.1.2.1.2.2.1.7.3"

	s, state := newSetTestServer(t, 3)
	s.v3Config.AuthProtocol = SNMPV3_AUTH_SHA1
	s.v3Config.PrivProtocol = SNMPV3_PRIV_AES128
	s.v3Config.Password = "authpassword"
	s.v3Config.PrivPassword = "privpassword"
	// The shipped default, stated rather than inherited: authNoPriv.
	s.setAdmission = setAdmissionConfig{MinSecurityLevel: securityLevelAuthNoPriv}

	port, stop, _ := interopListener(t, s)
	defer stop()
	target := "127.0.0.1:" + strconv.Itoa(port)
	authPriv := netsnmpArgs("3", s)
	noAuth := []string{"-v3", "-l", "noAuthNoPriv", "-u", s.v3Config.Username, "-t", "1", "-r", "0"}

	before := state.Snapshot(3)

	// POSITIVE CONTROL: authPriv reads work on this listener.
	out, err := runNetSNMP(t, snmpget, append(append([]string(nil), authPriv...), target, ifAdmin3)...)
	if err != nil {
		t.Fatalf("the control authPriv snmpget failed, so nothing below means anything: %v\n%s", err, out)
	}

	// The refusal.
	out, err = runNetSNMP(t, snmpset, append(append([]string(nil), noAuth...), target, ifAdmin3, "i", "2")...)
	if err == nil {
		t.Fatalf("a noAuthNoPriv snmpset SUCCEEDED against an authPriv device with an authNoPriv minimum\n%s", out)
	}
	// net-snmp prints "Unsupported security level" for the Report; a timeout
	// would mean nl6 answered nothing, which is the v1/v2c shape and wrong
	// here — RFC 3414 §3.2 step 5 prescribes a Report.
	low := strings.ToLower(out)
	if strings.Contains(low, "timeout") {
		t.Errorf("a v3 SET below the minimum was met with SILENCE; RFC 3414 §3.2 step 5 wants a Report:\n%s", out)
	}
	if !strings.Contains(low, "security level") && !strings.Contains(low, "securitylevel") {
		t.Errorf("net-snmp did not recognise the refusal as an unsupported security level:\n%s", out)
	}
	if state.Snapshot(3) != before {
		t.Fatal("a refused v3 SET moved interface 3")
	}

	// CLOSING CONTROL: at the minimum, the same listener accepts the write.
	out, err = runNetSNMP(t, snmpset, append(append([]string(nil), authPriv...), target, ifAdmin3, "i", "2")...)
	if err != nil {
		t.Fatalf("an authPriv snmpset at or above the minimum failed: %v\n%s", err, out)
	}
	if got := state.Snapshot(3).Admin; got != 2 {
		t.Errorf("ifAdminStatus.3 = %d after an admitted authPriv snmpset, want 2", got)
	}
}
