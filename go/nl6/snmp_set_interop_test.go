/*
 * Copyright 2026 Ronny Trommer <ronny@no42.org>
 * SPDX-License-Identifier: Apache-2.0
 */

package main

import (
	"fmt"
	"net"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"
)

// The external check on SET (add-snmp-set D8, nl6#684). net-snmp's snmpset
// builds the SetRequest, its snmpget reads the result back, and its snmptrapd
// receives the link trap the cascade fires. An in-package encoder and decoder
// that share one reading of RFC 3416 §4.2.5 prove nothing about it, so every
// error-status row is asserted from net-snmp's OWN printed reason.
//
// Gated and shaped like snmpv3_usm_interop_test.go: NL6_SNMP_INTEROP=1, and a
// missing binary FAILS rather than skips. Run by `make test-interop`.

// interopListener serves BOTH dispatchers on a real udp4 socket, choosing by
// the message's version field exactly as handleSingleRequest does. It also
// keeps the last REQUEST so a run can capture a real snmpset datagram.
func interopListener(t *testing.T, s *SNMPServer) (port int, stop func(), lastRequest func() []byte) {
	t.Helper()
	var mu sync.Mutex
	var last []byte
	conn, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	done := make(chan struct{})
	go func() {
		defer close(done)
		buf := make([]byte, 65535)
		for {
			if err := conn.SetReadDeadline(time.Now().Add(50 * time.Millisecond)); err != nil {
				return
			}
			n, addr, err := conn.ReadFromUDP(buf)
			if err != nil {
				if ne, ok := err.(net.Error); ok && ne.Timeout() {
					select {
					case <-done:
						return
					default:
						continue
					}
				}
				return
			}
			req := append([]byte(nil), buf[:n]...)
			mu.Lock()
			last = req
			mu.Unlock()
			var resp []byte
			if isSNMPv3Request(req) {
				resp = s.handleSNMPv3Request(req)
			} else {
				resp = s.handleSNMPv2cRequest(req)
			}
			if len(resp) > 0 {
				_, _ = conn.WriteToUDP(resp, addr)
			}
		}
	}()
	return conn.LocalAddr().(*net.UDPAddr).Port, func() {
			_ = conn.Close()
			<-done
		}, func() []byte {
			mu.Lock()
			defer mu.Unlock()
			return append([]byte(nil), last...)
		}
}

// netsnmpArgs is the per-version prefix of an snmpset / snmpget command line.
func netsnmpArgs(version string, s *SNMPServer) []string {
	switch version {
	case "1":
		return []string{"-v1", "-c", "public", "-t", "3", "-r", "0"}
	case "2c":
		return []string{"-v2c", "-c", "public", "-t", "3", "-r", "0"}
	}
	return []string{"-v3", "-l", "authPriv", "-u", s.v3Config.Username,
		"-a", "SHA", "-A", s.v3Config.Password, "-x", "AES", "-X", s.v3Config.PrivPassword,
		"-t", "3", "-r", "0"}
}

func runNetSNMP(t *testing.T, bin string, args ...string) (string, error) {
	t.Helper()
	cmd := exec.Command(bin, args...)
	// No MIBs: numeric OIDs in and out, and no MIB-derived type check on
	// snmpset's side, so the wrongType row really reaches nl6.
	cmd.Env = append(os.Environ(), "MIBS=")
	out, err := cmd.CombinedOutput()
	return strings.TrimSpace(string(out)), err
}

func TestSNMPSetInterop(t *testing.T) {
	if os.Getenv("NL6_SNMP_INTEROP") != "1" {
		t.Skip("set NL6_SNMP_INTEROP=1 to run the net-snmp interop check (net-snmp is not installed by CI)")
	}
	snmpset, err := exec.LookPath("snmpset")
	if err != nil {
		t.Fatalf("NL6_SNMP_INTEROP=1 but snmpset is not on PATH: %v\nDebian/Ubuntu: sudo apt-get install -y snmp", err)
	}
	snmpget, err := exec.LookPath("snmpget")
	if err != nil {
		t.Fatalf("NL6_SNMP_INTEROP=1 but snmpget is not on PATH: %v", err)
	}

	const ifAdmin3 = ".1.3.6.1.2.1.2.2.1.7.3"
	const ifOper3 = ".1.3.6.1.2.1.2.2.1.8.3"

	for _, version := range []string{"1", "2c", "3"} {
		t.Run("v"+version, func(t *testing.T) {
			s, state := newSetTestServer(t, 3)
			if version == "3" {
				s.v3Config.AuthProtocol = SNMPV3_AUTH_SHA1
				s.v3Config.PrivProtocol = SNMPV3_PRIV_AES128
				s.v3Config.Password = "authpassword"
				s.v3Config.PrivPassword = "privpassword"
			}
			port, stop, _ := interopListener(t, s)
			defer stop()
			target := "127.0.0.1:" + strconv.Itoa(port)
			base := netsnmpArgs(version, s)

			set := func(oid, typ, val string) (string, error) {
				return runNetSNMP(t, snmpset, append(append([]string(nil), base...), target, oid, typ, val)...)
			}
			get := func(oid string) string {
				out, err := runNetSNMP(t, snmpget, append(append([]string(nil), base...), target, oid)...)
				if err != nil {
					t.Fatalf("snmpget %s: %v\n%s", oid, err, out)
				}
				return out
			}

			// Success path: 2, then 1, then 3, read back on BOTH columns.
			for _, v := range []string{"2", "1", "3"} {
				if out, err := set(ifAdmin3, "i", v); err != nil {
					t.Fatalf("snmpset ifAdminStatus.3 = %s failed: %v\n%s", v, err, out)
				}
				if out := get(ifAdmin3); !strings.Contains(out, "INTEGER: "+v) {
					t.Errorf("after set %s, snmpget ifAdminStatus.3 printed %q", v, out)
				}
				if out := get(ifOper3); !strings.Contains(out, "INTEGER: "+v) {
					t.Errorf("after set %s, snmpget ifOperStatus.3 printed %q; oper did not follow", v, out)
				}
			}

			// The ladder, by net-snmp's own printed reason. v1 prints the RFC
			// 3584 §4.3 mapping.
			v1 := version == "1"
			pick := func(v2, v1name string) string {
				if v1 {
					return v1name
				}
				return v2
			}
			rows := []struct {
				name           string
				oid, typ, val  string
				wantReason     string
				wantUnchanged3 bool
			}{
				{"out of range", ifAdmin3, "i", "5", pick("wrongValue", "badValue"), true},
				{"read-only object", oidSysDescr0, "s", "x", pick("notWritable", "noSuchName"), true},
				{"wrong type", ifAdmin3, "s", "down", pick("wrongType", "badValue"), true},
				{"unknown instance", ".1.3.6.1.2.1.2.2.1.7.999", "i", "2", pick("noCreation", "noSuchName"), true},
			}
			before := state.Snapshot(3)
			for _, r := range rows {
				out, err := set(r.oid, r.typ, r.val)
				if err == nil {
					t.Errorf("%s: snmpset SUCCEEDED, want %s\n%s", r.name, r.wantReason, out)
					continue
				}
				if !strings.Contains(out, r.wantReason) {
					t.Errorf("%s: snmpset did not report %s:\n%s", r.name, r.wantReason, out)
				}
				if r.wantUnchanged3 && state.Snapshot(3) != before {
					t.Errorf("%s: a refused SET moved interface 3", r.name)
				}
			}

			// Two bindings, the second offending: nothing applied.
			out, err := runNetSNMP(t, snmpset, append(append([]string(nil), base...), target,
				ifAdmin3, "i", "2", oidSysDescr0, "s", "x")...)
			if err == nil {
				t.Errorf("two-binding SET with a read-only second binding SUCCEEDED\n%s", out)
			}
			if !strings.Contains(out, pick("notWritable", "noSuchName")) {
				t.Errorf("two-binding SET reason:\n%s", out)
			}
			if state.Snapshot(3) != before {
				t.Error("two-binding SET applied its first binding although the second failed")
			}
		})
	}
}

// TestSNMPSetInteropFiresLinkTrap is the trap half: snmpset drives the
// cascade, and snmptrapd receives the linkDown and then the linkUp the
// oper transition fires through the real attach path.
func TestSNMPSetInteropFiresLinkTrap(t *testing.T) {
	if os.Getenv("NL6_SNMP_INTEROP") != "1" {
		t.Skip("set NL6_SNMP_INTEROP=1 to run the net-snmp interop check")
	}
	snmpset, err := exec.LookPath("snmpset")
	if err != nil {
		t.Fatalf("NL6_SNMP_INTEROP=1 but snmpset is not on PATH: %v", err)
	}
	snmptrapd, err := exec.LookPath("snmptrapd")
	if err != nil {
		t.Fatalf("NL6_SNMP_INTEROP=1 but snmptrapd is not on PATH: %v\n"+
			"Debian/Ubuntu: sudo apt-get install -y snmptrapd (it is NOT in the `snmp` package)", err)
	}

	trapPort, output := snmptrapdRun(t, snmptrapd, "disableAuthorization yes\nauthCommunity log public\n")

	sm := newTestSimulatorManager()
	if err := sm.StartTrapSubsystem(TrapSubsystemConfig{
		PDUBudget:             maxTrapPDU,
		SourcePerDevice:       false,
		MeanSchedulerInterval: time.Hour,
	}); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(sm.StopTrapExport)

	deviceIP := net.IPv4(127, 0, 0, 1)
	device := setupTestDeviceForAttach(t, sm, "dev-set-interop", deviceIP)
	res := buildTestResources(t, []uint64{1_000_000_000, 1_000_000_000, 1_000_000_000})
	for i := 1; i <= 3; i++ {
		res.oidIndex.Store(fmt.Sprintf("%s.%d", oidIfAdminStatus, i), "1")
		res.oidIndex.Store(fmt.Sprintf("%s.%d", oidIfOperStatus, i), "1")
	}
	device.metricsCycler = NewMetricsCycler(0, GetDeviceProfile(""))
	device.metricsCycler.InitIfCountersWithScenario(res, 1, IfErrorClean)
	device.trapConfig = &DeviceTrapConfig{
		Collector:     "127.0.0.1:" + strconv.Itoa(trapPort),
		Mode:          "trap",
		Community:     "public",
		Interval:      jsonDuration(time.Hour),
		InformTimeout: jsonDuration(200 * time.Millisecond),
	}
	if err := sm.startDeviceTrapExporter(device); err != nil {
		t.Fatalf("startDeviceTrapExporter: %v", err)
	}
	sm.mu.Lock()
	sm.indexDeviceByIP(device)
	sm.mu.Unlock()

	s := &SNMPServer{device: device}
	port, stop, _ := interopListener(t, s)
	defer stop()
	target := "127.0.0.1:" + strconv.Itoa(port)

	const linkDown = "1.3.6.1.6.3.1.1.5.3"
	const linkUp = "1.3.6.1.6.3.1.1.5.4"
	for _, step := range []struct{ val, wantTrap string }{{"2", linkDown}, {"1", linkUp}} {
		out, err := runNetSNMP(t, snmpset, "-v2c", "-c", "public", "-t", "3", "-r", "0", target,
			".1.3.6.1.2.1.2.2.1.7.3", "i", step.val)
		if err != nil {
			t.Fatalf("snmpset ifAdminStatus.3 = %s: %v\n%s", step.val, err, out)
		}
		deadline := time.Now().Add(snmptrapdDeliveryWindow)
		logged := ""
		for time.Now().Before(deadline) {
			logged = output()
			if strings.Contains(logged, step.wantTrap) {
				break
			}
			time.Sleep(100 * time.Millisecond)
		}
		if !strings.Contains(logged, step.wantTrap) {
			t.Fatalf("snmptrapd never logged %s after snmpset ifAdminStatus.3 = %s.\n"+
				"The SET was answered noError (snmpset exited 0), so the failure is the CASCADE or the "+
				"notify wiring: admin moved but no oper transition reached the trap exporter.\n"+
				"snmptrapd said:\n%s", step.wantTrap, step.val, logged)
		}
	}
	st := sm.GetTrapStatus()
	if len(st.Collectors) != 1 || st.Collectors[0].Sent < 2 {
		t.Errorf("trap status %+v, want one collector with at least two traps sent", st.Collectors)
	}
}
