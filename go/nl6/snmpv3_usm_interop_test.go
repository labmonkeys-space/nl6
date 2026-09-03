/*
 * Copyright 2026 Ronny Trommer <ronny@no42.org>
 * SPDX-License-Identifier: Apache-2.0
 */

package main

import (
	"net"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"testing"
	"time"
)

// snmpv3_usm_interop_test.go — nl6#624's EXTERNAL verification.
//
// WHY THIS FILE EXISTS AT ALL. Every other SNMPv3 test in this package reads
// nl6's output with nl6's own parser, so a shared misunderstanding of RFC 3414
// passes all of them. That is not hypothetical here: nl6 shipped a v3 stack for
// years that computed no digest, sent a UNIX epoch as engine time and localized
// keys against the wrong bytes, and the whole suite was green. Only an
// independent implementation can tell you whether a manager accepts any of it.
//
// net-snmp does the half nl6 cannot check for itself: it discovers the engine,
// derives its OWN key from the password and the engine ID it RECEIVED, verifies
// the digest nl6 computed, and — for authPriv — decrypts with an IV it built
// independently. A pass means two implementations agree; a failure names the
// disagreement.
//
// IT IS OPT-IN, AND THAT IS A REAL LIMITATION, NOT A PREFERENCE. No workflow in
// this repo installs net-snmp, so a test that skipped when the binary is absent
// would assert nothing in CI while looking like coverage — the same failure mode
// the MIB fixtures under testdata/mibs/ were structured to avoid. Requiring
// NL6_SNMP_INTEROP=1 makes the skip an explicit choice rather than a silent one.
// Run it with:
//
//	NL6_SNMP_INTEROP=1 go test ./nl6/ -run TestUSMInteropWithNetSNMP -v
//
// RECORDED RESULT (2026-09-03, net-snmp 5.6.2.1, darwin/arm64): all six rows
// pass — noAuthNoPriv, authNoPriv under MD5 and SHA1, and authPriv under
// MD5+DES, MD5+AES128 and SHA1+AES128 — plus the wrong-password control.
//
// ITS FIRST RUN FAILED ALL SIX WITH THE REST OF THE PACKAGE GREEN, which is the
// whole argument for the file. nl6#624 corrected the engine ID in
// wrapScopedPDUInV3Message and left three other emitters — the discovery
// response, the Report response and createDiscoveryScopedPDU — sending the hex
// SPELLING and a UNIX epoch. A manager discovers the engine from the FIRST of
// those and localizes its key with what it received, so it derived a different
// key than nl6 did and rejected every authenticated response. Nothing in the
// package compared one emitter against another, so nothing failed.
// TestEveryEmitterAgreesOnTheEngineIdentity now does, but it was written
// AFTERWARDS, from a defect this test found.

// v3InteropListener serves handleSNMPv3Request on a real UDP socket.
//
// It is the dispatcher under test, reached the way a real manager reaches it,
// rather than a helper that calls the encoder directly: the seam nl6#527 broke
// was exactly a dispatcher-versus-direct-call difference.
func v3InteropListener(t *testing.T, s *SNMPServer) (port int, stop func()) {
	t.Helper()
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
			if resp := s.handleSNMPv3Request(req); len(resp) > 0 {
				_, _ = conn.WriteToUDP(resp, addr)
			}
		}
	}()
	return conn.LocalAddr().(*net.UDPAddr).Port, func() {
		_ = conn.Close()
		<-done
	}
}

func TestUSMInteropWithNetSNMP(t *testing.T) {
	if os.Getenv("NL6_SNMP_INTEROP") != "1" {
		t.Skip("set NL6_SNMP_INTEROP=1 to run the net-snmp interop check (net-snmp is not installed by CI)")
	}
	snmpget, err := exec.LookPath("snmpget")
	if err != nil {
		t.Fatalf("NL6_SNMP_INTEROP=1 but snmpget is not on PATH: %v", err)
	}

	const probeOID = ".1.3.6.1.2.1.1.1.0"
	const probeValue = "nl6 usm interop probe"

	rows := []struct {
		name      string
		level     string
		auth      int
		authName  string
		priv      int
		privName  string
		expectErr bool
	}{
		{name: "noAuthNoPriv", level: "noAuthNoPriv"},
		{name: "authNoPriv/md5", level: "authNoPriv", auth: SNMPV3_AUTH_MD5, authName: "MD5"},
		{name: "authNoPriv/sha1", level: "authNoPriv", auth: SNMPV3_AUTH_SHA1, authName: "SHA"},
		{name: "authPriv/md5+des", level: "authPriv", auth: SNMPV3_AUTH_MD5, authName: "MD5",
			priv: SNMPV3_PRIV_DES, privName: "DES"},
		{name: "authPriv/md5+aes", level: "authPriv", auth: SNMPV3_AUTH_MD5, authName: "MD5",
			priv: SNMPV3_PRIV_AES128, privName: "AES"},
		{name: "authPriv/sha1+aes", level: "authPriv", auth: SNMPV3_AUTH_SHA1, authName: "SHA",
			priv: SNMPV3_PRIV_AES128, privName: "AES"},
	}

	for _, r := range rows {
		t.Run(r.name, func(t *testing.T) {
			s := v3TestServer(map[string]string{probeOID: probeValue})
			s.v3Config.AuthProtocol = r.auth
			s.v3Config.PrivProtocol = r.priv
			s.v3Config.Password = "authpassword"
			s.v3Config.PrivPassword = "privpassword"

			port, stop := v3InteropListener(t, s)
			defer stop()

			args := []string{"-v3", "-l", r.level, "-u", s.v3Config.Username, "-t", "3", "-r", "0"}
			if r.auth != 0 {
				args = append(args, "-a", r.authName, "-A", s.v3Config.Password)
			}
			if r.priv != 0 {
				args = append(args, "-x", r.privName, "-X", s.v3Config.PrivPassword)
			}
			args = append(args, "127.0.0.1:"+strconv.Itoa(port), probeOID)

			out, err := exec.Command(snmpget, args...).CombinedOutput()
			got := strings.TrimSpace(string(out))
			if err != nil {
				t.Fatalf("snmpget %s failed: %v\noutput: %s\n\nnet-snmp derived its own key from the "+
					"password and the engine ID nl6 sent, and rejected what nl6 produced. That is an "+
					"interop defect no in-package test can see.", strings.Join(args, " "), err, got)
			}
			if !strings.Contains(got, probeValue) {
				t.Errorf("snmpget returned %q, want it to contain %q", got, probeValue)
			}
		})
	}
}

// TestUSMInteropRejectsAWrongPassword is the control for the test above.
//
// Without it, an agent that accepted every message would pass every row: six
// successful polls prove nl6 is reachable, not that it authenticates. This row
// requires net-snmp's poll to FAIL when the password is wrong, which is the
// property nl6#625 found missing and the one an operator testing a collector's
// wrong-credential handling actually depends on.
func TestUSMInteropRejectsAWrongPassword(t *testing.T) {
	if os.Getenv("NL6_SNMP_INTEROP") != "1" {
		t.Skip("set NL6_SNMP_INTEROP=1 to run the net-snmp interop check")
	}
	snmpget, err := exec.LookPath("snmpget")
	if err != nil {
		t.Fatalf("NL6_SNMP_INTEROP=1 but snmpget is not on PATH: %v", err)
	}

	const probeOID = ".1.3.6.1.2.1.1.1.0"
	s := v3TestServer(map[string]string{probeOID: "nl6 usm interop probe"})
	s.v3Config.AuthProtocol = SNMPV3_AUTH_MD5
	s.v3Config.Password = "authpassword"

	port, stop := v3InteropListener(t, s)
	defer stop()

	out, err := exec.Command(snmpget, "-v3", "-l", "authNoPriv", "-u", s.v3Config.Username,
		"-a", "MD5", "-A", "the-wrong-password", "-t", "3", "-r", "0",
		"127.0.0.1:"+strconv.Itoa(port), probeOID).CombinedOutput()
	if err == nil {
		t.Fatalf("snmpget SUCCEEDED with the wrong password, so nl6 is not verifying inbound "+
			"authentication.\noutput: %s", strings.TrimSpace(string(out)))
	}
	if got := strings.TrimSpace(string(out)); !strings.Contains(strings.ToLower(got), "authentication") &&
		!strings.Contains(strings.ToLower(got), "digest") {
		t.Logf("rejected, but the diagnosis net-snmp printed is not about authentication: %s", got)
	}
}
