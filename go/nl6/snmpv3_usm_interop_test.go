/*
 * Copyright 2026 Ronny Trommer <ronny@no42.org>
 * SPDX-License-Identifier: Apache-2.0
 */

package main

import (
	"encoding/hex"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
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
//	NL6_SNMP_INTEROP=1 go test ./nl6/ -run TestUSMInterop -v
//
// TestUSMInterop, not TestUSMInteropWithNetSNMP: the shorter pattern also runs
// the wrong-password control, without which six successful polls prove
// reachability rather than authentication.
//
// IT RUNS IN CI. The Build & Test gate installs net-snmp and calls
// `make test-interop`, so every push polls nl6 with net-snmp 5.9.4 on Linux.
// It was opt-in when it landed, which would have retired the one check here
// with detection power: nothing else in the package can see a disagreement
// between nl6 and a real manager.
//
// RECORDED RESULT (2026-09-03, net-snmp 5.6.2.1 on darwin/arm64 and 5.9.4 in
// CI on linux/amd64): all SEVEN rows
// pass — noAuthNoPriv, authNoPriv under MD5 and SHA1, and authPriv under
// MD5+DES, SHA1+DES, MD5+AES128 and SHA1+AES128 — plus the wrong-password
// control. Every combination of the two auth protocols with the two privacy
// protocols is covered, which matters because the localized privacy key is 16
// octets under MD5 and 20 under SHA1 while both consumers slice it at fixed
// indices.
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
func v3InteropListener(t *testing.T, s *SNMPServer) (port int, stop func(), lastResponse func() []byte) {
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
			if resp := s.handleSNMPv3Request(req); len(resp) > 0 {
				mu.Lock()
				last = append([]byte(nil), resp...)
				mu.Unlock()
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
		name     string
		level    string
		auth     int
		authName string
		priv     int
		privName string
	}{
		{name: "noAuthNoPriv", level: "noAuthNoPriv"},
		{name: "authNoPriv/md5", level: "authNoPriv", auth: SNMPV3_AUTH_MD5, authName: "MD5"},
		{name: "authNoPriv/sha1", level: "authNoPriv", auth: SNMPV3_AUTH_SHA1, authName: "SHA"},
		{name: "authPriv/md5+des", level: "authPriv", auth: SNMPV3_AUTH_MD5, authName: "MD5",
			priv: SNMPV3_PRIV_DES, privName: "DES"},
		{name: "authPriv/sha1+des", level: "authPriv", auth: SNMPV3_AUTH_SHA1, authName: "SHA",
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

			port, stop, _ := v3InteropListener(t, s)
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

	port, stop, lastResponse := v3InteropListener(t, s)
	defer stop()

	out, err := exec.Command(snmpget, "-v3", "-l", "authNoPriv", "-u", s.v3Config.Username,
		"-a", "MD5", "-A", "the-wrong-password", "-t", "3", "-r", "0",
		"127.0.0.1:"+strconv.Itoa(port), probeOID).CombinedOutput()
	if err == nil {
		t.Fatalf("snmpget SUCCEEDED with the wrong password, so nl6 is not verifying inbound "+
			"authentication.\noutput: %s", strings.TrimSpace(string(out)))
	}

	// A NON-ZERO EXIT IS NOT THE PROPERTY. snmpget also exits non-zero on a
	// timeout, which is what nl6 does when it drops a datagram — so "it
	// failed" is satisfied by nl6 saying nothing at all, and this control
	// would pass against an agent that had no USM in it. What distinguishes
	// rejection from silence is that nl6 ANSWERED, with a Report naming
	// usmStatsWrongDigests.
	resp := lastResponse()
	if len(resp) == 0 {
		t.Fatalf("nl6 sent no response at all: the wrong password was met with silence, which a "+
			"collector cannot tell from an unreachable device.\nsnmpget said: %s",
			strings.TrimSpace(string(out)))
	}
	if got := reportOIDOf(t, s, resp); got != strings.TrimPrefix(oidUsmStatsWrongDigests, ".") &&
		got != oidUsmStatsWrongDigests {
		t.Errorf("nl6 answered the wrong password with %q, want a Report naming usmStatsWrongDigests "+
			"(%s).\nsnmpget said: %s", got, oidUsmStatsWrongDigests, strings.TrimSpace(string(out)))
	}
}

// ── the notification half (nl6#98) ──────────────────────────────────────────
//
// snmpget cannot check a TRAP: nothing polls a notification. snmptrapd is the
// receiving half of the same net-snmp stack — it localizes ITS key from the
// password and the engine ID the trap CARRIES, verifies the digest nl6 computed,
// and decrypts with an IV it built for itself.
//
// A TRAP HAS NO DISCOVERY, which is why snmptrapd's user is created with `-e`:
// the receiver cannot ask the sender for its engine ID, so it must be told which
// engine to localize against. That makes this test the direct check on nl6#98's
// central decision — a per-device engine ID derived from the device address —
// because the config below names the engine nl6 will claim, and a mismatch shows
// up as a dropped trap rather than as a diagnosable error.
//
// PACKAGING: on Debian and Ubuntu snmptrapd is in its OWN package (`snmptrapd`,
// universe), NOT in `snmp`, which is client tools only, and not in `snmpd`,
// which is the agent. Verified on Ubuntu 24.04, the runner the gate uses.

// snmptrapdDeliveryWindow is how long BOTH the positive rows and the
// wrong-password control give snmptrapd to log a trap.
//
// SHARED DELIBERATELY. The control asserts an ABSENCE, so if it waited less
// than a positive row does it could pass by timing out on a slow runner — the
// same runner on which the positive rows were closest to failing. One constant
// makes that impossible to reintroduce.
const snmptrapdDeliveryWindow = 10 * time.Second

// snmptrapdRun starts snmptrapd on a free UDP port with the given config and
// returns the port plus a reader for everything it has logged so far.
//
// THE ACCESSOR IS READ-ONLY AND THE KILL IS t.Cleanup's. An earlier shape
// returned one function that both stopped the daemon and returned its log,
// which meant polling the log killed the receiver on the first poll and every
// row would have "failed to log the trap" for the wrong reason.
//
// SNMP_PERSISTENT_DIR is redirected into the test's temp dir: net-snmp writes
// its persistent USM state to /var/lib/snmp by default, which a CI job does not
// own, and the failure is a confusing permissions warning rather than a clear
// one.
func snmptrapdRun(t *testing.T, snmptrapd, config string) (port int, output func() string) {
	t.Helper()

	// Ask the kernel for a free UDP port and HOLD IT until snmptrapd is
	// launched, so the window in which another process can take the number is
	// as small as the API allows. Closing it immediately, as an earlier cut
	// did, leaves that window open across a config write and a file create —
	// nine times per run on a required CI gate, which is often enough for a
	// once-in-a-while flake to become a regular one.
	//
	// It cannot be closed to zero: snmptrapd must bind the port itself, so
	// there is always a gap between our close and its bind. Parsing the port out
	// of snmptrapd's own log was the alternative and it does not exist —
	// net-snmp logs no listening address at any verbosity this test can rely on.
	probe, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatalf("probe listen: %v", err)
	}
	port = probe.LocalAddr().(*net.UDPAddr).Port

	dir := t.TempDir()
	confPath := filepath.Join(dir, "snmptrapd.conf")
	if err := os.WriteFile(confPath, []byte(config), 0o600); err != nil {
		t.Fatalf("write snmptrapd.conf: %v", err)
	}

	// -f: stay in the foreground. -Lo: log to stdout. -C -c: read ONLY our
	// config, so a host's /etc/snmp/snmptrapd.conf cannot change the result.
	// -On: numeric OIDs, so no MIBs need to be installed for the assertions
	// below to read.
	cmd := exec.Command(snmptrapd, "-f", "-Lo", "-On", "-C", "-c", confPath,
		"udp:127.0.0.1:"+strconv.Itoa(port))
	cmd.Env = append(os.Environ(), "SNMP_PERSISTENT_DIR="+dir, "MIBS=")
	var out lockedBuffer
	cmd.Stdout = &out
	cmd.Stderr = &out
	// Released as late as possible — immediately before the daemon binds it.
	_ = probe.Close()
	if err := cmd.Start(); err != nil {
		t.Fatalf("start snmptrapd: %v", err)
	}

	t.Cleanup(func() {
		_ = cmd.Process.Kill()
		_ = cmd.Wait()
	})

	// Wait for it to announce itself before sending anything. A trap posted to
	// a socket nobody has bound yet is lost with no error — UDP — so without
	// this the test would be a flake generator.
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		if strings.Contains(out.String(), "NET-SNMP version") {
			return port, out.String
		}
		time.Sleep(50 * time.Millisecond)
	}
	t.Fatalf("snmptrapd did not start within 10s; it said:\n%s", out.String())
	return 0, out.String
}

// lockedBuffer is a strings.Builder safe for the exec goroutine to write while
// the test polls it.
type lockedBuffer struct {
	mu  sync.Mutex
	buf strings.Builder
}

func (b *lockedBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.Write(p)
}

func (b *lockedBuffer) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.String()
}

// snmptrapdUserConfig writes the createUser/authUser pair for one security
// level, naming the engine ID nl6 will claim.
func snmptrapdUserConfig(engineID []byte, cfg TrapV3Config) string {
	user := cfg.UserName
	line := "createUser -e 0x" + hex.EncodeToString(engineID) + " " + user
	level := "noauth"
	switch cfg.AuthProtocol {
	case SNMPV3_AUTH_MD5:
		line += " MD5 \"" + cfg.Password + "\""
		level = "auth"
	case SNMPV3_AUTH_SHA1:
		line += " SHA \"" + cfg.Password + "\""
		level = "auth"
	}
	switch cfg.PrivProtocol {
	case SNMPV3_PRIV_DES:
		line += " DES \"" + cfg.PrivPassword + "\""
		level = "priv"
	case SNMPV3_PRIV_AES128:
		line += " AES \"" + cfg.PrivPassword + "\""
		level = "priv"
	}
	// `disableAuthorization yes` turns off snmptrapd's ACCESS CONTROL — which
	// notification sources it will act on — and NOTHING about USM. A trap whose
	// digest does not verify, or whose ciphertext will not decrypt, is still
	// dropped by the security model before access control is consulted, which
	// is why the wrong-password control below still has teeth.
	//
	// IT IS HERE BECAUSE `authUser` IS NOT UNIVERSAL: net-snmp 5.6.2.1, which is
	// what macOS ships, does not register that token at all and answers every
	// trap with "No access configuration - dropping trap". Relying on authUser
	// alone made all seven rows fail on a developer machine for a reason that
	// had nothing to do with nl6. The authUser line is kept for the builds that
	// do have it, so the config is the stricter one wherever it can be.
	return "disableAuthorization yes\n" + line + "\nauthUser log " + user + " " + level + "\n"
}

// TestSNMPv3TrapInteropWithSnmptrapd is the external check on nl6#98.
//
// Seven rows, the same sweep the poll side runs: noAuthNoPriv, authNoPriv under
// both hashes, and authPriv at all four hash × cipher pairs. Crossing both
// hashes with both ciphers is not thoroughness for its own sake — nl6#624 found
// the two privacy derivations hardcoding OPPOSITE hashes, so md5+des and
// sha1+aes were accidentally right while the other two were wrong, and a
// diagonal saw nothing.
func TestSNMPv3TrapInteropWithSnmptrapd(t *testing.T) {
	if os.Getenv("NL6_SNMP_INTEROP") != "1" {
		t.Skip("set NL6_SNMP_INTEROP=1 to run the net-snmp interop check (net-snmp is not installed by CI)")
	}
	snmptrapd, err := exec.LookPath("snmptrapd")
	if err != nil {
		// NOT a skip. A silent skip is the failure mode testdata/mibs was
		// structured to avoid, and on Debian/Ubuntu the binary is in a
		// DIFFERENT package from snmpget — so a gate that installed `snmp` and
		// nothing else would run the poll rows and quietly skip these.
		t.Fatalf("NL6_SNMP_INTEROP=1 but snmptrapd is not on PATH: %v\n"+
			"Debian/Ubuntu: sudo apt-get install -y snmptrapd (it is NOT in the `snmp` package)", err)
	}

	deviceIP := net.IPv4(127, 0, 0, 1)
	engineID := snmpv3TrapEngineID(deviceIP)

	for _, row := range v3TrapRows {
		t.Run(row.name, func(t *testing.T) {
			cfg := v3TrapTestConfig(row.auth, row.priv)
			enc, err := NewSNMPv3TrapEncoder(deviceIP, cfg)
			if err != nil {
				t.Fatalf("NewSNMPv3TrapEncoder: %v", err)
			}

			port, output := snmptrapdRun(t, snmptrapd, snmptrapdUserConfig(engineID, cfg))

			buf := make([]byte, maxTrapPDU)
			n, err := enc.EncodeTrap("", 4242, v3TrapOID, v3TrapEnterprise, v3TrapUptime,
				v3TrapVarbinds, buf)
			if err != nil {
				t.Fatalf("EncodeTrap: %v", err)
			}

			// Sent repeatedly until the receiver logs it or the deadline
			// passes. UDP to a freshly-started daemon is lossy in a way that
			// says nothing about the encoding.
			conn, err := net.Dial("udp4", "127.0.0.1:"+strconv.Itoa(port))
			if err != nil {
				t.Fatalf("dial snmptrapd: %v", err)
			}
			defer func() { _ = conn.Close() }()

			const wantValue = "sim-9"
			deadline := time.Now().Add(snmptrapdDeliveryWindow)
			logged := ""
			for time.Now().Before(deadline) {
				if _, err := conn.Write(buf[:n]); err != nil {
					t.Fatalf("send trap: %v", err)
				}
				time.Sleep(200 * time.Millisecond)
				logged = output()
				if strings.Contains(logged, wantValue) {
					break
				}
			}
			if !strings.Contains(logged, wantValue) {
				t.Fatalf("snmptrapd never logged the trap's varbinds at %s.\n"+
					"It localized its own key from %q and the engine ID 0x%s that nl6 sent, verified "+
					"the digest and — under privacy — decrypted with an IV it built itself. A silent "+
					"drop means one of those disagreed with what nl6 produced, which is an interop "+
					"defect no in-package test can see.\nsnmptrapd said:\n%s",
					cfg.securityLevel(), cfg.Password, hex.EncodeToString(engineID), logged)
			}
			// And the trap identity, so "it logged something" is not the whole
			// assertion. -On makes the OIDs numeric, so no MIBs are needed.
			if !strings.Contains(logged, v3TrapOID) {
				t.Errorf("snmptrapd logged the trap but not snmpTrapOID %s; the notification identity "+
					"did not survive.\n%s", v3TrapOID, logged)
			}
		})
	}
}

// TestSNMPv3TrapInteropRejectsAWrongPassword is the control.
//
// Without it, seven logged traps prove snmptrapd is running and reachable, not
// that it authenticated anything: a receiver configured to log unauthenticated
// notifications would pass every row above. This one gives snmptrapd the WRONG
// password and requires the trap NOT to be logged.
//
// A SILENT DROP IS THE CORRECT OUTCOME HERE, unlike the poll-side control where
// silence was the defect. A trap is unacknowledged by definition, so a receiver
// that cannot authenticate one has nobody to tell — which is also why this
// control asserts the absence of the varbind rather than the presence of an
// error.
func TestSNMPv3TrapInteropRejectsAWrongPassword(t *testing.T) {
	if os.Getenv("NL6_SNMP_INTEROP") != "1" {
		t.Skip("set NL6_SNMP_INTEROP=1 to run the net-snmp interop check")
	}
	snmptrapd, err := exec.LookPath("snmptrapd")
	if err != nil {
		t.Fatalf("NL6_SNMP_INTEROP=1 but snmptrapd is not on PATH: %v", err)
	}

	deviceIP := net.IPv4(127, 0, 0, 1)
	engineID := snmpv3TrapEngineID(deviceIP)
	cfg := v3TrapTestConfig(SNMPV3_AUTH_SHA1, SNMPV3_PRIV_AES128)

	wrong := cfg
	wrong.Password = "the-wrong-password"
	wrong.PrivPassword = "the-wrong-password"
	port, output := snmptrapdRun(t, snmptrapd, snmptrapdUserConfig(engineID, wrong))

	enc, err := NewSNMPv3TrapEncoder(deviceIP, cfg)
	if err != nil {
		t.Fatalf("NewSNMPv3TrapEncoder: %v", err)
	}
	buf := make([]byte, maxTrapPDU)
	n, err := enc.EncodeTrap("", 4242, v3TrapOID, v3TrapEnterprise, v3TrapUptime, v3TrapVarbinds, buf)
	if err != nil {
		t.Fatalf("EncodeTrap: %v", err)
	}
	conn, err := net.Dial("udp4", "127.0.0.1:"+strconv.Itoa(port))
	if err != nil {
		t.Fatalf("dial snmptrapd: %v", err)
	}
	defer func() { _ = conn.Close() }()

	// IT MUST WAIT AT LEAST AS LONG AS A POSITIVE ROW DOES. This asserts an
	// ABSENCE, so a short wait is satisfied by a slow runner rather than by
	// snmptrapd rejecting anything — the control would then pass by timing on
	// exactly the machine where the positive rows were closest to failing.
	// snmptrapdDeliveryWindow is the same budget both sides use.
	deadline := time.Now().Add(snmptrapdDeliveryWindow)
	for time.Now().Before(deadline) {
		if _, err := conn.Write(buf[:n]); err != nil {
			t.Fatalf("send trap: %v", err)
		}
		time.Sleep(200 * time.Millisecond)
		if strings.Contains(output(), "sim-9") {
			break // fail below, with the log
		}
	}

	if logged := output(); strings.Contains(logged, "sim-9") {
		t.Fatalf("snmptrapd LOGGED a trap whose digest was computed with a different password, so it "+
			"is not authenticating and the seven rows above prove reachability rather than "+
			"authentication.\n%s", logged)
	}
}

// TestSNMPv3TrapInteropThroughTheExporter closes the dispatcher-versus-direct-
// call gap.
//
// The rows above call `enc.EncodeTrap` and dial their own socket, so they prove
// the ENCODER interoperates and say nothing about the path a running simulator
// takes to reach it: `startDeviceTrapExporter` picking the v3 branch,
// `fireWithCtx` choosing the reference-encoder path because SNMPv3TrapEncoder
// deliberately does not implement fastTrapEncoder, the pooled buffer clamped to
// maxTrapPDU, `writePDU`, and `FireTrapOnDevice` behind
// POST /api/v1/devices/{ip}/trap.
//
// THAT IS EXACTLY THE SHAPE nl6#527 COST, which the interop file's own header
// cites: hand the parser a slightly different thing than the dispatcher does and
// every direct-call test stays green. Here the specific risk is real — a missed
// attach-site branch leaves a "v3" fleet emitting v2c, and every test in
// trap_v3_test.go still passes.
//
// It runs ONE row (authPriv/SHA1+AES, the largest envelope and the only one that
// exercises both the HMAC and the cipher through the exporter). The security
// matrix is the sweep above's job.
func TestSNMPv3TrapInteropThroughTheExporter(t *testing.T) {
	if os.Getenv("NL6_SNMP_INTEROP") != "1" {
		t.Skip("set NL6_SNMP_INTEROP=1 to run the net-snmp interop check")
	}
	snmptrapd, err := exec.LookPath("snmptrapd")
	if err != nil {
		t.Fatalf("NL6_SNMP_INTEROP=1 but snmptrapd is not on PATH: %v\n"+
			"Debian/Ubuntu: sudo apt-get install -y snmptrapd", err)
	}

	deviceIP := net.IPv4(127, 0, 0, 1)
	cfg := v3TrapTestConfig(SNMPV3_AUTH_SHA1, SNMPV3_PRIV_AES128)
	port, output := snmptrapdRun(t, snmptrapd,
		snmptrapdUserConfig(snmpv3TrapEngineID(deviceIP), cfg))

	sm := newTestSimulatorManager()
	if err := sm.StartTrapSubsystem(TrapSubsystemConfig{
		PDUBudget:   maxTrapPDU,
		SNMPVersion: TrapSNMPv3,
		SNMPv3:      cfg,
		// The shared-socket path: a per-device bind needs the nl6sim netns and
		// root, which this test has neither of. What is under test is the
		// encoder reaching the wire through the exporter, not the source
		// address.
		SourcePerDevice:       false,
		MeanSchedulerInterval: time.Hour,
	}); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(sm.StopTrapExport)

	device := setupTestDeviceForAttach(t, sm, "dev-v3-interop", deviceIP)
	device.trapConfig = &DeviceTrapConfig{
		Collector:     "127.0.0.1:" + strconv.Itoa(port),
		Mode:          "trap",
		Community:     "public", // ignored under v3; here to prove it is
		Interval:      jsonDuration(time.Hour),
		InformTimeout: jsonDuration(200 * time.Millisecond),
	}
	if err := sm.startDeviceTrapExporter(device); err != nil {
		t.Fatalf("startDeviceTrapExporter: %v", err)
	}
	// FireTrapOnDevice resolves through devicesByIP, which setupTestDeviceForAttach
	// does not populate — it is written for the attach path, which takes the
	// *DeviceSimulator directly. Registering here rather than widening the shared
	// helper, so no other test's device map changes shape.
	sm.mu.Lock()
	sm.indexDeviceByIP(device)
	sm.mu.Unlock()

	// Through the REST entry point, not through the exporter's Fire directly:
	// FireTrapOnDevice is what the HTTP handler calls, and it resolves the
	// device's catalog on the way.
	deadline := time.Now().Add(snmptrapdDeliveryWindow)
	logged := ""
	for time.Now().Before(deadline) {
		if _, err := sm.FireTrapOnDevice(deviceIP.String(), "linkDown", map[string]string{
			"IfIndex": "7",
		}); err != nil {
			t.Fatalf("FireTrapOnDevice: %v", err)
		}
		time.Sleep(200 * time.Millisecond)
		logged = output()
		if strings.Contains(logged, "1.3.6.1.6.3.1.1.5.3") {
			break
		}
	}
	if !strings.Contains(logged, "1.3.6.1.6.3.1.1.5.3") {
		st := sm.GetTrapStatus()
		t.Fatalf("snmptrapd never decoded a trap fired through the exporter.\n"+
			"The encoder interoperates (the rows above prove it), so a failure here is the PATH: "+
			"the attach-site version branch, fireWithCtx's reference-encoder fallback, the pooled "+
			"buffer clamp, or writePDU.\ntrap status: %+v\nsnmptrapd said:\n%s", st, logged)
	}

	// The counters must agree with what the receiver saw: a fire counted as
	// sent that snmptrapd rejected would mean the exporter is reporting
	// success for a message the collector dropped.
	st := sm.GetTrapStatus()
	if len(st.Collectors) != 1 || st.Collectors[0].Sent == 0 {
		t.Errorf("trap status reports %+v, want one collector with a non-zero sent count",
			st.Collectors)
	}
	if st.Collectors[0].SendFailures != 0 {
		t.Errorf("%d send failures on a path snmptrapd accepted", st.Collectors[0].SendFailures)
	}
}
