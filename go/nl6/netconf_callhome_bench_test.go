/*
 * Copyright 2026 Ronny Trommer <ronny@no42.org>
 * SPDX-License-Identifier: Apache-2.0
 */

package main

import (
	"bufio"
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"runtime"
	"strconv"
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"
)

const netconfCallHomeBenchEnv = "NL6_NETCONF_CALLHOME_BENCH"

// BenchmarkNetconfCallHomeIdleClients is the client half of
// BenchmarkNetconfCallHomeIdleSessions. It listens, prints its address,
// accepts NL6_NETCONF_BENCH_N call-home connections, and on each skips the
// preamble, completes SSH and the hello, and subscribes. It does nothing
// unless the parent set the environment.
func BenchmarkNetconfCallHomeIdleClients(b *testing.B) {
	if os.Getenv(netconfCallHomeBenchEnv) == "" {
		b.Skip("client helper, started by BenchmarkNetconfCallHomeIdleSessions")
	}
	n, _ := strconv.Atoi(os.Getenv(netconfBenchNEnv))
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		fmt.Printf("error listen: %v\n", err)
		os.Exit(1)
	}
	fmt.Println("listen " + ln.Addr().String())
	hello := `<hello xmlns="urn:ietf:params:xml:ns:netconf:base:1.0"><capabilities><capability>urn:ietf:params:netconf:base:1.0</capability></capabilities></hello>`
	sub := `<rpc xmlns="urn:ietf:params:xml:ns:netconf:base:1.0" message-id="1"><create-subscription xmlns="` + junosNotificationNS + `"/></rpc>`
	cfg := &ssh.ClientConfig{
		User:            USERNAME,
		Auth:            []ssh.AuthMethod{ssh.Password(PASSWORD)},
		HostKeyCallback: ssh.InsecureIgnoreHostKey(), //nolint:gosec // bench server
		Timeout:         30 * time.Second,
	}
	fail := func(i int, what string, err error) {
		fmt.Printf("error %s %d: %v\n", what, i, err)
		os.Exit(1)
	}
	for i := 0; i < n; i++ {
		c, err := ln.Accept()
		if err != nil {
			fail(i, "accept", err)
		}
		var pre []byte
		one := make([]byte, 1)
		for !bytes.HasSuffix(pre, []byte("\r\n\r\n")) {
			if _, err := io.ReadFull(c, one); err != nil {
				fail(i, "preamble", err)
			}
			pre = append(pre, one[0])
		}
		sc, chans, reqs, err := ssh.NewClientConn(c, "", cfg)
		if err != nil {
			fail(i, "ssh", err)
		}
		s, err := ssh.NewClient(sc, chans, reqs).NewSession()
		if err != nil {
			fail(i, "session", err)
		}
		in, _ := s.StdinPipe()
		out, _ := s.StdoutPipe()
		if err := s.RequestSubsystem("netconf"); err != nil {
			fail(i, "subsystem", err)
		}
		f := newNetconfFramer(out, in)
		if _, err := f.ReadMessage(); err != nil {
			fail(i, "hello", err)
		}
		if err := f.WriteMessage([]byte(hello)); err != nil {
			fail(i, "client hello", err)
		}
		if err := f.WriteMessage([]byte(sub)); err != nil {
			fail(i, "rpc", err)
		}
		if _, err := f.ReadMessage(); err != nil {
			fail(i, "subscribe", err)
		}
		go func() {
			for {
				if _, err := f.ReadMessage(); err != nil {
					return
				}
			}
		}()
	}
	fmt.Println("ready")
	_, _ = bufio.NewReader(os.Stdin).ReadString('\n')
}

// BenchmarkNetconfCallHomeIdleSessions measures the server-side cost of one
// idle, subscribed call-home device: the exporter, its keepalive and the
// session. NL6_NETCONF_BENCH_N sets the device count (default 1000). The
// devices and their listeners exist before the baseline, so only call home
// is counted. Clients run in a child process.
func BenchmarkNetconfCallHomeIdleSessions(b *testing.B) {
	n := 1000
	if v := os.Getenv(netconfBenchNEnv); v != "" {
		n, _ = strconv.Atoi(v)
	}
	_, key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		b.Fatal(err)
	}
	signer, err := ssh.NewSignerFromKey(key)
	if err != nil {
		b.Fatal(err)
	}
	mgr := &SimulatorManager{
		devices:         map[string]*DeviceSimulator{},
		deviceIPs:       map[string]struct{}{},
		deviceTypesByIP: map[string]string{},
		sharedSSHSigner: signer,
	}
	if err := mgr.StartNetconfSubsystem(NetconfSubsystemConfig{Enabled: true}); err != nil {
		b.Fatal(err)
	}
	mgr.netconfPort = 0
	prev := manager
	manager = mgr
	defer func() { manager = prev }()
	// A short cycle so every device dials within seconds; the keepalive
	// interval stays at its default.
	prevCycle := netconfCallHomeCycle
	netconfCallHomeCycle = time.Second
	defer func() { netconfCallHomeCycle = prevCycle }()

	res, err := (&SimulatorManager{resourcesCache: make(map[string]*DeviceResources)}).LoadSpecificResources("juniper_mx10004.json")
	if err != nil {
		b.Fatal(err)
	}
	devs := make([]*DeviceSimulator, n)
	for i := range devs {
		mc := &MetricsCycler{}
		mc.InitIfCountersWithScenario(res, 1, IfErrorClean)
		d := &DeviceSimulator{resources: res, metricsCycler: mc, ID: fmt.Sprintf("mx-bench-%d", i), IP: net.IPv4(127, 0, 0, 1), resourceFile: "juniper_mx10004.json", sysName: fmt.Sprintf("mx-%04d", i)}
		mgr.devices[d.ID] = d
		d.mu.Lock()
		err := d.startNetconfServer()
		d.mu.Unlock()
		if err != nil {
			b.Fatalf("startNetconfServer: %v", err)
		}
		devs[i] = d
	}
	defer func() {
		for _, d := range devs {
			d.mu.Lock()
			d.stopNetconfServer()
			d.mu.Unlock()
		}
	}()

	settle := func() (uint64, int) {
		for i := 0; i < 3; i++ {
			runtime.GC()
			time.Sleep(200 * time.Millisecond)
		}
		var ms runtime.MemStats
		runtime.ReadMemStats(&ms)
		return ms.HeapAlloc, runtime.NumGoroutine()
	}

	b.ResetTimer()
	for iter := 0; iter < b.N; iter++ {
		cmd := exec.Command(os.Args[0], "-test.run=^$", "-test.bench=^BenchmarkNetconfCallHomeIdleClients$", "-test.benchtime=1x")
		cmd.Env = append(os.Environ(), netconfCallHomeBenchEnv+"=1", netconfBenchNEnv+"="+strconv.Itoa(n))
		stdin, err := cmd.StdinPipe()
		if err != nil {
			b.Fatal(err)
		}
		stdout, err := cmd.StdoutPipe()
		if err != nil {
			b.Fatal(err)
		}
		cmd.Stderr = os.Stderr
		if err := cmd.Start(); err != nil {
			b.Fatal(err)
		}
		reaped := false
		defer func() {
			if !reaped {
				_ = cmd.Process.Kill()
				_ = cmd.Wait()
			}
		}()
		lines := make(chan string, 4)
		go func() {
			sc := bufio.NewScanner(stdout)
			for sc.Scan() {
				lines <- sc.Text()
			}
			lines <- "error client helper exited"
		}()
		next := func() string {
			select {
			case l := <-lines:
				if strings.HasPrefix(l, "error") {
					b.Fatalf("client helper: %s", l)
				}
				return l
			case <-time.After(netconfBenchReadyWait):
				b.Fatalf("client helper silent for %v", netconfBenchReadyWait)
			}
			return ""
		}
		addr, ok := strings.CutPrefix(next(), "listen ")
		if !ok {
			b.Fatal("client helper printed no listen address")
		}

		heap0, gor0 := settle()
		for _, d := range devs {
			d.netconfCallHomeConfig = &DeviceNetconfCallHomeConfig{Client: addr}
			if err := mgr.startDeviceNetconfCallHome(d); err != nil {
				b.Fatalf("call home: %v", err)
			}
		}
		if l := next(); l != "ready" {
			b.Fatalf("client helper: %s", l)
		}
		heap1, gor1 := settle()
		b.ReportMetric(float64(int64(heap1)-int64(heap0))/float64(n), "heap-B/session")
		b.ReportMetric(float64(gor1-gor0)/float64(n), "goroutines/session")
		_ = stdin.Close()
		if err := cmd.Wait(); err != nil {
			b.Fatalf("client helper: %v", err)
		}
		reaped = true
	}
}
