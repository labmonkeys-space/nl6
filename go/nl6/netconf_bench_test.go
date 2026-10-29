/*
 * Copyright 2026 Ronny Trommer <ronny@no42.org>
 * SPDX-License-Identifier: Apache-2.0
 */

package main

import (
	"bufio"
	"crypto/ed25519"
	"crypto/rand"
	"fmt"
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

const (
	netconfBenchAddrEnv = "NL6_NETCONF_BENCH_ADDR"
	netconfBenchNEnv    = "NL6_NETCONF_BENCH_N"
	benchKeylessOperReq = `<establish-subscription xmlns="urn:ietf:params:xml:ns:yang:ietf-event-notifications" xmlns:yp="urn:ietf:params:xml:ns:yang:ietf-yang-push"><stream>yp:yang-push</stream><yp:xpath-filter>/interfaces-ios-xe-oper:interfaces/interface/oper-status</yp:xpath-filter><yp:dampening-period>0</yp:dampening-period></establish-subscription>`
)

// BenchmarkNetconfIdleClients is the client half of
// BenchmarkNetconfIdleSessions. It does nothing unless the parent set the
// environment, so a plain bench run skips it.
func BenchmarkNetconfIdleClients(b *testing.B) {
	addr := os.Getenv(netconfBenchAddrEnv)
	if addr == "" {
		b.Skip("client helper, started by BenchmarkNetconfIdleSessions")
	}
	n, _ := strconv.Atoi(os.Getenv(netconfBenchNEnv))
	hello := `<hello xmlns="urn:ietf:params:xml:ns:netconf:base:1.0"><capabilities><capability>urn:ietf:params:netconf:base:1.0</capability></capabilities></hello>`
	cfg := &ssh.ClientConfig{
		User:            USERNAME,
		Auth:            []ssh.AuthMethod{ssh.Password(PASSWORD)},
		HostKeyCallback: ssh.InsecureIgnoreHostKey(), //nolint:gosec // bench server
		Timeout:         30 * time.Second,
	}
	for i := 0; i < n; i++ {
		c, err := ssh.Dial("tcp", addr, cfg)
		if err != nil {
			fmt.Printf("error dial %d: %v\n", i, err)
			os.Exit(1)
		}
		s, err := c.NewSession()
		if err != nil {
			fmt.Printf("error session %d: %v\n", i, err)
			os.Exit(1)
		}
		in, _ := s.StdinPipe()
		out, _ := s.StdoutPipe()
		if err := s.RequestSubsystem("netconf"); err != nil {
			fmt.Printf("error subsystem %d: %v\n", i, err)
			os.Exit(1)
		}
		f := newNetconfFramer(out, in)
		if _, err := f.ReadMessage(); err != nil {
			fmt.Printf("error hello %d: %v\n", i, err)
			os.Exit(1)
		}
		_ = f.WriteMessage([]byte(hello))
		rpc := `<rpc xmlns="urn:ietf:params:xml:ns:netconf:base:1.0" message-id="1">` + benchKeylessOperReq + `</rpc>`
		_ = f.WriteMessage([]byte(rpc))
		if _, err := f.ReadMessage(); err != nil {
			fmt.Printf("error subscribe %d: %v\n", i, err)
			os.Exit(1)
		}
		// Keep the stream drained so the server never blocks on this client.
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

// BenchmarkNetconfIdleSessions measures the server-side cost of idle
// subscribed NETCONF sessions. NL6_NETCONF_BENCH_N sets the session count
// (default 1000). The clients run in a child process, so the numbers cover
// the server half only: the parent heap and goroutines before and after the
// sessions are established, each read after a forced GC.
func BenchmarkNetconfIdleSessions(b *testing.B) {
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
	prev := manager
	manager = mgr
	defer func() { manager = prev }()

	res, err := (&SimulatorManager{resourcesCache: make(map[string]*DeviceResources)}).LoadSpecificResources("cisco_catalyst_9500.json")
	if err != nil {
		b.Fatal(err)
	}
	mc := &MetricsCycler{}
	mc.InitIfCountersWithScenario(res, 1, IfErrorClean)
	dev := &DeviceSimulator{resources: res, metricsCycler: mc, ID: "cat9500-bench", IP: net.IPv4(127, 0, 0, 1), resourceFile: "cisco_catalyst_9500.json"}
	mgr.devices[dev.ID] = dev
	dev.mu.Lock()
	err = dev.startNetconfServer(0)
	dev.mu.Unlock()
	if err != nil || dev.netconfListener == nil {
		b.Fatalf("startNetconfServer: %v", err)
	}
	defer func() {
		dev.mu.Lock()
		dev.stopNetconfServer()
		dev.mu.Unlock()
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
		heap0, gor0 := settle()
		cmd := exec.Command(os.Args[0], "-test.run=^$", "-test.bench=^BenchmarkNetconfIdleClients$", "-test.benchtime=1x")
		cmd.Env = append(os.Environ(), netconfBenchAddrEnv+"="+dev.netconfListener.Addr().String(), netconfBenchNEnv+"="+strconv.Itoa(n))
		stdin, _ := cmd.StdinPipe()
		stdout, _ := cmd.StdoutPipe()
		cmd.Stderr = os.Stderr
		if err := cmd.Start(); err != nil {
			b.Fatal(err)
		}
		ready := false
		sc := bufio.NewScanner(stdout)
		for sc.Scan() {
			l := sc.Text()
			if l == "ready" {
				ready = true
				break
			}
			if strings.HasPrefix(l, "error") {
				b.Fatalf("client helper: %s", l)
			}
		}
		if !ready {
			b.Fatal("client helper exited before ready")
		}
		heap1, gor1 := settle()
		if got := netconfStateListeners(mc.ifCounters.Load().State()); got != n {
			b.Logf("state listeners %d, want %d", got, n)
		}
		b.ReportMetric(float64(int64(heap1)-int64(heap0))/float64(n), "heap-B/session")
		b.ReportMetric(float64(gor1-gor0)/float64(n), "goroutines/session")
		_ = stdin.Close()
		_ = cmd.Wait()
	}
}
