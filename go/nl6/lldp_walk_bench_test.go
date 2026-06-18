/*
 * Copyright 2026 Ronny Trommer <ronny@no42.org>
 * SPDX-License-Identifier: Apache-2.0
 */

package main

import (
	"fmt"
	"net"
	"sync"
	"testing"
)

// Benchmarks for the LLDP-walk CPU-amplification fix (perf/lldp-walk-cpu-
// amplification). Under SNMP polling of a large fabric, an Enlinkd LLDP walk
// called the per-step served-OID build O(walk_steps) times, and each build
// did an O(total_links) topology scan plus an O(total_devices) FindDeviceByIP
// per peer. The three sub-areas below are benchmarked against baselines that
// reproduce the pre-fix behaviour so the before/after ratio is self-contained.
//
// Representative scale mirrors the monkey-head deployment: 2500 devices,
// 6000 links, a spine-class subject degree of 48.
const (
	benchDevices       = 2500
	benchLinks         = 6000
	benchSubjectDegree = 48
)

// benchIP maps a counter into a unique 10.42.x.y address inside the /16.
func benchIP(n int) string { return fmt.Sprintf("10.42.%d.%d", (n>>8)&0xff, n&0xff) }

// --- pre-fix baselines (test-only) -----------------------------------------

// findDeviceByIPLinear is the pre-fix O(N) scan FindDeviceByIP used before the
// devicesByIP index was added.
func findDeviceByIPLinear(sm *SimulatorManager, ip string) *DeviceSimulator {
	sm.mu.RLock()
	defer sm.mu.RUnlock()
	for _, d := range sm.devices {
		if d.IP.String() == ip {
			return d
		}
	}
	return nil
}

// linksForScan is the pre-fix O(total_links) LinksFor scan used before the
// adjacency index was added.
func linksForScan(t *Topology, ip string) []localLink {
	parsed := net.ParseIP(ip)
	if parsed == nil || parsed.To4() == nil {
		return nil
	}
	norm := parsed.To4().String()
	t.mu.RLock()
	defer t.mu.RUnlock()
	var out []localLink
	for _, l := range t.links {
		switch norm {
		case l.A.IP:
			out = append(out, localLink{LocalIfIndex: l.A.IfIndex, PeerIP: l.B.IP, PeerIfIndex: l.B.IfIndex})
		case l.B.IP:
			out = append(out, localLink{LocalIfIndex: l.B.IfIndex, PeerIP: l.A.IP, PeerIfIndex: l.A.IfIndex})
		}
	}
	return out
}

// --- fixtures ---------------------------------------------------------------

// benchLLDPResources builds a device's resource set with ifSpeed/ifDescr for
// maxIf interfaces and a sysDescr, then indexes it (sortedOIDs + oidNextMap)
// so findNextOID exercises its real fast path.
func benchLLDPResources(maxIf int, name string) *DeviceResources {
	res := &DeviceResources{oidIndex: &sync.Map{}}
	res.oidIndex.Store(".1.3.6.1.2.1.1.1.0", name+" desc")
	for i := 1; i <= maxIf; i++ {
		res.oidIndex.Store(fmt.Sprintf(".1.3.6.1.2.1.31.1.1.1.15.%d", i), "1000")
		res.oidIndex.Store(fmt.Sprintf(".1.3.6.1.2.1.31.1.1.1.6.%d", i), "0")
		res.oidIndex.Store(fmt.Sprintf(".1.3.6.1.2.1.31.1.1.1.10.%d", i), "0")
		res.oidIndex.Store(fmt.Sprintf(".1.3.6.1.2.1.2.2.1.2.%d", i), fmt.Sprintf("GigabitEthernet0/%d", i))
	}
	indexResources(res)
	return res
}

// benchDevice builds a fully-functional device (state engine UP on every
// interface) suitable for the LLDP read path.
func benchDevice(ipStr string, maxIf int, name string, seed int64) *DeviceSimulator {
	res := benchLLDPResources(maxIf, name)
	d := &DeviceSimulator{
		ID:            "dev-" + ipStr,
		IP:            net.ParseIP(ipStr),
		sysName:       name,
		resources:     res,
		metricsCycler: NewMetricsCycler(seed, GetDeviceProfile("")),
	}
	d.cachedSysName.Store(name)
	d.metricsCycler.InitIfCountersWithScenario(res, seed, IfErrorClean)
	d.snmpServer = &SNMPServer{device: d}
	if st := d.metricsCycler.ifCounters.Load().State(); st != nil {
		for i := 1; i <= maxIf; i++ {
			st.SetOperStatus(i, OperUp)
		}
	}
	return d
}

// walkLLDPSubtree drives a GETNEXT walk across the 1.0.8802 LLDP subtree and
// returns the number of rows visited. When shared is true it builds the
// served-OID snapshot once (the fixed GETBULK behaviour); otherwise it lets
// each step rebuild it (the pre-fix per-step behaviour).
func walkLLDPSubtree(s *SNMPServer, shared bool) int {
	cur := lldpRoot
	var served []kvOID
	if shared {
		served = s.lldpServedOIDs()
	}
	steps := 0
	for {
		var next string
		if shared {
			next, _ = s.findNextOIDWithServed(cur, served)
		} else {
			next, _ = s.findNextOID(cur)
		}
		if next == "" || !isLLDPOID(next) {
			break
		}
		cur = next
		steps++
	}
	return steps
}

// --- benchmarks -------------------------------------------------------------

// BenchmarkFindDeviceByIP (fix 1): O(1) index vs the pre-fix O(N) scan, over
// benchDevices lightweight devices.
func BenchmarkFindDeviceByIP(b *testing.B) {
	sm := &SimulatorManager{
		devices:     make(map[string]*DeviceSimulator, benchDevices),
		devicesByIP: make(map[string]*DeviceSimulator, benchDevices),
	}
	ips := make([]string, benchDevices)
	for n := 0; n < benchDevices; n++ {
		ip := benchIP(n)
		ips[n] = ip
		d := &DeviceSimulator{ID: fmt.Sprintf("d%d", n), IP: net.ParseIP(ip)}
		sm.devices[d.ID] = d
		sm.indexDeviceByIP(d)
	}

	b.Run("indexed", func(b *testing.B) {
		b.ReportAllocs()
		for i := 0; i < b.N; i++ {
			if sm.FindDeviceByIP(ips[i%benchDevices]) == nil {
				b.Fatal("miss")
			}
		}
	})
	b.Run("linear", func(b *testing.B) {
		b.ReportAllocs()
		for i := 0; i < b.N; i++ {
			if findDeviceByIPLinear(sm, ips[i%benchDevices]) == nil {
				b.Fatal("miss")
			}
		}
	})
}

// BenchmarkTopologyLinksFor (fix 2): O(degree) adjacency index vs the pre-fix
// O(total_links) scan, with benchLinks links and a degree-benchSubjectDegree
// subject.
func BenchmarkTopologyLinksFor(b *testing.B) {
	tp := NewTopology()
	subjectIP := "10.42.255.1"

	// Subject's links: distinct peers on ports 1..degree.
	subjectLinks := make([]LinkJSON, benchSubjectDegree)
	for i := 0; i < benchSubjectDegree; i++ {
		subjectLinks[i] = LinkJSON{
			A: LinkEndpointJSON{IP: subjectIP, IfIndex: i + 1},
			B: LinkEndpointJSON{IP: benchIP(i), IfIndex: 1},
		}
	}
	if err := tp.AddLinks(subjectLinks); err != nil {
		b.Fatal(err)
	}
	// Filler links to reach benchLinks total, each using two fresh unique
	// (ip, port-1) endpoints so the point-to-point invariant holds.
	filler := benchLinks - benchSubjectDegree
	fl := make([]LinkJSON, filler)
	for i := 0; i < filler; i++ {
		fl[i] = LinkJSON{
			A: LinkEndpointJSON{IP: benchIP(1000 + 2*i), IfIndex: 1},
			B: LinkEndpointJSON{IP: benchIP(1000 + 2*i + 1), IfIndex: 1},
		}
	}
	if err := tp.AddLinks(fl); err != nil {
		b.Fatal(err)
	}

	b.Run("indexed", func(b *testing.B) {
		b.ReportAllocs()
		for i := 0; i < b.N; i++ {
			if len(tp.LinksFor(subjectIP)) != benchSubjectDegree {
				b.Fatal("degree mismatch")
			}
		}
	})
	b.Run("scan", func(b *testing.B) {
		b.ReportAllocs()
		for i := 0; i < b.N; i++ {
			if len(linksForScan(tp, subjectIP)) != benchSubjectDegree {
				b.Fatal("degree mismatch")
			}
		}
	})
}

// BenchmarkLLDPWalk (fix 3): a full LLDP-subtree GETNEXT walk of a
// degree-benchSubjectDegree subject, building the served-OID snapshot once
// per request (fixed) vs rebuilding it on every walk step (pre-fix). The
// subject and its peers are real devices; benchLinks-worth of filler links
// inflate the topology so each rebuild also pays the (now-indexed) lookups.
func BenchmarkLLDPWalk(b *testing.B) {
	sm := &SimulatorManager{
		devices:     make(map[string]*DeviceSimulator),
		devicesByIP: make(map[string]*DeviceSimulator),
		topology:    NewTopology(),
	}
	defer swapGlobalManager(sm)()

	subjectIP := "10.42.255.1"
	subject := benchDevice(subjectIP, benchSubjectDegree, "SUBJECT", 1)
	sm.devices[subject.ID] = subject
	sm.indexDeviceByIP(subject)

	subjectLinks := make([]LinkJSON, benchSubjectDegree)
	for i := 0; i < benchSubjectDegree; i++ {
		peerIP := benchIP(i)
		peer := benchDevice(peerIP, 2, fmt.Sprintf("PEER-%d", i), int64(i+2))
		sm.devices[peer.ID] = peer
		sm.indexDeviceByIP(peer)
		subjectLinks[i] = LinkJSON{
			A: LinkEndpointJSON{IP: subjectIP, IfIndex: i + 1},
			B: LinkEndpointJSON{IP: peerIP, IfIndex: 1},
		}
	}
	if err := sm.topology.AddLinks(subjectLinks); err != nil {
		b.Fatal(err)
	}
	filler := benchLinks - benchSubjectDegree
	fl := make([]LinkJSON, filler)
	for i := 0; i < filler; i++ {
		fl[i] = LinkJSON{
			A: LinkEndpointJSON{IP: benchIP(1000 + 2*i), IfIndex: 1},
			B: LinkEndpointJSON{IP: benchIP(1000 + 2*i + 1), IfIndex: 1},
		}
	}
	if err := sm.topology.AddLinks(fl); err != nil {
		b.Fatal(err)
	}

	steps := walkLLDPSubtree(subject.snmpServer, true)
	if steps == 0 {
		b.Fatal("walk produced no LLDP rows")
	}
	b.Logf("LLDP subtree rows per walk: %d", steps)

	b.Run("sharedServed", func(b *testing.B) {
		b.ReportAllocs()
		for i := 0; i < b.N; i++ {
			walkLLDPSubtree(subject.snmpServer, true)
		}
	})
	b.Run("perStepRebuild", func(b *testing.B) {
		b.ReportAllocs()
		for i := 0; i < b.N; i++ {
			walkLLDPSubtree(subject.snmpServer, false)
		}
	})
}
