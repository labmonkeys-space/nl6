/*
 * Copyright 2026 Ronny Trommer <ronny@no42.org>
 * SPDX-License-Identifier: Apache-2.0
 */

package main

import (
	"math/rand"
	"net"
	"strings"
	"testing"
	"time"
)

// countingSource counts RNG draws so a test can assert that the draw count
// does not depend on the data (nl6#462's rule).
type countingSource struct {
	src rand.Source
	n   int
}

func (c *countingSource) Int63() int64 { c.n++; return c.src.Int63() }
func (c *countingSource) Seed(s int64) { c.src.Seed(s) }

func nbar2TestCatalog(t *testing.T, doc []byte) *nbar2Catalog {
	t.Helper()
	cat, err := parseNbar2Catalog(doc, "gen")
	if err != nil {
		t.Fatal(err)
	}
	cat.ApplySizeBudget(maxFlowPayloadIPv4, "gen")
	cat.finalize()
	return cat
}

// The application fixes protocol and port: a catalog of one tcp/443 entry
// against a profile that only knows port 80 yields only tcp/443 records,
// each referencing the application.
func TestNbar2PortComesFromApplication(t *testing.T) {
	cat := nbar2TestCatalog(t, nbar2JSON("", `{"name":"ssl","engine":3,"selector":443,"proto":"tcp","dst_port":443}`))
	prof := *mtuTestProfile()
	prof.DstPorts = []PortWeight{{80, 1.0}}
	prof.UDPWeight, prof.ICMPWeight = 0.5, 0.2 // the profile would draw udp and icmp; the catalog must win
	fc := NewFlowCache(30*time.Second, 15*time.Second, 512)
	rng := rand.New(rand.NewSource(7))
	fc.GenerateFlowsFrom(&prof, 200, net.ParseIP("10.1.1.1").To4(), rng, time.Now(), 1000, cat)
	if fc.Len() != 200 {
		t.Fatalf("cache holds %d, want 200", fc.Len())
	}
	for _, r := range fc.Expire(time.Now().Add(time.Hour)) {
		if r.Protocol != 6 || r.DstPort != 443 || r.AVC.App != 1 {
			t.Fatalf("record proto=%d port=%d avc=%+v, want tcp/443 app 1", r.Protocol, r.DstPort, r.AVC)
		}
	}
}

// The draw count is data-independent: an application with hosts and URIs
// and one with neither consume the same number of RNG values per flow, and
// exactly one more than the plain draw (application instead of protocol and
// port, plus host and URI).
func TestNbar2DrawIsUnconditional(t *testing.T) {
	withLists := nbar2TestCatalog(t, nbar2JSON("", nbar2GoodHTTP))
	without := nbar2TestCatalog(t, nbar2JSON("", nbar2GoodDNS))
	prof := mtuTestProfile()
	ip := net.ParseIP("10.1.1.2").To4()
	count := func(f func(*rand.Rand)) int {
		cs := &countingSource{src: rand.NewSource(1)}
		f(rand.New(cs))
		return cs.n
	}
	a := count(func(r *rand.Rand) { syntheticAVCFlow(prof, withLists, ip, r, 1000) })
	b := count(func(r *rand.Rand) { syntheticAVCFlow(prof, without, ip, r, 1000) })
	plain := count(func(r *rand.Rand) { syntheticFlow(prof, ip, r, 1000) })
	if a != b {
		t.Fatalf("draws: with lists %d, without %d; the count depends on the data and a seeded stream desynchronises", a, b)
	}
	if a != plain+1 {
		t.Fatalf("AVC draw %d, plain %d; want plain+1 (app, host, uri replace proto, port)", a, plain)
	}
	// Control: the record from the list-less application carries no host
	// or URI index while still having consumed the draws.
	r := syntheticAVCFlow(prof, without, ip, rand.New(rand.NewSource(3)), 1000)
	if r.AVC.App != 1 || r.AVC.Host != 0 || r.AVC.URI != 0 {
		t.Fatalf("AVC = %+v, want app 1 with no host or URI", r.AVC)
	}
}

// A seeded NBAR2 device reproduces its stream exactly, AVC included.
func TestNbar2SeededRunReproduces(t *testing.T) {
	cat := nbar2TestCatalog(t, nbar2JSON("", nbar2GoodHTTP, nbar2GoodDNS))
	run := func() []FlowRecord {
		fc := NewFlowCache(30*time.Second, 15*time.Second, 512)
		rng := rand.New(rand.NewSource(42))
		now := time.Date(2026, 9, 19, 12, 0, 0, 0, time.UTC)
		fc.GenerateFlowsFrom(mtuTestProfile(), 100, net.ParseIP("10.1.1.3").To4(), rng, now, 1000, cat)
		return fc.Expire(now.Add(time.Hour))
	}
	a, b := run(), run()
	if len(a) != len(b) || len(a) == 0 {
		t.Fatalf("lengths %d / %d", len(a), len(b))
	}
	hosts := 0
	for i := range a {
		if a[i].AVC != b[i].AVC || a[i].DstPort != b[i].DstPort || a[i].SrcPort != b[i].SrcPort || a[i].Bytes != b[i].Bytes {
			t.Fatalf("record %d differs: %+v vs %+v", i, a[i], b[i])
		}
		if a[i].AVC.Host != 0 {
			hosts++
		}
	}
	if hosts == 0 {
		t.Fatal("no record drew a host; the http entry has two, so the weighted draw is not reaching them")
	}
}

// An oversized entry is never drawn: over 10000 flows every record
// references the usable entry.
func TestNbar2OversizedNeverDrawn(t *testing.T) {
	cat := nbar2TestCatalog(t, nbar2JSON("",
		`{"name":"big","engine":6,"selector":1,"proto":"udp","dst_port":9,"weight":1000,"uris":[{"value":"/`+strings.Repeat("u", 1450)+`"}]}`,
		`{"name":"ssh","engine":3,"selector":22,"proto":"tcp","dst_port":22,"weight":1}`))
	if cat.Usable() != 1 {
		t.Fatalf("usable = %d, want 1", cat.Usable())
	}
	rng := rand.New(rand.NewSource(9))
	for i := 0; i < 10000; i++ {
		ref, proto, port := cat.draw(rng)
		if ref.App != 1 || proto != 6 || port != 22 {
			t.Fatalf("draw %d hit the oversized entry: %+v %d/%d", i, ref, proto, port)
		}
	}
}
