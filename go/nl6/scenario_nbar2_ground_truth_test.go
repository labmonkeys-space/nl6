/*
 * Copyright 2026 Ronny Trommer <ronny@no42.org>
 * SPDX-License-Identifier: Apache-2.0
 */

package main

import (
	"bytes"
	"context"
	"encoding/json"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

// scenario_nbar2_ground_truth_test.go — NBAR2 Plan C: the three-part
// application key (l4_proto, dst_port, application_id) resolved through the
// participant's catalog at ledger time, the l7_values block, and the report
// shapes that carry both.

// testNbar2Catalog parses, budgets and finalises a catalog from JSON entries,
// the way StartNbar2Catalogs does, so tests hold a catalog the ledger and the
// AVC encoder can both resolve against.
func testNbar2Catalog(t *testing.T, source string, entries ...string) *nbar2Catalog {
	t.Helper()
	cat, err := parseNbar2Catalog(nbar2JSON("", entries...), source)
	if err != nil {
		t.Fatalf("%s: %v", source, err)
	}
	cat.ApplySizeBudget(maxFlowPayloadIPv4, source)
	cat.finalize()
	return cat
}

const (
	nbar2TestAppHTTP = 3<<24 | 80 // engine 3, selector 80
	nbar2TestAppDNS  = 3<<24 | 53
	nbar2TestAppSSL  = 3<<24 | 443
)

// avcFlow is an injectable expired flow carrying an AVC index triple.
func avcFlow(i int, proto uint8, port uint16, byteCount uint64, pkts uint32, ref avcRef) FlowRecord {
	return FlowRecord{
		SrcIP: net.ParseIP("10.0.0.1").To4(), DstIP: net.ParseIP("10.0.0.2").To4(),
		NextHop: net.IPv4(0, 0, 0, 0).To4(), SrcPort: uint16(50000 + i), DstPort: port,
		Protocol: proto, Bytes: byteCount, Packets: pkts, AVC: ref,
	}
}

// The key carries the WIRE id resolved through the catalog, and 0 where
// nothing resolves: an NBAR2 participant's record with index 0, and a plain
// participant's record even if an index is set (there is no catalog to
// resolve it against).
func TestNbar2GroundTruth_KeyCarriesWireID(t *testing.T) {
	cat := testNbar2Catalog(t, "t", nbar2GoodHTTP, nbar2GoodDNS)
	gate := &atomic.Pointer[gateState]{}
	t0 := time.Unix(1_700_000_000, 0)
	gate.Store(&gateState{phase: phaseRunning, t0: t0, t1: t0.Add(time.Hour)})

	nb := &scenarioPart{gate: gate, ledger: &ledgerEntry{}, drain: &drainGate{}, now: time.Now, countApps: true, nbar2: cat}
	nb.bucketFlowBatch(t0.Add(time.Second), []FlowRecord{
		avcFlow(0, 6, 80, 100, 1, avcRef{App: 1, Host: 1, URI: 2}),
		avcFlow(1, 6, 80, 100, 1, avcRef{}), // index 0: a plain record from an NBAR2 device
	})
	apps := nb.ledger.appSnapshot()
	if c := apps[appKey{6, 80, nbar2TestAppHTTP}]; c.records != 1 {
		t.Fatalf("NBAR2 row = %+v, want 1 record under the wire id %#x; rows: %+v", c, nbar2TestAppHTTP, apps)
	}
	if c := apps[appKey{6, 80, 0}]; c.records != 1 {
		t.Fatalf("index-0 record must land under application_id 0; rows: %+v", apps)
	}

	plain := &scenarioPart{gate: gate, ledger: &ledgerEntry{}, drain: &drainGate{}, now: time.Now, countApps: true}
	plain.bucketFlowBatch(t0.Add(time.Second), []FlowRecord{avcFlow(0, 6, 80, 100, 1, avcRef{App: 1, Host: 1})})
	apps = plain.ledger.appSnapshot()
	if c := apps[appKey{6, 80, 0}]; c.records != 1 || len(apps) != 1 {
		t.Fatalf("a plain participant has no catalog, so every record is application_id 0; rows: %+v", apps)
	}
	if l7 := plain.ledger.l7Snapshot(); l7 != nil {
		t.Fatalf("a plain participant must fold no layer-7 rows: %+v", l7)
	}
}

// installScenPart captures the exporter's catalog on the part; swapping the
// exporter's pointer afterwards does not change what the ledger resolves
// through (a re-attach mid-scenario must not re-key a running ledger).
func TestNbar2GroundTruth_CatalogCapturedAtInstall(t *testing.T) {
	catA := testNbar2Catalog(t, "a", nbar2GoodHTTP)
	catB := testNbar2Catalog(t, "b", nbar2GoodDNS)
	fe := newTestFlowExporter(testDevice("10.42.9.1"), zeroGenFlowProfile(), time.Millisecond, time.Millisecond, 10*time.Minute)
	fe.protocol = "ipfix"
	fe.nbar2 = catA
	dev := testDevice("10.42.9.1")
	dev.flowExporter = fe
	sm := &SimulatorManager{devicesByIP: map[string]*DeviceSimulator{"10.42.9.1": dev}}
	c := newScenarioController(sm, nil)
	c.spec = &Scenario{Protocol: "ipfix"}
	part := &scenarioPart{gate: &atomic.Pointer[gateState]{}, ledger: &ledgerEntry{}, drain: &drainGate{}, now: time.Now}
	if ok, reason, _ := c.installScenPart(dev, part); !ok {
		t.Fatalf("installScenPart: %s", reason)
	}
	if part.nbar2 != catA {
		t.Fatal("installScenPart must capture the exporter's catalog on the part")
	}
	fe.nbar2 = catB // swapped after install
	t0 := time.Unix(1_700_000_000, 0)
	part.gate.Store(&gateState{phase: phaseRunning, t0: t0, t1: t0.Add(time.Hour)})
	part.bucketFlowBatch(t0.Add(time.Second), []FlowRecord{avcFlow(0, 6, 80, 100, 1, avcRef{App: 1})})
	apps := part.ledger.appSnapshot()
	if _, ok := apps[appKey{6, 80, nbar2TestAppHTTP}]; !ok {
		t.Fatalf("ledger must keep resolving through the catalog captured at install (http, %#x), got %+v", nbar2TestAppHTTP, apps)
	}
}

// nbar2ScenarioFixture is a scenario over several test-constructed ipfix
// participants, each with its own catalog (nil = plain), driven through the
// real controller, ledger and report.
type nbar2ScenarioFixture struct {
	sm       *SimulatorManager
	c        *ScenarioController
	fes      map[string]*FlowExporter
	conn     *net.UDPConn
	addr     *net.UDPAddr
	ch       <-chan []byte
	base     time.Time
	clockNow *time.Time
}

func newNbar2ScenarioFixture(t *testing.T, cats map[string]*nbar2Catalog) *nbar2ScenarioFixture {
	t.Helper()
	ln, ch := testUDPListener(t)
	t.Cleanup(func() { ln.Close() })
	conn := testSender(t)
	t.Cleanup(func() { conn.Close() })
	addr := ln.LocalAddr().(*net.UDPAddr)

	sm := &SimulatorManager{devices: map[string]*DeviceSimulator{}, deviceIPs: map[string]struct{}{},
		deviceTypesByIP: map[string]string{}, devicesByIP: map[string]*DeviceSimulator{}}
	fes := map[string]*FlowExporter{}
	ips := make([]string, 0, len(cats))
	for ip, cat := range cats {
		dev := testDevice(ip)
		dev.ID = "device-" + ip
		fe := newTestFlowExporter(dev, zeroGenFlowProfile(), time.Millisecond, time.Millisecond, 10*time.Minute)
		fe.collectorAddr = addr
		fe.collectorStr = "127.0.0.1:4739"
		fe.protocol = "ipfix"
		if cat != nil {
			fe.encoder = cat.Encoder()
			fe.nbar2 = cat
		} else {
			fe.encoder = IPFIXEncoder{}
		}
		dev.flowExporter = fe
		sm.devices[dev.ID] = dev
		sm.deviceIPs[ip] = struct{}{}
		sm.devicesByIP[ip] = dev
		fes[ip] = fe
		ips = append(ips, ip)
	}
	base := time.Unix(1_700_000_000, 0)
	clockNow := base
	c := newScenarioController(sm, func() time.Time { return clockNow })
	spec := &Scenario{Participants: ips, Protocol: "ipfix", Rate: 1, Window: time.Hour, Seed: 1}
	if err := c.Submit(spec, "s-nbar2c"); err != nil {
		t.Fatal(err)
	}
	if _, _, err := c.Arm(); err != nil {
		t.Fatal(err)
	}
	if err := c.Start(context.Background()); err != nil {
		t.Fatal(err)
	}
	return &nbar2ScenarioFixture{sm: sm, c: c, fes: fes, conn: conn, addr: addr, ch: ch, base: base, clockNow: &clockNow}
}

// inject adds expired flows to one participant and ticks it once at base+1m.
func (f *nbar2ScenarioFixture) inject(ip string, recs ...FlowRecord) {
	fe := f.fes[ip]
	past := f.base.Add(-time.Hour)
	for _, r := range recs {
		fe.cache.Add(r, past)
	}
	fe.Tick(f.base.Add(time.Minute), f.conn, testPool())
	for receivePacket(f.ch) != nil {
	}
}

// finish advances the clock to the window end, stops, and builds the report.
func (f *nbar2ScenarioFixture) finish(t *testing.T) *scenarioReport {
	t.Helper()
	*f.clockNow = f.base.Add(time.Hour)
	if _, err := f.c.Stop(); err != nil {
		t.Fatal(err)
	}
	rep := buildScenarioReport(f.sm, f.c)
	if rep == nil {
		t.Fatal("no report")
	}
	return rep
}

// Two participants whose catalogs put DIFFERENT applications at index 1
// yield two rows keyed by wire id, never one merged index-1 row; and a plain
// participant on the same port yields a third row without an id, sorted
// first. application_name comes from the catalogs.
func TestNbar2GroundTruth_MixedFleetRowsByWireID(t *testing.T) {
	f := newNbar2ScenarioFixture(t, map[string]*nbar2Catalog{
		"10.42.9.11": testNbar2Catalog(t, "a", nbar2GoodHTTP, nbar2GoodDNS), // index 1 = http
		"10.42.9.12": testNbar2Catalog(t, "b", nbar2GoodDNS, nbar2GoodHTTP), // index 1 = dns
		"10.42.9.13": nil,
	})
	f.inject("10.42.9.11", avcFlow(0, 6, 80, 1000, 10, avcRef{App: 1, Host: 1, URI: 1}), avcFlow(1, 6, 80, 1000, 10, avcRef{App: 1, Host: 2, URI: 1}))
	f.inject("10.42.9.12", avcFlow(0, 17, 53, 200, 2, avcRef{App: 1}), avcFlow(1, 6, 80, 500, 5, avcRef{App: 2, Host: 1, URI: 2}))
	f.inject("10.42.9.13", avcFlow(0, 6, 80, 300, 3, avcRef{}))
	rep := f.finish(t)

	// Expected rows in key order: (tcp,80,plain) (tcp,80,http) (udp,53,dns).
	if len(rep.Applications) != 3 {
		t.Fatalf("applications = %+v, want 3 rows", rep.Applications)
	}
	r := rep.Applications
	if r[0].DstPort != 80 || r[0].ApplicationID != 0 || r[0].ApplicationName != "" || r[0].Records != 1 {
		t.Fatalf("row 0 must be the plain tcp/80 row: %+v", r[0])
	}
	if r[1].DstPort != 80 || r[1].ApplicationID != nbar2TestAppHTTP || r[1].ApplicationName != "http" || r[1].Records != 3 || r[1].Bytes != 2500 {
		t.Fatalf("row 1 must merge both participants' http records by WIRE id (index 1 on one, 2 on the other): %+v", r[1])
	}
	if r[2].L4Proto != "udp" || r[2].ApplicationID != nbar2TestAppDNS || r[2].ApplicationName != "dns" || r[2].Records != 1 {
		t.Fatalf("row 2 must be dns: %+v", r[2])
	}
	var sum uint64
	for _, row := range r {
		sum += row.Records
	}
	if sum != rep.Summary.Sent {
		t.Fatalf("Σ applications[].records = %d, want summary.sent = %d", sum, rep.Summary.Sent)
	}
	// JSON shape: the plain row carries neither new key; the NBAR2 row both.
	b, _ := json.Marshal(rep.Applications)
	if strings.Count(string(b), `"application_id"`) != 2 || strings.Count(string(b), `"application_name"`) != 2 {
		t.Fatalf("application_id/application_name must appear on the two NBAR2 rows only:\n%s", b)
	}

	// l7_values: http hosts 2+1 (www.example.com from both participants: index 1
	// in catalog a, index 1 in catalog b), cdn.example.net 1; URIs "/" 2 and
	// "/index.html" 1. Sorted by (id, field, value).
	want := []scenarioL7Row{
		{ApplicationID: nbar2TestAppHTTP, ApplicationName: "http", Field: "http_host", Value: "cdn.example.net", Records: 1, Bytes: 1000, Packets: 10},
		{ApplicationID: nbar2TestAppHTTP, ApplicationName: "http", Field: "http_host", Value: "www.example.com", Records: 2, Bytes: 1500, Packets: 15},
		{ApplicationID: nbar2TestAppHTTP, ApplicationName: "http", Field: "http_uri", Value: "/", Records: 2, Bytes: 2000, Packets: 20},
		{ApplicationID: nbar2TestAppHTTP, ApplicationName: "http", Field: "http_uri", Value: "/index.html", Records: 1, Bytes: 500, Packets: 5},
	}
	if len(rep.L7Values) != len(want) {
		t.Fatalf("l7_values = %+v, want %d rows", rep.L7Values, len(want))
	}
	for i := range want {
		got := rep.L7Values[i]
		got.AvgBytesPerSecond = 0
		if got != want[i] {
			t.Fatalf("l7_values[%d] = %+v, want %+v", i, got, want[i])
		}
	}
	// Rate basis: in-window bytes over the 1h window.
	if rep.L7Values[1].AvgBytesPerSecond != 1500/time.Hour.Seconds() {
		t.Fatalf("avg_bytes_per_second = %g, want %g", rep.L7Values[1].AvgBytesPerSecond, 1500/time.Hour.Seconds())
	}
}

// The inequality Σ l7_values[field].records ≤ Σ applications[].records, with
// BOTH arms: strictly less when an application has no hosts (dns), equal
// when every record carries exactly one host and one URI. A fold that counts
// nothing passes the first arm alone; the second is the positive control.
func TestNbar2GroundTruth_InequalityBothArms(t *testing.T) {
	sumField := func(rows []scenarioL7Row, field string) (n uint64) {
		for _, r := range rows {
			if r.Field == field {
				n += r.Records
			}
		}
		return n
	}
	sumApps := func(rows []scenarioAppRow) (n uint64) {
		for _, r := range rows {
			n += r.Records
		}
		return n
	}

	// Arm 1: http (hosts) + dns (none) → strictly less.
	f := newNbar2ScenarioFixture(t, map[string]*nbar2Catalog{"10.42.9.21": testNbar2Catalog(t, "a", nbar2GoodHTTP, nbar2GoodDNS)})
	f.inject("10.42.9.21",
		avcFlow(0, 6, 80, 100, 1, avcRef{App: 1, Host: 1, URI: 1}),
		avcFlow(1, 6, 80, 100, 1, avcRef{App: 1, Host: 2, URI: 2}),
		avcFlow(2, 17, 53, 100, 1, avcRef{App: 2}),
		avcFlow(3, 17, 53, 100, 1, avcRef{App: 2}))
	rep := f.finish(t)
	if h, a := sumField(rep.L7Values, "http_host"), sumApps(rep.Applications); !(h < a) || h != 2 || a != 4 {
		t.Fatalf("host rows %d must be strictly below application records %d (want 2 < 4)", h, a)
	}

	// Arm 2: one application, one host, one URI → equality on both fields.
	g := newNbar2ScenarioFixture(t, map[string]*nbar2Catalog{"10.42.9.22": testNbar2Catalog(t, "b",
		`{"name":"http","description":"HTTP","engine":3,"selector":80,"proto":"tcp","dst_port":80,"hosts":[{"value":"h"}],"uris":[{"value":"/u"}]}`)})
	g.inject("10.42.9.22",
		avcFlow(0, 6, 80, 100, 1, avcRef{App: 1, Host: 1, URI: 1}),
		avcFlow(1, 6, 80, 100, 1, avcRef{App: 1, Host: 1, URI: 1}),
		avcFlow(2, 6, 80, 100, 1, avcRef{App: 1, Host: 1, URI: 1}))
	rep = g.finish(t)
	a := sumApps(rep.Applications)
	if a != 3 || sumField(rep.L7Values, "http_host") != a || sumField(rep.L7Values, "http_uri") != a {
		t.Fatalf("positive control: every record carried one host and one URI, so both fields must equal %d; l7=%+v", a, rep.L7Values)
	}
}

// A plain-only scenario serializes applications rows with no new keys (the
// pre-Plan-C shape) and an empty l7_values block.
func TestNbar2GroundTruth_PlainOnlyShapeUnchanged(t *testing.T) {
	f := newNbar2ScenarioFixture(t, map[string]*nbar2Catalog{"10.42.9.31": nil})
	f.inject("10.42.9.31", avcFlow(0, 6, 443, 1000, 10, avcRef{}), avcFlow(1, 17, 53, 200, 2, avcRef{}))
	rep := f.finish(t)
	b, err := json.Marshal(rep)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(b, []byte(`"application_id"`)) || bytes.Contains(b, []byte(`"application_name"`)) {
		t.Fatalf("plain rows must carry neither application_id nor application_name:\n%s", b)
	}
	if !bytes.Contains(b, []byte(`"l7_values":[]`)) {
		t.Fatalf("l7_values must be present and empty:\n%s", b)
	}
	if i, j := bytes.Index(b, []byte(`"applications"`)), bytes.Index(b, []byte(`"l7_values"`)); i < 0 || j < i {
		t.Fatal("l7_values must follow applications")
	}
}

// Failed sends fold nothing into l7_values; drain bytes count in bytes but
// not in the rate, the applications convention.
func TestNbar2GroundTruth_L7FailedAndDrain(t *testing.T) {
	cat := testNbar2Catalog(t, "t", nbar2GoodHTTP)
	fe := newTestFlowExporter(testDevice("10.42.9.41"), zeroGenFlowProfile(), time.Millisecond, time.Millisecond, 10*time.Minute)
	fe.encoder = cat.Encoder()
	fe.nbar2 = cat
	conn := testSender(t)
	conn.Close() // closed socket → WriteTo fails
	badAddr := &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 9}
	gate := &atomic.Pointer[gateState]{}
	led := &ledgerEntry{}
	part := &scenarioPart{gate: gate, ledger: led, drain: &drainGate{}, now: time.Now, countApps: true, nbar2: cat}
	fe.scenPart.Store(part)
	t0 := time.Unix(1_700_000_000, 0)
	t1 := t0.Add(10 * time.Second)
	gate.Store(&gateState{phase: phaseRunning, t0: t0, t1: t1})
	for i := 0; i < 3; i++ {
		fe.cache.Add(avcFlow(i, 6, 80, 100, 1, avcRef{App: 1, Host: 1, URI: 1}), t0.Add(-time.Hour))
	}
	tickWithEncoder(fe, t0.Add(time.Second), cat.Encoder(), conn, badAddr, testPool())
	if led.sendFailures.Load() != 3 {
		t.Fatalf("send_failures = %d, want 3", led.sendFailures.Load())
	}
	if l7 := led.l7Snapshot(); l7 != nil {
		t.Fatalf("failed batch reached the layer-7 tally: %+v", l7)
	}

	part.bucketFlowBatch(t0.Add(time.Second), []FlowRecord{avcFlow(0, 6, 80, 100, 1, avcRef{App: 1, Host: 1})})
	part.bucketFlowBatch(t1.Add(200*time.Millisecond), []FlowRecord{avcFlow(1, 6, 80, 40, 1, avcRef{App: 1, Host: 1})})
	l7 := led.l7Snapshot()
	k := l7Key{appID: nbar2TestAppHTTP, field: l7FieldHost, value: "www.example.com"}
	if c := l7[k]; c.records != 2 || c.bytes != 140 || c.inWindowBytes != 100 {
		t.Fatalf("host row = %+v, want 2 records, 140 bytes, 100 in-window", c)
	}
	rows := buildL7Rows(&ScenarioResult{T0Actual: t0, T1Actual: t1, L7: map[l7Key]l7Counters{k: l7[k]}, AppNames: map[uint32]string{nbar2TestAppHTTP: "http"}})
	if len(rows) != 1 || rows[0].AvgBytesPerSecond != 10 || rows[0].Bytes != 140 || rows[0].ApplicationName != "http" {
		t.Fatalf("l7 row = %+v, want avg 10 B/s (in-window basis), bytes 140, name http", rows)
	}
}

// The l7 projection is deterministic and sorted by (id, field, value).
func TestNbar2GroundTruth_L7Determinism(t *testing.T) {
	res := &ScenarioResult{T0Actual: time.Unix(0, 0), T1Actual: time.Unix(10, 0),
		L7: map[l7Key]l7Counters{
			{nbar2TestAppSSL, l7FieldHost, "b"}:  {records: 1},
			{nbar2TestAppHTTP, l7FieldURI, "/z"}: {records: 1},
			{nbar2TestAppHTTP, l7FieldHost, "b"}: {records: 1},
			{nbar2TestAppHTTP, l7FieldHost, "a"}: {records: 1},
		}}
	a, _ := json.Marshal(buildL7Rows(res))
	for i := 0; i < 20; i++ {
		if b, _ := json.Marshal(buildL7Rows(res)); !bytes.Equal(a, b) {
			t.Fatalf("non-deterministic serialization:\n%s\n%s", a, b)
		}
	}
	rows := buildL7Rows(res)
	if rows[0].Value != "a" || rows[1].Value != "b" || rows[2].Field != "http_uri" || rows[3].ApplicationID != nbar2TestAppSSL {
		t.Fatalf("row order wrong: %+v", rows)
	}
}

// Every shipped catalog names each applicationId the same way, which is what
// makes the report's first-seen id → name table safe. Positive control
// first: two planted overlays that disagree must be named.
func TestNbar2CatalogsAgreeOnNames(t *testing.T) {
	universal, err := LoadEmbeddedNbar2Catalog()
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	for slug, name := range map[string]string{"typea": "http", "typeb": "web"} {
		if err := os.MkdirAll(filepath.Join(dir, slug), 0o755); err != nil {
			t.Fatal(err)
		}
		doc := `{"extends": false, "entries":[{"name":"` + name + `","description":"x","engine":3,"selector":80,"proto":"tcp","dst_port":80}]}`
		if err := os.WriteFile(filepath.Join(dir, slug, "nbar2.json"), []byte(doc), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	planted, err := ScanPerTypeNbar2Catalogs(universal, dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(planted) != 2 {
		t.Fatalf("planted scan returned %d catalogs, want 2", len(planted))
	}
	err = nbar2CatalogsAgreeOnNames(planted)
	if err == nil || !strings.Contains(err.Error(), "typea") || !strings.Contains(err.Error(), `"http"`) || !strings.Contains(err.Error(), `"web"`) {
		t.Fatalf("positive control: a rule that reports nothing at this input is broken; got %v", err)
	}

	shipped := nbar2TestManager(t).nbar2CatalogsByType
	if len(shipped) < 2 {
		t.Fatalf("shipped catalogs = %d, want the universal plus at least one overlay", len(shipped))
	}
	if err := nbar2CatalogsAgreeOnNames(shipped); err != nil {
		t.Fatal(err)
	}
}
