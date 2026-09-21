/*
 * Copyright 2026 Ronny Trommer <ronny@no42.org>
 * SPDX-License-Identifier: Apache-2.0
 */

package main

import (
	"bufio"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"sort"
	"strings"
	"sync"
	"testing"
	"time"
)

// ipfix_interop_test.go — the check with detection power for NBAR2 export
// (spec section 6, "External interop, the load-bearing check").
//
// Every other IPFIX/AVC test in the package decodes nl6's bytes with nl6's
// own decoder, so a shared misreading of RFC 7011 section 7 or of Cisco's
// PEN 9 numbers passes all of them. This one drives nl6's REAL exporter over
// a REAL UDP socket at a REAL IPFIXcol2 (CESNET; started by
// `make test-interop-ipfix` as a container on the host network) and reads
// what the collector's own JSON output says it decoded. The nl6#624 lesson
// applies verbatim: the first SNMPv3 interop run failed every row with the
// Go suite green.
//
// Gated on NL6_IPFIX_INTEROP=1 the nl6#624 way: env unset skips (no plain
// `go test` has the container), env set with the collector unreachable
// FAILS, because a silent skip asserts nothing.
//
// What the collector's output looks like (observed 2026-09-21 against
// ipfixcol2 2.8.0 from Debian forky with the config in
// examples/ipfixcol2/ipfixcol2.xml, nonPrintableChar ON; every assertion
// below keys on this):
//
//	{"@type":"ipfix.entry","iana:octetDeltaCount":380217,"iana:packetDeltaCount":140,
//	 "iana:protocolIdentifier":6,...,"iana:destinationTransportPort":80,...,
//	 "iana:applicationId":50331728,
//	 "cisco:appHTTPHost":"\u0003\u0000\u0000P4\u0002www.example.com",
//	 "cisco:appHTTPUriStatistics":"/api/v1/status\u0000\u0000\u0001",
//	 "ipfix:exportTime":1789866258,"ipfix:seqNumber":8,"ipfix:odid":168361985,
//	 "ipfix:msgLength":1212,"ipfix:srcAddr":"127.0.0.1","ipfix:templateId":258}
//	{"@type":"ipfix.optionsEntry","iana:applicationId":50331728,
//	 "iana:applicationName":"http","iana:applicationDescription":"Hypertext Transfer Protocol",
//	 ...,"ipfix:templateId":259}
//
// Three facts shape the assertions. applicationId (octetArray 4) is rendered
// as an INTEGER under octetArrayAsUint. The two PEN 9 fields are rendered BY
// NAME from libfds's own cisco.xml, which is the point: had nl6 sent a wrong
// number they would read en9:idNNNN (an id cisco.xml DOES define renders
// under that name instead, so a wrong-id mutation must pick one it does not:
// 12232 to 12242 and 12244 are all defined). And libfds types both 12235 and
// 9357 as `string`, which is lossless ONLY with nonPrintableChar on: every
// non-printable byte is then a \u00XX escape that encoding/json turns back
// into the byte, so Cisco's six-byte host prefix (nl6#679) and the URI
// statistics' NUL and two-byte hit count are asserted here byte for byte.
// With the flag OFF (the config before 2026-09-21, and the state the comment
// there wrongly described as showing those bytes) the collector DROPPED
// them: the host rendered "P4www.example.com", prefix-only "P4", the URI
// "/api/v1/status" with no count, and an earlier version of this comment
// read that as "the collector cuts at the NUL". It does not; it discards.
//
// The collector does not log UDP sequence gaps, so the RFC 7011 section 3.1
// rule (the sequence number counts Data Records, options records included)
// is checked from the records themselves: for every observation domain the
// sequence carried by message N+1 equals message N's plus the number of
// data records the collector reported for message N.

const (
	ipfixInteropEnvGate = "NL6_IPFIX_INTEROP"
	// ipfixInteropCollector must match <localPort> in examples/ipfixcol2/
	// ipfixcol2.xml and the collector attachNbar2Device configures.
	ipfixInteropCollector = "127.0.0.1:4739"
	// ipfixInteropSinkAddr must match the <send> block in the same file.
	ipfixInteropSinkAddr = "127.0.0.1:14739"
)

// ipfixInteropRecord is one line of the collector's NDJSON, decoded loosely:
// numbers as float64 (every field here fits exactly), strings as strings.
type ipfixInteropRecord map[string]any

func (r ipfixInteropRecord) num(key string) (float64, bool) {
	v, ok := r[key].(float64)
	return v, ok
}

func (r ipfixInteropRecord) str(key string) string {
	s, _ := r[key].(string)
	return s
}

// fixedStr reads a FIXED-WIDTH string element (applicationName 24,
// applicationDescription 55): with nonPrintableChar on, the collector renders
// the NUL padding as \u0000 escapes, so the padding is trimmed here. Not
// used for the variable-length PEN 9 fields, whose NULs are data.
func (r ipfixInteropRecord) fixedStr(key string) string {
	return strings.TrimRight(r.str(key), "\x00")
}

// interopHostAfterPrefix returns the hostname the collector decoded for IE
// 12235: the value must start with avcHostPrefix (a real IOS-XE and nl6 since
// nl6#679 never send the field without it), and the remainder is the host,
// empty for a prefix-only value. The bytes reach us intact because the
// collector escapes non-printables (see the file comment).
func interopHostAfterPrefix(t *testing.T, value string) string {
	t.Helper()
	if !strings.HasPrefix(value, string(avcHostPrefix)) {
		t.Fatalf("collector's IE 12235 value %q (%x) lacks Cisco's host prefix %x (nl6#679)", value, value, avcHostPrefix)
	}
	return value[len(avcHostPrefix):]
}

// interopURIStats parses the collector's IE 9357 rendering as uriStatsValue
// writes it: URI, NUL, big-endian uint16 hit count, no trailing delimiter. An
// empty value (a record with no URI) returns "", 0.
func interopURIStats(t *testing.T, value string) (string, uint16) {
	t.Helper()
	if value == "" {
		return "", 0
	}
	nul := strings.IndexByte(value, 0)
	if nul < 0 || len(value) != nul+3 {
		t.Fatalf("collector's IE 9357 value %q (%x) is not URI, NUL, 2-byte count", value, value)
	}
	return value[:nul], uint16(value[nul+1])<<8 | uint16(value[nul+2])
}

func (r ipfixInteropRecord) isData() bool    { return r.str("@type") == "ipfix.entry" }
func (r ipfixInteropRecord) isOptions() bool { return r.str("@type") == "ipfix.optionsEntry" }

// ipfixInteropSink is the TCP listener the collector's JSON output sends to.
// ONE per test process, never closed: the collector's <send> output holds a
// single connection and does not reconnect promptly after the peer goes
// away, so a per-test listener left the second test reading nothing. Each
// test takes a start offset and reads only what arrived after it.
type ipfixInteropSink struct {
	ln   net.Listener
	mu   sync.Mutex
	recs []ipfixInteropRecord
}

var (
	ipfixInteropSinkOnce sync.Once
	ipfixInteropSinkInst *ipfixInteropSink
	ipfixInteropSinkErr  error
)

// startIPFIXInteropSink returns the process-wide sink and the index of the
// first record this test will see. The collector connects lazily, on its
// first record, so the listener is up before the first datagram is sent.
func startIPFIXInteropSink(t *testing.T) (*ipfixInteropSink, int) {
	t.Helper()
	ipfixInteropSinkOnce.Do(func() {
		ln, err := net.Listen("tcp", ipfixInteropSinkAddr)
		if err != nil {
			ipfixInteropSinkErr = err
			return
		}
		s := &ipfixInteropSink{ln: ln}
		ipfixInteropSinkInst = s
		go func() {
			for {
				c, err := ln.Accept()
				if err != nil {
					return
				}
				go func() {
					defer c.Close()
					sc := bufio.NewScanner(c)
					sc.Buffer(make([]byte, 1<<20), 1<<20)
					for sc.Scan() {
						var rec ipfixInteropRecord
						if err := json.Unmarshal(sc.Bytes(), &rec); err != nil {
							continue
						}
						s.mu.Lock()
						s.recs = append(s.recs, rec)
						s.mu.Unlock()
					}
				}()
			}
		}()
	})
	if ipfixInteropSinkErr != nil {
		t.Fatalf("listen %s for the collector's JSON output: %v", ipfixInteropSinkAddr, ipfixInteropSinkErr)
	}
	s := ipfixInteropSinkInst
	s.mu.Lock()
	defer s.mu.Unlock()
	return s, len(s.recs)
}

// recordsFrom returns a copy of everything received at or after index from.
func (s *ipfixInteropSink) recordsFrom(from int) []ipfixInteropRecord {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]ipfixInteropRecord, len(s.recs)-from)
	copy(out, s.recs[from:])
	return out
}

// settle waits until no new record has arrived for quiet (and at least one
// has arrived since from), or until max.
func (s *ipfixInteropSink) settle(from int, quiet, max time.Duration) {
	deadline := time.Now().Add(max)
	last := -1
	for time.Now().Before(deadline) {
		s.mu.Lock()
		n := len(s.recs)
		s.mu.Unlock()
		if n == last && n > from {
			return
		}
		last = n
		time.Sleep(quiet)
	}
}

// requireIPFIXInterop applies the gate and checks the collector is bound.
func requireIPFIXInterop(t *testing.T) {
	t.Helper()
	if os.Getenv(ipfixInteropEnvGate) != "1" {
		t.Skipf("set %s=1 (via `make test-interop-ipfix`) to run the IPFIXcol2 interop check", ipfixInteropEnvGate)
	}
	// A UDP "connect" cannot prove a listener; the collector's TCP sender is
	// the only reachability signal, and it connects lazily. So the check is
	// on the container's presence via its bound port: the kernel refuses a
	// second bind of the collector's UDP port while ipfixcol2 holds it.
	probe, err := net.ListenPacket("udp4", ipfixInteropCollector)
	if err == nil {
		probe.Close()
		t.Fatalf("%s=1 but nothing holds %s: is the IPFIXcol2 container running (make test-interop-ipfix)?", ipfixInteropEnvGate, ipfixInteropCollector)
	}
}

// awaitIPFIXCollector ticks a throwaway plain exporter at the collector
// until the sink receives its first record, or fails after max. The
// collector's JSON <send> output connects to the sink LAZILY and, when the
// sink was not yet listening at its first attempt, retries on its own
// schedule; on the CI runner that schedule left the first test's records
// unseen for the whole of its 15 s settle while the second test, 20 s
// later, passed. Warming the path up first makes the tests independent of
// that policy. The warm-up device has its own observation domain, so its
// records never count against another device's sent total.
func awaitIPFIXCollector(t *testing.T, sink *ipfixInteropSink, from int, max time.Duration) {
	t.Helper()
	sm := nbar2TestManager(t)
	warm := attachNbar2Device(t, sm, "10.9.0.250", "cisco_ios.json", false)
	defer warm.flowExporter.Close()
	warm.flowExporter.cache = NewFlowCache(time.Second, time.Second, 4)
	conn := testSender(t)
	defer conn.Close()
	start := time.Now()
	deadline := start.Add(max)
	for i := 0; time.Now().Before(deadline); i++ {
		warm.flowExporter.Tick(start.Add(time.Duration(i)*2*time.Second), conn, testPool())
		time.Sleep(time.Second)
		if len(sink.recordsFrom(from)) > 0 {
			t.Logf("collector output reached the sink after %s", time.Since(start).Round(100*time.Millisecond))
			return
		}
	}
	t.Fatalf("collector delivered nothing to the sink within %s: is its JSON <send> output pointed at %s, and is the container on the host network?", max, ipfixInteropSinkAddr)
}

// interopEnterpriseKey names the PEN 9 element the collector resolved, or
// fails with both possible causes when it did not.
func interopEnterpriseKey(t *testing.T, rec ipfixInteropRecord, name string, id int) string {
	t.Helper()
	key := "cisco:" + name
	if _, ok := rec[key]; ok {
		return key
	}
	if _, ok := rec[fmt.Sprintf("en9:id%d", id)]; ok {
		t.Fatalf("IPFIXcol2 rendered IE %d under PEN 9 as en9:id%d, not %s: either the collector's libfds has no definition for it, or nl6 put a wrong element id on the wire (testdata/cisco-avc/elements.tsv is the pinned reading)", id, id, key)
	}
	t.Fatalf("record carries neither %s nor en9:id%d: %v", key, id, rec)
	return ""
}

// TestIPFIXInteropAVCDecodes: one NBAR2 exporter and one plain IPFIX exporter
// tick at the collector; the collector's output must resolve the enterprise
// elements by name, decode applicationId, carry the application table for
// every id seen in a data record, keep the RFC 7011 sequence arithmetic,
// and show NONE of that on the plain control.
func TestIPFIXInteropAVCDecodes(t *testing.T) {
	requireIPFIXInterop(t)
	sink, from := startIPFIXInteropSink(t)
	awaitIPFIXCollector(t, sink, from, 90*time.Second)
	from = len(sink.recordsFrom(0))

	sm := nbar2TestManager(t)
	avc := attachNbar2Device(t, sm, "10.9.0.1", "cisco_ios.json", true)
	plain := attachNbar2Device(t, sm, "10.9.0.4", "cisco_ios.json", false)
	defer avc.flowExporter.Close()
	defer plain.flowExporter.Close()
	cat := sm.Nbar2CatalogFor("cisco_ios.json")
	for _, d := range []*DeviceSimulator{avc, plain} {
		d.flowExporter.cache = NewFlowCache(time.Second, time.Second, 16)
	}
	conn := testSender(t)
	defer conn.Close()

	var sentAVC, sentPlain uint64
	now := time.Now()
	for i := 0; i < 6; i++ {
		at := now.Add(time.Duration(i) * 2 * time.Second)
		sentAVC += avc.flowExporter.Tick(at, conn, testPool()).RecordsSent
		sentPlain += plain.flowExporter.Tick(at, conn, testPool()).RecordsSent
		time.Sleep(200 * time.Millisecond)
	}
	if sentAVC == 0 || sentPlain == 0 {
		t.Fatalf("exporters sent %d AVC / %d plain records; the test drove nothing", sentAVC, sentPlain)
	}
	sink.settle(from, 500*time.Millisecond, 15*time.Second)
	recs := sink.recordsFrom(from)
	if len(recs) == 0 {
		t.Fatal("collector delivered no records to the sink: is its JSON <send> output pointed at " + ipfixInteropSinkAddr + "?")
	}

	odidAVC := float64(avc.flowExporter.domainID)
	odidPlain := float64(plain.flowExporter.domainID)
	byID := map[uint32]*avcApplication{}
	for i := range cat.Encoder().Applications() {
		app := &cat.Encoder().Applications()[i]
		byID[app.ID] = app
	}

	// 1-4: data records from the AVC device.
	var avcData, avcWithHost int
	seenIDs := map[uint32]bool{}
	for _, r := range recs {
		if od, _ := r.num("ipfix:odid"); od != odidAVC || !r.isData() {
			continue
		}
		avcData++
		if tid, _ := r.num("ipfix:templateId"); tid != float64(ipfixAVCTemplateID) {
			t.Fatalf("AVC device data record on template %v, want %d: %v", tid, ipfixAVCTemplateID, r)
		}
		idf, ok := r.num("iana:applicationId")
		if !ok {
			t.Fatalf("AVC record without a decoded applicationId: %v", r)
		}
		app := byID[uint32(idf)]
		if app == nil {
			t.Fatalf("applicationId %d is not in the cisco_ios catalog: %v", uint32(idf), r)
		}
		seenIDs[app.ID] = true
		if p, _ := r.num("iana:protocolIdentifier"); uint8(p) != app.Proto {
			t.Fatalf("record protocol %v disagrees with application %s (%d)", p, app.Name, app.Proto)
		}
		if p, _ := r.num("iana:destinationTransportPort"); uint16(p) != app.DstPort {
			t.Fatalf("record port %v disagrees with application %s (%d)", p, app.Name, app.DstPort)
		}
		hostKey := interopEnterpriseKey(t, r, "appHTTPHost", ciscoHTTPHost)
		uriKey := interopEnterpriseKey(t, r, "appHTTPUriStatistics", ciscoHTTPURIStatistics)
		host := interopHostAfterPrefix(t, r.str(hostKey))
		uri, hits := interopURIStats(t, r.str(uriKey))
		if host != "" {
			avcWithHost++
			if !interopHasString(app.Hosts, host) {
				t.Fatalf("decoded host %q is not a catalog host of %s (%v)", host, app.Name, app.Hosts)
			}
		} else if len(app.Hosts) > 0 {
			t.Fatalf("application %s has hosts but the record carried none: %v", app.Name, r)
		}
		if uri != "" {
			if !interopHasString(app.URIs, uri) {
				t.Fatalf("decoded URI %q is not a catalog URI of %s (%v)", uri, app.Name, app.URIs)
			}
			if hits != 1 {
				t.Fatalf("decoded URI hit count %d, want 1 (uriStatsValue's per-record count)", hits)
			}
		} else if len(app.URIs) > 0 {
			t.Fatalf("application %s has URIs but the record carried none: %v", app.Name, r)
		}
	}
	if avcData == 0 {
		t.Fatal("no data record from the AVC device reached the collector")
	}
	if avcWithHost == 0 {
		t.Fatal("no AVC record carried an HTTP host; the shipped catalog has HTTP entries, so the collector decoded none of them")
	}

	// 5: application table (template 259) agrees with the data stream.
	table := map[uint32]ipfixInteropRecord{}
	for _, r := range recs {
		if od, _ := r.num("ipfix:odid"); od != odidAVC || !r.isOptions() {
			continue
		}
		if tid, _ := r.num("ipfix:templateId"); tid != float64(ipfixAppTableTemplateID) {
			t.Fatalf("options record on template %v, want %d: %v", tid, ipfixAppTableTemplateID, r)
		}
		idf, _ := r.num("iana:applicationId")
		table[uint32(idf)] = r
	}
	if len(table) == 0 {
		t.Fatal("no application-table record reached the collector (ignoreOptions must be false in ipfixcol2.xml)")
	}
	for id, app := range byID {
		row, ok := table[id]
		if !ok {
			t.Fatalf("application table lacks %s (%d)", app.Name, id)
		}
		if row.fixedStr("iana:applicationName") != app.Name || row.fixedStr("iana:applicationDescription") != app.Description {
			t.Fatalf("application table row for %d = %q / %q, want %q / %q", id, row.fixedStr("iana:applicationName"), row.fixedStr("iana:applicationDescription"), app.Name, app.Description)
		}
	}
	for id := range seenIDs {
		if _, ok := table[id]; !ok {
			t.Fatalf("data record carried applicationId %d that the application table never advertised", id)
		}
	}

	// 6: the plain control carries no AVC field at all.
	var plainData int
	for _, r := range recs {
		if od, _ := r.num("ipfix:odid"); od != odidPlain {
			continue
		}
		if r.isOptions() {
			t.Fatalf("plain device emitted an options record: %v", r)
		}
		plainData++
		if tid, _ := r.num("ipfix:templateId"); tid != float64(ipfixTemplateID) {
			t.Fatalf("plain device data record on template %v, want %d", tid, ipfixTemplateID)
		}
		for k := range r {
			if strings.HasPrefix(k, "cisco:") || strings.HasPrefix(k, "en9:") || k == "iana:applicationId" {
				t.Fatalf("plain control record carries %s: %v", k, r)
			}
		}
	}
	if plainData == 0 {
		t.Fatal("no data record from the plain control reached the collector")
	}

	// Sequence arithmetic per observation domain (RFC 7011 section 3.1).
	checkIPFIXInteropSequence(t, recs)

	// Received equals sent, per device: UDP on loopback to a local container
	// does not lose datagrams, so a shortfall is a decode failure.
	if uint64(avcData) != sentAVC || uint64(plainData) != sentPlain {
		t.Fatalf("collector decoded %d AVC / %d plain data records; nl6 sent %d / %d", avcData, plainData, sentAVC, sentPlain)
	}
}

// checkIPFIXInteropSequence groups records by (odid, seqNumber) into
// messages and requires each message's sequence to equal the previous
// message's plus the previous message's record count, options records
// included. Template-only messages produce no records and advance nothing,
// so they are invisible here and the arithmetic still holds.
func checkIPFIXInteropSequence(t *testing.T, recs []ipfixInteropRecord) {
	t.Helper()
	type msgKey struct{ odid, seq float64 }
	counts := map[msgKey]int{}
	for _, r := range recs {
		od, _ := r.num("ipfix:odid")
		seq, ok := r.num("ipfix:seqNumber")
		if !ok {
			t.Fatalf("record without ipfix:seqNumber (detailedInfo must be true in ipfixcol2.xml): %v", r)
		}
		counts[msgKey{od, seq}]++
	}
	byODID := map[float64][]msgKey{}
	for k := range counts {
		byODID[k.odid] = append(byODID[k.odid], k)
	}
	checked := 0
	for od, msgs := range byODID {
		sort.Slice(msgs, func(i, j int) bool { return msgs[i].seq < msgs[j].seq })
		for i := 1; i < len(msgs); i++ {
			prev, cur := msgs[i-1], msgs[i]
			if want := prev.seq + float64(counts[prev]); cur.seq != want {
				t.Fatalf("odid %v: message with sequence %v followed one at %v carrying %d records; RFC 7011 section 3.1 requires %v", od, cur.seq, prev.seq, counts[prev], want)
			}
			checked++
		}
	}
	if checked == 0 {
		t.Fatal("fewer than two messages per domain reached the collector; the sequence rule was not exercised")
	}
}

func interopHasString(list []string, s string) bool {
	for _, v := range list {
		if v == s {
			return true
		}
	}
	return false
}

// TestIPFIXInteropGroundTruthReconciles runs a real scenario over three
// NBAR2 participants (both capable types) and one plain IPFIX participant at
// the collector, then compares the report's applications[] and l7_values[]
// against sums over the COLLECTOR'S decoded records, per key, exactly. The
// reference is the collector, never nl6's own counters (that would be a
// parity test over a shared wrong answer).
func TestIPFIXInteropGroundTruthReconciles(t *testing.T) {
	requireIPFIXInterop(t)
	sink, from := startIPFIXInteropSink(t)
	awaitIPFIXCollector(t, sink, from, 90*time.Second)
	from = len(sink.recordsFrom(0))

	sm := nbar2TestManager(t)
	sm.flowBufPool.New = func() any { b := make([]byte, flowBufSize); return &b }
	sm.devicesByIP = map[string]*DeviceSimulator{}
	type participant struct {
		ip, rf string
		nbar2  bool
	}
	parts := []participant{
		{"10.9.5.1", "cisco_ios.json", true},
		{"10.9.5.2", "cisco_ios.json", true},
		{"10.9.5.3", "cisco_catalyst_9500.json", true},
		{"10.9.5.4", "cisco_ios.json", false},
	}
	ips := make([]string, 0, len(parts))
	for _, p := range parts {
		d := attachNbar2Device(t, sm, p.ip, p.rf, p.nbar2)
		d.ID = "device-" + p.ip
		// Short timeouts so the cache turns over within the window; the
		// scenario's pacing override sizes it.
		d.flowExporter.cache = NewFlowCache(time.Second, time.Second, 64)
		defer d.flowExporter.Close()
		sm.devices[d.ID] = d
		sm.deviceIPs[p.ip] = struct{}{}
		sm.devicesByIP[p.ip] = d
		ips = append(ips, p.ip)
	}
	t.Cleanup(sm.closeFlowConnPool)

	const window = 6 * time.Second
	c := newScenarioController(sm, time.Now)
	if err := c.Submit(&Scenario{Participants: ips, Protocol: "ipfix", Rate: 4, Window: window, Seed: 7}, "s-interop"); err != nil {
		t.Fatal(err)
	}
	if _, excluded, err := c.Arm(); err != nil || len(excluded) != 0 {
		t.Fatalf("arm: err=%v excluded=%+v", err, excluded)
	}
	if err := c.Start(t.Context()); err != nil {
		t.Fatal(err)
	}
	// The window's auto-stop finalizes; wait for it (bounded by the finalize
	// budget on top of the window).
	deadline := time.Now().Add(window + 90*time.Second)
	for c.Result() == nil {
		if time.Now().After(deadline) {
			t.Fatalf("scenario did not finalize within %s; phase %s", window+90*time.Second, c.Phase())
		}
		time.Sleep(100 * time.Millisecond)
	}
	rep := buildScenarioReport(sm, c)
	if rep == nil {
		t.Fatal("no report")
	}
	if rep.Summary.Sent == 0 {
		t.Fatal("the scenario sent nothing; nothing to reconcile")
	}
	sink.settle(from, 500*time.Millisecond, 20*time.Second)
	recs := sink.recordsFrom(from)

	// Sum the collector's decode by the report's keys.
	type appK struct {
		proto uint8
		port  uint16
		id    uint32
	}
	type sums struct{ records, bytes, packets uint64 }
	apps := map[appK]*sums{}
	l7 := map[l7Key]*sums{}
	names := map[uint32]string{}
	var total uint64
	for _, r := range recs {
		if r.isOptions() {
			idf, _ := r.num("iana:applicationId")
			names[uint32(idf)] = r.fixedStr("iana:applicationName")
			continue
		}
		if !r.isData() {
			continue
		}
		total++
		p, _ := r.num("iana:protocolIdentifier")
		port, _ := r.num("iana:destinationTransportPort")
		b, _ := r.num("iana:octetDeltaCount")
		pk, _ := r.num("iana:packetDeltaCount")
		var id uint32
		if idf, ok := r.num("iana:applicationId"); ok {
			id = uint32(idf)
		}
		k := appK{uint8(p), uint16(port), id}
		s := apps[k]
		if s == nil {
			s = &sums{}
			apps[k] = s
		}
		s.records++
		s.bytes += uint64(b)
		s.packets += uint64(pk)
		add := func(field l7Field, value string) {
			if value == "" {
				return
			}
			lk := l7Key{appID: id, field: field, value: value}
			ls := l7[lk]
			if ls == nil {
				ls = &sums{}
				l7[lk] = ls
			}
			ls.records++
			ls.bytes += uint64(b)
			ls.packets += uint64(pk)
		}
		// The report's http_host value is the bare hostname; the wire carries
		// Cisco's prefix in front of it, so the fold strips it (and fails on
		// an AVC record without it). The http_uri value is the URI half of
		// 9357. The plain control participant's records (template 256) carry
		// neither key and fold into no l7 row, which is the report's rule too.
		if v, ok := r["cisco:appHTTPHost"].(string); ok {
			add(l7FieldHost, interopHostAfterPrefix(t, v))
		}
		if v, ok := r["cisco:appHTTPUriStatistics"].(string); ok {
			uri, _ := interopURIStats(t, v)
			add(l7FieldURI, uri)
		}
	}

	if total != rep.Summary.Sent {
		t.Fatalf("collector decoded %d data records, report summary.sent = %d", total, rep.Summary.Sent)
	}
	var appRecords uint64
	for _, row := range rep.Applications {
		appRecords += row.Records
		k := appK{l4ProtoNumber(t, row.L4Proto), row.DstPort, row.ApplicationID}
		got := apps[k]
		if got == nil {
			t.Fatalf("report row %+v has no collector counterpart; collector keys: %v", row, interopKeysOf(apps))
		}
		if got.records != row.Records || got.bytes != row.Bytes || got.packets != row.Packets {
			t.Fatalf("applications row (%s, %d, %d): report %d/%d/%d, collector %d/%d/%d (records/bytes/packets)",
				row.L4Proto, row.DstPort, row.ApplicationID, row.Records, row.Bytes, row.Packets, got.records, got.bytes, got.packets)
		}
		if row.ApplicationID != 0 && names[row.ApplicationID] != row.ApplicationName {
			t.Fatalf("application_name %q for %d disagrees with the collector's application table %q", row.ApplicationName, row.ApplicationID, names[row.ApplicationID])
		}
		delete(apps, k)
	}
	if len(apps) != 0 {
		t.Fatalf("collector saw keys the report lacks: %v", interopKeysOf(apps))
	}
	if appRecords != rep.Summary.Sent {
		t.Fatalf("Σ applications[].records = %d, want summary.sent = %d", appRecords, rep.Summary.Sent)
	}
	if len(rep.L7Values) == 0 {
		t.Fatal("report carries no l7_values rows; three NBAR2 participants with HTTP entries must produce some")
	}
	for _, row := range rep.L7Values {
		field := l7FieldHost
		if row.Field == "http_uri" {
			field = l7FieldURI
		}
		k := l7Key{appID: row.ApplicationID, field: field, value: row.Value}
		got := l7[k]
		if got == nil {
			t.Fatalf("l7_values row %+v has no collector counterpart", row)
		}
		if got.records != row.Records || got.bytes != row.Bytes || got.packets != row.Packets {
			t.Fatalf("l7_values row (%d, %s, %q): report %d/%d/%d, collector %d/%d/%d",
				row.ApplicationID, row.Field, row.Value, row.Records, row.Bytes, row.Packets, got.records, got.bytes, got.packets)
		}
		delete(l7, k)
	}
	if len(l7) != 0 {
		t.Fatalf("collector saw layer-7 values the report lacks: %v", interopKeysOf(l7))
	}
	checkIPFIXInteropSequence(t, recs)
}

func l4ProtoNumber(t *testing.T, name string) uint8 {
	t.Helper()
	switch name {
	case "tcp":
		return 6
	case "udp":
		return 17
	case "icmp":
		return 1
	}
	var n uint8
	if _, err := fmt.Sscanf(name, "%d", &n); err != nil {
		t.Fatalf("unrecognised l4_proto %q", name)
	}
	return n
}

func interopKeysOf[K comparable, V any](m map[K]V) []K {
	out := make([]K, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	return out
}
