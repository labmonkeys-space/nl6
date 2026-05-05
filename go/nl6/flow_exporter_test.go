/*
 * © 2025 Labmonkeys Space
 *
 * Layer 8 Ecosystem is licensed under the Apache License, Version 2.0.
 * You may obtain a copy of the License at:
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package main

import (
	"crypto/md5"
	"encoding/hex"
	"net"
	"sync"
	"testing"
	"time"
)

// ── Helpers ──────────────────────────────────────────────────────────────────

// newTestFlowExporter wraps the production NewFlowExporter with dummy
// collector/encoder/protocol defaults so pre-phase-3 test call sites keep
// working after the constructor signature grew. Tests that exercise
// specific wire formats mutate `fe.encoder` / `fe.collectorAddr` via
// `tickWithEncoder` below.
func newTestFlowExporter(device *DeviceSimulator, profile *FlowProfile,
	activeTimeout, inactiveTimeout, templateInterval time.Duration) *FlowExporter {
	addr, _ := net.ResolveUDPAddr("udp", "127.0.0.1:0")
	return NewFlowExporter(device, profile,
		activeTimeout, inactiveTimeout, templateInterval,
		"127.0.0.1:0", addr, "netflow9", NetFlow9Encoder{})
}

// tickWithEncoder emulates the pre-phase-3 Tick signature for existing
// tests. The new FlowExporter.Tick reads encoder + collectorAddr from
// the exporter itself; this shim overwrites those fields on the fly so
// tests that construct ad-hoc listeners and pick specific encoders don't
// need per-test rewiring. Production code never calls this.
func tickWithEncoder(fe *FlowExporter, now time.Time, enc FlowEncoder,
	conn *net.UDPConn, addr *net.UDPAddr, pool *sync.Pool) FlowTickStats {
	fe.encoder = enc
	fe.collectorAddr = addr
	return fe.Tick(now, conn, pool)
}

// testUDPListener opens an ephemeral loopback UDP socket, returning the
// listener and a channel that delivers raw packet bytes as they arrive.
// The goroutine exits when the listener is closed.
func testUDPListener(t *testing.T) (*net.UDPConn, <-chan []byte) {
	t.Helper()
	ln, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 0})
	if err != nil {
		t.Fatalf("ListenUDP: %v", err)
	}
	ch := make(chan []byte, 64)
	go func() {
		defer close(ch)
		buf := make([]byte, 2048)
		for {
			n, _, err := ln.ReadFromUDP(buf)
			if err != nil {
				return // listener closed
			}
			pkt := make([]byte, n)
			copy(pkt, buf[:n])
			ch <- pkt
		}
	}()
	return ln, ch
}

// testSender opens an ephemeral UDP socket for sending.
func testSender(t *testing.T) *net.UDPConn {
	t.Helper()
	conn, err := net.ListenUDP("udp4", &net.UDPAddr{})
	if err != nil {
		t.Fatalf("ListenUDP (sender): %v", err)
	}
	return conn
}

// testDevice builds a minimal DeviceSimulator with the given IPv4 address.
func testDevice(ipStr string) *DeviceSimulator {
	return &DeviceSimulator{IP: net.ParseIP(ipStr).To4()}
}

// testPool returns a sync.Pool supplying 1500-byte buffers.
func testPool() *sync.Pool {
	return &sync.Pool{New: func() interface{} { return make([]byte, 1500) }}
}

// receivePacket reads one packet from ch with a short deadline.
// Returns nil if nothing arrives within 200 ms.
func receivePacket(ch <-chan []byte) []byte {
	select {
	case pkt := <-ch:
		return pkt
	case <-time.After(200 * time.Millisecond):
		return nil
	}
}

// ── Tests ────────────────────────────────────────────────────────────────────

func TestNewFlowExporter_DomainID(t *testing.T) {
	device := testDevice("10.0.0.1")
	fe := newTestFlowExporter(device, flowProfileEdgeRouter, 30*time.Second, 15*time.Second, 60*time.Second)

	// domainID must be the device IPv4 encoded as big-endian uint32.
	if fe.domainID != 0x0A000001 {
		t.Errorf("domainID = %08x, want 0a000001", fe.domainID)
	}
	if fe.cache == nil {
		t.Error("cache is nil")
	}
	if fe.rng == nil {
		t.Error("rng is nil")
	}
}

func TestNewFlowExporter_DifferentDevicesDifferentDomainIDs(t *testing.T) {
	feA := newTestFlowExporter(testDevice("10.0.0.1"), flowProfileEdgeRouter, time.Second, time.Second, time.Minute)
	feB := newTestFlowExporter(testDevice("10.0.0.2"), flowProfileEdgeRouter, time.Second, time.Second, time.Minute)

	if feA.domainID == feB.domainID {
		t.Errorf("expected different domainIDs for different devices, both got %08x", feA.domainID)
	}
}

func TestDomainIDtoIP_RoundTrip(t *testing.T) {
	cases := []string{"10.0.0.1", "192.168.1.100", "172.16.0.1"}
	for _, c := range cases {
		original := net.ParseIP(c).To4()
		device := &DeviceSimulator{IP: original}
		fe := newTestFlowExporter(device, flowProfileEdgeRouter, time.Second, time.Second, time.Minute)
		recovered := domainIDtoIP(fe.domainID)
		if !recovered.Equal(original) {
			t.Errorf("%s: domainIDtoIP(%08x) = %v, want %v", c, fe.domainID, recovered, original)
		}
	}
}

// TestFlowExporter_Tick_TemplateOnFirstCall verifies that Tick sends a
// template-only NF9 packet on the first call (seqNo == 0) even when no flows
// have expired yet. This satisfies the RFC 3954 requirement to send the
// template before any data records.
func TestFlowExporter_Tick_TemplateOnFirstCall(t *testing.T) {
	ln, ch := testUDPListener(t)
	defer ln.Close()

	conn := testSender(t)
	defer conn.Close()

	collectorAddr := ln.LocalAddr().(*net.UDPAddr)

	// Large timeouts so nothing expires during the test.
	fe := newTestFlowExporter(testDevice("10.1.2.3"), flowProfileEdgeRouter,
		10*time.Minute, 5*time.Minute, 10*time.Minute)

	tickWithEncoder(fe, time.Now(), NetFlow9Encoder{}, conn, collectorAddr, testPool())

	pkt := receivePacket(ch)
	if pkt == nil {
		t.Fatal("no UDP packet received on first Tick (expected template)")
	}

	// Decode and verify it is a valid NF9 packet containing a template.
	decoded := decodeNF9Packet(t, pkt)
	if decoded.Header.Version != 9 {
		t.Errorf("version = %d, want 9", decoded.Header.Version)
	}
	if len(decoded.Templates) != 1 {
		t.Errorf("template count = %d, want 1", len(decoded.Templates))
	}
	// seqNo should have advanced.
	if fe.seqNo != 1 {
		t.Errorf("seqNo after first Tick = %d, want 1", fe.seqNo)
	}
}

// TestFlowExporter_Tick_NoSendWithoutExpiredFlows verifies that Tick skips
// packet encoding when no flows have expired and the template interval has
// not elapsed (i.e., seqNo > 0 and lastTempl is fresh).
func TestFlowExporter_Tick_NoSendWhenIdle(t *testing.T) {
	ln, ch := testUDPListener(t)
	defer ln.Close()

	conn := testSender(t)
	defer conn.Close()

	collectorAddr := ln.LocalAddr().(*net.UDPAddr)

	fe := newTestFlowExporter(testDevice("10.1.2.4"), flowProfileEdgeRouter,
		10*time.Minute, 5*time.Minute, 10*time.Minute)

	now := time.Now()

	// First Tick sends template (seqNo=0).
	tickWithEncoder(fe, now, NetFlow9Encoder{}, conn, collectorAddr, testPool())
	receivePacket(ch) // drain

	// Second Tick immediately after — no flows expired, template fresh.
	tickWithEncoder(fe, now, NetFlow9Encoder{}, conn, collectorAddr, testPool())

	pkt := receivePacket(ch)
	if pkt != nil {
		t.Error("expected no packet on idle Tick, but one was received")
	}
}

// TestFlowExporter_Tick_SendsFlowsWhenExpired pre-populates the cache with
// flows at a past createdAt so they are immediately expired, then calls Tick
// and verifies that flow records are received by the collector.
func TestFlowExporter_Tick_SendsFlowsWhenExpired(t *testing.T) {
	ln, ch := testUDPListener(t)
	defer ln.Close()

	conn := testSender(t)
	defer conn.Close()

	collectorAddr := ln.LocalAddr().(*net.UDPAddr)

	// Very short timeouts so manually-inserted flows are expired immediately.
	fe := newTestFlowExporter(testDevice("10.1.2.5"), flowProfileEdgeRouter,
		1*time.Millisecond, 1*time.Millisecond, 10*time.Minute)

	// Insert 3 flows directly into the cache, timestamped far in the past.
	past := time.Now().Add(-1 * time.Hour)
	for i := 0; i < 3; i++ {
		fe.cache.Add(FlowRecord{
			SrcIP:    net.ParseIP("10.0.0.1").To4(),
			DstIP:    net.ParseIP("10.0.0.2").To4(),
			NextHop:  net.IPv4(0, 0, 0, 0).To4(),
			SrcPort:  uint16(1000 + i),
			DstPort:  443,
			Protocol: 6,
			Bytes:    1024,
			Packets:  10,
		}, past)
	}

	tickWithEncoder(fe, time.Now(), NetFlow9Encoder{}, conn, collectorAddr, testPool())

	pkt := receivePacket(ch)
	if pkt == nil {
		t.Fatal("no packet received after Tick with expired flows")
	}
	decoded := decodeNF9Packet(t, pkt)
	if len(decoded.Records) != 3 {
		t.Errorf("expected 3 flow records, got %d", len(decoded.Records))
	}
}

// TestFlowExporter_Tick_TemplateRetransmit verifies that the template is
// re-sent after templateInterval has elapsed since the last transmission.
func TestFlowExporter_Tick_TemplateRetransmit(t *testing.T) {
	ln, ch := testUDPListener(t)
	defer ln.Close()

	conn := testSender(t)
	defer conn.Close()

	collectorAddr := ln.LocalAddr().(*net.UDPAddr)

	fe := newTestFlowExporter(testDevice("10.1.2.6"), flowProfileEdgeRouter,
		10*time.Minute, 5*time.Minute, 60*time.Second)

	now := time.Now()

	// First Tick: sends template.
	tickWithEncoder(fe, now, NetFlow9Encoder{}, conn, collectorAddr, testPool())
	pkt1 := receivePacket(ch)
	if pkt1 == nil {
		t.Fatal("expected template on first Tick")
	}

	// Second Tick: template interval has not elapsed — no send.
	tickWithEncoder(fe, now, NetFlow9Encoder{}, conn, collectorAddr, testPool())
	if pkt := receivePacket(ch); pkt != nil {
		t.Error("unexpected packet before template interval elapsed")
	}

	// Simulate template interval elapsed by advancing lastTempl back.
	fe.lastTempl = now.Add(-61 * time.Second)

	// Third Tick: template should be retransmitted.
	tickWithEncoder(fe, now, NetFlow9Encoder{}, conn, collectorAddr, testPool())
	pkt3 := receivePacket(ch)
	if pkt3 == nil {
		t.Fatal("expected template retransmission after interval elapsed")
	}
	decoded := decodeNF9Packet(t, pkt3)
	if len(decoded.Templates) != 1 {
		t.Errorf("expected 1 template on retransmission, got %d", len(decoded.Templates))
	}
}

// TestFlowExporter_Tick_IPFIXTemplateOnFirstCall verifies that the first Tick
// with an IPFIXEncoder sends an IPFIX message containing a Template Set.
func TestFlowExporter_Tick_IPFIXTemplateOnFirstCall(t *testing.T) {
	ln, ch := testUDPListener(t)
	defer ln.Close()

	conn := testSender(t)
	defer conn.Close()

	collectorAddr := ln.LocalAddr().(*net.UDPAddr)

	fe := newTestFlowExporter(testDevice("10.2.3.4"), flowProfileEdgeRouter,
		10*time.Minute, 5*time.Minute, 10*time.Minute)

	tickWithEncoder(fe, time.Now(), IPFIXEncoder{}, conn, collectorAddr, testPool())

	pkt := receivePacket(ch)
	if pkt == nil {
		t.Fatal("no UDP packet received on first IPFIX Tick (expected template)")
	}

	decoded := decodeIPFIXPacket(t, pkt)
	if decoded.Header.Version != 10 {
		t.Errorf("IPFIX version = %d, want 10", decoded.Header.Version)
	}
	if len(decoded.Templates) != 1 {
		t.Errorf("template count = %d, want 1", len(decoded.Templates))
	}
	if fe.seqNo != 1 {
		t.Errorf("seqNo after first Tick = %d, want 1", fe.seqNo)
	}
}

// TestFlowExporter_Tick_IPFIXPagination verifies that 80 expired records are
// fully delivered across multiple IPFIX datagrams with no silent record loss.
// This specifically exercises the pagination logic with ipfixRecordSize=53
// (which is larger than nf9RecordSize=45 and was previously causing 5 records
// to be silently discarded per datagram).
func TestFlowExporter_Tick_IPFIXPagination(t *testing.T) {
	ln, ch := testUDPListener(t)
	defer ln.Close()

	conn := testSender(t)
	defer conn.Close()

	collectorAddr := ln.LocalAddr().(*net.UDPAddr)

	profile := &FlowProfile{
		TCPWeight: 1.0, UDPWeight: 0, ICMPWeight: 0,
		DstPorts:   []PortWeight{{443, 1.0}},
		SrcPortMin: 1024, SrcPortMax: 65535,
		BytesMin: 100, BytesMax: 200,
		PktsMin: 1, PktsMax: 2,
		DurationMinMs: 100, DurationMaxMs: 200,
		ConcurrentFlows: 100,
		MaxFlows:        256,
	}

	fe := newTestFlowExporter(testDevice("10.2.3.5"), profile,
		1*time.Millisecond, 1*time.Millisecond, 10*time.Minute)

	// Insert 80 distinct flows all with past timestamps so they expire immediately.
	past := time.Now().Add(-1 * time.Hour)
	for i := 0; i < 80; i++ {
		fe.cache.Add(FlowRecord{
			SrcIP:    net.ParseIP("10.0.0.1").To4(),
			DstIP:    net.ParseIP("10.0.0.2").To4(),
			NextHop:  net.IPv4(0, 0, 0, 0).To4(),
			SrcPort:  uint16(1024 + i),
			DstPort:  443,
			Protocol: 6,
			Bytes:    100,
			Packets:  1,
		}, past)
	}

	if got := fe.cache.Len(); got != 80 {
		t.Fatalf("expected 80 cache entries, got %d", got)
	}

	tickWithEncoder(fe, time.Now(), IPFIXEncoder{}, conn, collectorAddr, testPool())

	// Collect all received packets.
	var packets [][]byte
	for {
		pkt := receivePacket(ch)
		if pkt == nil {
			break
		}
		packets = append(packets, pkt)
	}

	if len(packets) < 2 {
		t.Errorf("expected ≥2 IPFIX packets for 80 records, got %d", len(packets))
	}

	// Count total records across all packets — must equal 80 with no loss.
	total := 0
	for _, pkt := range packets {
		decoded := decodeIPFIXPacket(t, pkt)
		if decoded.Header.Version != 10 {
			t.Errorf("packet version = %d, want 10 (IPFIX)", decoded.Header.Version)
		}
		total += len(decoded.Records)
	}
	if total != 80 {
		t.Errorf("total IPFIX records across all packets = %d, want 80 (no silent loss)", total)
	}
}

// TestFlowExporter_Tick_Pagination verifies that when more records expire than
// fit in a single 1500-byte UDP datagram, multiple packets are sent.
func TestFlowExporter_Tick_Pagination(t *testing.T) {
	ln, ch := testUDPListener(t)
	defer ln.Close()

	conn := testSender(t)
	defer conn.Close()

	collectorAddr := ln.LocalAddr().(*net.UDPAddr)

	// Use a large MaxFlows to allow many concurrent entries.
	profile := &FlowProfile{
		TCPWeight: 1.0, UDPWeight: 0, ICMPWeight: 0,
		DstPorts:   []PortWeight{{443, 1.0}},
		SrcPortMin: 1024, SrcPortMax: 65535,
		BytesMin: 100, BytesMax: 200,
		PktsMin: 1, PktsMax: 2,
		DurationMinMs: 100, DurationMaxMs: 200,
		ConcurrentFlows: 100,
		MaxFlows:        256,
	}

	fe := newTestFlowExporter(testDevice("10.1.2.7"), profile,
		1*time.Millisecond, 1*time.Millisecond, 10*time.Minute)

	// Insert 80 distinct flows all with past timestamps so they expire immediately.
	past := time.Now().Add(-1 * time.Hour)
	for i := 0; i < 80; i++ {
		fe.cache.Add(FlowRecord{
			SrcIP:    net.ParseIP("10.0.0.1").To4(),
			DstIP:    net.ParseIP("10.0.0.2").To4(),
			NextHop:  net.IPv4(0, 0, 0, 0).To4(),
			SrcPort:  uint16(1024 + i),
			DstPort:  443,
			Protocol: 6,
			Bytes:    100,
			Packets:  1,
		}, past)
	}

	if got := fe.cache.Len(); got != 80 {
		t.Fatalf("expected 80 cache entries, got %d", got)
	}

	tickWithEncoder(fe, time.Now(), NetFlow9Encoder{}, conn, collectorAddr, testPool())

	// Collect all received packets.
	var packets [][]byte
	for {
		pkt := receivePacket(ch)
		if pkt == nil {
			break
		}
		packets = append(packets, pkt)
	}

	if len(packets) < 2 {
		t.Errorf("expected ≥2 packets for 80 records, got %d", len(packets))
	}

	// Count total records across all packets.
	total := 0
	for _, pkt := range packets {
		decoded := decodeNF9Packet(t, pkt)
		total += len(decoded.Records)
	}
	if total != 80 {
		t.Errorf("total records across all packets = %d, want 80", total)
	}
}

// TestFlowTickStats_Counters verifies that Tick() returns non-zero PacketsSent,
// BytesSent, and RecordsSent when there are records to export.
func TestFlowTickStats_Counters(t *testing.T) {
	ln, ch := testUDPListener(t)
	defer ln.Close()
	conn := testSender(t)
	defer conn.Close()
	collectorAddr := ln.LocalAddr().(*net.UDPAddr)

	fe := newTestFlowExporter(testDevice("10.0.0.3"), flowProfileEdgeRouter, 30*time.Second, 15*time.Second, 60*time.Second)

	// Pre-populate 5 expired records.
	past := time.Now().Add(-2 * time.Minute)
	for i := 0; i < 5; i++ {
		fe.cache.Add(FlowRecord{
			SrcIP:    net.ParseIP("10.1.0.1").To4(),
			DstIP:    net.ParseIP("10.2.0.1").To4(),
			NextHop:  net.IPv4(0, 0, 0, 0).To4(),
			SrcPort:  uint16(1000 + i),
			DstPort:  80,
			Protocol: 6,
			Bytes:    500,
			Packets:  5,
		}, past)
	}

	stats := tickWithEncoder(fe, time.Now(), NetFlow9Encoder{}, conn, collectorAddr, testPool())
	// Drain sent packets so the listener goroutine can exit cleanly.
	receivePacket(ch)

	if stats.PacketsSent == 0 {
		t.Error("PacketsSent = 0, want >0")
	}
	if stats.BytesSent == 0 {
		t.Error("BytesSent = 0, want >0")
	}
	if stats.RecordsSent != 5 {
		t.Errorf("RecordsSent = %d, want 5", stats.RecordsSent)
	}
	// seqNo == 0 on first call, so a template must have been sent.
	if stats.LastTemplateMs == 0 {
		t.Error("LastTemplateMs = 0 on first Tick, want non-zero")
	}
}

// TestFlowTickStats_NoRecordsNoTemplate verifies that Tick() returns zero stats
// when there is nothing to export and no template is due.
func TestFlowTickStats_NoRecordsNoTemplate(t *testing.T) {
	ln, _ := testUDPListener(t)
	defer ln.Close()
	conn := testSender(t)
	defer conn.Close()
	collectorAddr := ln.LocalAddr().(*net.UDPAddr)

	fe := newTestFlowExporter(testDevice("10.0.0.4"), flowProfileEdgeRouter, 30*time.Second, 15*time.Second, 60*time.Minute)

	// Advance past the first (seqNo==0) template send so the next call has no template due.
	tickWithEncoder(fe, time.Now(), NetFlow9Encoder{}, conn, collectorAddr, testPool())
	// Second tick with empty cache and no template interval elapsed → zero stats.
	stats := tickWithEncoder(fe, time.Now(), NetFlow9Encoder{}, conn, collectorAddr, testPool())

	if stats.PacketsSent != 0 || stats.BytesSent != 0 || stats.RecordsSent != 0 || stats.LastTemplateMs != 0 {
		t.Errorf("expected zero stats on idle tick, got %+v", stats)
	}
}

// TestGetFlowStatus_NoExportingDevices verifies that GetFlowStatus returns
// an empty Collectors array when no device has a FlowExporter attached.
// Under the per-device-export-config model "feature off" is expressed as
// `len(collectors) == 0`.
func TestGetFlowStatus_NoExportingDevices(t *testing.T) {
	sm := &SimulatorManager{devices: make(map[string]*DeviceSimulator)}
	status := sm.GetFlowStatus()
	if len(status.Collectors) != 0 {
		t.Errorf("expected empty Collectors, got %+v", status.Collectors)
	}
	if status.DevicesExporting != 0 {
		t.Errorf("DevicesExporting = %d, want 0", status.DevicesExporting)
	}
}

// TestGetFlowStatus_AggregatesAcrossDevices verifies that GetFlowStatus
// aggregates per-device counters by (collector, protocol) tuple. Two
// devices pointing at the same collector/protocol collapse into one
// record; one device on a distinct collector yields a second record.
func TestGetFlowStatus_AggregatesAcrossDevices(t *testing.T) {
	sm := &SimulatorManager{devices: make(map[string]*DeviceSimulator)}

	mkExporter := func(ip, collector, protocol string, encoder FlowEncoder,
		packets, bytesSent, records uint64) *DeviceSimulator {
		d := testDevice(ip)
		addr, _ := net.ResolveUDPAddr("udp", collector)
		fe := NewFlowExporter(d, flowProfileEdgeRouter,
			30*time.Second, 15*time.Second, 60*time.Second,
			collector, addr, protocol, encoder)
		fe.statPackets.Store(packets)
		fe.statBytes.Store(bytesSent)
		fe.statRecords.Store(records)
		d.flowExporter = fe
		return d
	}

	sm.devices["1"] = mkExporter("10.0.0.1", "a:2055", "netflow9", NetFlow9Encoder{}, 10, 100, 5)
	sm.devices["2"] = mkExporter("10.0.0.2", "a:2055", "netflow9", NetFlow9Encoder{}, 20, 200, 7)
	sm.devices["3"] = mkExporter("10.0.0.3", "b:4739", "ipfix", IPFIXEncoder{}, 3, 30, 1)

	status := sm.GetFlowStatus()

	if status.DevicesExporting != 3 {
		t.Errorf("DevicesExporting = %d, want 3", status.DevicesExporting)
	}
	if len(status.Collectors) != 2 {
		t.Fatalf("Collectors = %+v, want 2 records", status.Collectors)
	}
	for _, c := range status.Collectors {
		switch {
		case c.Collector == "a:2055" && c.Protocol == "netflow9":
			if c.Devices != 2 {
				t.Errorf("a:2055/netflow9 Devices = %d, want 2", c.Devices)
			}
			if c.SentPackets != 30 || c.SentBytes != 300 || c.SentRecords != 12 {
				t.Errorf("a:2055/netflow9 counters wrong: %+v", c)
			}
		case c.Collector == "b:4739" && c.Protocol == "ipfix":
			if c.Devices != 1 {
				t.Errorf("b:4739/ipfix Devices = %d, want 1", c.Devices)
			}
			if c.SentPackets != 3 || c.SentBytes != 30 || c.SentRecords != 1 {
				t.Errorf("b:4739/ipfix counters wrong: %+v", c)
			}
		default:
			t.Errorf("unexpected collector record: %+v", c)
		}
	}
}

// TestFlowExporter_Tick_PrefersPerDeviceConn verifies that Tick uses fe.conn
// (the per-device socket) when set, ignoring the fallback conn parameter.
// This underpins the per-device source-IP mode: each device's flows leave
// via its own socket bound to the device IP.
func TestFlowExporter_Tick_PrefersPerDeviceConn(t *testing.T) {
	// Collector that receives the packets.
	ln, ch := testUDPListener(t)
	defer ln.Close()
	collectorAddr := ln.LocalAddr().(*net.UDPAddr)

	// Per-device socket bound to loopback — this is what Tick should use.
	perDevice, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 0})
	if err != nil {
		t.Fatalf("ListenUDP (per-device): %v", err)
	}
	defer perDevice.Close()

	// Fallback conn that we explicitly close — if Tick mistakenly uses it,
	// WriteTo would fail and no packet would arrive. If Tick correctly
	// prefers fe.conn, the closed fallback is never touched.
	fallback, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 0})
	if err != nil {
		t.Fatalf("ListenUDP (fallback): %v", err)
	}
	fallback.Close()

	fe := newTestFlowExporter(testDevice("10.9.9.9"), flowProfileEdgeRouter,
		10*time.Minute, 5*time.Minute, 10*time.Minute)
	fe.conn.Store(perDevice)

	stats := tickWithEncoder(fe, time.Now(), NetFlow9Encoder{}, fallback, collectorAddr, testPool())

	pkt := receivePacket(ch)
	if pkt == nil {
		t.Fatal("no packet received — Tick did not use per-device conn")
	}
	if stats.PacketsSent == 0 {
		t.Error("stats.PacketsSent == 0, want ≥1")
	}
}

// TestFlowExporter_Tick_CloseRace drives Tick and Close concurrently to
// catch races on fe.conn. Meant to be run under `go test -race`; without
// atomic.Pointer the old implementation would trip the race detector here.
func TestFlowExporter_Tick_CloseRace(t *testing.T) {
	ln, _ := testUDPListener(t)
	defer ln.Close()
	collectorAddr := ln.LocalAddr().(*net.UDPAddr)

	fe := newTestFlowExporter(testDevice("10.9.9.11"), flowProfileEdgeRouter,
		10*time.Minute, 5*time.Minute, 10*time.Minute)

	perDevice, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 0})
	if err != nil {
		t.Fatalf("ListenUDP: %v", err)
	}
	fe.conn.Store(perDevice)

	fallback, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 0})
	if err != nil {
		t.Fatalf("ListenUDP (fallback): %v", err)
	}
	defer fallback.Close()

	stop := make(chan struct{})
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		pool := testPool()
		for {
			select {
			case <-stop:
				return
			default:
				tickWithEncoder(fe, time.Now(), NetFlow9Encoder{}, fallback, collectorAddr, pool)
			}
		}
	}()

	// Let Tick run for a bit, then close concurrently.
	time.Sleep(10 * time.Millisecond)
	if err := fe.Close(); err != nil {
		t.Errorf("Close returned error: %v", err)
	}
	close(stop)
	wg.Wait()

	if fe.conn.Load() != nil {
		t.Error("fe.conn should be nil after Close")
	}
}

// TestBuildFlowEncoder_UnknownProtocol verifies that the default-case
// error message lists all supported protocols including sflow. Ported
// from the retired InitFlowExport test against the `buildFlowEncoder`
// helper that replaced it in the per-device-export-config refactor.
func TestBuildFlowEncoder_UnknownProtocol(t *testing.T) {
	_, _, err := buildFlowEncoder("nonexistent")
	if err == nil {
		t.Fatal("expected error for unknown protocol, got nil")
	}
	msg := err.Error()
	for _, want := range []string{"netflow9", "ipfix", "sflow"} {
		if !contains(msg, want) {
			t.Errorf("error message %q missing substring %q", msg, want)
		}
	}
}

// TestBuildFlowEncoder_SFlowCanonicalized verifies both sflow and sflow5
// select the sFlow encoder and canonicalize to "sflow". Ported from the
// retired InitFlowExport-based test; canonicalisation now lives in
// `buildFlowEncoder`.
func TestBuildFlowEncoder_SFlowCanonicalized(t *testing.T) {
	for _, alias := range []string{"sflow", "sflow5", "SFLOW", "SFlow5"} {
		_, canonical, err := buildFlowEncoder(alias)
		if err != nil {
			t.Errorf("alias %q: buildFlowEncoder returned error: %v", alias, err)
			continue
		}
		if canonical != "sflow" {
			t.Errorf("alias %q: canonical = %q, want \"sflow\"", alias, canonical)
		}
	}
}

// contains is a tiny stand-in for strings.Contains to avoid growing this test
// file's import list for a single use.
func contains(haystack, needle string) bool {
	if len(needle) == 0 {
		return true
	}
	for i := 0; i+len(needle) <= len(haystack); i++ {
		if haystack[i:i+len(needle)] == needle {
			return true
		}
	}
	return false
}

// ── Byte-identity regression tests (PR #47 review fix #2) ────────────────────
//
// These tests guard against regressions in the NetFlow9 / IPFIX / NetFlow5
// wire output after the `MaxRecordSize()` + `SeqIncrement()` FlowEncoder
// interface extensions. The fixed-size encoders must continue to emit the
// exact same byte layout they did before the extensions landed.
//
// The tests encode a canned FlowRecord slice with pinned inputs (domainID,
// seqNo, uptimeMs), then zero out the two wall-clock timestamp fields that
// legitimately vary between runs (unix_secs for NF9/NF5, export_time for
// IPFIX, plus unix_nsecs for NF5) and hash the rest. Any change to the
// structural wire layout — field order, sizes, padding, template content —
// flips the hash.
//
// If a legitimate change bumps the layout, update the pinned hash below;
// the point is that the change is visible and reviewed, not silent.

// canonicalFlowRecords returns the canned FlowRecord slice used by every
// byte-identity test. Keep this stable — pinned hashes depend on it.
func canonicalFlowRecords() []FlowRecord {
	return []FlowRecord{
		{
			SrcIP:    net.ParseIP("10.0.0.1").To4(),
			DstIP:    net.ParseIP("10.0.0.2").To4(),
			NextHop:  net.IPv4(0, 0, 0, 0).To4(),
			SrcPort:  54321,
			DstPort:  443,
			Protocol: 6,
			TCPFlags: 0x18,
			ToS:      0,
			Bytes:    9876,
			Packets:  7,
			StartMs:  1000,
			EndMs:    2500,
			InIface:  3,
			OutIface: 4,
			SrcMask:  24,
			DstMask:  24,
		},
		{
			SrcIP:    net.ParseIP("10.0.0.3").To4(),
			DstIP:    net.ParseIP("10.0.0.4").To4(),
			NextHop:  net.IPv4(0, 0, 0, 0).To4(),
			SrcPort:  55555,
			DstPort:  53,
			Protocol: 17,
			TCPFlags: 0,
			ToS:      0,
			Bytes:    128,
			Packets:  1,
			StartMs:  2000,
			EndMs:    2100,
			InIface:  5,
			OutIface: 6,
			SrcMask:  24,
			DstMask:  24,
		},
	}
}

// zeroBytes sets buf[start:start+count] to zero. Used to mask wall-clock
// fields before hashing.
func zeroBytes(buf []byte, start, count int) {
	for i := start; i < start+count && i < len(buf); i++ {
		buf[i] = 0
	}
}

// TestByteIdentity_NetFlow9 pins the structural (non-wall-clock) bytes of a
// NetFlow v9 packet against an MD5 hash. NetFlow v9 header layout:
//
//	u16 version (=9)       // 0..2
//	u16 count              // 2..4
//	u32 uptimeMs           // 4..8   (caller-supplied, stable)
//	u32 unix_secs          // 8..12  (wall clock — masked)
//	u32 seqNo              // 12..16 (caller-supplied, stable)
//	u32 domainID           // 16..20 (caller-supplied, stable)
func TestByteIdentity_NetFlow9(t *testing.T) {
	enc := NetFlow9Encoder{}
	buf := make([]byte, 1500)
	n, err := enc.EncodePacket(0x0A000001, 42, 5000, canonicalFlowRecords(), true, buf)
	if err != nil {
		t.Fatalf("EncodePacket: %v", err)
	}
	out := append([]byte(nil), buf[:n]...)
	// Mask unix_secs at offset 8 (4 bytes).
	zeroBytes(out, 8, 4)

	const wantHash = "db530ac552b2a47f7a27d4ef673e1598"
	got := md5.Sum(out)
	gotHex := hex.EncodeToString(got[:])
	if gotHex != wantHash {
		t.Errorf("NetFlow9 byte-identity hash mismatch:\n  got:  %s\n  want: %s\n  "+
			"(structural bytes changed; if intentional, update wantHash — length was %d)",
			gotHex, wantHash, n)
	}
}

// TestByteIdentity_IPFIX pins IPFIX structural bytes. IPFIX header layout:
//
//	u16 version (=10)       // 0..2
//	u16 length              // 2..4
//	u32 export_time         // 4..8  (wall clock — masked)
//	u32 seqNo               // 8..12 (caller-supplied, stable)
//	u32 domainID            // 12..16
//
// Within data records, lastSwitched / firstSwitched are absolute epoch ms
// computed from uptimeMs and wall-clock time. Because the test freezes
// uptimeMs to a known value and those fields resolve relative to the *test's*
// wall-clock, they also drift. We mask them too.
func TestByteIdentity_IPFIX(t *testing.T) {
	enc := IPFIXEncoder{}
	buf := make([]byte, 1500)
	n, err := enc.EncodePacket(0x0A000001, 42, 5000, canonicalFlowRecords(), true, buf)
	if err != nil {
		t.Fatalf("EncodePacket: %v", err)
	}
	out := append([]byte(nil), buf[:n]...)

	// Mask export_time at offset 4 (4 bytes).
	zeroBytes(out, 4, 4)

	// IPFIX records contain absolute epoch-ms timestamps (flowStartMilliseconds
	// and flowEndMilliseconds). These are 8-byte fields positioned at the end
	// of each 53-byte data record. With templates + header, the data record
	// section starts at:
	//   header(16) + templateSet(80) + dataSetHeader(4) = 100.
	// Each record is 53 bytes; the last 16 bytes are the two 8-byte timestamps.
	const ipfixRecStart = 100
	const ipfixRecLen = 53
	const tsTailBytes = 16
	for i := 0; i < len(canonicalFlowRecords()); i++ {
		recStart := ipfixRecStart + i*ipfixRecLen
		zeroBytes(out, recStart+ipfixRecLen-tsTailBytes, tsTailBytes)
	}

	const wantHash = "3307363c55a2bd3d40ddca19cd4e9598"
	got := md5.Sum(out)
	gotHex := hex.EncodeToString(got[:])
	if gotHex != wantHash {
		t.Errorf("IPFIX byte-identity hash mismatch:\n  got:  %s\n  want: %s\n  "+
			"(structural bytes changed; if intentional, update wantHash — length was %d)",
			gotHex, wantHash, n)
	}
}

// TestByteIdentity_NetFlow5 pins NetFlow v5 structural bytes. NF5 header:
//
//	u16 version (=5)         // 0..2
//	u16 count                // 2..4
//	u32 uptimeMs             // 4..8   (caller-supplied, stable)
//	u32 unix_secs            // 8..12  (wall clock — masked)
//	u32 unix_nsecs           // 12..16 (wall clock — masked)
//	u32 seqNo                // 16..20 (caller-supplied, stable)
//	u8  engine_type          // 20
//	u8  engine_id            // 21
//	u16 sampling_interval    // 22..24
func TestByteIdentity_NetFlow5(t *testing.T) {
	enc := &NetFlow5Encoder{}
	buf := make([]byte, 1500)
	n, err := enc.EncodePacket(0x0A000001, 42, 5000, canonicalFlowRecords(), false, buf)
	if err != nil {
		t.Fatalf("EncodePacket: %v", err)
	}
	out := append([]byte(nil), buf[:n]...)
	// Mask unix_secs + unix_nsecs at offsets 8 and 12 (8 bytes total).
	zeroBytes(out, 8, 8)

	const wantHash = "32619195905a513bd84a1677d438587b"
	got := md5.Sum(out)
	gotHex := hex.EncodeToString(got[:])
	if gotHex != wantHash {
		t.Errorf("NetFlow5 byte-identity hash mismatch:\n  got:  %s\n  want: %s\n  "+
			"(structural bytes changed; if intentional, update wantHash — length was %d)",
			gotHex, wantHash, n)
	}
}

// TestByteIdentity_NetFlow9_Deterministic is a secondary cross-check: two
// encodes of identical inputs SHALL produce byte-identical output once the
// wall-clock field is masked. Catches any accidental non-deterministic
// behaviour in the encoder that the pinned-hash tests might mask by updating.
func TestByteIdentity_NetFlow9_Deterministic(t *testing.T) {
	enc := NetFlow9Encoder{}
	buf1 := make([]byte, 1500)
	buf2 := make([]byte, 1500)
	recs := canonicalFlowRecords()
	n1, err := enc.EncodePacket(0x0A000001, 42, 5000, recs, true, buf1)
	if err != nil {
		t.Fatalf("encode 1: %v", err)
	}
	n2, err := enc.EncodePacket(0x0A000001, 42, 5000, recs, true, buf2)
	if err != nil {
		t.Fatalf("encode 2: %v", err)
	}
	if n1 != n2 {
		t.Fatalf("encode lengths differ: %d vs %d", n1, n2)
	}
	zeroBytes(buf1, 8, 4)
	zeroBytes(buf2, 8, 4)
	for i := 0; i < n1; i++ {
		if buf1[i] != buf2[i] {
			t.Fatalf("NetFlow9 non-deterministic at byte %d: %02x vs %02x", i, buf1[i], buf2[i])
		}
	}
}

// TestFlowExporter_Close_Idempotent verifies that Close is safe on nil and
// repeat invocations — required because both DeviceSimulator.Stop and
// DeviceSimulator.stopListenersOnly call Close during shutdown paths.
func TestFlowExporter_Close_Idempotent(t *testing.T) {
	var nilFE *FlowExporter
	if err := nilFE.Close(); err != nil {
		t.Errorf("Close on nil exporter returned error: %v", err)
	}

	fe := newTestFlowExporter(testDevice("10.9.9.10"), flowProfileEdgeRouter,
		time.Second, time.Second, time.Minute)
	if err := fe.Close(); err != nil {
		t.Errorf("Close without conn returned error: %v", err)
	}

	conn, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 0})
	if err != nil {
		t.Fatalf("ListenUDP: %v", err)
	}
	fe.conn.Store(conn)
	if err := fe.Close(); err != nil {
		t.Errorf("first Close returned error: %v", err)
	}
	if err := fe.Close(); err != nil {
		t.Errorf("second Close returned error: %v", err)
	}
	if fe.conn.Load() != nil {
		t.Error("fe.conn should be nil after Close")
	}
}
