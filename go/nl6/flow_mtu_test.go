/*
 * Copyright 2026 Ronny Trommer <ronny@no42.org>
 * SPDX-License-Identifier: Apache-2.0
 */

package main

import (
	"encoding/binary"
	"fmt"
	"net"
	"sync"
	"testing"
	"time"
)

// nl6#485: FlowExporter.Tick paginated against len(buf) while the pool handed
// out full-MTU (1500 B) buffers, so the budget was spent on the UDP PAYLOAD
// and the IP + UDP headers pushed the frame over the MTU. NetFlow v9 emitted
// 32 records per datagram (1496 B payload → 1524 B frame) and IPFIX 27
// (1480 → 1508); both fragmented. A capture at flow rate 8 showed 888 of 2062
// datagrams fragmented, every one a first fragment at exactly 1500 bytes.
//
// The tests below assert the invariant that was missing: the on-wire FRAME,
// not the buffer, is what has to fit. They drive the real Tick path rather
// than calling encoders directly, so pagination, template datagrams, option
// datagrams and the sFlow counters loop are all covered by the same bound.
//
// A unit test alone is not sufficient evidence for this bug — fragmentation
// is invisible on loopback, which is exactly why it survived every prior
// in-process measurement. Wire verification belongs in the PR.

// frameBytes converts a received UDP payload length into the IPv4 frame size
// that carried it: payload + UDP header + IPv4 header.
func frameBytes(payloadLen int) int {
	return payloadLen + udpHeaderBytes + ipv4HeaderBytes
}

// assertDatagramsFitMTU fails if any datagram's frame exceeds the link MTU.
// It returns the largest frame observed so callers can assert that a case
// actually produced a full-sized datagram (an empty or tiny result would
// otherwise pass the bound vacuously).
func assertDatagramsFitMTU(t *testing.T, label string, packets [][]byte) int {
	t.Helper()
	largest := 0
	for i, pkt := range packets {
		frame := frameBytes(len(pkt))
		if frame > largest {
			largest = frame
		}
		if len(pkt) > maxFlowPayloadIPv4 {
			t.Errorf("%s: datagram %d payload = %d B (frame %d B) exceeds the IPv4 budget of %d B "+
				"(MTU %d) — this fragments on the wire",
				label, i, len(pkt), frame, maxFlowPayloadIPv4, linkMTU)
		}
	}
	return largest
}

// drainPackets collects every datagram the listener has buffered.
func drainPackets(ch <-chan []byte) [][]byte {
	var packets [][]byte
	for {
		pkt := receivePacket(ch)
		if pkt == nil {
			return packets
		}
		packets = append(packets, pkt)
	}
}

// mtuTestProfile is a flow profile shaped for datagram-size testing: enough
// concurrent flows to fill several datagrams, IPv4-only so no record is
// filtered out from under the pagination.
func mtuTestProfile() *FlowProfile {
	return &FlowProfile{
		TCPWeight: 1.0, UDPWeight: 0, ICMPWeight: 0,
		DstPorts:   []PortWeight{{443, 1.0}},
		SrcPortMin: 49152, SrcPortMax: 65535,
		BytesMin: 100, BytesMax: 200,
		PktsMin: 1, PktsMax: 2,
		DurationMinMs: 100, DurationMaxMs: 200,
		ConcurrentFlows: 100,
		MaxFlows:        512,
	}
}

// fillExpiredFlows inserts n distinct already-expired records so the next
// Tick has to paginate them across datagrams.
func fillExpiredFlows(t *testing.T, fe *FlowExporter, n int) {
	t.Helper()
	past := time.Now().Add(-1 * time.Hour)
	for i := 0; i < n; i++ {
		fe.cache.Add(FlowRecord{
			SrcIP:    net.ParseIP("10.0.0.1").To4(),
			DstIP:    net.ParseIP("10.0.0.2").To4(),
			NextHop:  net.IPv4(0, 0, 0, 0).To4(),
			SrcPort:  uint16(49152 + i),
			DstPort:  443,
			Protocol: 6,
			Bytes:    100,
			Packets:  1,
		}, past)
	}
}

// TestFlowDatagramsFitMTU is the regression test for nl6#485. Every datagram
// every encoder emits through Tick must fit the link MTU once the IP and UDP
// headers are added.
//
// Both a template-bearing tick and a data-only tick are exercised: a template
// enlarges `overhead`, which shrinks the record count but leaves the payload
// filling toward the same ceiling, so the two ticks stress the bound
// differently.
func TestFlowDatagramsFitMTU(t *testing.T) {
	cases := []struct {
		protocol string
		encoder  FlowEncoder
		// tightlyPacked asks for the second half of the invariant: not just
		// that datagrams fit, but that they fill. A budget that fits by being
		// far too small wastes wire and would pass a bound-only assertion, so
		// fixed-size encoders must land within one record of the ceiling.
		//
		// Asserted as a margin rather than an exact frame size because both
		// protocols pad their sets to a 4-byte boundary, and NetFlow v9's
		// padding makes the exact figure a function of the record size rather
		// than something worth restating here.
		tightlyPacked bool
	}{
		{"netflow9", NetFlow9Encoder{}, true},
		{"ipfix", IPFIXEncoder{}, true},
		// NetFlow v5 tops out at its own 30-record datagram cap, which lands
		// inside one record of the budget by coincidence, not by design.
		{"netflow5", &NetFlow5Encoder{}, true},
		// Variable-length records: pagination bounds by the 128 B worst case
		// while real samples run ~100 B, so sFlow datagrams sit well below the
		// ceiling by construction. Only the bound applies.
		{"sflow", SFlowEncoder{}, false},
	}

	for _, tc := range cases {
		t.Run(tc.protocol, func(t *testing.T) {
			ln, ch := testUDPListener(t)
			defer ln.Close()
			conn := testSender(t)
			defer conn.Close()

			collectorAddr := ln.LocalAddr().(*net.UDPAddr)
			fe := newTestFlowExporter(testDevice("10.1.2.7"), mtuTestProfile(),
				1*time.Millisecond, 1*time.Millisecond, 10*time.Minute)
			fe.protocol = tc.protocol
			if tc.protocol == "sflow" {
				// Force the counters_sample datagram, which paginates on its
				// own path (sflowMaxCountersSampleSize) off the same buffer.
				fe.counterSources = []CounterSource{NewCPUCounterSource(nil)}
			}

			// Tick 1 carries the template (lastTempl is zero).
			fillExpiredFlows(t, fe, 240)
			tickWithEncoder(fe, time.Now(), tc.encoder, conn, collectorAddr, testPool())
			withTemplate := drainPackets(ch)
			if len(withTemplate) < 2 {
				t.Fatalf("expected ≥2 datagrams for 240 records, got %d", len(withTemplate))
			}
			largest := assertDatagramsFitMTU(t, tc.protocol+" (template tick)", withTemplate)

			// Tick 2 is data-only.
			fillExpiredFlows(t, fe, 240)
			tickWithEncoder(fe, time.Now(), tc.encoder, conn, collectorAddr, testPool())
			dataOnly := drainPackets(ch)
			if len(dataOnly) < 2 {
				t.Fatalf("expected ≥2 datagrams on the data-only tick, got %d", len(dataOnly))
			}
			if l := assertDatagramsFitMTU(t, tc.protocol+" (data tick)", dataOnly); l > largest {
				largest = l
			}

			if tc.tightlyPacked {
				_, _, recSize := tc.encoder.PacketSizes()
				largestPayload := largest - udpHeaderBytes - ipv4HeaderBytes
				if slack := maxFlowPayloadIPv4 - largestPayload; slack >= recSize {
					t.Errorf("largest %s payload = %d B, leaving %d B of the %d B budget "+
						"unused — that is ≥ one %d B record, so pagination is under-filling",
						tc.protocol, largestPayload, slack, maxFlowPayloadIPv4, recSize)
				}
			}
		})
	}
}

// TestFlowOptionDatagramsFitMTU covers the option-table datagrams, which
// paginate on their own path inside EncodeOptionsDatagram but size off the
// same buffer Tick reslices. They ride the template cadence, so one tick with
// a large interface universe is enough to force multiple option datagrams.
func TestFlowOptionDatagramsFitMTU(t *testing.T) {
	shapes := []string{flowOptionShapeIfScoped, flowOptionShapeSystemScoped}
	encoders := map[string]FlowEncoder{
		"netflow9": NetFlow9Encoder{},
		"ipfix":    IPFIXEncoder{},
	}

	for protocol, encoder := range encoders {
		for _, shape := range shapes {
			t.Run(protocol+"/"+shape, func(t *testing.T) {
				ln, ch := testUDPListener(t)
				defer ln.Close()
				conn := testSender(t)
				defer conn.Close()

				collectorAddr := ln.LocalAddr().(*net.UDPAddr)
				fe := newTestFlowExporter(testDevice("10.1.2.8"), mtuTestProfile(),
					1*time.Millisecond, 1*time.Millisecond, 10*time.Minute)
				fe.protocol = protocol
				fe.optionShape = shape

				// 200 interfaces: option records carry two 32-byte padded
				// string fields, so this spans several datagrams.
				for i := 1; i <= 200; i++ {
					fe.optionIfaces = append(fe.optionIfaces, flowOptionIface{
						ifIndex: uint32(i),
						name:    fmt.Sprintf("GigabitEthernet0/%d", i),
					})
				}

				tickWithEncoder(fe, time.Now(), encoder, conn, collectorAddr, testPool())
				packets := drainPackets(ch)
				if len(packets) < 2 {
					t.Fatalf("expected ≥2 datagrams (options paginate over 200 interfaces), got %d", len(packets))
				}
				assertDatagramsFitMTU(t, protocol+"/"+shape+" options", packets)
			})
		}
	}
}

// TestFlowEncoderPadBudget guards the trailing-pad hazard the datagram-budget
// change exposed. Both NetFlow v9 and IPFIX pad their data set to a 4-byte
// boundary AFTER writing the records, but record capacity was computed as
// `available / recordSize` with no allowance for that pad, so any buffer whose
// leftover bytes were fewer than the pad an odd record count needs wrote past
// the end and panicked in the shared flow-ticker goroutine.
//
// This was latent under the old full-MTU buffer and is one byte away under the
// new budget: at maxFlowPayloadIPv6 a full NetFlow v9 packet lands on exactly
// len(buf) with ZERO bytes spare. A later change to linkMTU or a header
// constant would otherwise convert a clean size error into a process-killing
// panic, so the bound is asserted across every buffer size rather than at the
// two budgets alone.
func TestFlowEncoderPadBudget(t *testing.T) {
	records := make([]FlowRecord, 64)
	for i := range records {
		records[i] = FlowRecord{
			SrcIP: net.ParseIP("10.0.0.1").To4(), DstIP: net.ParseIP("10.0.0.2").To4(),
			NextHop: net.IPv4(0, 0, 0, 0).To4(),
			SrcPort: uint16(49152 + i), DstPort: 443, Protocol: 6, Bytes: 100, Packets: 1,
		}
	}

	for _, enc := range []struct {
		name    string
		encoder FlowEncoder
	}{
		{"netflow9", NetFlow9Encoder{}},
		{"ipfix", IPFIXEncoder{}},
	} {
		t.Run(enc.name, func(t *testing.T) {
			overhead, templSize, recSize := enc.encoder.PacketSizes()

			for _, withTemplate := range []bool{false, true} {
				base := overhead
				if withTemplate {
					base += templSize
				}
				// Sweep every buffer size from "one record won't fit" up past
				// several records: the overflow only bites at specific
				// residues, so a spot check would miss it.
				for size := base; size <= base+recSize*4; size++ {
					buf := make([]byte, size)
					n, err := func() (n int, err error) {
						defer func() {
							if r := recover(); r != nil {
								t.Fatalf("%s: EncodePacket panicked at len(buf)=%d "+
									"(template=%v): %v — the trailing pad is not budgeted",
									enc.name, size, withTemplate, r)
							}
						}()
						return enc.encoder.EncodePacket(1, 1, 1, records, withTemplate, buf)
					}()
					if err != nil {
						continue // "buffer too small" is the correct answer, not a panic
					}
					if n > size {
						t.Errorf("%s: wrote %d bytes into a %d-byte buffer (template=%v)",
							enc.name, n, size, withTemplate)
					}
				}
			}

			// The two production budgets specifically, with the spare-byte
			// count called out: netflow9 at the IPv6 budget is the zero-spare
			// case that makes this test load-bearing rather than defensive.
			for _, budget := range []int{maxFlowPayloadIPv4, maxFlowPayloadIPv6} {
				buf := make([]byte, budget)
				n, err := enc.encoder.EncodePacket(1, 1, 1, records, false, buf)
				if err != nil {
					t.Fatalf("%s at budget %d: %v", enc.name, budget, err)
				}
				if n > budget {
					t.Errorf("%s: wrote %d bytes into the %d-byte budget", enc.name, n, budget)
				}
			}
		})
	}
}

// countWireRecords walks the data sets of a NetFlow v9 or IPFIX datagram and
// returns the number of flow records actually on the wire. Both protocols use
// the same set framing (ID uint16, length uint16), so one walker serves both;
// the trailing pad is absorbed by the integer division since it is always
// smaller than a record.
func countWireRecords(t *testing.T, pkt []byte, headerSize, dataSetID, recSize int) int {
	t.Helper()
	total := 0
	for pos := headerSize; pos+4 <= len(pkt); {
		setID := int(binary.BigEndian.Uint16(pkt[pos:]))
		length := int(binary.BigEndian.Uint16(pkt[pos+2:]))
		if length < 4 || pos+length > len(pkt) {
			t.Fatalf("malformed set at offset %d: id=%d length=%d (datagram %d B)",
				pos, setID, length, len(pkt))
		}
		if setID == dataSetID {
			total += (length - 4) / recSize
		}
		pos += length
	}
	return total
}

// TestFlowTickCapacityMatchesEncoder guards the silent-loss path between Tick's
// pagination and the encoder's own record cap.
//
// Tick decides how many records leave the expiry queue, and `expired` is
// advanced by that count before the encoder ever sees the batch. If the
// encoder then truncates the batch — which it does when the trailing set pad
// will not fit — the surplus records are gone from the queue, absent from the
// wire, and still counted into RecordsSent and the scenario ledger. No error,
// no dropped counter, an over-reporting ground truth.
//
// So the assertion is wire-versus-reported, not reported-versus-reported:
// RecordsSent is derived from len(batch) and would happily agree with itself.
//
// Buffer sizes are swept rather than spot-checked because the mismatch only
// appears at the residues where the pad does not fit.
func TestFlowTickCapacityMatchesEncoder(t *testing.T) {
	cases := []struct {
		name       string
		encoder    FlowEncoder
		headerSize int
		dataSetID  int
		recSize    int
	}{
		{"netflow9", NetFlow9Encoder{}, nf9HeaderSize, nf9TemplateID, nf9RecordSize},
		{"ipfix", IPFIXEncoder{}, ipfixHeaderSize, ipfixTemplateID, ipfixRecordSize},
		// NetFlow v5 is the case this test originally missed. It has no set
		// framing to walk, so countWireRecords cannot parse it — the v5
		// coverage lives in TestFlowTickHonoursRecordCountCap instead, which
		// reads the header's own record count.
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			overhead, _, _ := tc.encoder.PacketSizes()
			minViable := overhead + tc.recSize + tc.encoder.TrailingPadBytes(1)

			for size := overhead + tc.recSize; size <= overhead+tc.recSize*5; size++ {
				ln, ch := testUDPListener(t)
				conn := testSender(t)
				collectorAddr := ln.LocalAddr().(*net.UDPAddr)

				fe := newTestFlowExporter(testDevice("10.1.2.11"), mtuTestProfile(),
					1*time.Millisecond, 1*time.Millisecond, 10*time.Minute)
				// Skip the template so every datagram is data-only and the
				// sweep can reach down to the smallest data-only buffer.
				// Tick sends a template when `seqNo == 0` OR the interval has
				// elapsed, so BOTH have to be suppressed — setting lastTempl
				// alone still templates the first tick. Template framing is
				// covered by TestFlowDatagramsFitMTU.
				fe.seqNo = 1
				fe.lastTempl = time.Now()

				const want = 24
				fillExpiredFlows(t, fe, want)

				pool := &sync.Pool{New: func() interface{} {
					buf := make([]byte, size)
					return &buf
				}}
				stats := tickWithEncoder(fe, time.Now(), tc.encoder, conn, collectorAddr, pool)

				// Read exactly the datagrams Tick says it sent, rather than
				// draining until a timeout: the sweep is a few hundred
				// iterations and a per-iteration timeout tail would put this
				// test over a minute. Every write completes before Tick
				// returns, so a missing packet here is a real failure, not a
				// race.
				onWire := 0
				for i := 0; i < int(stats.PacketsSent); i++ {
					pkt := receivePacket(ch)
					if pkt == nil {
						t.Fatalf("%s at len(buf)=%d: Tick reported %d datagrams but only %d arrived",
							tc.name, size, stats.PacketsSent, i)
					}
					onWire += countWireRecords(t, pkt, tc.headerSize, tc.dataSetID, tc.recSize)
				}
				conn.Close()
				ln.Close()

				// The invariant that must hold at EVERY size: what Tick reports
				// as sent is what actually reached the wire.
				if onWire != int(stats.RecordsSent) {
					t.Fatalf("%s at len(buf)=%d: %d records on the wire but RecordsSent=%d "+
						"— Tick handed the encoder more records than it encoded, and they are "+
						"gone from the expiry queue",
						tc.name, size, onWire, stats.RecordsSent)
				}
				// Full delivery is only meaningful once the buffer can hold a
				// padded record at all. Below that the encoder can emit nothing
				// and Tick correctly reports zero; production buffers are two
				// orders of magnitude above this, so the degenerate sizes are
				// swept for the over-report check alone.
				if size >= minViable && onWire != want {
					t.Fatalf("%s at len(buf)=%d: %d records on the wire, want all %d "+
						"(records were dropped between the cache and the wire)",
						tc.name, size, onWire, want)
				}
			}
		})
	}
}

// TestFlowPayloadBudget pins the header arithmetic and the address-family
// branch. An IPv6 collector costs 20 more header bytes than IPv4, enough to
// change the record count per datagram, so the family is resolved rather than
// assumed. A nil or family-less address must take the conservative branch:
// over-budgeting fragments, under-budgeting only wastes a few bytes.
func TestFlowPayloadBudget(t *testing.T) {
	if maxFlowPayloadIPv4 != 1472 {
		t.Errorf("maxFlowPayloadIPv4 = %d, want 1472 (1500 - 20 - 8)", maxFlowPayloadIPv4)
	}
	if maxFlowPayloadIPv6 != 1452 {
		t.Errorf("maxFlowPayloadIPv6 = %d, want 1452 (1500 - 40 - 8)", maxFlowPayloadIPv6)
	}

	cases := []struct {
		name string
		addr *net.UDPAddr
		want int
	}{
		{"ipv4", &net.UDPAddr{IP: net.ParseIP("10.0.0.1"), Port: 2055}, maxFlowPayloadIPv4},
		{"ipv4-in-ipv6-form", &net.UDPAddr{IP: net.ParseIP("::ffff:10.0.0.1"), Port: 2055}, maxFlowPayloadIPv4},
		{"ipv6", &net.UDPAddr{IP: net.ParseIP("2001:db8::1"), Port: 2055}, maxFlowPayloadIPv6},
		{"nil-addr", nil, maxFlowPayloadIPv6},
		{"nil-ip", &net.UDPAddr{Port: 2055}, maxFlowPayloadIPv6},
	}
	for _, tc := range cases {
		if got := flowPayloadBudget(tc.addr); got != tc.want {
			t.Errorf("flowPayloadBudget(%s) = %d, want %d", tc.name, got, tc.want)
		}
	}
}

// TestFlowTickRespectsIPv6Budget checks that Tick applies the narrower IPv6
// budget end to end rather than computing it and discarding it. It exports to
// a real IPv6 loopback collector, so the budget branch, the pagination and the
// emitted payload lengths are all the production ones.
//
// Skipped where IPv6 loopback is unavailable (some CI containers); the branch
// itself is still covered by TestFlowPayloadBudget.
func TestFlowTickRespectsIPv6Budget(t *testing.T) {
	ln, err := net.ListenUDP("udp6", &net.UDPAddr{IP: net.ParseIP("::1"), Port: 0})
	if err != nil {
		t.Skipf("IPv6 loopback unavailable: %v", err)
	}
	defer ln.Close()

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

	conn, err := net.ListenUDP("udp6", &net.UDPAddr{IP: net.ParseIP("::1"), Port: 0})
	if err != nil {
		t.Skipf("IPv6 sender socket unavailable: %v", err)
	}
	defer conn.Close()

	collectorAddr := ln.LocalAddr().(*net.UDPAddr)
	if collectorAddr.IP.To4() != nil {
		t.Skip("IPv6 listener resolved to a v4-mapped address")
	}

	fe := newTestFlowExporter(testDevice("10.1.2.9"), mtuTestProfile(),
		1*time.Millisecond, 1*time.Millisecond, 10*time.Minute)
	fillExpiredFlows(t, fe, 240)
	tickWithEncoder(fe, time.Now(), NetFlow9Encoder{}, conn, collectorAddr, testPool())

	packets := drainPackets(ch)
	if len(packets) < 2 {
		t.Fatalf("expected ≥2 datagrams for 240 records, got %d", len(packets))
	}

	// (1452 - 24) / 46 = 31 records, plus 2 bytes of pad for the odd count →
	// 1452 B, the same payload as IPv4 and exactly the v6 budget with zero
	// bytes spare (see TestFlowEncoderPadBudget). Assert the budget, not a
	// record count: what must hold is that no payload exceeds the v6 ceiling.
	largest := 0
	for i, pkt := range packets {
		if len(pkt) > largest {
			largest = len(pkt)
		}
		if len(pkt) > maxFlowPayloadIPv6 {
			frame := len(pkt) + udpHeaderBytes + ipv6HeaderBytes
			t.Errorf("datagram %d payload = %d B (frame %d B) exceeds the IPv6 budget of %d B",
				i, len(pkt), frame, maxFlowPayloadIPv6)
		}
	}
	if largest == 0 {
		t.Fatal("no datagram carried a payload")
	}
}

// TestFlowTickHonoursRecordCountCap covers the gap that let a High-severity
// regression through: a protocol record-COUNT ceiling that buffer arithmetic
// cannot see.
//
// TestFlowTickCapacityMatchesEncoder walks data sets to count records, which
// only works for the set-framed protocols (NetFlow v9, IPFIX) — so NetFlow v5,
// the one encoder with a hard 30-record cap, was never covered by it. And it
// sweeps SMALL buffers, while this failure needs a LARGE one.
//
// Before `-datagram-mtu`, `(1472-24)/48` happened to equal exactly 30 and Tick
// and the encoder agreed by coincidence. Raising the MTU broke that: at 9000,
// Tick handed the encoder 186 records, EncodePacket kept 30, and the other 156
// were gone from `expired` while still counted into RecordsSent and into
// flow_sequence — which counts RECORDS under v5, so a collector reads the gap
// as lost flows.
func TestFlowTickHonoursRecordCountCap(t *testing.T) {
	restoreLinkMTU(t)

	const records = 240
	for _, mtu := range []int{1500, 1540, 2000, 9000} {
		t.Run(fmt.Sprintf("mtu%d", mtu), func(t *testing.T) {
			if err := SetLinkMTU(mtu); err != nil {
				t.Fatalf("SetLinkMTU(%d): %v", mtu, err)
			}

			ln, ch := testUDPListener(t)
			defer ln.Close()
			conn := testSender(t)
			defer conn.Close()

			fe := newTestFlowExporter(testDevice("10.1.2.7"), mtuTestProfile(),
				1*time.Millisecond, 1*time.Millisecond, 10*time.Minute)
			fe.seqNo = 1 // suppress the first-tick template
			fe.lastTempl = time.Now()
			fillExpiredFlows(t, fe, records)
			seqBefore := fe.seqNo

			stats := tickWithEncoder(fe, time.Now(), &NetFlow5Encoder{}, conn,
				ln.LocalAddr().(*net.UDPAddr), testPool())

			// NetFlow v5's header carries its own record count at bytes 2:4,
			// so the wire truth is readable without set framing.
			onWire := 0
			for _, pkt := range drainPackets(ch) {
				if len(pkt) < 4 {
					t.Fatalf("runt datagram: %d bytes", len(pkt))
				}
				n := int(binary.BigEndian.Uint16(pkt[2:]))
				if n > netFlow5MaxRecords {
					t.Errorf("datagram carries %d records, over the v5 cap of %d",
						n, netFlow5MaxRecords)
				}
				onWire += n
			}

			if onWire != records {
				t.Errorf("at MTU %d: %d records on the wire, want all %d — Tick handed "+
					"the encoder more than its %d-record cap and the surplus was discarded",
					mtu, onWire, records, netFlow5MaxRecords)
			}
			if int(stats.RecordsSent) != onWire {
				t.Errorf("at MTU %d: RecordsSent=%d but %d on the wire — over-reporting "+
					"records that never left", mtu, stats.RecordsSent, onWire)
			}
			// v5 advances flow_sequence by RECORD count, so a mismatch here is
			// what a collector reads as lost flows.
			if adv := int(fe.seqNo - seqBefore); adv != onWire {
				t.Errorf("at MTU %d: flow_sequence advanced %d but %d records were sent — "+
					"a collector reads the %d-record gap as flow loss",
					mtu, adv, onWire, adv-onWire)
			}
		})
	}
}

// TestFlowTickSeparatesSendFailuresFromSends is the regression test for
// nl6#491: Tick used to increment PacketsSent, BytesSent and RecordsSent after
// a FAILED WriteTo, so GET /api/v1/flows/status reported datagrams that never
// left the host and a down collector was invisible there.
//
// Syslog already had this right — syslog_exporter.go increments SendFailures
// and returns, and only reaches Sent on the success path. This aligns flow with
// its sibling rather than inventing a new convention.
//
// The failure is induced by closing the socket before the tick, which is the
// cheapest way to make every WriteTo fail deterministically.
func TestFlowTickSeparatesSendFailuresFromSends(t *testing.T) {
	restoreLinkMTU(t)

	ln, _ := testUDPListener(t)
	addr := ln.LocalAddr().(*net.UDPAddr)
	ln.Close()

	conn := testSender(t)
	conn.Close() // every WriteTo from here on fails

	fe := newTestFlowExporter(testDevice("10.1.2.12"), mtuTestProfile(),
		1*time.Millisecond, 1*time.Millisecond, 10*time.Minute)
	fe.seqNo = 1 // suppress the template so every datagram is data
	fe.lastTempl = time.Now()
	fillExpiredFlows(t, fe, 240)

	stats := tickWithEncoder(fe, time.Now(), NetFlow9Encoder{}, conn, addr, testPool())

	if stats.SendFailures == 0 {
		t.Fatal("no send failures recorded against a closed socket; the test induced nothing")
	}
	if stats.PacketsSent != 0 {
		t.Errorf("PacketsSent = %d after every write failed — status would report datagrams "+
			"that never left the host, and a down collector stays invisible", stats.PacketsSent)
	}
	if stats.BytesSent != 0 {
		t.Errorf("BytesSent = %d after every write failed", stats.BytesSent)
	}
	if stats.RecordsSent != 0 {
		t.Errorf("RecordsSent = %d after every write failed", stats.RecordsSent)
	}
}

// TestFlowTickCountsSuccessfulSends is the other half: the split must not
// stop counting the normal path.
func TestFlowTickCountsSuccessfulSends(t *testing.T) {
	restoreLinkMTU(t)

	ln, ch := testUDPListener(t)
	defer ln.Close()
	conn := testSender(t)
	defer conn.Close()

	fe := newTestFlowExporter(testDevice("10.1.2.13"), mtuTestProfile(),
		1*time.Millisecond, 1*time.Millisecond, 10*time.Minute)
	fe.seqNo = 1
	fe.lastTempl = time.Now()
	fillExpiredFlows(t, fe, 240)

	stats := tickWithEncoder(fe, time.Now(), NetFlow9Encoder{}, conn, addrOf(ln), testPool())
	got := len(drainPackets(ch))

	if stats.SendFailures != 0 {
		t.Errorf("SendFailures = %d on a working socket", stats.SendFailures)
	}
	if stats.PacketsSent == 0 {
		t.Fatal("PacketsSent = 0 on a working socket")
	}
	if int(stats.PacketsSent) != got {
		t.Errorf("PacketsSent = %d but %d datagrams arrived — the counter must track the wire",
			stats.PacketsSent, got)
	}
}

func addrOf(ln *net.UDPConn) *net.UDPAddr { return ln.LocalAddr().(*net.UDPAddr) }
