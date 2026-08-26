/*
 * Copyright 2026 Ronny Trommer <ronny@no42.org>
 * SPDX-License-Identifier: Apache-2.0
 */

package main

import (
	"fmt"
	"net"
	"testing"
	"time"
)

// nl6#485: FlowExporter.Tick paginated against len(buf) while the pool handed
// out full-MTU (1500 B) buffers, so the budget was spent on the UDP PAYLOAD
// and the IP + UDP headers pushed the frame over the MTU. NetFlow v9 emitted
// 32 records per datagram (1496 B payload → 1524 B frame) and IPFIX 27
// (1478 → 1506); both fragmented. A capture at flow rate 8 showed 888 of 2062
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
	return payloadLen + flowUDPHeaderBytes + flowIPv4HeaderBytes
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
				label, i, len(pkt), frame, maxFlowPayloadIPv4, flowLinkMTU)
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
				largestPayload := largest - flowUDPHeaderBytes - flowIPv4HeaderBytes
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

	// (1452 - 24) / 46 = 31 records → the same 1450 B payload as IPv4 here,
	// because 46 divides the extra 20 bytes away. Assert the budget, not a
	// record count: what must hold is that no payload exceeds the v6 ceiling.
	largest := 0
	for i, pkt := range packets {
		if len(pkt) > largest {
			largest = len(pkt)
		}
		if len(pkt) > maxFlowPayloadIPv6 {
			frame := len(pkt) + flowUDPHeaderBytes + flowIPv6HeaderBytes
			t.Errorf("datagram %d payload = %d B (frame %d B) exceeds the IPv6 budget of %d B",
				i, len(pkt), frame, maxFlowPayloadIPv6)
		}
	}
	if largest == 0 {
		t.Fatal("no datagram carried a payload")
	}
}
