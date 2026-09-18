/*
 * Copyright 2026 Ronny Trommer <ronny@no42.org>
 * SPDX-License-Identifier: Apache-2.0
 */

package main

import (
	"encoding/binary"
	"net"
	"testing"
	"time"
)

// RFC 7011 section 3.1 defines the IPFIX Sequence Number as the
// "incremental sequence counter modulo 2^32 of all IPFIX Data Records sent in
// the current stream from the current Observation Domain", and adds that
// "Template and Options Template Records do not increase the Sequence
// Number". Options Data Records are Data Records, so they do.
//
// nl6 advanced the counter once per MESSAGE, which a collector reads as a
// sequence gap on every multi-record datagram. These tests drive the real
// Tick path and read the counter back off the wire.

// ipfixSequenceExporter returns an exporter whose GENERATED flows never
// expire inside the test (10-minute timeouts) while records inserted through
// fillExpiredFlows (created an hour in the past) always do. That lets a tick
// carry exactly the records the test planted, or none at all.
func ipfixSequenceExporter(ip string) *FlowExporter {
	return newTestFlowExporter(testDevice(ip), mtuTestProfile(),
		10*time.Minute, 5*time.Minute, 10*time.Minute)
}

// TestIPFIXSequenceCountsDataRecords: across a paginated tick, every
// message's sequence number equals the count of data records in all
// earlier messages, and a template-only message advances it by zero.
func TestIPFIXSequenceCountsDataRecords(t *testing.T) {
	ln, ch := testUDPListener(t)
	defer ln.Close()
	conn := testSender(t)
	defer conn.Close()
	collectorAddr := ln.LocalAddr().(*net.UDPAddr)

	fe := ipfixSequenceExporter("10.1.2.40")

	// Tick 1: template + 100 records, which paginates across several
	// datagrams at the 1472-byte budget (26 records fit a data-only message).
	fillExpiredFlows(t, fe, 100)
	stats := tickWithEncoder(fe, time.Now(), IPFIXEncoder{}, conn, collectorAddr, testPool())
	if stats.PacketsSent < 3 {
		t.Fatalf("expected >=3 datagrams for 100 records, got %d", stats.PacketsSent)
	}
	var sent uint32
	for i := 0; i < int(stats.PacketsSent); i++ {
		pkt := receivePacket(ch)
		if pkt == nil {
			t.Fatalf("datagram %d never arrived", i)
		}
		dec := decodeIPFIXPacket(t, pkt)
		if dec.Header.SequenceNumber != sent {
			t.Fatalf("datagram %d: sequence = %d, want %d (data records sent before it)",
				i, dec.Header.SequenceNumber, sent)
		}
		sent += uint32(len(dec.Records))
	}
	if sent != 100 {
		t.Fatalf("decoded %d records across the tick, want 100", sent)
	}
	if fe.seqNo != 100 {
		t.Fatalf("fe.seqNo after 100 records = %d, want 100", fe.seqNo)
	}

	// Tick 2: force a template refresh with nothing expired. The message
	// carries a Template Set and no Data Records, so it must not advance.
	fe.lastTempl = time.Time{}
	stats = tickWithEncoder(fe, time.Now(), IPFIXEncoder{}, conn, collectorAddr, testPool())
	if stats.PacketsSent != 1 || stats.RecordsSent != 0 {
		t.Fatalf("template-only tick: PacketsSent=%d RecordsSent=%d, want 1 and 0",
			stats.PacketsSent, stats.RecordsSent)
	}
	pkt := receivePacket(ch)
	if pkt == nil {
		t.Fatal("template-only datagram never arrived")
	}
	dec := decodeIPFIXPacket(t, pkt)
	if len(dec.Templates) != 1 || len(dec.Records) != 0 {
		t.Fatalf("template-only datagram: %d templates, %d records", len(dec.Templates), len(dec.Records))
	}
	if dec.Header.SequenceNumber != 100 {
		t.Fatalf("template-only datagram: sequence = %d, want 100", dec.Header.SequenceNumber)
	}
	if fe.seqNo != 100 {
		t.Fatalf("fe.seqNo after a template-only message = %d, want 100 (templates do not count)", fe.seqNo)
	}

	// Tick 2b: still nothing expired and the template is fresh, so nothing
	// may be sent. This is the hazard the record-count semantic exposes:
	// Tick used `seqNo == 0` as its "first tick, send the template" marker,
	// and a counter that no longer moves on a template-only message would
	// re-send the template on every idle tick until the first data record.
	stats = tickWithEncoder(fe, time.Now(), IPFIXEncoder{}, conn, collectorAddr, testPool())
	if stats.PacketsSent != 0 {
		t.Fatalf("idle tick after a template-only message sent %d datagram(s), want 0 (template spam)", stats.PacketsSent)
	}

	// Tick 3: five more records; the next data message must resume at 100.
	fillExpiredFlows(t, fe, 5)
	tickWithEncoder(fe, time.Now(), IPFIXEncoder{}, conn, collectorAddr, testPool())
	pkt = receivePacket(ch)
	if pkt == nil {
		t.Fatal("third-tick datagram never arrived")
	}
	dec = decodeIPFIXPacket(t, pkt)
	if dec.Header.SequenceNumber != 100 || len(dec.Records) != 5 {
		t.Fatalf("third tick: sequence = %d with %d records, want 100 and 5",
			dec.Header.SequenceNumber, len(dec.Records))
	}
	if fe.seqNo != 105 {
		t.Fatalf("fe.seqNo = %d, want 105", fe.seqNo)
	}
}

// TestIPFIXIdleExporterSendsTemplateOnce: an exporter whose first tick is
// template-only and that never sees a data record must not re-send the
// template on every tick. Tick used `seqNo == 0` as its "first tick" marker,
// and under the record-count semantic that counter stays 0 for as long as
// the device is idle, so the marker would stay true and the template would
// be repeated at the tick cadence instead of the template interval. The
// data-carrying path in TestIPFIXSequenceCountsDataRecords cannot see this,
// because its first tick moves the counter off zero.
func TestIPFIXIdleExporterSendsTemplateOnce(t *testing.T) {
	ln, ch := testUDPListener(t)
	defer ln.Close()
	conn := testSender(t)
	defer conn.Close()
	collectorAddr := ln.LocalAddr().(*net.UDPAddr)

	// No generated flows at all: this test is about the template marker, and
	// a generated flow that happens to expire would show up as a data
	// datagram and be mistaken for a repeated template.
	idle := *mtuTestProfile()
	idle.ConcurrentFlows = 0
	fe := newTestFlowExporter(testDevice("10.1.2.43"), &idle,
		10*time.Minute, 5*time.Minute, 10*time.Minute)
	now := time.Now()
	first := tickWithEncoder(fe, now, IPFIXEncoder{}, conn, collectorAddr, testPool())
	if first.PacketsSent != 1 || first.RecordsSent != 0 {
		t.Fatalf("first tick: PacketsSent=%d RecordsSent=%d, want 1 and 0 (template only)",
			first.PacketsSent, first.RecordsSent)
	}
	if pkt := receivePacket(ch); pkt == nil {
		t.Fatal("template datagram never arrived")
	}
	if fe.seqNo != 0 {
		t.Fatalf("seqNo after a template-only first tick = %d, want 0", fe.seqNo)
	}
	for i := 0; i < 3; i++ {
		s := tickWithEncoder(fe, now.Add(time.Duration(i+1)*time.Second), IPFIXEncoder{}, conn, collectorAddr, testPool())
		if s.PacketsSent != 0 {
			pkt := receivePacket(ch)
			var templates, records int
			if pkt != nil {
				dec := decodeIPFIXPacket(t, pkt)
				templates, records = len(dec.Templates), len(dec.Records)
			}
			t.Fatalf("idle tick %d sent %d datagram(s) (records=%d, templates in first=%d, data records in first=%d); "+
				"want 0, the template interval is 10m", i+1, s.PacketsSent, s.RecordsSent, templates, records)
		}
	}
}

// TestIPFIXSequenceCountsOptionsDataRecords: an interface option-table
// datagram carries one Options Data Record per interface, and those are
// Data Records, so the counter advances by the interface count.
func TestIPFIXSequenceCountsOptionsDataRecords(t *testing.T) {
	ln, ch := testUDPListener(t)
	defer ln.Close()
	conn := testSender(t)
	defer conn.Close()
	collectorAddr := ln.LocalAddr().(*net.UDPAddr)

	fe := ipfixSequenceExporter("10.1.2.41")
	fe.optionShape = "if-scoped"
	fe.optionIfaces = []flowOptionIface{
		{ifIndex: 1, name: "GigabitEthernet0/1"},
		{ifIndex: 2, name: "GigabitEthernet0/2"},
		{ifIndex: 3, name: "GigabitEthernet0/3"},
	}

	// First tick: template + 4 data records + one options datagram (options
	// ride the template-refresh cadence). Expected order on the wire: the
	// data message at sequence 0, then the options message at sequence 4.
	fillExpiredFlows(t, fe, 4)
	stats := tickWithEncoder(fe, time.Now(), IPFIXEncoder{}, conn, collectorAddr, testPool())
	if stats.PacketsSent != 2 {
		t.Fatalf("expected 2 datagrams (data, options), got %d", stats.PacketsSent)
	}
	data := receivePacket(ch)
	opts := receivePacket(ch)
	if data == nil || opts == nil {
		t.Fatal("expected two datagrams on the wire")
	}
	if got := binary.BigEndian.Uint32(data[8:]); got != 0 {
		t.Fatalf("data message sequence = %d, want 0", got)
	}
	if got := binary.BigEndian.Uint32(opts[8:]); got != 4 {
		t.Fatalf("options message sequence = %d, want 4 (the data records before it)", got)
	}
	if fe.seqNo != 7 {
		t.Fatalf("fe.seqNo = %d, want 7 (4 flow records + 3 options data records)", fe.seqNo)
	}
}

// TestNetFlow9SequenceStillCountsPackets: the RFC 3954 semantic is per
// export packet, and the IPFIX change must not leak into it. Same shape
// as the IPFIX test so the two can be read side by side.
func TestNetFlow9SequenceStillCountsPackets(t *testing.T) {
	ln, ch := testUDPListener(t)
	defer ln.Close()
	conn := testSender(t)
	defer conn.Close()
	collectorAddr := ln.LocalAddr().(*net.UDPAddr)

	fe := ipfixSequenceExporter("10.1.2.42")
	fillExpiredFlows(t, fe, 100)
	stats := tickWithEncoder(fe, time.Now(), NetFlow9Encoder{}, conn, collectorAddr, testPool())
	for i := 0; i < int(stats.PacketsSent); i++ {
		pkt := receivePacket(ch)
		if pkt == nil {
			t.Fatalf("datagram %d never arrived", i)
		}
		if got := decodeNF9Packet(t, pkt).Header.SequenceNo; got != uint32(i) {
			t.Fatalf("v9 datagram %d: sequence = %d, want %d (one per packet)", i, got, i)
		}
	}
	if uint64(fe.seqNo) != stats.PacketsSent {
		t.Fatalf("v9 fe.seqNo = %d, want %d packets", fe.seqNo, stats.PacketsSent)
	}
}
