/*
 * Copyright 2026 Ronny Trommer <ronny@no42.org>
 * SPDX-License-Identifier: Apache-2.0
 */

package main

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"os"
	"strconv"
	"strings"
	"testing"
)

const (
	captureSegSize   = 1436
	capturePublisher = 0x0101040d
	captureMessageID = 1
)

type captureSegment struct {
	header []byte
	length int
}

func loadCaptureSegments(t *testing.T) []captureSegment {
	t.Helper()
	raw, err := os.ReadFile("testdata/yangpush/huawei/segments-8.hex")
	if err != nil {
		t.Fatal(err)
	}
	var out []captureSegment
	for _, line := range strings.Split(string(raw), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		f := strings.Fields(line)
		h, err := hex.DecodeString(f[0])
		if err != nil {
			t.Fatal(err)
		}
		n, err := strconv.Atoi(f[1])
		if err != nil {
			t.Fatal(err)
		}
		out = append(out, captureSegment{h, n})
	}
	return out
}

func testPayload(n int) []byte {
	p := make([]byte, n)
	for i := range p {
		p[i] = byte('a' + i%26)
	}
	return p
}

func TestUdpNotifHeaderUnsegmented(t *testing.T) {
	payload := testPayload(100)
	d := udpNotifFrame(capturePublisher, 7, payload, captureSegSize)
	if len(d) != 1 {
		t.Fatalf("datagrams = %d, want 1", len(d))
	}
	b := d[0]
	if b[0] != 0x21 || b[1] != 12 {
		t.Fatalf("first bytes % x, want 21 0c", b[:2])
	}
	if got := binary.BigEndian.Uint16(b[2:4]); got != 112 {
		t.Fatalf("message length %d, want 112", got)
	}
	if binary.BigEndian.Uint32(b[4:8]) != capturePublisher || binary.BigEndian.Uint32(b[8:12]) != 7 {
		t.Fatalf("ids % x", b[4:12])
	}
	if !bytes.Equal(b[12:], payload) {
		t.Fatal("payload mismatch")
	}
}

func TestUdpNotifSegmentsMatchCapture(t *testing.T) {
	want := loadCaptureSegments(t)
	total := 0
	for _, s := range want {
		total += s.length - len(s.header)
	}
	d := udpNotifFrame(capturePublisher, captureMessageID, testPayload(total), captureSegSize)
	if len(d) != len(want) {
		t.Fatalf("segments = %d, want %d", len(d), len(want))
	}
	for i, s := range want {
		if len(d[i]) != s.length {
			t.Errorf("segment %d length %d, want %d", i, len(d[i]), s.length)
		}
		if !bytes.Equal(d[i][:16], s.header) {
			t.Errorf("segment %d header % x, want % x", i, d[i][:16], s.header)
		}
	}
}

func TestUdpNotifLastSegmentFlag(t *testing.T) {
	d := udpNotifFrame(1, 2, testPayload(10000), captureSegSize)
	if len(d) < 3 {
		t.Fatalf("expected several segments, got %d", len(d))
	}
	for i, b := range d {
		opt := binary.BigEndian.Uint16(b[14:16])
		if int(opt>>1) != i {
			t.Errorf("segment %d number %d", i, opt>>1)
		}
		if last := opt&1 == 1; last != (i == len(d)-1) {
			t.Errorf("segment %d last=%v", i, last)
		}
	}
}

func TestUdpNotifReassembles(t *testing.T) {
	in := testPayload(12345)
	var got []byte
	for _, b := range udpNotifFrame(1, 2, in, captureSegSize) {
		got = append(got, b[16:]...)
	}
	if !bytes.Equal(got, in) {
		t.Fatal("reassembled payload differs")
	}
}

func TestUdpNotifLargeDevice(t *testing.T) {
	payload := testPayload(200 * 1200)
	d := udpNotifFrame(1, 2, payload, captureSegSize)
	if len(d) < 2 {
		t.Fatal("expected segmentation")
	}
	for i, b := range d {
		if len(b) > captureSegSize {
			t.Errorf("segment %d is %d bytes, over %d", i, len(b), captureSegSize)
		}
		if int(binary.BigEndian.Uint16(b[2:4])) != len(b) {
			t.Errorf("segment %d message length field wrong", i)
		}
	}
}

func TestUdpNotifTinySegSizePanics(t *testing.T) {
	defer func() {
		if recover() == nil {
			t.Fatal("expected panic for segSize <= header size")
		}
	}()
	udpNotifFrame(1, 2, testPayload(100), 16)
}
