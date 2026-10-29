/*
 * Copyright 2026 Ronny Trommer <ronny@no42.org>
 * SPDX-License-Identifier: Apache-2.0
 */

package main

import (
	"bytes"
	"strings"
	"testing"
)

func TestNetconfFramingEOMRoundTrip(t *testing.T) {
	var buf bytes.Buffer
	w := newNetconfFramer(nil, &buf)
	if err := w.WriteMessage([]byte("<hello/>")); err != nil {
		t.Fatal(err)
	}
	if got, want := buf.String(), "<hello/>]]>]]>"; got != want {
		t.Fatalf("wire = %q, want %q", got, want)
	}
	r := newNetconfFramer(&buf, nil)
	msg, err := r.ReadMessage()
	if err != nil {
		t.Fatal(err)
	}
	if string(msg) != "<hello/>" {
		t.Fatalf("read %q", msg)
	}
}

func TestNetconfFramingChunkedRoundTrip(t *testing.T) {
	in := "\n#4\nabcd\n#3\nefg\n##\n"
	r := newNetconfFramer(strings.NewReader(in+in), nil)
	r.chunked = true
	for i := 0; i < 2; i++ {
		msg, err := r.ReadMessage()
		if err != nil {
			t.Fatal(err)
		}
		if string(msg) != "abcdefg" {
			t.Fatalf("read %q", msg)
		}
	}

	var buf bytes.Buffer
	w := newNetconfFramer(nil, &buf)
	w.chunked = true
	if err := w.WriteMessage([]byte("<rpc-reply/>")); err != nil {
		t.Fatal(err)
	}
	rr := newNetconfFramer(&buf, nil)
	rr.chunked = true
	msg, err := rr.ReadMessage()
	if err != nil || string(msg) != "<rpc-reply/>" {
		t.Fatalf("round trip = %q, %v", msg, err)
	}
}

func TestNetconfFramingRejectsOversize(t *testing.T) {
	big := strings.Repeat("a", netconfMaxMessageBytes+1)
	r := newNetconfFramer(strings.NewReader(big+"]]>]]>"), nil)
	if _, err := r.ReadMessage(); err == nil {
		t.Fatal("EOM oversize accepted")
	}
	c := newNetconfFramer(strings.NewReader("\n#4294967295\nabc"), nil)
	c.chunked = true
	if _, err := c.ReadMessage(); err == nil {
		t.Fatal("chunked oversize accepted")
	}
	// Many small chunks that add up past the limit.
	var sb strings.Builder
	for i := 0; i < 1100; i++ {
		sb.WriteString("\n#1024\n" + strings.Repeat("a", 1024))
	}
	sb.WriteString("\n##\n")
	m := newNetconfFramer(strings.NewReader(sb.String()), nil)
	m.chunked = true
	if _, err := m.ReadMessage(); err == nil {
		t.Fatal("summed chunked oversize accepted")
	}
}

func TestNetconfFramingRejectsBadChunkHeader(t *testing.T) {
	for _, in := range []string{"\n#0\n", "\n#x\n", "\n#4294967296\n", "\n#04\nabcd", "\n#\n", "\nX4\nabcd"} {
		r := newNetconfFramer(strings.NewReader(in), nil)
		r.chunked = true
		if _, err := r.ReadMessage(); err == nil {
			t.Errorf("header %q accepted", in)
		}
	}
}

func FuzzNetconfReadMessage(f *testing.F) {
	f.Add([]byte("<hello/>]]>]]>"), false)
	f.Add([]byte("\n#4\nabcd\n#3\nefg\n##\n"), true)
	f.Fuzz(func(t *testing.T, data []byte, chunked bool) {
		r := newNetconfFramer(bytes.NewReader(data), nil)
		r.chunked = chunked
		for i := 0; i < 4; i++ {
			msg, err := r.ReadMessage()
			if len(msg) > netconfMaxMessageBytes {
				t.Fatalf("returned %d bytes", len(msg))
			}
			if err != nil {
				return
			}
		}
	})
}
