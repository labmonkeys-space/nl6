/*
 * Copyright 2026 Ronny Trommer <ronny@no42.org>
 * SPDX-License-Identifier: Apache-2.0
 */

package main

import "testing"

// TestParseLengthLongFormIsBoundedBeforeConversion pins the CodeQL
// go/incorrect-integer-conversion fix: the long-form accumulator is a uint32
// that is bounded at MaxInt32 BEFORE it becomes an int, so a four-octet
// length can no longer wrap negative on a 32-bit build and slip past a
// caller's `n > len(buf)-pos` test as a small number.
func TestParseLengthLongFormIsBoundedBeforeConversion(t *testing.T) {
	cases := []struct {
		name string
		enc  []byte
		want int
	}{
		{"short form", []byte{0x05}, 5},
		{"one octet", []byte{0x81, 0xFF}, 255},
		{"two octets", []byte{0x82, 0x01, 0x00}, 256},
		{"three octets", []byte{0x83, 0x01, 0x00, 0x00}, 65536},
		{"four octets at the bound", []byte{0x84, 0x7F, 0xFF, 0xFF, 0xFF}, 0x7FFFFFFF},
		{"four octets one over the bound", []byte{0x84, 0x80, 0x00, 0x00, 0x00}, -1},
		{"four octets all ones", []byte{0x84, 0xFF, 0xFF, 0xFF, 0xFF}, -1},
		{"five octets refused", []byte{0x85, 0x01, 0x00, 0x00, 0x00, 0x00}, -1},
		{"indefinite form refused", []byte{0x80}, -1},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got, _ := parseLength(c.enc, 0)
			if got != c.want {
				t.Fatalf("parseLength(% X) = %d, want %d", c.enc, got, c.want)
			}
		})
	}
}
