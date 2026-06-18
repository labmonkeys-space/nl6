/*
 * Copyright 2026 Ronny Trommer <ronny@no42.org>
 * SPDX-License-Identifier: Apache-2.0
 */

package main

import (
	"math/rand"
	"strconv"
	"strings"
	"testing"
)

// compareOIDsRef is the previous strings.Split + strconv.Atoi implementation of
// compareOIDs, kept verbatim as the reference oracle for the differential test
// below. The allocation-free compareOIDs must agree with it on every input.
func compareOIDsRef(oid1, oid2 string) int {
	var parts1, parts2 []string
	if s := strings.TrimPrefix(oid1, "."); s != "" {
		parts1 = strings.Split(s, ".")
	}
	if s := strings.TrimPrefix(oid2, "."); s != "" {
		parts2 = strings.Split(s, ".")
	}

	maxLen := len(parts1)
	if len(parts2) > maxLen {
		maxLen = len(parts2)
	}

	for i := 0; i < maxLen; i++ {
		var val1, val2 int
		if i < len(parts1) {
			val1, _ = strconv.Atoi(parts1[i])
		}
		if i < len(parts2) {
			val2, _ = strconv.Atoi(parts2[i])
		}
		if val1 < val2 {
			return -1
		} else if val1 > val2 {
			return 1
		}
	}

	if len(parts1) < len(parts2) {
		return -1
	} else if len(parts1) > len(parts2) {
		return 1
	}
	return 0
}

func TestCompareOIDsTable(t *testing.T) {
	cases := []struct {
		a, b string
		want int
	}{
		{"", "", 0},
		{".", "", 0},
		{".1.3.6", "1.3.6", 0},
		{"1.3.6.1", "1.3.6.1", 0},
		{"1.3.6.1", "1.3.6.2", -1},
		{"1.3.6.2", "1.3.6.1", 1},
		{"1.3.6", "1.3.6.1", -1},   // shorter sorts first
		{"1.3.6.1", "1.3.6", 1},    // longer sorts after
		{"1.3.6.10", "1.3.6.9", 1}, // numeric, not lexicographic
		{"1.3.6.9", "1.3.6.10", -1},
		{"1.0.8802.1.1.2", "1.3.6.1.2.1", -1}, // LLDP root sorts before mib-2
	}
	for _, c := range cases {
		if got := sign(compareOIDs(c.a, c.b)); got != c.want {
			t.Errorf("compareOIDs(%q,%q) = %d, want %d", c.a, c.b, got, c.want)
		}
	}
}

// TestCompareOIDsDifferential fuzzes compareOIDs against the reference for both
// well-formed and malformed OIDs (leading/trailing/double dots, non-numeric
// segments) and asserts the sign of the result matches on every pair.
func TestCompareOIDsDifferential(t *testing.T) {
	r := rand.New(rand.NewSource(1))
	const iterations = 200000
	for i := 0; i < iterations; i++ {
		a := randOID(r)
		b := randOID(r)
		got := sign(compareOIDs(a, b))
		want := sign(compareOIDsRef(a, b))
		if got != want {
			t.Fatalf("mismatch: compareOIDs(%q,%q)=%d ref=%d", a, b, got, want)
		}
		// Antisymmetry: swapping arguments negates the result.
		if s := sign(compareOIDs(b, a)); s != -got {
			t.Fatalf("antisymmetry broken: compareOIDs(%q,%q)=%d but swapped=%d", a, b, got, s)
		}
	}
}

func TestCompareOIDsZeroAlloc(t *testing.T) {
	a, b := ".1.3.6.1.2.1.31.1.1.1.6.10", ".1.3.6.1.2.1.31.1.1.1.6.11"
	if n := testing.AllocsPerRun(1000, func() { compareOIDs(a, b) }); n != 0 {
		t.Errorf("compareOIDs allocated %v times/op, want 0", n)
	}
}

// randOID builds a random OID string, deliberately including malformed shapes
// (empty, leading/trailing/double dots, non-numeric runs) to exercise edge
// cases the previous Split-based implementation handled implicitly.
func randOID(r *rand.Rand) string {
	if r.Intn(20) == 0 {
		return [...]string{"", ".", "..", "1.", ".1", "1..2", "a.b"}[r.Intn(7)]
	}
	var sb strings.Builder
	if r.Intn(2) == 0 {
		sb.WriteByte('.')
	}
	n := 1 + r.Intn(8)
	for i := 0; i < n; i++ {
		if i > 0 {
			sb.WriteByte('.')
		}
		switch r.Intn(10) {
		case 0:
			// empty segment (double/trailing dot effect)
		case 1:
			sb.WriteString("x") // non-numeric → 0
		default:
			sb.WriteString(strconv.Itoa(r.Intn(300)))
		}
	}
	return sb.String()
}

func sign(n int) int {
	switch {
	case n < 0:
		return -1
	case n > 0:
		return 1
	default:
		return 0
	}
}

func BenchmarkCompareOIDsNew(b *testing.B) {
	x, y := ".1.3.6.1.2.1.31.1.1.1.6.10", ".1.3.6.1.2.1.31.1.1.1.6.11"
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		_ = compareOIDs(x, y)
	}
}

func BenchmarkCompareOIDsRef(b *testing.B) {
	x, y := ".1.3.6.1.2.1.31.1.1.1.6.10", ".1.3.6.1.2.1.31.1.1.1.6.11"
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		_ = compareOIDsRef(x, y)
	}
}
