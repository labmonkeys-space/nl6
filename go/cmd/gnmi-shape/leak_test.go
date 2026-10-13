/*
 * Copyright 2026 Ronny Trommer <ronny@no42.org>
 * SPDX-License-Identifier: Apache-2.0
 */

package main

import (
	"os"
	"strconv"
	"strings"
	"testing"
)

func fakeTokens(t *testing.T) tokenSet {
	t.Helper()
	f, err := os.Open("testdata/fake-capture.log")
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	set := tokenSet{}
	if err := captureTokens(f, set); err != nil {
		t.Fatal(err)
	}
	return set
}

func TestCaptureTokens(t *testing.T) {
	set := fakeTokens(t)
	for _, want := range []string{"bundle-ether77", "ether77", "bundle", "192.0.2.10:57400", "192.0.2.10", "198.51.100.77", "424242", "99887766", "uplink", "0/rp0/cpu0", "tengige0/0/0/3"} {
		if _, ok := set[want]; !ok {
			t.Errorf("token %q missing", want)
		}
	}
	// Short digit runs from values and booleans are not tokens.
	for _, not := range []string{"731", "true", "12.5", "lab"} {
		if _, ok := set[not]; ok {
			t.Errorf("token %q should not be in the set", not)
		}
	}
}

func TestParseUnifiedDiff(t *testing.T) {
	// "+++ x" inside a hunk is an added line "++ x", not a file header.
	diff := "diff --git a/x.txt b/x.txt\n--- a/x.txt\n+++ b/x.txt\n@@ -1,0 +3,2 @@\n+first\n+second\n@@ -9 +20,2 @@\n-old\n+third\n+++ x\n"
	lines, err := parseUnifiedDiff(strings.NewReader(diff))
	if err != nil {
		t.Fatal(err)
	}
	got := ""
	for _, l := range lines {
		got += l.File + ":" + strconv.Itoa(l.Line) + ":" + l.Text + ";"
	}
	if got != "x.txt:0:x.txt;x.txt:3:first;x.txt:4:second;x.txt:20:third;x.txt:21:++ x;" {
		t.Fatalf("got %s", got)
	}
}

func TestScanFindsEmbeddedAndCaseFoldedTokens(t *testing.T) {
	set := fakeTokens(t)
	lines := []addedLine{
		{"a.go", 1, `name := "x=BUNDLE-Ether77.102"`},
		{"a.go", 2, `addr := "see 198.51.100.77:9"`},
		{"a.go", 3, `port := "TenGigE0/0/0/3"`}, // grammar
		{"a.go", 4, `n := 731`},                 // below the digit floor
	}
	hits := scanLines(lines, set, grammarAllowed)
	if len(hits) != 2 || hits[0].Line != 1 || hits[1].Line != 2 {
		t.Fatalf("got %+v, want hits on lines 1 and 2", hits)
	}
}

func TestScanHonoursAllowed(t *testing.T) {
	set := tokenSet{"uplink": {}}
	hits := scanLines([]addedLine{{"a", 1, "uplink"}}, set, func(tok string) bool { return tok == "uplink" })
	if len(hits) != 0 {
		t.Fatalf("allowed token reported: %+v", hits)
	}
}

// Text outside the JSON objects (the echoed command, a pasted prompt) and
// a hostname inside a sentence-like value are tokens too.
func TestCaptureTokensIncludeTextOutsideObjects(t *testing.T) {
	in := "gnmic sub -a 192.0.2.10:57400\r\n{\"prefix\":\"x:a\",\"updates\":[{\"Path\":\"d\",\"values\":{\"d\":\"lab-r1 uplink\"}}]}\r\n[lab@fake-r1 ~]$ "
	set := tokenSet{}
	if err := captureTokens(strings.NewReader(in), set); err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"fake-r1", "192.0.2.10:57400", "lab-r1"} {
		if _, ok := set[want]; !ok {
			t.Errorf("token %q missing", want)
		}
	}
}

// Every token in the set must be one scanLines can form, or the scan can
// never report it (nl6#809). Each token is looked up through the real
// scanner, not a second copy of its rule.
func TestEveryCaptureTokenIsScannable(t *testing.T) {
	set := fakeTokens(t)
	in := "gnmic sub -a 192.0.2.1:57400 --insecure\n{\"d\":\"edge -r1.ams core h1.lab: up via s2.par. a.b.c.d.e.f.g.h.i.j.k.l.m.n.o.p.q.r\"}\n"
	if err := captureTokens(strings.NewReader(in), set); err != nil {
		t.Fatal(err)
	}
	never := func(string) bool { return false }
	for tok := range set {
		hits := scanLines([]addedLine{{"t", 1, tok}}, set, never)
		if len(hits) != 1 || hits[0].Length != len(tok) {
			t.Errorf("token of %d chars cannot be formed by scanLines: %+v", len(tok), hits)
		}
	}
}
