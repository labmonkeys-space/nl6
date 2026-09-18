/*
 * Copyright 2026 Ronny Trommer <ronny@no42.org>
 * SPDX-License-Identifier: Apache-2.0
 */

package main

import (
	"bufio"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// The Cisco AVC extract is the evidence base for every IE number the NBAR2
// encoder emits (spec section 1). These tests make a row unable to cite
// nothing: every element names a source that exists, every source carries a
// URL and a fetch date, and status is one of three spelled values. They do
// not, and cannot, check that the extract is RIGHT; only sourcing can.

type avcSource struct {
	ID, Title, Revision, URL, Fetched string
}

type avcElement struct {
	PEN, ID, Name, Type, Length, Status, Note string
	Sources                                   []string
}

func readTSV(t *testing.T, path string, want int) [][]string {
	t.Helper()
	f, err := os.Open(path)
	if err != nil {
		t.Fatalf("open %s: %v", path, err)
	}
	defer f.Close()
	var rows [][]string
	sc := bufio.NewScanner(f)
	line := 0
	for sc.Scan() {
		line++
		s := sc.Text()
		if strings.TrimSpace(s) == "" || strings.HasPrefix(s, "#") {
			continue
		}
		cols := strings.Split(s, "\t")
		if len(cols) != want {
			t.Fatalf("%s:%d: %d columns, want %d", path, line, len(cols), want)
		}
		rows = append(rows, cols)
	}
	if err := sc.Err(); err != nil {
		t.Fatalf("scan %s: %v", path, err)
	}
	if len(rows) < 2 {
		t.Fatalf("%s: no data rows", path)
	}
	return rows[1:] // drop header
}

func loadCiscoAVCExtract(t *testing.T) (map[string]avcSource, []avcElement) {
	t.Helper()
	dir := filepath.Join("testdata", "cisco-avc")
	sources := map[string]avcSource{}
	for _, r := range readTSV(t, filepath.Join(dir, "sources.tsv"), 5) {
		s := avcSource{r[0], r[1], r[2], r[3], r[4]}
		if _, dup := sources[s.ID]; dup {
			t.Fatalf("sources.tsv: duplicate id %q", s.ID)
		}
		sources[s.ID] = s
	}
	var elements []avcElement
	for _, r := range readTSV(t, filepath.Join(dir, "elements.tsv"), 8) {
		elements = append(elements, avcElement{
			PEN: r[0], ID: r[1], Name: r[2], Type: r[3], Length: r[4],
			Status: r[5], Sources: strings.Split(r[6], ","), Note: r[7],
		})
	}
	return sources, elements
}

func TestCiscoAVCExtract_SourcesAreComplete(t *testing.T) {
	sources, _ := loadCiscoAVCExtract(t)
	for id, s := range sources {
		if s.Title == "" || s.Revision == "" || s.Fetched == "" {
			t.Errorf("source %q: title, revision and fetched are all required", id)
		}
		if !strings.HasPrefix(s.URL, "https://") {
			t.Errorf("source %q: url %q must be https", id, s.URL)
		}
	}
}

func TestCiscoAVCExtract_EveryElementCitesAKnownSource(t *testing.T) {
	sources, elements := loadCiscoAVCExtract(t)
	valid := map[string]bool{"verified": true, "contested": true, "unresolved": true}
	seen := map[string]bool{}
	for _, e := range elements {
		key := e.PEN + "/" + e.ID
		if seen[key] {
			t.Errorf("elements.tsv: duplicate element %s", key)
		}
		seen[key] = true
		if !valid[e.Status] {
			t.Errorf("element %s: status %q not in verified|contested|unresolved", key, e.Status)
		}
		for _, src := range e.Sources {
			if _, ok := sources[strings.TrimSpace(src)]; !ok {
				t.Errorf("element %s: cites unknown source %q", key, src)
			}
		}
		if e.Status == "contested" && len(e.Sources) < 2 {
			t.Errorf("element %s: contested needs at least two sources", key)
		}
	}
}

// RFC 6759 is the IETF publication of Cisco's applicationId export. Its
// engine-id table decides which classification engine a collector resolves
// an applicationId against, so the values the encoder uses must be read from
// the checked-in extract, never recalled.
func TestCiscoAVCExtract_RFC6759EngineIDsArePinned(t *testing.T) {
	data, err := os.ReadFile(filepath.Join("testdata", "rfc", "rfc6759-application-information.txt"))
	if err != nil {
		t.Fatalf("read extract: %v", err)
	}
	text := string(data)
	for _, want := range []string{
		"IANA-L4", "USER-Defined", "PANA-L7",
		"applicationName", "applicationDescription",
		"Section 4.3",
	} {
		if !strings.Contains(text, want) {
			t.Errorf("rfc6759 extract is missing %q", want)
		}
	}
	sources, elements := loadCiscoAVCExtract(t)
	if _, ok := sources["rfc6759"]; !ok {
		t.Fatal("sources.tsv has no rfc6759 row")
	}
	var have94 bool
	for _, e := range elements {
		if e.PEN == "0" && e.ID == "94" {
			have94 = true
		}
	}
	if !have94 {
		t.Error("elements.tsv has no applicationDescription (IE 94) row")
	}
}
