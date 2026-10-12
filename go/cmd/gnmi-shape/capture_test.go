/*
 * Copyright 2026 Ronny Trommer <ronny@no42.org>
 * SPDX-License-Identifier: Apache-2.0
 */

package main

import (
	"os"
	"strings"
	"testing"
)

func TestReadCaptureSkipsEchoAndNonNotifications(t *testing.T) {
	f, err := os.Open("testdata/fake-capture.log")
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	var prefixes []string
	updates := 0
	if err := readCapture(f, func(n notification) error {
		prefixes = append(prefixes, n.Prefix)
		updates += len(n.Updates)
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	// The sync-response object carries no prefix and no updates.
	if len(prefixes) != 3 || updates != 9 {
		t.Fatalf("got %d notifications and %d updates, want 3 and 9", len(prefixes), updates)
	}
}

func TestReadCaptureErrorNamesOffsetNotContent(t *testing.T) {
	err := readCapture(strings.NewReader(`{"prefix":"secret-token-xyz","updates":[`), func(notification) error { return nil })
	if err == nil {
		t.Fatal("truncated JSON accepted")
	}
	if strings.Contains(err.Error(), "secret") || !strings.Contains(err.Error(), "byte") {
		t.Fatalf("error %q must name a byte offset and no content", err)
	}
}

// The reference was captured on a Windows host: CRLF line endings and a
// shell prompt pasted after the last object, both fabricated here.
func TestReadCaptureToleratesCRLFAndTrailingPrompt(t *testing.T) {
	in := "gnmic sub -a 192.0.2.10:57400 --mode once\r\n{\r\n  \"prefix\": \"x:a[k={v}]\",\r\n  \"updates\": [{\"Path\": \"b\", \"values\": {\"b\": \"}\"}}]\r\n}\r\n{\r\n  \"sync-response\": true\r\n}\r\n[lab@fake-r1 ~]$ "
	n := 0
	var text []string
	if err := readCaptureText(strings.NewReader(in), func(notification) error { n++; return nil }, func(s string) { text = append(text, s) }); err != nil {
		t.Fatal(err)
	}
	if n != 1 {
		t.Fatalf("%d notifications, want 1", n)
	}
	joined := strings.Join(text, "|")
	if !strings.Contains(joined, "192.0.2.10") || !strings.Contains(joined, "fake-r1") {
		t.Fatalf("text outside objects not reported: %q", joined)
	}
}

// A terminal that hard-wraps long lines puts a raw CRLF inside a JSON
// string. JSON forbids raw line breaks in strings, so the wrap is the only
// source and dropping it restores the original.
func TestReadCaptureJoinsTerminalWrappedStrings(t *testing.T) {
	in := "{\"prefix\": \"x:interfaces/interface[name=a]/sub\r\ninterfaces\", \"updates\": [{\"Path\": \"b\", \"values\": {\"b\": 1}}]}"
	var got string
	if err := readCapture(strings.NewReader(in), func(n notification) error { got = n.Prefix; return nil }); err != nil {
		t.Fatal(err)
	}
	if got != "x:interfaces/interface[name=a]/subinterfaces" {
		t.Fatalf("prefix %q", got)
	}
}
