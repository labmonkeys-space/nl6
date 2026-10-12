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
