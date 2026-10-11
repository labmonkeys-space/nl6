/*
 * Copyright 2026 Ronny Trommer <ronny@no42.org>
 * SPDX-License-Identifier: Apache-2.0
 */

package main

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"
)

// TestCommittedOutputsMatchModel fails when a generated file was hand-edited
// or the model changed without `make gen-junos-chassis`.
func TestCommittedOutputsMatchModel(t *testing.T) {
	files, err := renderAll()
	if err != nil {
		t.Fatal(err)
	}
	for name, want := range files {
		got, err := os.ReadFile(filepath.Join(resourceDir, name))
		if err != nil {
			t.Errorf("%s: %v (run make gen-junos-chassis)", name, err)
			continue
		}
		if !bytes.Equal(got, want) {
			i := firstDiff(got, want)
			lo := max(0, i-80)
			t.Errorf("%s differs from the model at byte %d; edit go/cmd/junos-chassis and run make gen-junos-chassis\ncommitted: %q\nrendered:  %q",
				name, i, got[lo:min(len(got), i+80)], want[lo:min(len(want), i+80)])
		}
	}
}
