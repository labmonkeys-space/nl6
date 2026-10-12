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

// The generated parts are committed; a hand edit, or a model edit without a
// regeneration, fails here.
func TestCommittedOutputsMatchModel(t *testing.T) {
	files, err := renderAll()
	if err != nil {
		t.Fatal(err)
	}
	for name, want := range files {
		got, err := os.ReadFile(filepath.Join("..", "..", "nl6", "resources", "cisco_asr9902", name))
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(got, want) {
			t.Errorf("%s is not what models/cisco_asr9902.json renders; edit the model and run make gen-xr-chassis", name)
		}
	}
}
