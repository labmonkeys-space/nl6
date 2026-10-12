/*
 * Copyright 2026 Ronny Trommer <ronny@no42.org>
 * SPDX-License-Identifier: Apache-2.0
 */

package main

import (
	"encoding/json"
	"testing"
)

// The rendered bindings carry the skeleton unchanged plus one components
// row per expanded component, with its tags and synthetic serial.
func TestRenderBindings(t *testing.T) {
	c := shipped(t)
	sk, err := assets.ReadFile("models/cisco_asr9902-gnmi.json")
	if err != nil {
		t.Fatal(err)
	}
	b, err := RenderBindings(c, sk)
	if err != nil {
		t.Fatal(err)
	}
	var out struct {
		Notification map[string]any `json:"notification"`
		Components   []Component    `json:"components"`
		Subtrees     []any          `json:"subtrees"`
	}
	if err := json.Unmarshal(b, &out); err != nil {
		t.Fatal(err)
	}
	if len(out.Components) != len(c.Components) || len(out.Subtrees) != 7 || out.Notification["response_origin"] != "module" {
		t.Fatalf("%d components (want %d), %d subtrees (want 7), notification %v", len(out.Components), len(c.Components), len(out.Subtrees), out.Notification)
	}
	if out.Components[0].Name != "Rack 0" || out.Components[0].SerialNo == "" {
		t.Errorf("first component %+v, want Rack 0 with a serial", out.Components[0])
	}
}
