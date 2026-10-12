/*
 * Copyright 2026 Ronny Trommer <ronny@no42.org>
 * SPDX-License-Identifier: Apache-2.0
 */

package main

import (
	"bytes"
	"encoding/json"
	"fmt"
)

// bindingComponent is one gnmi-bindings.json component row. ent_class is
// ENTITY-MIB only and is not emitted.
type bindingComponent struct {
	Name        string   `json:"name"`
	Type        string   `json:"type"`
	Parent      string   `json:"parent"`
	PartNo      string   `json:"part_no"`
	Description string   `json:"description"`
	SerialNo    string   `json:"serial_no"`
	Temperature bool     `json:"temperature"`
	Tags        []string `json:"tags,omitempty"`
}

// bindingsKeys is the order gnmi-bindings.json writes its top-level keys.
var bindingsKeys = []string{"comment", "vendor", "notification", "components", "neighbors", "subtrees"}

// RenderBindings inserts the expanded components into the hand-edited
// skeleton and writes gnmi-bindings.json.
func RenderBindings(c *Chassis, skeleton []byte) ([]byte, error) {
	var top map[string]json.RawMessage
	if err := json.Unmarshal(skeleton, &top); err != nil {
		return nil, fmt.Errorf("bindings skeleton: %w", err)
	}
	if _, ok := top["components"]; ok {
		return nil, fmt.Errorf("bindings skeleton: components come from the chassis model, not the skeleton")
	}
	rows := make([]bindingComponent, 0, len(c.Components))
	for _, comp := range c.Components {
		rows = append(rows, bindingComponent{comp.Name, comp.Type, comp.Parent, comp.PartNo, comp.Description, comp.SerialNo, comp.Temperature, comp.Tags})
	}
	comps, err := marshalResource(rows)
	if err != nil {
		return nil, err
	}
	top["components"] = bytes.TrimSpace(comps)
	var b bytes.Buffer
	b.WriteString("{\n")
	for i, k := range bindingsKeys {
		v, ok := top[k]
		if !ok {
			return nil, fmt.Errorf("bindings skeleton: missing %q", k)
		}
		var ind bytes.Buffer
		if err := json.Indent(&ind, v, "  ", "  "); err != nil {
			return nil, err
		}
		fmt.Fprintf(&b, "  %q: %s", k, ind.Bytes())
		if i < len(bindingsKeys)-1 {
			b.WriteString(",")
		}
		b.WriteString("\n")
	}
	if len(top) != len(bindingsKeys) {
		return nil, fmt.Errorf("bindings skeleton: unexpected top-level keys (want %v)", bindingsKeys)
	}
	b.WriteString("}\n")
	return b.Bytes(), nil
}
