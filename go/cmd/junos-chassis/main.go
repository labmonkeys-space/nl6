/*
 * Copyright 2026 Ronny Trommer <ronny@no42.org>
 * SPDX-License-Identifier: Apache-2.0
 */

// Command junos-chassis renders the juniper_mx10004 hardware files from one
// chassis model: gnmi-bindings.json, the SNMP chassis part and the SSH
// chassis part. Run it through `make gen-junos-chassis`.
package main

import (
	"flag"
	"fmt"
	"os"
	"path/filepath"
)

func renderAll() (map[string][]byte, error) {
	m, err := loadModel()
	if err != nil {
		return nil, err
	}
	c, err := Expand(m)
	if err != nil {
		return nil, err
	}
	bindings, err := RenderBindings(c)
	if err != nil {
		return nil, err
	}
	snmp, err := RenderSNMPFile(c)
	if err != nil {
		return nil, err
	}
	ssh, err := RenderSSHFile(c)
	if err != nil {
		return nil, err
	}
	return map[string][]byte{
		"gnmi-bindings.json":                bindings,
		"juniper_mx10004_snmp_chassis.json": snmp,
		"juniper_mx10004_ssh_chassis.json":  ssh,
	}, nil
}

func main() {
	out := flag.String("out", "nl6/resources/juniper_mx10004", "resource directory to write into")
	flag.Parse()
	files, err := renderAll()
	if err != nil {
		fmt.Fprintln(os.Stderr, "junos-chassis:", err)
		os.Exit(1)
	}
	for name, b := range files {
		if err := os.WriteFile(filepath.Join(*out, name), b, 0o600); err != nil {
			fmt.Fprintln(os.Stderr, "junos-chassis:", err)
			os.Exit(1)
		}
	}
}
