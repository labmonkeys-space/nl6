/*
 * Copyright 2026 Ronny Trommer <ronny@no42.org>
 * SPDX-License-Identifier: Apache-2.0
 */

// Command xr-chassis renders the cisco_asr9902 hardware files from one
// chassis model: the SNMP chassis part and the SSH chassis part. Run it
// through `make gen-xr-chassis`.
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
	rows, err := RenderSNMPRows(c)
	if err != nil {
		return nil, fmt.Errorf("snmp: %w", err)
	}
	snmp, err := marshalResource(struct {
		SNMP []SNMPRow `json:"snmp"`
	}{rows})
	if err != nil {
		return nil, err
	}
	ssh, err := marshalResource(struct {
		SSH []sshEntry `json:"ssh"`
	}{RenderSSHEntries(c)})
	if err != nil {
		return nil, err
	}
	return map[string][]byte{
		"cisco_asr9902_snmp_chassis.json": snmp,
		"cisco_asr9902_ssh_chassis.json":  ssh,
	}, nil
}

func main() {
	out := flag.String("out", "nl6/resources/cisco_asr9902", "resource directory to write into")
	flag.Parse()
	files, err := renderAll()
	if err != nil {
		fmt.Fprintln(os.Stderr, "xr-chassis:", err)
		os.Exit(1)
	}
	if err := os.MkdirAll(*out, 0o750); err != nil {
		fmt.Fprintln(os.Stderr, "xr-chassis:", err)
		os.Exit(1)
	}
	for name, b := range files {
		if err := os.WriteFile(filepath.Join(*out, name), b, 0o600); err != nil {
			fmt.Fprintln(os.Stderr, "xr-chassis:", err)
			os.Exit(1)
		}
	}
}
