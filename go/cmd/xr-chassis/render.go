/*
 * Copyright 2026 Ronny Trommer <ronny@no42.org>
 * SPDX-License-Identifier: Apache-2.0
 */

package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"sort"
	"strconv"
	"strings"
)

type SNMPRow struct {
	OID      string `json:"oid"`
	Response string `json:"response"`
}

// oidLess orders dotted OIDs numerically, arc by arc.
func oidLess(a, b string) bool {
	as, bs := strings.Split(a, "."), strings.Split(b, ".")
	for i := 0; i < len(as) && i < len(bs); i++ {
		x, _ := strconv.ParseUint(as[i], 10, 64)
		y, _ := strconv.ParseUint(bs[i], 10, 64)
		if x != y {
			return x < y
		}
	}
	return len(as) < len(bs)
}

// ifSpeedFor saturates at the Gauge32 maximum, as RFC 2863 asks for ports
// faster than 4.3 Gbit/s; ifHighSpeed carries the rate.
func ifSpeedFor(mbps int) string {
	if bps := uint64(mbps) * 1_000_000; bps < 4294967295 {
		return strconv.FormatUint(bps, 10)
	}
	return "4294967295"
}

// RenderSNMPRows returns every SNMP row the chassis owns: ifNumber, ifTable,
// the ifXTable name, HC registration and speed columns, and ENTITY-MIB.
// ifAdminStatus and ifOperStatus are shipped because the interface state
// engine seeds from them.
func RenderSNMPRows(c *Chassis) ([]SNMPRow, error) {
	in := c.Model.Interfaces
	if in.HCPeriod <= 0 {
		return nil, fmt.Errorf("interfaces: hc_period must be positive")
	}
	rows := []SNMPRow{{"1.3.6.1.2.1.2.1.0", strconv.Itoa(len(c.Ports))}}
	add := func(oid, v string) { rows = append(rows, SNMPRow{oid, v}) }
	for _, p := range c.Ports {
		ix := strconv.Itoa(p.IfIndex)
		k := uint64((p.IfIndex - 1) % in.HCPeriod)
		add("1.3.6.1.2.1.2.2.1.1."+ix, ix)
		add("1.3.6.1.2.1.2.2.1.2."+ix, p.IfName)
		add("1.3.6.1.2.1.2.2.1.3."+ix, "6")
		add("1.3.6.1.2.1.2.2.1.4."+ix, in.MTU)
		add("1.3.6.1.2.1.2.2.1.5."+ix, ifSpeedFor(p.SpeedMbps))
		add("1.3.6.1.2.1.2.2.1.6."+ix, fmt.Sprintf("%s%02x", in.MACPrefix, p.IfIndex))
		add("1.3.6.1.2.1.2.2.1.7."+ix, "1")
		add("1.3.6.1.2.1.2.2.1.8."+ix, "1")
		add("1.3.6.1.2.1.31.1.1.1.1."+ix, p.Short)
		add("1.3.6.1.2.1.31.1.1.1.6."+ix, strconv.FormatUint(in.HCInBase+k*in.HCInStep, 10))
		add("1.3.6.1.2.1.31.1.1.1.10."+ix, strconv.FormatUint(in.HCOutBase+k*in.HCOutStep, 10))
		add("1.3.6.1.2.1.31.1.1.1.15."+ix, strconv.Itoa(p.SpeedMbps))
	}
	ent, err := entityRows(c)
	if err != nil {
		return nil, err
	}
	rows = append(rows, ent...)
	sort.SliceStable(rows, func(i, j int) bool { return oidLess(rows[i].OID, rows[j].OID) })
	return rows, nil
}

// entityRows builds entPhysicalTable and entAliasMappingTable. Entities are
// the components with an ent_class, numbered 1.. in component order; entity
// 1 must be the chassis. entPhysicalContainedIn is the nearest ancestor that
// is an entity. A part number with no vendor_types entry gets no
// entPhysicalVendorType row rather than a guessed OID.
func entityRows(c *Chassis) ([]SNMPRow, error) {
	const ent = "1.3.6.1.2.1.47.1.1.1.1."
	idx := map[string]int{}
	var rows []SNMPRow
	next := 1
	for _, comp := range c.Components {
		if comp.EntClass == "" {
			continue
		}
		contained := 0
		for p := comp.Parent; p != ""; p = c.Component(p).Parent {
			if i, ok := idx[p]; ok {
				contained = i
				break
			}
		}
		switch {
		case next == 1 && comp.EntClass != "3":
			return nil, fmt.Errorf("entity 1 must be the chassis (class 3), got %s", comp.Name)
		case next > 1 && contained == 0:
			return nil, fmt.Errorf("entity %s: no ancestor is an entity", comp.Name)
		}
		s := strconv.Itoa(next)
		idx[comp.Name] = next
		add := func(col, v string) { rows = append(rows, SNMPRow{ent + col + "." + s, v}) }
		add("2", comp.Description)
		if vt, ok := c.Model.VendorTypes[comp.PartNo]; ok {
			add("3", vt)
		}
		add("4", strconv.Itoa(contained))
		add("5", comp.EntClass)
		add("7", comp.Name)
		add("12", "Cisco Systems, Inc.")
		if comp.PartNo != "" {
			add("8", c.Model.HardwareRev)
			add("10", c.Model.SoftwareRev)
			add("11", comp.SerialNo)
			add("13", comp.PartNo)
		}
		next++
	}
	for _, p := range c.Ports {
		e, ok := idx[p.Component]
		if !ok {
			return nil, fmt.Errorf("port %s: component %s is not an entity", p.IfName, p.Component)
		}
		rows = append(rows, SNMPRow{fmt.Sprintf("1.3.6.1.2.1.47.1.3.2.1.2.%d.0", e), "1.3.6.1.2.1.2.2.1.1." + strconv.Itoa(p.IfIndex)})
	}
	return rows, nil
}

type sshEntry struct {
	Command  string `json:"command"`
	Response string `json:"response"`
}

// RenderSSHEntries renders the CLI the chassis owns. show inventory and show
// platform follow the ASR 9000 System Management command reference samples;
// show interfaces brief keeps the layout the asr9k profile ships.
func RenderSSHEntries(c *Chassis) []sshEntry {
	var inv []string
	for _, comp := range c.Components {
		if comp.PartNo == "" {
			continue
		}
		inv = append(inv, fmt.Sprintf("NAME: %q, DESCR: %q\nPID: %-18s, VID: %s, SN: %s", comp.Name, comp.Description, comp.PartNo, c.Model.HardwareRev, comp.SerialNo))
	}
	brief := []string{"Interface          IP-Address  Status  Protocol"}
	for _, p := range c.Ports {
		pad := 19 - len(p.IfName)
		if pad < 1 {
			pad = 1
		}
		brief = append(brief, p.IfName+strings.Repeat(" ", pad)+fmt.Sprintf("%-12s%-8s%s", "unassigned", "up", "up"))
	}
	// Columns, rule and config state follow the show platform sample in the
	// ASR 9000 System Management command reference.
	plat := []string{
		fmt.Sprintf("%-16s%-26s%-17s%s", "Node", "Type", "State", "Config State"),
		strings.Repeat("-", 77),
	}
	for _, p := range c.Model.Platform {
		plat = append(plat, fmt.Sprintf("%-16s%-26s%-17s%s", p.Node, p.Type, p.State, "PWR,NSHUT,MON"))
	}
	return []sshEntry{
		{"show inventory", strings.Join(inv, "\n\n")},
		{"show platform", strings.Join(plat, "\n")},
		{"show interfaces brief", strings.Join(brief, "\n")},
	}
}

// marshalResource writes a resource part the way nl6's other parts look:
// two-space indent, no HTML escaping, trailing newline.
func marshalResource(v any) ([]byte, error) {
	var b bytes.Buffer
	enc := json.NewEncoder(&b)
	enc.SetEscapeHTML(false)
	enc.SetIndent("", "  ")
	if err := enc.Encode(v); err != nil {
		return nil, err
	}
	return b.Bytes(), nil
}
