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
	"text/template"
)

// jsonString quotes s as JSON without HTML escaping, so "<", ">" and "&"
// stay as written in descriptions.
func jsonString(s string) string {
	var b bytes.Buffer
	enc := json.NewEncoder(&b)
	enc.SetEscapeHTML(false)
	_ = enc.Encode(s) // a string always encodes
	return strings.TrimSuffix(b.String(), "\n")
}

// jsonList renders a string list the way gnmi-bindings.json writes it.
func jsonList(s []string) string {
	q := make([]string, len(s))
	for i, v := range s {
		q[i] = jsonString(v)
	}
	return "[" + strings.Join(q, ", ") + "]"
}

// componentJSON renders one component row in gnmi-bindings.json's layout.
func componentJSON(c Component) string {
	var b strings.Builder
	fmt.Fprintf(&b, `{"name": %s, "type": %s, "parent": %s, "part_no": %s, "description": %s, "serial_no": %s, "temperature": %t`,
		jsonString(c.Name), jsonString(c.Type), jsonString(c.Parent), jsonString(c.PartNo),
		jsonString(c.Description), jsonString(c.SerialNo), c.Temperature)
	for _, f := range [][2]string{{"form_factor", c.FormFactor}, {"ethernet_pmd", c.EthernetPMD}, {"connector_type", c.ConnectorType}, {"wavelength", c.Wavelength}} {
		if f[1] != "" {
			fmt.Fprintf(&b, ", %q: %s", f[0], jsonString(f[1]))
		}
	}
	b.WriteString("}")
	return b.String()
}

// hwrow lays out one "show chassis hardware" row. Junos starts the columns
// at 17, 26, 39 and 57; a field that runs past its column pushes the next
// one right by a single space.
func hwrow(item, version, part, serial, desc string) string {
	cols := []int{17, 26, 39, 57}
	var b strings.Builder
	for i, f := range []string{item, version, part, serial} {
		b.WriteString(f)
		pad := cols[i] - b.Len()
		if pad < 1 {
			pad = 1
		}
		b.WriteString(strings.Repeat(" ", pad))
	}
	b.WriteString(desc)
	return b.String()
}

// envrow lays out one "show chassis environment" temperature row.
func envrow(class, item string, celsius int) string {
	return fmt.Sprintf("%-6s%-32s%-11s%d degrees C / %d degrees F", class, item, "OK", celsius, celsius*9/5+32)
}

var templateFuncs = template.FuncMap{
	"json":       jsonList,
	"component":  componentJSON,
	"list":       func(s ...string) []string { return s },
	"hwrow":      hwrow,
	"envrow":     envrow,
	"hasPrefix":  strings.HasPrefix,
	"trimPrefix": strings.TrimPrefix,
}

// execTemplate runs templates/<name> with << >> delimiters, because the
// JSON and CLI text the templates hold never contain them.
func execTemplate(name string, data any) (string, error) {
	src, err := assets.ReadFile("templates/" + name)
	if err != nil {
		return "", err
	}
	tm, err := template.New(name).Delims("<<", ">>").Funcs(templateFuncs).Option("missingkey=error").Parse(string(src))
	if err != nil {
		return "", err
	}
	var b strings.Builder
	if err := tm.Execute(&b, data); err != nil {
		return "", err
	}
	return b.String(), nil
}

type fabricPair struct {
	Src, Dst FPC
}

type bindingsData struct {
	Components         []Component
	CPUIndexes         []string
	CPUCores           []string // CPU0:COREn, one per /system/cpus/cpu index
	HardwareRev        string
	SoftwareRev        string
	PropertyComponents []string
	OverTemperature    []string
	PacketUsage        []string
	FPCs               []FPC
	FPCNames           []string
	FabricPairs        []fabricPair
}

func bindingsDataFor(c *Chassis) bindingsData {
	d := bindingsData{Components: c.Components, HardwareRev: c.Model.HardwareRev, SoftwareRev: c.Model.SoftwareRev}
	for i := 0; i < c.Model.CPUCount; i++ {
		d.CPUIndexes = append(d.CPUIndexes, strconv.Itoa(i))
		d.CPUCores = append(d.CPUCores, "CPU0:CORE"+strconv.Itoa(i))
	}
	var cbs, res, fabrics []string
	for _, comp := range c.Components {
		switch {
		case comp.Type == "CONTROLLER_CARD" && strings.HasPrefix(comp.Name, "CB"):
			cbs = append(cbs, comp.Name)
		case comp.Type == "CONTROLLER_CARD" && strings.HasPrefix(comp.Name, "Routing Engine"):
			res = append(res, comp.Name)
		case comp.Type == "FABRIC":
			fabrics = append(fabrics, comp.Name)
		}
	}
	var pics, firstPICs []string
	for _, f := range c.FPCs {
		d.FPCNames = append(d.FPCNames, f.Name)
		for _, p := range f.PICs {
			pics = append(pics, p.Component.Name)
		}
		if len(f.PICs) > 0 {
			firstPICs = append(firstPICs, f.PICs[0].Component.Name)
		}
		for _, u := range f.Card.PacketUsage {
			d.PacketUsage = append(d.PacketUsage, f.Name+":"+u)
		}
	}
	d.PropertyComponents = append(append(append(append(d.PropertyComponents, cbs...), d.FPCNames...), firstPICs...), res...)
	d.OverTemperature = append(append(append(d.OverTemperature, pics...), res...), fabrics...)
	d.FPCs = c.FPCs
	for _, src := range c.FPCs {
		for _, dst := range c.FPCs {
			d.FabricPairs = append(d.FabricPairs, fabricPair{Src: src, Dst: dst})
		}
	}
	return d
}

func RenderBindings(c *Chassis) ([]byte, error) {
	s, err := execTemplate("gnmi-bindings.json.tmpl", bindingsDataFor(c))
	if err != nil {
		return nil, fmt.Errorf("gnmi-bindings: %w", err)
	}
	return []byte(s), nil
}

// oidLess orders dotted OIDs numerically, arc by arc.
func oidLess(a, b string) bool {
	as, bs := strings.Split(strings.TrimPrefix(a, "."), "."), strings.Split(strings.TrimPrefix(b, "."), ".")
	for i := 0; i < len(as) && i < len(bs); i++ {
		x, _ := strconv.ParseUint(as[i], 10, 64)
		y, _ := strconv.ParseUint(bs[i], 10, 64)
		if x != y {
			return x < y
		}
	}
	return len(as) < len(bs)
}

// RenderSNMPRows returns every SNMP row the chassis owns: ifNumber, ifTable,
// ifXTable (name, the HC registration rows, ifHighSpeed, ifAlias), the
// jnxOperating rows per Routing Engine, and the ENTITY-MIB rows.
func RenderSNMPRows(c *Chassis) ([]SNMPRow, error) {
	in := c.Model.Interfaces
	rows := []SNMPRow{{"1.3.6.1.2.1.2.1.0", strconv.Itoa(len(c.Ports))}}
	add := func(oid, v string) { rows = append(rows, SNMPRow{oid, v}) }
	for _, p := range c.Ports {
		ix := strconv.Itoa(p.IfIndex)
		k := uint64((p.IfIndex - 1) % in.HCPeriod)
		add("1.3.6.1.2.1.2.2.1.1."+ix, ix)
		add("1.3.6.1.2.1.2.2.1.2."+ix, p.IfName)
		add("1.3.6.1.2.1.2.2.1.3."+ix, "6")
		add("1.3.6.1.2.1.2.2.1.4."+ix, in.MTU)
		add("1.3.6.1.2.1.2.2.1.5."+ix, in.IfSpeed)
		add("1.3.6.1.2.1.2.2.1.6."+ix, fmt.Sprintf("%s%02x", in.MACPrefix, p.IfIndex))
		add("1.3.6.1.2.1.2.2.1.7."+ix, "1")
		add("1.3.6.1.2.1.2.2.1.8."+ix, "1")
		add("1.3.6.1.2.1.31.1.1.1.1."+ix, p.IfName)
		add("1.3.6.1.2.1.31.1.1.1.6."+ix, strconv.FormatUint(in.HCInBase+k*in.HCInStep, 10))
		add("1.3.6.1.2.1.31.1.1.1.10."+ix, strconv.FormatUint(in.HCOutBase+k*in.HCOutStep, 10))
		add("1.3.6.1.2.1.31.1.1.1.15."+ix, strconv.Itoa(p.SpeedMbps))
		add("1.3.6.1.2.1.31.1.1.1.18."+ix, fmt.Sprintf(in.AliasFormat, p.IfIndex))
	}
	for _, re := range c.Model.RoutingEngines {
		idx := fmt.Sprintf("9.%d.0.0", re.Slot+1)
		add("1.3.6.1.4.1.2636.3.1.13.1.5."+idx, fmt.Sprintf("Routing Engine %d", re.Slot))
		add("1.3.6.1.4.1.2636.3.1.13.1.20."+idx, re.LoadAvg1)
		add("1.3.6.1.4.1.2636.3.1.13.1.21."+idx, re.LoadAvg5)
		for _, col := range [][2]string{{"7", re.Temp}, {"8", re.CPU}, {"11", re.Buffer}} {
			if col[1] != "" {
				add("1.3.6.1.4.1.2636.3.1.13.1."+col[0]+"."+idx, col[1])
			}
		}
	}
	ent, err := entityRows(c)
	if err != nil {
		return nil, err
	}
	rows = append(rows, ent...)
	rows = append(rows, c.Model.ChassisEntity...)
	sort.SliceStable(rows, func(i, j int) bool { return oidLess(rows[i].OID, rows[j].OID) })
	return rows, nil
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

func RenderSNMPFile(c *Chassis) ([]byte, error) {
	rows, err := RenderSNMPRows(c)
	if err != nil {
		return nil, fmt.Errorf("snmp: %w", err)
	}
	return marshalResource(struct {
		SNMP []SNMPRow `json:"snmp"`
	}{rows})
}

type sshEntry struct {
	Command  string `json:"command"`
	Response string `json:"response"`
}

type picData struct {
	FPC FPC
	PIC PIC
}

// RenderSSHEntries renders every SSH command the chassis owns. A template
// ends with one newline more than the response, which is trimmed here.
func RenderSSHEntries(c *Chassis) ([]sshEntry, error) {
	var out []sshEntry
	add := func(cmd, tmpl string, data any) error {
		s, err := execTemplate("ssh/"+tmpl, data)
		if err != nil {
			return fmt.Errorf("%s: %w", cmd, err)
		}
		out = append(out, sshEntry{Command: cmd, Response: strings.TrimSuffix(s, "\n")})
		return nil
	}
	for _, s := range []struct{ cmd, tmpl string }{
		{"show interfaces terse", "terse.tmpl"},
		{"show chassis environment", "environment.tmpl"},
		{"show chassis hardware", "hardware.tmpl"},
		{"show chassis fpc", "fpc.tmpl"},
		{"show chassis routing-engine", "routing-engine.tmpl"},
	} {
		if err := add(s.cmd, s.tmpl, c); err != nil {
			return nil, err
		}
	}
	for _, f := range c.FPCs {
		for _, p := range f.PICs {
			if err := add(fmt.Sprintf("show chassis pic fpc-slot %d pic-slot %d", f.Slot, p.Index), "pic.tmpl", picData{FPC: f, PIC: p}); err != nil {
				return nil, err
			}
		}
	}
	if err := add("show chassis power", "power.tmpl", c); err != nil {
		return nil, err
	}
	return out, nil
}

func RenderSSHFile(c *Chassis) ([]byte, error) {
	entries, err := RenderSSHEntries(c)
	if err != nil {
		return nil, err
	}
	return marshalResource(struct {
		SSH []sshEntry `json:"ssh"`
	}{entries})
}

// entityClass maps a gNMI component type to entPhysicalClass.
var entityClass = map[string]string{
	"CHASSIS": "9", "BACKPLANE": "4", "CONTROLLER_CARD": "9", "LINECARD": "9",
	"CPU": "12", "FABRIC": "9", "POWER_SUPPLY": "6", "FAN": "7",
}

// entityRows builds entPhysicalTable and entAliasMappingTable from the
// inventory. Entity 1, the chassis, keeps its descriptive rows in
// chassis_entity; its revisions, serial and model come from the Chassis
// component like every board's, so the views agree. Boards take 2..n
// in component order, ports 1000+ifIndex; sensors, transceivers and single
// fans are not entities. A board whose parent is not an earlier entity is an
// error: entPhysicalContainedIn would otherwise read 0.
func entityRows(c *Chassis) ([]SNMPRow, error) {
	const ent = "1.3.6.1.2.1.47.1.1.1.1."
	idx := map[string]int{"Chassis": 1}
	hw, sw := c.Model.HardwareRev, c.Model.SoftwareRev
	var rows []SNMPRow
	add := func(n int, descr, contained, class, serial, model string) {
		s := strconv.Itoa(n)
		for _, kv := range [][2]string{
			{"1", s}, {"2", descr}, {"4", contained}, {"5", class}, {"7", descr}, {"8", hw},
			{"9", sw}, {"10", sw}, {"11", serial}, {"12", "Juniper Networks, Inc."}, {"13", model},
		} {
			rows = append(rows, SNMPRow{ent + kv[0] + "." + s, kv[1]})
		}
	}
	chassis := c.Component("Chassis")
	if chassis == nil {
		return nil, fmt.Errorf("entity 1: no Chassis component")
	}
	for _, kv := range [][2]string{{"8", hw}, {"9", sw}, {"10", sw}, {"11", chassis.SerialNo}, {"13", chassis.PartNo}} {
		rows = append(rows, SNMPRow{ent + kv[0] + ".1", kv[1]})
	}
	next := 2
	for _, comp := range c.Components {
		class, ok := entityClass[comp.Type]
		if !ok || comp.Name == "Chassis" || strings.Contains(comp.Name, " Fan ") {
			continue
		}
		parent, ok := idx[comp.Parent]
		if !ok {
			return nil, fmt.Errorf("entity %s: parent %q is not an earlier entity", comp.Name, comp.Parent)
		}
		idx[comp.Name] = next
		add(next, comp.Name, strconv.Itoa(parent), class, comp.SerialNo, comp.PartNo)
		next++
	}
	for _, f := range c.FPCs {
		for _, p := range f.PICs {
			for _, port := range p.Ports {
				n := 1000 + port.IfIndex
				add(n, port.IfName, strconv.Itoa(idx[p.Component.Name]), "10", port.Port.SerialNo, f.Card.EntityPortModel)
				rows = append(rows, SNMPRow{fmt.Sprintf("1.3.6.1.2.1.47.1.3.2.1.2.%d.0", n), "1.3.6.1.2.1.2.2.1.1." + strconv.Itoa(port.IfIndex)})
			}
		}
	}
	return rows, nil
}
