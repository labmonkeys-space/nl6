/*
 * Copyright 2026 Ronny Trommer <ronny@no42.org>
 * SPDX-License-Identifier: Apache-2.0
 */

package main

import (
	"bytes"
	"encoding/json"
	"fmt"
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
	for _, f := range [][2]string{{"form_factor", c.FormFactor}, {"ethernet_pmd", c.EthernetPMD}, {"wavelength", c.Wavelength}} {
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
	PropertyComponents []string
	OverTemperature    []string
	PacketUsage        []string
	FPCs               []FPC
	FPCNames           []string
	FabricPairs        []fabricPair
}

func bindingsDataFor(c *Chassis) bindingsData {
	d := bindingsData{Components: c.Components}
	for i := 0; i < c.Model.CPUCount; i++ {
		d.CPUIndexes = append(d.CPUIndexes, strconv.Itoa(i))
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
