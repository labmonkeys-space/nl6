/*
 * Copyright 2026 Ronny Trommer <ronny@no42.org>
 * SPDX-License-Identifier: Apache-2.0
 */

package main

import (
	"bytes"
	"embed"
	"encoding/json"
	"fmt"
	"net/netip"
	"strconv"
	"strings"
)

//go:embed models/juniper_mx10004.json templates
var assets embed.FS

// Component is one gNMI inventory row, in gnmi-bindings.json's field order.
// The three optic fields are written only when set.
type Component struct {
	Name          string `json:"name"`
	Type          string `json:"type"`
	Parent        string `json:"parent"`
	PartNo        string `json:"part_no"`
	Description   string `json:"description"`
	SerialNo      string `json:"serial_no"`
	Temperature   bool   `json:"temperature"`
	FormFactor    string `json:"form_factor,omitempty"`
	EthernetPMD   string `json:"ethernet_pmd,omitempty"`
	ConnectorType string `json:"connector_type,omitempty"`
	Wavelength    string `json:"wavelength,omitempty"`
}

type Part struct {
	PartNo      string `json:"part_no"`
	Description string `json:"description"`
}

// Optic is the transceiver a card type ships in every port. The catalogue
// reads FormFactor, EthernetPMD and ConnectorType from the transceiver
// component and Wavelength from the port; Expand refuses an optic missing
// any of them.
type Optic struct {
	PartNo        string `json:"part_no"`
	Description   string `json:"description"`
	FormFactor    string `json:"form_factor"`
	EthernetPMD   string `json:"ethernet_pmd"`
	ConnectorType string `json:"connector_type"`
	Wavelength    string `json:"wavelength"`
	Cable         string `json:"cable"`
	Fiber         string `json:"fiber"`
}

type Sensor struct {
	Name    string `json:"name"`
	Ordinal int    `json:"ordinal"`
}

type EnvReading struct {
	Item    string `json:"item"`
	Celsius int    `json:"celsius"`
}

type CardType struct {
	PartNo          string       `json:"part_no"`
	Description     string       `json:"description"`
	CPU             Part         `json:"cpu"`
	Mezz            Part         `json:"mezz"`
	MezzCount       int          `json:"mezz_count"`
	PIC             Part         `json:"pic"`
	PICCount        int          `json:"pic_count"`
	PortsPerPIC     int          `json:"ports_per_pic"`
	PortPrefix      string       `json:"port_prefix"`
	SpeedMbps       int          `json:"speed_mbps"`
	EntityPortModel string       `json:"entity_port_model"`
	Optic           Optic        `json:"optic"`
	Sensors         []Sensor     `json:"sensors"`
	PFEs            int          `json:"pfes"`
	PacketUsage     []string     `json:"packet_usage"`
	SSHFPCStatus    string       `json:"ssh_fpc_status"`
	SSHEnvironment  []EnvReading `json:"ssh_environment"`
	SSHPICCelsius   int          `json:"ssh_pic_celsius"`
}

type FPCSlot struct {
	Slot int    `json:"slot"`
	Card string `json:"card"`
}

type RoutingEngine struct {
	Slot     int    `json:"slot"`
	LoadAvg1 string `json:"jnx_load_avg_1m"`
	LoadAvg5 string `json:"jnx_load_avg_5m"`
	// Static jnxOperatingCPU, Buffer and Temp for an RE nl6 does not
	// serve from the metrics cycler: the cycler is one per device, so a
	// backup RE served from it would mirror the master. Empty means
	// code-served (metrics_oids.go).
	CPU    string `json:"jnx_cpu,omitempty"`
	Buffer string `json:"jnx_buffer,omitempty"`
	Temp   string `json:"jnx_temp,omitempty"`
}

type Interfaces struct {
	MTU         string `json:"mtu"`
	MACPrefix   string `json:"mac_prefix"`
	AliasFormat string `json:"alias_format"`
	HCPeriod    int    `json:"hc_period"`
	HCInBase    uint64 `json:"hc_in_base"`
	HCInStep    uint64 `json:"hc_in_step"`
	HCOutBase   uint64 `json:"hc_out_base"`
	HCOutStep   uint64 `json:"hc_out_step"`
}

// Unit is a logical unit the device configures on a port, named
// <parent>.<unit> as Junos names it. Inet is the address `show interfaces
// terse` lists for it. Family is the protocol family the unit carries
// without an address ("inet", as a VRF unit configured `family inet;`);
// an Inet address implies it, and neither lists no family.
type Unit struct {
	Parent string `json:"parent"`
	Unit   int    `json:"unit"`
	Inet   string `json:"inet,omitempty"`
	Family string `json:"family,omitempty"`
}

// SystemInterface is an interface the Routing Engine owns rather than a
// line card: the management port fxp0 (ethernetCsmacd, 6) or the loopback
// lo0 (softwareLoopback, 24). It carries unit 0, addressed Inet.
type SystemInterface struct {
	Name      string `json:"name"`
	IfType    int    `json:"iftype"`
	MTU       string `json:"mtu"`
	SpeedMbps int    `json:"speed_mbps"`
	Inet      string `json:"inet"`
}

type SNMPRow struct {
	OID      string `json:"oid"`
	Response string `json:"response"`
}

// Model is the chassis description. Head and Tail are literal component
// rows around the line cards; FPCs expand from CardTypes.
type Model struct {
	Comment   string              `json:"comment"`
	Head      []Component         `json:"head"`
	FPCSlots  int                 `json:"fpc_slots"`
	FPCs      []FPCSlot           `json:"fpcs"`
	Tail      []Component         `json:"tail"`
	CardTypes map[string]CardType `json:"card_types"`
	CPUCount  int                 `json:"cpu_count"`
	// HardwareRev and SoftwareRev are the revisions every board reports,
	// in gNMI (hardware-version, firmware/software-version) and in
	// ENTITY-MIB (entPhysicalHardwareRev, FirmwareRev, SoftwareRev).
	HardwareRev    string          `json:"hardware_rev"`
	SoftwareRev    string          `json:"software_rev"`
	RoutingEngines []RoutingEngine `json:"routing_engines"`
	Interfaces     Interfaces      `json:"interfaces"`
	// Units follow the physical ports in ifIndex order; the system
	// interfaces follow the units, each with its own unit 0 after it.
	Units            []Unit            `json:"units,omitempty"`
	SystemInterfaces []SystemInterface `json:"system_interfaces,omitempty"`
	ChassisEntity    []SNMPRow         `json:"chassis_entity"`
}

type Port struct {
	Index     int // port number on its PIC
	IfIndex   int
	IfName    string
	IfType    string // IANAifType: "6" on a line-card port
	MTU       string
	SpeedMbps int
	Port      Component
	Xcvr      Component
}

// LogicalUnit is an expanded Unit: its own ifIndex after the last port, and
// the port it belongs to.
type LogicalUnit struct {
	IfIndex int
	IfName  string
	Unit    int
	Inet    string
	Family  string
	Parent  Port
}

type PIC struct {
	Index     int
	Component Component
	Ports     []Port
}

type FPC struct {
	Slot     int
	SlotName string // "0"
	Name     string // "FPC0"
	Card     CardType
	FPC      Component
	CPU      Component
	Mezz     []Component
	PICs     []PIC
	Sensors  []Component
	PFEs     []string // "0".."n-1"
}

type SlotView struct {
	Slot int
	FPC  *FPC
	Last bool
}

// Chassis is the expanded model every renderer reads.
type Chassis struct {
	Model      *Model
	Components []Component
	FPCs       []FPC
	Slots      []SlotView
	Ports      []Port // every line-card port, in ifIndex order
	Units      []LogicalUnit
	System     []Port // the system interfaces, after the units, no components
}

func loadModel() (*Model, error) {
	b, err := assets.ReadFile("models/juniper_mx10004.json")
	if err != nil {
		return nil, err
	}
	return parseModel(b)
}

func parseModel(b []byte) (*Model, error) {
	dec := json.NewDecoder(bytes.NewReader(b))
	dec.DisallowUnknownFields()
	var m Model
	if err := dec.Decode(&m); err != nil {
		return nil, fmt.Errorf("model: %w", err)
	}
	return &m, nil
}

// Expand turns the model into components and FPC views. Serial rules: FPC and
// FPC CPU number by slot+1, mezzanines by slot*count+index+1, PICs and ports
// count up across FPCs, transceivers encode slot, PIC and port, FPC sensors
// encode slot and the card's sensor ordinal.
func Expand(m *Model) (*Chassis, error) {
	c := &Chassis{Model: m}
	c.Components = append(c.Components, m.Head...)
	picSerial, ifIndex := 0, 0
	for _, s := range m.FPCs {
		card, ok := m.CardTypes[s.Card]
		if !ok {
			return nil, fmt.Errorf("FPC%d: unknown card type %q", s.Slot, s.Card)
		}
		if s.Slot < 0 || s.Slot >= m.FPCSlots {
			return nil, fmt.Errorf("FPC%d: slot outside 0..%d", s.Slot, m.FPCSlots-1)
		}
		if o := card.Optic; o.FormFactor == "" || o.EthernetPMD == "" || o.ConnectorType == "" || o.Wavelength == "" {
			return nil, fmt.Errorf("card type %q: optic needs form_factor, ethernet_pmd, connector_type and wavelength", s.Card)
		}
		if card.SpeedMbps < 0 {
			return nil, fmt.Errorf("card type %q: speed_mbps %d is negative", s.Card, card.SpeedMbps)
		}
		name := fmt.Sprintf("FPC%d", s.Slot)
		f := FPC{Slot: s.Slot, SlotName: strconv.Itoa(s.Slot), Name: name, Card: card}
		f.FPC = Component{Name: name, Type: "LINECARD", Parent: "Chassis", PartNo: card.PartNo,
			Description: card.Description, SerialNo: fmt.Sprintf("NL6FPC%06d", s.Slot+1), Temperature: true}
		f.CPU = Component{Name: name + ":CPU", Type: "CPU", Parent: name, PartNo: card.CPU.PartNo,
			Description: card.CPU.Description, SerialNo: fmt.Sprintf("NL6CPU%06d", s.Slot+1)}
		c.Components = append(c.Components, f.FPC, f.CPU)
		for i := 0; i < card.MezzCount; i++ {
			mz := Component{Name: fmt.Sprintf("%s:MEZZ%d", name, i), Type: "LINECARD", Parent: name,
				PartNo: card.Mezz.PartNo, Description: card.Mezz.Description,
				SerialNo: fmt.Sprintf("NL6MEZ%06d", s.Slot*card.MezzCount+i+1)}
			f.Mezz = append(f.Mezz, mz)
			c.Components = append(c.Components, mz)
		}
		for p := 0; p < card.PICCount; p++ {
			picSerial++
			pc := Component{Name: fmt.Sprintf("%s:PIC%d", name, p), Type: "LINECARD", Parent: name,
				PartNo: card.PIC.PartNo, Description: card.PIC.Description, SerialNo: fmt.Sprintf("NL6PIC%06d", picSerial)}
			f.PICs = append(f.PICs, PIC{Index: p, Component: pc})
			c.Components = append(c.Components, pc)
		}
		for p := range f.PICs {
			for n := 0; n < card.PortsPerPIC; n++ {
				ifIndex++
				pn := fmt.Sprintf("%s:PIC%d:PORT%d", name, p, n)
				port := Port{Index: n, IfIndex: ifIndex, IfName: fmt.Sprintf("%s-%d/%d/%d", card.PortPrefix, s.Slot, p, n), IfType: "6", MTU: m.Interfaces.MTU, SpeedMbps: card.SpeedMbps}
				port.Port = Component{Name: pn, Type: "PORT", Parent: f.PICs[p].Component.Name, PartNo: card.PIC.PartNo,
					Description: port.IfName, SerialNo: fmt.Sprintf("NL6PRT%06d", ifIndex)}
				port.Xcvr = Component{Name: pn + ":Xcvr0", Type: "TRANSCEIVER", Parent: pn, PartNo: card.Optic.PartNo,
					Description: card.Optic.Description, SerialNo: fmt.Sprintf("NL6XCV%02d%02d%02d", s.Slot, p, n)}
				port.Port.Wavelength = card.Optic.Wavelength
				port.Xcvr.FormFactor = card.Optic.FormFactor
				port.Xcvr.EthernetPMD = card.Optic.EthernetPMD
				port.Xcvr.ConnectorType = card.Optic.ConnectorType
				f.PICs[p].Ports = append(f.PICs[p].Ports, port)
				c.Ports = append(c.Ports, port)
				c.Components = append(c.Components, port.Port, port.Xcvr)
			}
		}
		for _, sn := range card.Sensors {
			sc := Component{Name: name + ":" + sn.Name, Type: "SENSOR", Parent: name, PartNo: card.PartNo,
				Description: fmt.Sprintf("%s %s Temp Sensor", name, sn.Name),
				SerialNo:    fmt.Sprintf("NL6FPS%02d%04d", s.Slot, sn.Ordinal), Temperature: true}
			f.Sensors = append(f.Sensors, sc)
			c.Components = append(c.Components, sc)
		}
		for i := 0; i < card.PFEs; i++ {
			f.PFEs = append(f.PFEs, strconv.Itoa(i))
		}
		c.FPCs = append(c.FPCs, f)
	}
	c.Components = append(c.Components, m.Tail...)
	// Pointers into c.FPCs are taken only after the last append.
	bySlot := map[int]*FPC{}
	for i := range c.FPCs {
		if bySlot[c.FPCs[i].Slot] != nil {
			return nil, fmt.Errorf("duplicate FPC slot %d", c.FPCs[i].Slot)
		}
		bySlot[c.FPCs[i].Slot] = &c.FPCs[i]
	}
	for s := 0; s < m.FPCSlots; s++ {
		c.Slots = append(c.Slots, SlotView{Slot: s, FPC: bySlot[s], Last: s == m.FPCSlots-1})
	}
	if len(c.Ports) > 255 {
		return nil, fmt.Errorf("%d ports: ifPhysAddress encodes the ifIndex in one byte, at most 255", len(c.Ports))
	}
	if err := c.expandUnits(m); err != nil {
		return nil, err
	}
	if err := c.expandSystem(m); err != nil {
		return nil, err
	}
	names, serials := map[string]bool{}, map[string]bool{}
	for _, comp := range c.Components {
		if names[comp.Name] {
			return nil, fmt.Errorf("duplicate component name %q", comp.Name)
		}
		if serials[comp.SerialNo] {
			return nil, fmt.Errorf("duplicate serial %q (component %s)", comp.SerialNo, comp.Name)
		}
		names[comp.Name], serials[comp.SerialNo] = true, true
	}
	return c, nil
}

// maxJunosUnit is the highest logical unit number Junos accepts.
const maxJunosUnit = 16385

// expandUnits numbers the units after the last port, each on a port the
// chassis has.
func (c *Chassis) expandUnits(m *Model) error {
	ports := map[string]Port{}
	for _, p := range c.Ports {
		ports[p.IfName] = p
	}
	seen := map[string]bool{}
	for _, u := range m.Units {
		parent, ok := ports[u.Parent]
		if !ok {
			return fmt.Errorf("units: parent %s is not a port", u.Parent)
		}
		if u.Unit < 0 || u.Unit > maxJunosUnit {
			return fmt.Errorf("units: %s unit %d outside 0..%d", u.Parent, u.Unit, maxJunosUnit)
		}
		if _, err := netip.ParsePrefix(u.Inet); u.Inet != "" && err != nil {
			return fmt.Errorf("units: %s unit %d inet: %w", u.Parent, u.Unit, err)
		}
		family := u.Family
		switch {
		case u.Inet != "" && family == "":
			family = "inet"
		case u.Inet != "" && family != "inet":
			return fmt.Errorf("units: %s unit %d carries an inet address but family %q", u.Parent, u.Unit, family)
		case family != "" && family != "inet":
			return fmt.Errorf("units: %s unit %d family %q is not inet", u.Parent, u.Unit, family)
		}
		name := fmt.Sprintf("%s.%d", u.Parent, u.Unit)
		if seen[name] {
			return fmt.Errorf("units: %s defined twice", name)
		}
		seen[name] = true
		c.Units = append(c.Units, LogicalUnit{IfIndex: len(c.Ports) + len(c.Units) + 1, IfName: name, Unit: u.Unit, Inet: u.Inet, Family: family, Parent: parent})
	}
	return nil
}

// expandSystem numbers each system interface after the last unit, followed
// by its own unit 0, and appends that unit to c.Units so every unit consumer
// sees it. The ifIndexes of the ports and their units do not move.
func (c *Chassis) expandSystem(m *Model) error {
	seen := map[string]bool{}
	for _, p := range c.Ports {
		seen[p.IfName] = true
	}
	for _, u := range c.Units {
		seen[u.IfName] = true
	}
	next := len(c.Ports) + len(c.Units)
	for _, si := range m.SystemInterfaces {
		if si.IfType != 6 && si.IfType != 24 {
			return fmt.Errorf("system_interfaces: %s iftype %d is neither ethernetCsmacd(6) nor softwareLoopback(24)", si.Name, si.IfType)
		}
		if si.Name == "" || seen[si.Name] || seen[si.Name+".0"] {
			return fmt.Errorf("system_interfaces: %q clashes with a port or unit", si.Name)
		}
		// The name is spliced into the catalogue's interfaces filter
		// (whitespace-separated terms, comma-separated names) and a JSON
		// string; a name those cannot carry fails here, not at load.
		if strings.ContainsAny(si.Name, " \t\r\n,:\"\\") {
			return fmt.Errorf("system_interfaces: %q holds whitespace, a comma, a colon, a quote or a backslash, which the gNMI interfaces filter cannot name", si.Name)
		}
		prefix, err := netip.ParsePrefix(si.Inet)
		if err != nil {
			return fmt.Errorf("system_interfaces: %s inet: %w", si.Name, err)
		}
		if !prefix.Addr().Is4() {
			return fmt.Errorf("system_interfaces: %s inet %s is not IPv4, which is what family inet carries", si.Name, si.Inet)
		}
		if si.IfType == 24 && prefix.Bits() != 32 {
			return fmt.Errorf("system_interfaces: %s is a loopback, so its address must be a /32, not %s", si.Name, si.Inet)
		}
		if si.MTU == "" || si.SpeedMbps < 0 {
			return fmt.Errorf("system_interfaces: %s needs an mtu and a non-negative speed_mbps", si.Name)
		}
		next++
		port := Port{IfIndex: next, IfName: si.Name, IfType: strconv.Itoa(si.IfType), MTU: si.MTU, SpeedMbps: si.SpeedMbps}
		c.System = append(c.System, port)
		next++
		c.Units = append(c.Units, LogicalUnit{IfIndex: next, IfName: si.Name + ".0", Inet: si.Inet, Family: "inet", Parent: port})
		seen[si.Name], seen[si.Name+".0"] = true, true
	}
	return nil
}

// Interfaces returns every physical interface, the line-card ports then
// the system interfaces, in ifIndex order.
func (c *Chassis) Interfaces() []Port {
	return append(append(make([]Port, 0, len(c.Ports)+len(c.System)), c.Ports...), c.System...)
}

// UnitsOf returns the logical units on the port named port, in model order.
func (c *Chassis) UnitsOf(port string) []LogicalUnit {
	var out []LogicalUnit
	for _, u := range c.Units {
		if u.Parent.IfName == port {
			out = append(out, u)
		}
	}
	return out
}

// Component returns the expanded component named name, or nil.
func (c *Chassis) Component(name string) *Component {
	for i := range c.Components {
		if c.Components[i].Name == name {
			return &c.Components[i]
		}
	}
	return nil
}
