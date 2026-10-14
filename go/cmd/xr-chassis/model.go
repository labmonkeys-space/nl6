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
	"maps"
	"regexp"
	"slices"
	"strconv"
	"strings"
)

//go:embed models/cisco_asr9902.json models/cisco_asr9902-gnmi.json
var assets embed.FS

// Component is one inventory row. Type is empty for the components IOS-XR
// serves without a type leaf. EntClass is the entPhysicalClass the component
// takes in ENTITY-MIB; empty means it is not an entity.
type Component struct {
	Name        string `json:"name"`
	Type        string `json:"type"`
	Parent      string `json:"parent"`
	PartNo      string `json:"part_no,omitempty"`
	Description string `json:"description"`
	SerialNo    string `json:"serial_no,omitempty"`
	Temperature bool   `json:"temperature,omitempty"`
	EntClass    string `json:"ent_class,omitempty"`
	// Tags are the leaf groups the component reports beyond its type's,
	// served through tag:<name> filters in the gNMI catalogue.
	Tags []string `json:"tags,omitempty"`
	// entIndex is the entPhysicalIndex, 0 when EntClass is empty.
	entIndex int
}

// Board instantiates the component templates of one kind with Vars
// substituted for {name} placeholders.
type Board struct {
	Kind string            `json:"kind"`
	Vars map[string]string `json:"vars"`
}

// Optic is one front-port flavour: the transceiver every bay of that flavour
// is populated with, and the names XR gives the bay, its module and port.
type Optic struct {
	PartNo      string            `json:"part_no"`
	Description string            `json:"description"`
	Lanes       int               `json:"lanes"`
	PortPrefix  string            `json:"port_prefix"`
	ShortPrefix string            `json:"short_prefix"`
	SpeedMbps   int               `json:"speed_mbps"`
	PortDescr   string            `json:"port_description"`
	BayName     string            `json:"bay_name"`
	BayType     string            `json:"bay_type"`
	BayDescr    string            `json:"bay_description"`
	ModuleName  string            `json:"module_name"`
	ModuleDescr string            `json:"module_description"`
	SensorDescr map[string]string `json:"sensor_descriptions"`
	// Tags per generated role: module, bay, port, transceiver, and the
	// sensor kinds current, power, temperature, voltage, idprom.
	Tags map[string][]string `json:"tags"`
	// FPD, when set, is the plugged module's FPD row, added only for a
	// populated bay; {card} and {n} are the card and the bay position.
	FPD *Component `json:"fpd,omitempty"`
}

// FrontPorts lays out the line card's ports: positions 0..Count-1, PerSlice
// per slice, QSFPBays taking the QSFP optic and every other position the SFP.
// EmptyBays hold no optic: no transceiver or sensor components.
type FrontPorts struct {
	Card      string `json:"card"`
	Count     int    `json:"count"`
	PerSlice  int    `json:"per_slice"`
	QSFPBays  []int  `json:"qsfp_bays"`
	EmptyBays []int  `json:"empty_bays,omitempty"`
	SFP       Optic  `json:"sfp"`
	QSFP      Optic  `json:"qsfp"`
}

// MgmtPort is an interface outside the front panel; its component must be
// defined by a board template.
type MgmtPort struct {
	IfName    string `json:"if_name"`
	Short     string `json:"short"`
	SpeedMbps int    `json:"speed_mbps"`
}

// LogicalPort is an interface with no physical component: a bundle, a
// BVI, a loopback or Null0. IfType is its IF-MIB ifType. MTU overrides
// interfaces.mtu; NoPhysAddress serves an empty ifPhysAddress, as IOS-XR
// does for a Loopback or Null0.
type LogicalPort struct {
	IfName        string `json:"if_name"`
	Short         string `json:"short"`
	IfType        int    `json:"if_type"`
	SpeedMbps     int    `json:"speed_mbps"`
	MTU           string `json:"mtu,omitempty"`
	NoPhysAddress bool   `json:"no_phys_address,omitempty"`
	// BundleMembers names the physical ports an aggregate is made of, each
	// an earlier front port listed once; their speeds must sum to SpeedMbps.
	// Rendered as ifStackStatus.<bundle>.<member> rows.
	BundleMembers []string `json:"bundle_members,omitempty"`
}

// Subinterface is a dot1q VLAN subinterface, named <parent>.<index> as
// IOS-XR names it. It takes its parent's speed.
type Subinterface struct {
	Parent string `json:"parent"`
	Index  int    `json:"index"`
}

// PlatformRow is one `show platform` node; Type is a PID the model uses,
// optionally followed by a role in parentheses.
type PlatformRow struct {
	Node  string `json:"node"`
	Type  string `json:"type"`
	State string `json:"state"`
}

type Interfaces struct {
	MTU       string `json:"mtu"`
	MACPrefix string `json:"mac_prefix"`
	HCPeriod  int    `json:"hc_period"`
	HCInBase  uint64 `json:"hc_in_base"`
	HCInStep  uint64 `json:"hc_in_step"`
	HCOutBase uint64 `json:"hc_out_base"`
	HCOutStep uint64 `json:"hc_out_step"`
}

// Model is the chassis description.
type Model struct {
	Comment     string                 `json:"comment"`
	HardwareRev string                 `json:"hardware_rev"`
	SoftwareRev string                 `json:"software_rev"`
	VendorTypes map[string]string      `json:"vendor_types"`
	Kinds       map[string][]Component `json:"kinds"`
	// Packages instantiate a template naming {package} once each.
	Packages   []string      `json:"packages,omitempty"`
	Boards     []Board       `json:"boards"`
	FrontPorts FrontPorts    `json:"front_ports"`
	MgmtPorts  []MgmtPort    `json:"mgmt_ports"`
	Platform   []PlatformRow `json:"platform"`
	Interfaces Interfaces    `json:"interfaces"`
	// LogicalPorts and Subinterfaces follow the physical ports in ifIndex
	// order.
	LogicalPorts  []LogicalPort  `json:"logical_ports,omitempty"`
	Subinterfaces []Subinterface `json:"subinterfaces,omitempty"`
}

// Port is one interface: IF-MIB row and the PORT component ENTITY-MIB maps
// its ifIndex to. Component is empty for a logical interface. MTU empty
// means interfaces.mtu.
type Port struct {
	IfIndex       int
	IfName        string
	Short         string
	IfType        int
	SpeedMbps     int
	Component     string
	MTU           string
	NoPhysAddress bool
	// OperDown is a front port with no optic: admin up, oper down.
	OperDown bool
	// Members is an aggregate's member ifIndexes, in model order.
	Members []int
}

// ifTypeEthernet is IF-MIB ethernetCsmacd(6), every physical port's type;
// ifTypeL2VLAN is l2vlan(135), a dot1q subinterface's.
const (
	ifTypeEthernet = 6
	ifTypeL2VLAN   = 135
	// ifTypeLAG is ieee8023adLag(161), the only type that may name members.
	ifTypeLAG = 161
)

// Chassis is the expanded model every renderer reads. Components are the
// present components; slots are every component in order, absent optics
// of empty bays included, so that entity indices and serials are reserved
// per bay and emptying one renumbers nothing else.
type Chassis struct {
	Model      *Model
	Components []Component
	Ports      []Port
	byName     map[string]int
	slots      []slot
}

// slot is a component position: present indexes Components, an absent
// one keeps the component it reserves numbers for.
type slot struct {
	present int
	absent  *Component
}

func loadModel() (*Model, error) {
	b, err := assets.ReadFile("models/cisco_asr9902.json")
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

var placeholderRe = regexp.MustCompile(`\{[a-z_]+\}`)

// vendorTypeArc is CISCO-ENTITY-VENDORTYPE-OID-MIB's cevMIBObjects.
const vendorTypeArc = "1.3.6.1.4.1.9.12.3.1."

func instantiate(t Component, vars map[string]string) (Component, error) {
	pairs := make([]string, 0, 2*len(vars))
	for k, v := range vars {
		pairs = append(pairs, "{"+k+"}", v)
	}
	r := strings.NewReplacer(pairs...)
	t.Name, t.Parent, t.PartNo, t.Description = r.Replace(t.Name), r.Replace(t.Parent), r.Replace(t.PartNo), r.Replace(t.Description)
	for _, f := range []string{t.Name, t.Parent, t.PartNo, t.Description} {
		if p := placeholderRe.FindString(f); p != "" {
			return t, fmt.Errorf("component %q: placeholder %s has no value", t.Name, p)
		}
	}
	return t, nil
}

func (c *Chassis) add(comp Component) error {
	if _, dup := c.byName[comp.Name]; dup {
		return fmt.Errorf("duplicate component %q", comp.Name)
	}
	if comp.Parent != "" {
		if _, ok := c.byName[comp.Parent]; !ok {
			return fmt.Errorf("component %q: parent %q is not an earlier component", comp.Name, comp.Parent)
		}
	}
	c.byName[comp.Name] = len(c.Components)
	c.slots = append(c.slots, slot{present: len(c.Components)})
	c.Components = append(c.Components, comp)
	return nil
}

// reserve takes a slot for a component an empty bay does not have.
func (c *Chassis) reserve(comp Component) {
	c.slots = append(c.slots, slot{absent: &comp})
}

// namesPackage reports whether a template uses {package} in any field
// instantiate substitutes.
func namesPackage(t Component) bool {
	for _, f := range []string{t.Name, t.Parent, t.PartNo, t.Description} {
		if strings.Contains(f, "{package}") {
			return true
		}
	}
	return false
}

// Component returns the expanded component named name, or nil.
func (c *Chassis) Component(name string) *Component {
	if i, ok := c.byName[name]; ok {
		return &c.Components[i]
	}
	return nil
}

var sensorKinds = []string{"current", "power", "temperature", "voltage", "idprom"}

// expandFrontPorts adds, per position: the port module, the bay, the PORT, the
// transceiver and its sensors, in that order, as XR nests them.
func (c *Chassis) expandFrontPorts(fp FrontPorts) error {
	for n := 0; n < fp.Count; n++ {
		o := fp.SFP
		if slices.Contains(fp.QSFPBays, n) {
			o = fp.QSFP
		}
		s := n / fp.PerSlice
		mod := fmt.Sprintf("%s-Slice %d %s #%d", fp.Card, s, o.ModuleName, n)
		bay := fmt.Sprintf("%s-%s %d", fp.Card, o.BayName, n)
		ifName := fmt.Sprintf("%s%s/0/%d", o.PortPrefix, fp.Card, n)
		port := fp.Card + "-" + ifName
		rows := []Component{
			{Name: mod, Parent: fmt.Sprintf("%s-Slice %d Lightspeed", fp.Card, s), Description: o.ModuleDescr, Tags: o.Tags["module"]},
			{Name: bay, Type: o.BayType, Parent: mod, Description: o.BayDescr, EntClass: "5", Tags: o.Tags["bay"]},
			{Name: port, Type: "PORT", Parent: mod, Description: o.PortDescr, EntClass: "10", Tags: o.Tags["port"]},
		}
		for _, r := range rows {
			if err := c.add(r); err != nil {
				return err
			}
		}
		empty := slices.Contains(fp.EmptyBays, n)
		optic := opticRows(o, ifName, bay)
		if !empty && o.FPD != nil {
			fpd, err := instantiate(*o.FPD, map[string]string{"card": fp.Card, "n": strconv.Itoa(n)})
			if err != nil {
				return err
			}
			optic = append(optic, fpd)
		}
		for _, r := range optic {
			if empty {
				c.reserve(r)
			} else if err := c.add(r); err != nil {
				return err
			}
		}
		c.Ports = append(c.Ports, Port{IfIndex: n + 1, IfName: ifName, Short: o.ShortPrefix + fp.Card + "/0/" + strconv.Itoa(n), IfType: ifTypeEthernet, SpeedMbps: o.SpeedMbps, Component: port, OperDown: empty})
	}
	return nil
}

// opticRows are the transceiver in bay and its sensors.
func opticRows(o Optic, ifName, bay string) []Component {
	rows := []Component{{Name: ifName, Type: "TRANSCEIVER", Parent: bay, PartNo: o.PartNo, Description: o.Description, EntClass: "9", Tags: o.Tags["transceiver"]}}
	for _, k := range []struct{ format, descr string }{
		{"Tx Lane %d Current", "current"}, {"Tx Lane %d Power", "power"}, {"Rx Lane %d Power", "power"},
	} {
		for l := 0; l < o.Lanes; l++ {
			rows = append(rows, Component{Name: ifName + "-" + fmt.Sprintf(k.format, l), Type: "SENSOR", Parent: ifName, Description: o.SensorDescr[k.descr], Tags: o.Tags[k.descr]})
		}
	}
	return append(rows,
		Component{Name: ifName + "-Module Temp", Type: "SENSOR", Parent: ifName, Description: o.SensorDescr["temperature"], Temperature: true, Tags: o.Tags["temperature"]},
		Component{Name: ifName + "-3.3 V", Type: "SENSOR", Parent: ifName, Description: o.SensorDescr["voltage"], Tags: o.Tags["voltage"]},
		Component{Name: ifName + "-IDPROM", Parent: ifName, Description: o.SensorDescr["idprom"], Tags: o.Tags["idprom"]},
	)
}

// expandLogicalPorts appends the logical ports, then the subinterfaces,
// each parented by an earlier port that is not itself a subinterface.
func (c *Chassis) expandLogicalPorts(m *Model) error {
	byName := map[string]Port{}
	for _, p := range c.Ports {
		byName[p.IfName] = p
	}
	add := func(p Port) error {
		if _, dup := byName[p.IfName]; dup {
			return fmt.Errorf("interface %s defined twice", p.IfName)
		}
		p.IfIndex = len(c.Ports) + 1
		byName[p.IfName] = p
		c.Ports = append(c.Ports, p)
		return nil
	}
	for _, lp := range m.LogicalPorts {
		if lp.IfType <= 0 {
			return fmt.Errorf("logical_ports: %s needs a positive if_type", lp.IfName)
		}
		var members []int
		seen := map[string]bool{}
		speed := 0
		if len(lp.BundleMembers) > 0 && lp.IfType != ifTypeLAG {
			return fmt.Errorf("logical_ports: %s has bundle_members but if_type %d is not ieee8023adLag(%d)", lp.IfName, lp.IfType, ifTypeLAG)
		}
		for _, name := range lp.BundleMembers {
			mp, ok := byName[name]
			if !ok || mp.Component == "" || mp.IfType != ifTypeEthernet {
				return fmt.Errorf("logical_ports: %s member %s is not an earlier physical port", lp.IfName, name)
			}
			if seen[name] {
				return fmt.Errorf("logical_ports: %s member %s listed twice", lp.IfName, name)
			}
			seen[name] = true
			members = append(members, mp.IfIndex)
			speed += mp.SpeedMbps
		}
		if len(members) > 0 && speed != lp.SpeedMbps {
			return fmt.Errorf("logical_ports: %s speed_mbps %d is not the sum of its members, %d", lp.IfName, lp.SpeedMbps, speed)
		}
		if err := add(Port{IfName: lp.IfName, Short: lp.Short, IfType: lp.IfType, SpeedMbps: lp.SpeedMbps, MTU: lp.MTU, NoPhysAddress: lp.NoPhysAddress, Members: members}); err != nil {
			return err
		}
	}
	for _, s := range m.Subinterfaces {
		parent, ok := byName[s.Parent]
		if !ok || parent.IfType == ifTypeL2VLAN {
			return fmt.Errorf("subinterfaces: parent %s is not an earlier interface", s.Parent)
		}
		if s.Index <= 0 {
			return fmt.Errorf("subinterfaces: %s index %d must be positive", s.Parent, s.Index)
		}
		ix := "." + strconv.Itoa(s.Index)
		if err := add(Port{IfName: s.Parent + ix, Short: parent.Short + ix, IfType: ifTypeL2VLAN, SpeedMbps: parent.SpeedMbps}); err != nil {
			return err
		}
	}
	return nil
}

// Expand turns the model into components and ports, then validates what the
// renderers rely on. Serials go, in component order, to every component with
// a part number.
func Expand(m *Model) (*Chassis, error) {
	c := &Chassis{Model: m, byName: map[string]int{}}
	if len(m.Packages) > 0 && !slices.ContainsFunc(slices.Collect(maps.Values(m.Kinds)), func(k []Component) bool {
		return slices.ContainsFunc(k, namesPackage)
	}) {
		return nil, fmt.Errorf("packages: no template names {package}")
	}
	ordinal := map[string]int{}
	for _, b := range m.Boards {
		tmpl, ok := m.Kinds[b.Kind]
		if !ok {
			return nil, fmt.Errorf("board %v: unknown kind %q", b.Vars, b.Kind)
		}
		if _, set := b.Vars["n"]; set {
			return nil, fmt.Errorf("board %v: {n} is the board's ordinal among the %s boards, not a var", b.Vars, b.Kind)
		}
		ordinal[b.Kind]++
		bv := maps.Clone(b.Vars)
		if bv == nil {
			bv = map[string]string{}
		}
		bv["n"] = strconv.Itoa(ordinal[b.Kind])
		for _, t := range tmpl {
			vars := []map[string]string{bv}
			if namesPackage(t) && len(m.Packages) > 0 {
				vars = vars[:0]
				for _, p := range m.Packages {
					v := maps.Clone(bv)
					v["package"] = p
					vars = append(vars, v)
				}
			}
			for _, v := range vars {
				comp, err := instantiate(t, v)
				if err != nil {
					return nil, err
				}
				if err := c.add(comp); err != nil {
					return nil, err
				}
			}
		}
	}
	fp := m.FrontPorts
	if fp.Count <= 0 || fp.PerSlice <= 0 {
		return nil, fmt.Errorf("front_ports: count and per_slice must be positive")
	}
	for _, n := range fp.EmptyBays {
		if n < 0 || n >= fp.Count {
			return nil, fmt.Errorf("front_ports: empty bay %d is not a front port", n)
		}
	}
	for _, o := range []Optic{fp.SFP, fp.QSFP} {
		if o.Lanes <= 0 {
			return nil, fmt.Errorf("optic %s: lanes must be positive", o.PartNo)
		}
		for _, k := range sensorKinds {
			if o.SensorDescr[k] == "" {
				return nil, fmt.Errorf("optic %s: sensor_descriptions needs %q", o.PartNo, k)
			}
		}
	}
	if err := c.expandFrontPorts(fp); err != nil {
		return nil, err
	}
	for i, mp := range m.MgmtPorts {
		if c.Component(mp.IfName) == nil {
			return nil, fmt.Errorf("mgmt_ports: %s has no component", mp.IfName)
		}
		c.Ports = append(c.Ports, Port{IfIndex: fp.Count + i + 1, IfName: mp.IfName, Short: mp.Short, IfType: ifTypeEthernet, SpeedMbps: mp.SpeedMbps, Component: mp.IfName})
	}
	if err := c.expandLogicalPorts(m); err != nil {
		return nil, err
	}
	if len(c.Ports) > 255 {
		return nil, fmt.Errorf("%d ports: ifPhysAddress encodes the ifIndex in one byte, at most 255", len(c.Ports))
	}
	used := map[string]bool{}
	serial, entity := 0, 0
	for _, s := range c.slots {
		comp := s.absent
		if comp == nil {
			comp = &c.Components[s.present]
		}
		if comp.PartNo != "" {
			serial++
			if s.absent == nil {
				used[comp.PartNo] = true
				comp.SerialNo = fmt.Sprintf("NL6%08d", serial)
			}
		}
		if comp.EntClass != "" {
			entity++
			comp.entIndex = entity
		}
	}
	for pid, oid := range m.VendorTypes {
		if !used[pid] {
			return nil, fmt.Errorf("vendor_types: %s is not a part number any component uses", pid)
		}
		if !strings.HasPrefix(oid, vendorTypeArc) {
			return nil, fmt.Errorf("vendor_types: %s = %s is outside CISCO-ENTITY-VENDORTYPE-OID-MIB (%s)", pid, oid, vendorTypeArc)
		}
	}
	for _, p := range m.Platform {
		pid, _, _ := strings.Cut(p.Type, "(")
		if !used[pid] {
			return nil, fmt.Errorf("platform: node %s type %s is not a part number any component uses", p.Node, pid)
		}
	}
	return c, nil
}
