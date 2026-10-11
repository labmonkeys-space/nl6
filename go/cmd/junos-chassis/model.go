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
	"strconv"
)

//go:embed models/juniper_mx10004.json templates
var assets embed.FS

// Component is one gNMI inventory row, in gnmi-bindings.json's field order.
// The three optic fields are written only when set.
type Component struct {
	Name        string `json:"name"`
	Type        string `json:"type"`
	Parent      string `json:"parent"`
	PartNo      string `json:"part_no"`
	Description string `json:"description"`
	SerialNo    string `json:"serial_no"`
	Temperature bool   `json:"temperature"`
	FormFactor  string `json:"form_factor,omitempty"`
	EthernetPMD string `json:"ethernet_pmd,omitempty"`
	Wavelength  string `json:"wavelength,omitempty"`
}

type Part struct {
	PartNo      string `json:"part_no"`
	Description string `json:"description"`
}

// Optic is the transceiver a card type ships in every port. FormFactor and
// EthernetPMD are left empty until the catalogue reads them (Task 9); while
// they are empty no optic field is written onto components.
type Optic struct {
	PartNo      string `json:"part_no"`
	Description string `json:"description"`
	FormFactor  string `json:"form_factor,omitempty"`
	EthernetPMD string `json:"ethernet_pmd,omitempty"`
	Wavelength  string `json:"wavelength"`
	Cable       string `json:"cable"`
	Fiber       string `json:"fiber"`
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
}

type Interfaces struct {
	MTU         string `json:"mtu"`
	IfSpeed     string `json:"if_speed"`
	MACPrefix   string `json:"mac_prefix"`
	AliasFormat string `json:"alias_format"`
	HCPeriod    int    `json:"hc_period"`
	HCInBase    uint64 `json:"hc_in_base"`
	HCInStep    uint64 `json:"hc_in_step"`
	HCOutBase   uint64 `json:"hc_out_base"`
	HCOutStep   uint64 `json:"hc_out_step"`
}

type SNMPRow struct {
	OID      string `json:"oid"`
	Response string `json:"response"`
}

// Model is the chassis description. Head and Tail are literal component
// rows around the line cards; FPCs expand from CardTypes.
type Model struct {
	Comment        string              `json:"comment"`
	Head           []Component         `json:"head"`
	FPCSlots       int                 `json:"fpc_slots"`
	FPCs           []FPCSlot           `json:"fpcs"`
	Tail           []Component         `json:"tail"`
	CardTypes      map[string]CardType `json:"card_types"`
	CPUCount       int                 `json:"cpu_count"`
	RoutingEngines []RoutingEngine     `json:"routing_engines"`
	Interfaces     Interfaces          `json:"interfaces"`
	ChassisEntity  []SNMPRow           `json:"chassis_entity"`
}

type Port struct {
	Index     int // port number on its PIC
	IfIndex   int
	IfName    string
	SpeedMbps int
	Port      Component
	Xcvr      Component
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
	Ports      []Port // every port, in ifIndex order
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
				port := Port{Index: n, IfIndex: ifIndex, IfName: fmt.Sprintf("%s-%d/%d/%d", card.PortPrefix, s.Slot, p, n), SpeedMbps: card.SpeedMbps}
				port.Port = Component{Name: pn, Type: "PORT", Parent: f.PICs[p].Component.Name, PartNo: card.PIC.PartNo,
					Description: port.IfName, SerialNo: fmt.Sprintf("NL6PRT%06d", ifIndex)}
				port.Xcvr = Component{Name: pn + ":Xcvr0", Type: "TRANSCEIVER", Parent: pn, PartNo: card.Optic.PartNo,
					Description: card.Optic.Description, SerialNo: fmt.Sprintf("NL6XCV%02d%02d%02d", s.Slot, p, n)}
				if card.Optic.FormFactor != "" {
					port.Port.Wavelength = card.Optic.Wavelength
					port.Xcvr.FormFactor = card.Optic.FormFactor
					port.Xcvr.EthernetPMD = card.Optic.EthernetPMD
				}
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
