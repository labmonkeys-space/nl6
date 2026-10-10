/*
 * Copyright 2026 Ronny Trommer <ronny@no42.org>
 * SPDX-License-Identifier: Apache-2.0
 */

package main

import (
	"errors"
	"fmt"

	"github.com/openconfig/gnmi/proto/gnmi_ext"
	"google.golang.org/protobuf/encoding/protowire"
)

// juniperHeader is the subset of Juniper's
// GnmiJuniperTelemetryHeaderExtension that nl6 fills. Field numbers
// follow the upstream proto (Juniper/telemetry, Apache-2.0); it is
// hand-encoded with protowire so the repo needs no protoc step.
type juniperHeader struct {
	SystemID        string // 1
	ComponentID     uint32 // 2
	SensorName      string // 4
	SubscribedPath  string // 5
	StreamedPath    string // 6
	Component       string // 7
	SequenceNumber  uint64 // 8
	ExportTimestamp int64  // 12
}

const juniperHeaderExtensionID = gnmi_ext.ExtensionID(1) // EID_JUNIPER_TELEMETRY_HEADER

func (h juniperHeader) marshal() []byte {
	var b []byte
	str := func(num protowire.Number, s string) {
		if s == "" {
			return
		}
		b = protowire.AppendTag(b, num, protowire.BytesType)
		b = protowire.AppendString(b, s)
	}
	str(1, h.SystemID)
	if h.ComponentID != 0 {
		b = protowire.AppendTag(b, 2, protowire.VarintType)
		b = protowire.AppendVarint(b, uint64(h.ComponentID))
	}
	str(4, h.SensorName)
	str(5, h.SubscribedPath)
	str(6, h.StreamedPath)
	str(7, h.Component)
	if h.SequenceNumber != 0 {
		b = protowire.AppendTag(b, 8, protowire.VarintType)
		b = protowire.AppendVarint(b, h.SequenceNumber)
	}
	if h.ExportTimestamp != 0 {
		b = protowire.AppendTag(b, 12, protowire.VarintType)
		b = protowire.AppendVarint(b, uint64(h.ExportTimestamp))
	}
	return b
}

func juniperHeaderExtension(h juniperHeader) *gnmi_ext.Extension {
	return &gnmi_ext.Extension{Ext: &gnmi_ext.Extension_RegisteredExt{
		RegisteredExt: &gnmi_ext.RegisteredExtension{Id: juniperHeaderExtensionID, Msg: h.marshal()},
	}}
}

// decodeJuniperHeader parses the fields nl6 writes; unknown fields are
// skipped. Used by tests and by the shape fixture check.
func decodeJuniperHeader(b []byte) (juniperHeader, error) {
	var h juniperHeader
	for len(b) > 0 {
		num, typ, n := protowire.ConsumeTag(b)
		if n < 0 {
			return h, fmt.Errorf("juniper header: bad tag: %w", protowire.ParseError(n))
		}
		b = b[n:]
		switch typ {
		case protowire.BytesType:
			s, n := protowire.ConsumeString(b)
			if n < 0 {
				return h, errors.New("juniper header: bad string")
			}
			b = b[n:]
			switch num {
			case 1:
				h.SystemID = s
			case 4:
				h.SensorName = s
			case 5:
				h.SubscribedPath = s
			case 6:
				h.StreamedPath = s
			case 7:
				h.Component = s
			}
		case protowire.VarintType:
			v, n := protowire.ConsumeVarint(b)
			if n < 0 {
				return h, errors.New("juniper header: bad varint")
			}
			b = b[n:]
			switch num {
			case 2:
				h.ComponentID = uint32(v)
			case 8:
				h.SequenceNumber = v
			case 12:
				h.ExportTimestamp = int64(v)
			}
		default:
			n := protowire.ConsumeFieldValue(num, typ, b)
			if n < 0 {
				return h, errors.New("juniper header: bad field")
			}
			b = b[n:]
		}
	}
	return h, nil
}
