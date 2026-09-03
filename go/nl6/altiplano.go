package main

import (
	"encoding/json"
	"strings"

	"github.com/labmonkeys-space/nl6/go/nl6/resources/altiplano"
	gnmipb "github.com/openconfig/gnmi/proto/gnmi"
	"github.com/openconfig/ygot/ygot"
	"github.com/openconfig/ygot/ytypes"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

func (d *DeviceSimulator) initAltiplanoData() {
	if !strings.Contains(d.resourceFile, "altiplano") {
		return
	}

	d.AltiplanoData = &altiplano.Device{}
	d.AltiplanoData.Interfaces = &altiplano.OpenconfigInterfaces_Interfaces{}
	
	// Create 4 standard interfaces
	for i := 1; i <= 4; i++ {
		name := "eth" + string(rune(i+'0'))
		iface, err := d.AltiplanoData.Interfaces.NewInterface(name)
		if err == nil {
			iface.State = &altiplano.OpenconfigInterfaces_Interfaces_Interface_State{
				Name:        ygot.String(name),
				Type:        ygot.String("ethernetCsmacd"),
				AdminStatus: ygot.String("UP"),
				OperStatus:  ygot.String("UP"),
				Counters: &altiplano.OpenconfigInterfaces_Interfaces_Interface_State_Counters{
					InOctets:       ygot.Uint64(0),
					InUnicastPkts:  ygot.Uint64(0),
					OutOctets:      ygot.Uint64(0),
					OutUnicastPkts: ygot.Uint64(0),
				},
			}
		}
	}

	d.AltiplanoData.AccessNode = &altiplano.BbfTr_413_AccessNode{
		State: &altiplano.BbfTr_413_AccessNode_State{
			SoftwareVersion: ygot.String("22.12.R1"),
			Uptime:          ygot.Uint64(1000),
		},
	}
}

func (r *pathResolver) resolveAltiplano(p *gnmipb.Path) ([]resolvedUpdate, error) {
	// Use ytypes.GetNode to evaluate the path against the ygot GoStruct
	// ytypes.GetNode takes a go struct, its schema, and a gNMI Path.
	
	schema, err := altiplano.Schema()
	if err != nil {
		return nil, status.Errorf(codes.Internal, "failed to load schema: %v", err)
	}
	
	nodes, err := ytypes.GetNode(schema.RootSchema(), r.device.AltiplanoData, p)
	if err != nil {
		return nil, status.Errorf(codes.NotFound, "path not found in Altiplano schema: %v", err)
	}
	
	if len(nodes) == 0 {
		return nil, status.Errorf(codes.NotFound, "path %q not found", pathToString(p))
	}
	
	var updates []resolvedUpdate
	
	for _, node := range nodes {
		// node.Data is the actual ygot node (a GoStruct or leaf scalar)
		if goStruct, ok := node.Data.(ygot.GoStruct); ok {
			jsonStr, err := ygot.EmitJSON(goStruct, &ygot.EmitJSONConfig{
				Format: ygot.RFC7951,
				Indent: "  ",
				RFC7951Config: &ygot.RFC7951JSONConfig{
					AppendModuleName: true,
				},
			})
			if err != nil {
				return nil, status.Errorf(codes.Internal, "failed to serialize altiplano data: %v", err)
			}
			updates = append(updates, resolvedUpdate{
				Path:  node.Path, // use the exact path matching this node
				Value: json.RawMessage(jsonStr),
			})
		} else {
			// Leaf node (scalar)
			// Wait, ygot nodes can be scalar types like *string, *uint64 etc.
			// Let's dereference if it's a pointer.
			// reflection or type switch can deref.
			// Actually, gnmiEncodeTypedValue only supports string, uint32, uint64, gnmiDecimal, json.RawMessage.
			// We can just encode leaf nodes as JSON via EmitJSON if it's a GoStruct, or use json.Marshal
			b, err := json.Marshal(node.Data)
			if err != nil {
				return nil, status.Errorf(codes.Internal, "failed to serialize leaf data: %v", err)
			}
			updates = append(updates, resolvedUpdate{
				Path:  node.Path,
				Value: json.RawMessage(b),
			})
		}
	}
	
	return updates, nil
}
