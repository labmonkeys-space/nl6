package main

import (
	"encoding/json"
	"fmt"
	"path/filepath"
	"strconv"
	"sync"

	"github.com/labmonkeys-space/nl6/go/nl6/resources/altiplano"
	gnmipb "github.com/openconfig/gnmi/proto/gnmi"
	"github.com/openconfig/ygot/ygot"
	"github.com/openconfig/ygot/ytypes"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

func (d *DeviceSimulator) initAltiplanoData() {
	if filepath.Base(d.resourceFile) != "altiplano.json" {
		return
	}

	d.AltiplanoMu.Lock()
	defer d.AltiplanoMu.Unlock()

	d.AltiplanoData = &altiplano.Device{}
	d.AltiplanoData.Interfaces = &altiplano.OpenconfigInterfaces_Interfaces{}

	// Create 4 standard interfaces
	for i := 1; i <= 4; i++ {
		name := fmt.Sprintf("eth%d", i)
		if d.resources != nil && d.resources.oidIndex != nil {
			d.resources.oidIndex.Store(fmt.Sprintf(".1.3.6.1.2.1.31.1.1.1.6.%d", i), "0")
		}
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

var (
	altiplanoSchema     *ytypes.Schema
	altiplanoSchemaErr  error
	altiplanoSchemaOnce sync.Once
)

func getAltiplanoSchema() (*ytypes.Schema, error) {
	altiplanoSchemaOnce.Do(func() {
		altiplanoSchema, altiplanoSchemaErr = altiplano.Schema()
	})
	return altiplanoSchema, altiplanoSchemaErr
}

func (r *pathResolver) resolveAltiplano(p *gnmipb.Path) ([]resolvedUpdate, error) {
	// Use ytypes.GetNode to evaluate the path against the ygot GoStruct
	// ytypes.GetNode takes a go struct, its schema, and a gNMI Path.

	schema, err := getAltiplanoSchema()
	if err != nil {
		return nil, status.Errorf(codes.Internal, "failed to load schema: %v", err)
	}

	// Update Altiplano interface counters from the traffic simulator engine
	if r.device.metricsCycler != nil && r.device.metricsCycler.ifCounters.Load() != nil {
		ic := r.device.metricsCycler.ifCounters.Load()
		r.device.AltiplanoMu.Lock()
		for i := 1; i <= 4; i++ {
			name := fmt.Sprintf("eth%d", i)
			if iface, ok := r.device.AltiplanoData.Interfaces.Interface[name]; ok && iface.State != nil && iface.State.Counters != nil {
				if val := ic.GetDynamic(fmt.Sprintf(".1.3.6.1.2.1.31.1.1.1.6.%d", i)); val != "" {
					if v, err := strconv.ParseUint(val, 10, 64); err == nil {
						iface.State.Counters.InOctets = ygot.Uint64(v)
					}
				}
				if val := ic.GetDynamic(fmt.Sprintf(".1.3.6.1.2.1.31.1.1.1.10.%d", i)); val != "" {
					if v, err := strconv.ParseUint(val, 10, 64); err == nil {
						iface.State.Counters.OutOctets = ygot.Uint64(v)
					}
				}
				if val := ic.GetDynamic(fmt.Sprintf(".1.3.6.1.2.1.2.2.1.11.%d", i)); val != "" { // ifInUcastPkts
					if v, err := strconv.ParseUint(val, 10, 64); err == nil {
						iface.State.Counters.InUnicastPkts = ygot.Uint64(v)
					}
				}
				if val := ic.GetDynamic(fmt.Sprintf(".1.3.6.1.2.1.2.2.1.17.%d", i)); val != "" { // ifOutUcastPkts
					if v, err := strconv.ParseUint(val, 10, 64); err == nil {
						iface.State.Counters.OutUnicastPkts = ygot.Uint64(v)
					}
				}
			}
		}
		r.device.AltiplanoMu.Unlock()
	}

	r.device.AltiplanoMu.RLock()
	nodes, err := ytypes.GetNode(schema.RootSchema(), r.device.AltiplanoData, p)
	r.device.AltiplanoMu.RUnlock()
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
			var v interface{} = node.Data
			switch ptr := v.(type) {
			case *string:
				v = *ptr
			case *uint64:
				v = strconv.FormatUint(*ptr, 10)
			case *uint32:
				v = *ptr
			case *int32:
				v = *ptr
			case *int64:
				v = strconv.FormatInt(*ptr, 10)
			case *bool:
				v = *ptr
			}
			b, err := json.Marshal(v)
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
