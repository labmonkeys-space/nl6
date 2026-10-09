/*
 * Copyright 2026 Ronny Trommer <ronny@no42.org>
 * SPDX-License-Identifier: Apache-2.0
 */

package main

import (
	"errors"
	"fmt"
	"hash/fnv"
	"math"
	"net"
	"strconv"
	"strings"
	"time"
)

// gnmiGenCtx is what a binding sees when a leaf is resolved. keys are
// the concrete key values of the list entry in catalogue key order
// (for example ["xe-0/0/0", "3"]); ifIndex is set when the first key
// source is `interfaces`, else 0; t is seconds since device start.
type gnmiGenCtx struct {
	dev     *DeviceSimulator
	cat     *gnmiCatalog
	keys    []string
	ifIndex int
	t       float64
	now     time.Time
}

type gnmiLeafGen func(ctx *gnmiGenCtx) (any, bool)

type gnmiGenFactory func(arg string) (gnmiLeafGen, error)

// gnmiGenRegistry maps binding prefixes to factories. Unknown prefixes
// fail catalogue load (Task 1 validate), never serve time.
var gnmiGenRegistry = map[string]gnmiGenFactory{
	"const":     genConst,
	"key":       genKey,
	"ifcounter": genIfCounter,
	"ifstate":   genIfState,
	"sine":      genSine,
	"counter":   genCounter,
	"inventory": genInventory,
	"neighbor":  genNeighbor,
	"timestamp": genTimestamp,
}

func compileGnmiBinding(spec string) (gnmiLeafGen, error) {
	if spec == "" {
		return nil, errors.New("empty binding")
	}
	prefix, arg, _ := strings.Cut(spec, ":")
	f, ok := gnmiGenRegistry[prefix]
	if !ok {
		return nil, fmt.Errorf("unknown binding prefix %q", prefix)
	}
	g, err := f(arg)
	if err != nil {
		return nil, fmt.Errorf("binding %q: %w", spec, err)
	}
	return g, nil
}

func genConst(arg string) (gnmiLeafGen, error) {
	return func(*gnmiGenCtx) (any, bool) { return arg, true }, nil
}

func genKey(arg string) (gnmiLeafGen, error) {
	n, err := strconv.Atoi(arg)
	if err != nil || n < 0 {
		return nil, fmt.Errorf("key index %q", arg)
	}
	return func(ctx *gnmiGenCtx) (any, bool) {
		if n >= len(ctx.keys) {
			return nil, false
		}
		return ctx.keys[n], true
	}, nil
}

// ifCounterColumns maps IF-MIB column names to the OID prefix and
// column the counter cycler keys on, so gNMI, SNMP and sFlow agree.
var ifCounterColumns = map[string]struct {
	prefix string
	column int
}{
	"ifHCInOctets":         {ifXTablePrefix, colIfHCInOctets},
	"ifHCOutOctets":        {ifXTablePrefix, colIfHCOutOctets},
	"ifHCInUcastPkts":      {ifXTablePrefix, colIfHCInUcastPkts},
	"ifHCInMulticastPkts":  {ifXTablePrefix, colIfHCInMulticastPkts},
	"ifHCInBroadcastPkts":  {ifXTablePrefix, colIfHCInBroadcastPkts},
	"ifHCOutUcastPkts":     {ifXTablePrefix, colIfHCOutUcastPkts},
	"ifHCOutMulticastPkts": {ifXTablePrefix, colIfHCOutMulticastPkts},
	"ifHCOutBroadcastPkts": {ifXTablePrefix, colIfHCOutBroadcastPkts},
	"ifInDiscards":         {ifTablePrefix, colIfInDiscards},
	"ifInErrors":           {ifTablePrefix, colIfInErrors},
	"ifOutDiscards":        {ifTablePrefix, colIfOutDiscards},
	"ifOutErrors":          {ifTablePrefix, colIfOutErrors},
}

func genIfCounter(arg string) (gnmiLeafGen, error) {
	col, ok := ifCounterColumns[arg]
	if !ok {
		return nil, fmt.Errorf("unknown IF-MIB column %q", arg)
	}
	return func(ctx *gnmiGenCtx) (any, bool) {
		if ctx.dev == nil || ctx.dev.metricsCycler == nil || ctx.ifIndex == 0 {
			return nil, false
		}
		ic := ctx.dev.metricsCycler.ifCounters.Load()
		if ic == nil {
			return nil, false
		}
		oid := col.prefix + strconv.Itoa(col.column) + "." + strconv.Itoa(ctx.ifIndex)
		return ic.GetDynamicAt(oid, ctx.t), true
	}, nil
}

func genIfState(arg string) (gnmiLeafGen, error) {
	switch arg {
	case "name", "ifindex", "oper", "admin", "last-change":
	default:
		return nil, fmt.Errorf("unknown interface state field %q", arg)
	}
	return func(ctx *gnmiGenCtx) (any, bool) {
		if ctx.ifIndex == 0 {
			return nil, false
		}
		switch arg {
		case "name":
			if n := lookupIfDescr(ctx.dev, ctx.ifIndex); n != "" {
				return n, true
			}
			return synthIfName(ctx.ifIndex), true
		case "ifindex":
			return uint64(ctx.ifIndex), true
		}
		if ctx.dev == nil || ctx.dev.metricsCycler == nil {
			return nil, false
		}
		ic := ctx.dev.metricsCycler.ifCounters.Load()
		if ic == nil || ic.State() == nil {
			return nil, false
		}
		st := ic.State()
		switch arg {
		case "oper":
			return bareGnmiIdentity(operStatusOpenConfig(st.OperStatus(ctx.ifIndex))), true
		case "admin":
			return bareGnmiIdentity(adminStatusOpenConfig(st.AdminStatus(ctx.ifIndex))), true
		default:
			return st.LastChangeNs(ctx.ifIndex), true
		}
	}, nil
}

// bareGnmiIdentity drops any module prefix. Catalogue devices emit the
// bare identity like the Junos capture; the legacy resolver keeps its prefixed form.
func bareGnmiIdentity(s string) string {
	return s[strings.LastIndexByte(s, ':')+1:]
}

// gnmiSeed hashes the device IP and a per-entry key into a phase so a
// fleet does not oscillate in lockstep while each device stays
// deterministic across reads.
func gnmiSeed(ip net.IP, key string) uint64 {
	h := fnv.New64a()
	h.Write([]byte(ip.String()))
	h.Write([]byte{0})
	h.Write([]byte(key))
	return h.Sum64()
}

func genSine(arg string) (gnmiLeafGen, error) {
	parts := strings.Split(arg, ",")
	if len(parts) != 3 {
		return nil, fmt.Errorf("sine wants base,amplitude,period_s, got %q", arg)
	}
	var f [3]float64
	for i, p := range parts {
		v, err := strconv.ParseFloat(strings.TrimSpace(p), 64)
		if err != nil {
			return nil, fmt.Errorf("sine argument %q: %w", p, err)
		}
		f[i] = v
	}
	if f[2] <= 0 {
		return nil, fmt.Errorf("sine period must be > 0, got %v", f[2])
	}
	base, amp, period := f[0], f[1], f[2]
	return func(ctx *gnmiGenCtx) (any, bool) {
		var ip net.IP
		if ctx.dev != nil {
			ip = ctx.dev.IP
		}
		phase := float64(gnmiSeed(ip, strings.Join(ctx.keys, "/"))%1000) / 1000
		return base + amp*math.Sin(2*math.Pi*(ctx.t/period+phase)), true
	}, nil
}

func genCounter(arg string) (gnmiLeafGen, error) {
	rate, err := strconv.ParseFloat(arg, 64)
	if err != nil || rate < 0 {
		return nil, fmt.Errorf("counter rate %q", arg)
	}
	return func(ctx *gnmiGenCtx) (any, bool) {
		var ip net.IP
		if ctx.dev != nil {
			ip = ctx.dev.IP
		}
		jitter := 0.9 + float64(gnmiSeed(ip, strings.Join(ctx.keys, "/"))%200)/1000 // 0.9 .. 1.1
		return uint64(rate * ctx.t * jitter), true
	}, nil
}

func genInventory(arg string) (gnmiLeafGen, error) {
	switch arg {
	case "name", "type", "parent", "part_no", "description", "serial_no":
	default:
		return nil, fmt.Errorf("unknown inventory field %q", arg)
	}
	return func(ctx *gnmiGenCtx) (any, bool) {
		if ctx.cat == nil || len(ctx.keys) == 0 {
			return nil, false
		}
		for _, c := range ctx.cat.Components {
			if c.Name != ctx.keys[0] {
				continue
			}
			switch arg {
			case "name":
				return c.Name, true
			case "type":
				return c.Type, true
			case "parent":
				return c.Parent, true
			case "part_no":
				return c.PartNo, true
			case "description":
				return c.Description, true
			default:
				return c.SerialNo, true
			}
		}
		return nil, false
	}, nil
}

func genNeighbor(arg string) (gnmiLeafGen, error) {
	switch arg {
	case "address", "peer_as", "local_as", "state":
	default:
		return nil, fmt.Errorf("unknown neighbor field %q", arg)
	}
	return func(ctx *gnmiGenCtx) (any, bool) {
		if ctx.cat == nil || len(ctx.keys) == 0 {
			return nil, false
		}
		for _, n := range ctx.cat.Neighbors {
			if n.Address != ctx.keys[0] {
				continue
			}
			switch arg {
			case "address":
				return n.Address, true
			case "peer_as":
				return uint64(n.PeerAS), true
			case "local_as":
				return uint64(n.LocalAS), true
			default:
				return n.State, true
			}
		}
		return nil, false
	}, nil
}

func genTimestamp(arg string) (gnmiLeafGen, error) {
	switch arg {
	case "now":
		return func(ctx *gnmiGenCtx) (any, bool) { return uint64(ctx.now.UnixNano()), true }, nil
	case "boot":
		return func(ctx *gnmiGenCtx) (any, bool) {
			return uint64(ctx.now.Add(-time.Duration(ctx.t * float64(time.Second))).UnixNano()), true
		}, nil
	}
	return nil, fmt.Errorf("timestamp wants now or boot, got %q", arg)
}

// castGnmiLeaf converts a binding's result to the Go type the encoder
// expects for the leaf's YANG type.
func castGnmiLeaf(v any, yangType string) (any, error) {
	toF := func() (float64, bool) {
		switch x := v.(type) {
		case float64:
			return x, true
		case uint64:
			return float64(x), true
		case int64:
			return float64(x), true
		case string:
			f, err := strconv.ParseFloat(x, 64)
			return f, err == nil
		}
		return 0, false
	}
	switch yangType {
	case "uint64", "uint32", "uint16", "uint8", "counter64", "counter32":
		if s, ok := v.(string); ok {
			u, err := strconv.ParseUint(s, 10, 64)
			if err != nil {
				return nil, fmt.Errorf("%q is not a uint64", s)
			}
			if yangType == "uint32" || yangType == "uint16" || yangType == "uint8" || yangType == "counter32" {
				return uint32(u), nil
			}
			return u, nil
		}
		f, ok := toF()
		if !ok || f < 0 {
			return nil, fmt.Errorf("%v (%T) is not a %s", v, v, yangType)
		}
		if yangType == "uint32" || yangType == "uint16" || yangType == "uint8" || yangType == "counter32" {
			return uint32(f), nil
		}
		return uint64(f), nil
	case "int64", "int32", "int16", "int8":
		f, ok := toF()
		if !ok {
			return nil, fmt.Errorf("%v (%T) is not an %s", v, v, yangType)
		}
		return int64(f), nil
	case "decimal64":
		f, ok := toF()
		if !ok {
			return nil, fmt.Errorf("%v (%T) is not a decimal64", v, v)
		}
		return gnmiDecimal{val: f, digits: 2}, nil
	case "boolean":
		switch x := v.(type) {
		case bool:
			return x, nil
		case string:
			if b, err := strconv.ParseBool(x); err == nil {
				return b, nil
			}
		}
		return nil, fmt.Errorf("%v (%T) is not a boolean", v, v)
	case "string", "enumeration", "identityref", "leafref", "union":
		switch x := v.(type) {
		case string:
			return x, nil
		case uint64:
			return strconv.FormatUint(x, 10), nil
		case int64:
			return strconv.FormatInt(x, 10), nil
		case float64:
			return strconv.FormatFloat(x, 'f', -1, 64), nil
		case bool:
			return strconv.FormatBool(x), nil
		}
		return nil, fmt.Errorf("%v (%T) is not a string", v, v)
	}
	return nil, fmt.Errorf("unknown YANG type %q", yangType)
}
