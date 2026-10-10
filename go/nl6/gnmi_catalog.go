/*
 * Copyright 2026 Ronny Trommer <ronny@no42.org>
 * SPDX-License-Identifier: Apache-2.0
 */

package main

import (
	"bytes"
	"embed"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"log"
	"os"
	"path/filepath"
	"slices"
	"sort"
	"strings"

	gnmipb "github.com/openconfig/gnmi/proto/gnmi"
)

// Per-type gNMI catalogues ship as resources/<slug>/gnmi.json. The
// pattern mirrors the trap catalogue: embedded by default, a file in
// the resource directory replaces the embedded one for that type, and
// -gnmi-catalog replaces every type's catalogue with one file.
//
//go:embed resources/*/gnmi.json
var embeddedGnmiCatalogFS embed.FS

const gnmiCatalogFileName = "gnmi.json"

const (
	gnmiPrefixListEntry = "list-entry"
	gnmiPrefixFlat      = "flat"

	gnmiExtensionNone          = "none"
	gnmiExtensionJuniperHeader = "juniper-header"

	gnmiKeySourceInterfaces = "interfaces"
	gnmiKeySourceComponents = "components"
	gnmiKeySourceNeighbors  = "neighbors"
	gnmiKeySourceStatic     = "static"

	gnmiDecimalDouble = "double"
	gnmiDecimalVal    = "decimal_val"
)

type gnmiCatalog struct {
	Comment      string                  `json:"comment"`
	Vendor       string                  `json:"vendor"`
	Notification gnmiCatalogNotification `json:"notification"`
	Models       []gnmiCatalogModel      `json:"models"`
	Components   []gnmiCatalogComponent  `json:"components"`
	Neighbors    []gnmiCatalogNeighbor   `json:"neighbors"`
	Subtrees     []*gnmiCatalogSubtree   `json:"subtrees"`

	encodings map[gnmipb.Encoding]bool
}

type gnmiCatalogNotification struct {
	Origin       string   `json:"origin"`
	NativeOrigin string   `json:"native_origin"`
	Prefix       string   `json:"prefix"`
	Encodings    []string `json:"encodings"`
	Extension    string   `json:"extension"`
	// OriginAliases maps a request origin an operator types (a YANG
	// module name such as `openconfig-interfaces`, or Junos's `Native`)
	// to Origin or NativeOrigin. Responses carry the canonical origin,
	// as hardware does (nl6#770). Declared per catalogue so a type
	// without aliases keeps refusing unknown origins.
	OriginAliases map[string]string `json:"origin_aliases,omitempty"`
	// DecimalEncoding is the PROTO wire form of decimal64 leaves:
	// "double" (default, double_val) or "decimal_val" (gNMI Decimal64,
	// what Junos sends). Catalogue-local by decision (nl6#772).
	DecimalEncoding string `json:"decimal_encoding,omitempty"`
}

type gnmiCatalogModel struct {
	Name         string `json:"name"`
	Organization string `json:"organization"`
	Version      string `json:"version"`
}

type gnmiCatalogComponent struct {
	Name        string `json:"name"`
	Type        string `json:"type"`
	Parent      string `json:"parent"`
	PartNo      string `json:"part_no"`
	Description string `json:"description"`
	SerialNo    string `json:"serial_no"`
	Temperature bool   `json:"temperature"`
}

type gnmiCatalogNeighbor struct {
	Address string `json:"address"`
	PeerAS  uint32 `json:"peer_as"`
	LocalAS uint32 `json:"local_as"`
	State   string `json:"state"`
}

type gnmiCatalogKey struct {
	Source string   `json:"source"`
	Filter string   `json:"filter,omitempty"`
	Names  []string `json:"names,omitempty"`
}

// gnmiCatalogSubtree is one list entry: `path` is the entry path that
// becomes the notification prefix under `prefix: list-entry`; leaves
// are relative to it. `aliases` are subscription paths, such as a Junos
// native sensor path, that request the whole subtree.
type gnmiCatalogSubtree struct {
	Path    string             `json:"path"`
	Origin  string             `json:"origin"`
	Aliases []string           `json:"aliases,omitempty"`
	Keys    []gnmiCatalogKey   `json:"keys"`
	Leaves  []*gnmiCatalogLeaf `json:"leaves"`

	elems   []*gnmipb.PathElem   // compiled from Path; wildcard keys hold "*"
	aliases [][]*gnmipb.PathElem // compiled from Aliases
	// componentKey and neighborKey are the positions of the first
	// components and neighbors key sources in Keys, or -1. inventory and
	// neighbor bindings read the entry key at that position.
	componentKey int
	neighborKey  int
}

// gnmiCatalogLeaf is one served leaf. `filter` narrows the leaf to the
// components matching it (same vocabulary as the `components` key
// source), so one subtree can serve every component and carry a sensor
// leaf on only the components that have the sensor. Splitting the leaf
// into a second subtree on the same entry path instead renders that
// entry twice (nl6#765), which parseGnmiCatalog refuses.
type gnmiCatalogLeaf struct {
	Name   string   `json:"name"`
	Type   string   `json:"type"`
	Enum   []string `json:"enum,omitempty"`
	Gen    string   `json:"gen"`
	Filter string   `json:"filter,omitempty"`
	Digits int      `json:"digits,omitempty"` // decimal64 fraction-digits from YANG; 0 = 2

	elems       []*gnmipb.PathElem // compiled from Name
	gen         gnmiLeafGen        // compiled from Gen
	filterNames map[string]bool    // component names matching Filter; nil when unfiltered
}

var gnmiEncodingNames = map[string]gnmipb.Encoding{
	"PROTO":     gnmipb.Encoding_PROTO,
	"JSON":      gnmipb.Encoding_JSON,
	"JSON_IETF": gnmipb.Encoding_JSON_IETF,
}

func parseGnmiCatalog(data []byte, source string) (*gnmiCatalog, error) {
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	var c gnmiCatalog
	if err := dec.Decode(&c); err != nil {
		return nil, fmt.Errorf("gnmi catalog %s: %w", source, err)
	}
	if err := c.validate(source); err != nil {
		return nil, err
	}
	return &c, nil
}

func (c *gnmiCatalog) validate(source string) error {
	fail := func(format string, args ...any) error {
		return fmt.Errorf("gnmi catalog %s: "+format, append([]any{source}, args...)...)
	}
	if c.Vendor == "" {
		return fail("vendor is required")
	}
	n := c.Notification
	if n.Prefix != gnmiPrefixListEntry && n.Prefix != gnmiPrefixFlat {
		return fail("notification.prefix %q: want %q or %q", n.Prefix, gnmiPrefixListEntry, gnmiPrefixFlat)
	}
	if n.Extension != gnmiExtensionNone && n.Extension != gnmiExtensionJuniperHeader {
		return fail("notification.extension %q unknown", n.Extension)
	}
	if n.Origin == "" {
		return fail("notification.origin is required")
	}
	switch n.DecimalEncoding {
	case "", gnmiDecimalDouble, gnmiDecimalVal:
	default:
		return fail("notification.decimal_encoding %q: want %q or %q", n.DecimalEncoding, gnmiDecimalDouble, gnmiDecimalVal)
	}
	aliases := make([]string, 0, len(n.OriginAliases))
	for alias := range n.OriginAliases {
		aliases = append(aliases, alias)
	}
	sort.Strings(aliases) // the first bad alias reported is the same on every run
	for _, alias := range aliases {
		target := n.OriginAliases[alias]
		if alias == "" || alias == n.Origin || alias == n.NativeOrigin {
			return fail("notification.origin_aliases: %q is a canonical origin, not an alias", alias)
		}
		canonical := []string{n.Origin}
		if n.NativeOrigin != "" {
			canonical = append(canonical, n.NativeOrigin)
		}
		if !slices.Contains(canonical, target) {
			return fail("notification.origin_aliases: %q maps to %q, want one of %q", alias, target, canonical)
		}
	}
	if len(n.Encodings) == 0 {
		return fail("notification.encodings is empty")
	}
	c.encodings = map[gnmipb.Encoding]bool{}
	for _, e := range n.Encodings {
		enc, ok := gnmiEncodingNames[e]
		if !ok {
			return fail("notification.encodings: unknown encoding %q", e)
		}
		c.encodings[enc] = true
	}
	names := map[string]bool{}
	for _, comp := range c.Components {
		if comp.Name == "" || names[comp.Name] {
			return fail("components: empty or duplicate name %q", comp.Name)
		}
		names[comp.Name] = true
	}
	for i, st := range c.Subtrees {
		if st.Origin == "" {
			return fail("subtree %d (%s): origin is required", i, st.Path)
		}
		if st.Origin != n.Origin && st.Origin != n.NativeOrigin {
			return fail("subtree %d (%s): origin %q is neither %q nor %q", i, st.Path, st.Origin, n.Origin, n.NativeOrigin)
		}
		elems, err := parseCatalogPath(st.Path)
		if err != nil {
			return fail("subtree %d: %v", i, err)
		}
		st.elems = elems
		st.aliases = nil
		for _, a := range st.Aliases {
			ae, err := parseCatalogPath(a)
			if err != nil {
				return fail("subtree %d (%s): alias %q: %v", i, st.Path, a, err)
			}
			for _, e := range ae {
				for _, v := range e.Key {
					if v == "*" {
						return fail("subtree %d (%s): alias %q has a wildcard key", i, st.Path, a)
					}
				}
			}
			st.aliases = append(st.aliases, ae)
		}
		wild := 0
		for _, e := range elems {
			for _, v := range e.Key {
				if v == "*" {
					wild++
				}
			}
		}
		if wild != len(st.Keys) {
			return fail("subtree %d (%s): %d wildcard keys but %d key sources", i, st.Path, wild, len(st.Keys))
		}
		ifaceKeys := 0
		for _, k := range st.Keys {
			if k.Source == gnmiKeySourceInterfaces {
				ifaceKeys++
			}
		}
		if ifaceKeys > 1 {
			return fail("subtree %d (%s): at most one interfaces key source", i, st.Path)
		}
		st.componentKey, st.neighborKey = -1, -1
		for j, k := range st.Keys {
			switch k.Source {
			case gnmiKeySourceInterfaces:
			case gnmiKeySourceComponents:
				if st.componentKey < 0 {
					st.componentKey = j
				}
			case gnmiKeySourceNeighbors:
				if st.neighborKey < 0 {
					st.neighborKey = j
				}
			case gnmiKeySourceStatic:
				if len(k.Names) == 0 {
					return fail("subtree %d key %d: static key source needs names", i, j)
				}
			default:
				return fail("subtree %d key %d: unknown key source %q", i, j, k.Source)
			}
		}
		seen := map[string]bool{}
		for _, leaf := range st.Leaves {
			if seen[leaf.Name] {
				return fail("subtree %d (%s): duplicate leaf %q", i, st.Path, leaf.Name)
			}
			seen[leaf.Name] = true
			le, err := parseCatalogPath(leaf.Name)
			if err != nil {
				return fail("subtree %d leaf %q: %v", i, leaf.Name, err)
			}
			leaf.elems = le
			if leaf.Type == "" {
				return fail("subtree %d leaf %q: type is required", i, leaf.Name)
			}
			if !gnmiLeafTypes[leaf.Type] {
				return fail("subtree %d leaf %q: type %q is not a supported YANG type", i, leaf.Name, leaf.Type)
			}
			g, err := compileGnmiBinding(leaf.Gen)
			if err != nil {
				return fail("subtree %d leaf %q: binding: %v", i, leaf.Name, err)
			}
			switch prefix, _, _ := strings.Cut(leaf.Gen, ":"); {
			case prefix == "inventory" && st.componentKey < 0:
				return fail("subtree %d leaf %q: inventory binding needs a components key source", i, leaf.Name)
			case prefix == "neighbor" && st.neighborKey < 0:
				return fail("subtree %d leaf %q: neighbor binding needs a neighbors key source", i, leaf.Name)
			}
			leaf.gen = g
			if leaf.Filter != "" {
				if st.componentKey < 0 {
					return fail("subtree %d leaf %q: filter needs a components key source", i, leaf.Name)
				}
				// Intersect with what the subtree's own components key
				// expands to: a filter the key can never satisfy would load
				// as a leaf nothing serves while AllLeafPaths still lists it.
				keyed := map[string]bool{}
				for _, comp := range c.components(st.Keys[st.componentKey].Filter) {
					keyed[comp.Name] = true
				}
				leaf.filterNames = map[string]bool{}
				for _, comp := range c.components(leaf.Filter) {
					if keyed[comp.Name] {
						leaf.filterNames[comp.Name] = true
					}
				}
				if len(leaf.filterNames) == 0 {
					return fail("subtree %d leaf %q: filter %q matches no component of this subtree", i, leaf.Name, leaf.Filter)
				}
			}
		}
	}
	if err := c.checkSamePathSubtrees(); err != nil {
		return fail("%v", err)
	}
	return nil
}

// keyValues enumerates one key source without a device: components,
// neighbors and static. The interfaces source is per device and stays
// in the resolver; ok is false for it. The resolver and the same-path
// guard both expand through here so the guard cannot drift from what
// the resolver renders.
func (c *gnmiCatalog) keyValues(k gnmiCatalogKey) (vals []string, ok bool) {
	switch k.Source {
	case gnmiKeySourceComponents:
		for _, comp := range c.components(k.Filter) {
			vals = append(vals, comp.Name)
		}
	case gnmiKeySourceNeighbors:
		for _, n := range c.Neighbors {
			vals = append(vals, n.Address)
		}
	case gnmiKeySourceStatic:
		vals = k.Names
	default:
		return nil, false
	}
	return vals, true
}

// entryTuples is the cartesian product of a subtree's key sources as
// joined key strings, or ok=false when a source needs a device.
func (c *gnmiCatalog) entryTuples(st *gnmiCatalogSubtree) (tuples []string, ok bool) {
	tuples = []string{""}
	for _, k := range st.Keys {
		vals, found := c.keyValues(k)
		if !found {
			return nil, false
		}
		var next []string
		for _, t := range tuples {
			for _, v := range vals {
				next = append(next, t+"\x00"+v)
			}
		}
		tuples = next
	}
	return tuples, true
}

// checkSamePathSubtrees refuses two subtrees of one origin on one entry
// path whose entries intersect: under `prefix: list-entry` they would
// render one prefix as two notifications (nl6#765). Only key sources
// resolvable at load are compared; a pair with an interfaces key on
// either side is not checked, because the interface name set exists
// only per device.
//
// Same-path subtrees with DISJOINT entries are allowed (the shipped
// MX10004 keeps `CPU0:CORE0` beside the inventory on one path). Paths
// are compared compiled, since parseCatalogPath trims slashes. A pair
// of key-less root subtrees is refused too: both render the origin-only
// prefix, so their leaves belong in one root subtree.
func (c *gnmiCatalog) checkSamePathSubtrees() error {
	for i, a := range c.Subtrees {
		var seen map[string]bool // expanded on the first same-path partner
		for j := i + 1; j < len(c.Subtrees); j++ {
			b := c.Subtrees[j]
			if b.Origin != a.Origin || !pathElemsEqual(a.elems, b.elems) {
				continue
			}
			if seen == nil {
				ta, ok := c.entryTuples(a)
				if !ok {
					break
				}
				seen = make(map[string]bool, len(ta))
				for _, t := range ta {
					seen[t] = true
				}
			}
			tb, ok := c.entryTuples(b)
			if !ok {
				continue
			}
			for _, t := range tb {
				if !seen[t] {
					continue
				}
				remedy := "fold the leaves into one subtree"
				if a.componentKey >= 0 {
					remedy += " and narrow a per-component leaf with a leaf filter"
				}
				return fmt.Errorf("subtree %d and subtree %d both serve %s %s at entry %q, which would render one prefix twice; %s",
					i, j, a.Origin, a.Path, strings.ReplaceAll(strings.TrimPrefix(t, "\x00"), "\x00", ","), remedy)
			}
		}
	}
	return nil
}

// pathElemsEqual compares compiled entry paths element by element,
// keys included.
func pathElemsEqual(a, b []*gnmipb.PathElem) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i].Name != b[i].Name || len(a[i].Key) != len(b[i].Key) {
			return false
		}
		for k, v := range a[i].Key {
			if b[i].Key[k] != v {
				return false
			}
		}
	}
	return true
}

func (c *gnmiCatalog) acceptsEncoding(enc gnmipb.Encoding) bool {
	return c.encodings[enc]
}

// components returns the component list filtered by `filter`: "" for
// all, "temperature" for sensors, or a component type such as "FAN".
func (c *gnmiCatalog) components(filter string) []gnmiCatalogComponent {
	if filter == "" {
		return c.Components
	}
	var out []gnmiCatalogComponent
	for _, comp := range c.Components {
		if (filter == "temperature" && comp.Temperature) || comp.Type == filter {
			out = append(out, comp)
		}
	}
	return out
}

// parseCatalogPath parses "/a/b[name=*]/c" into PathElems. Key values
// may not contain ']' or '/'; that is enough for the catalogue grammar.
func parseCatalogPath(s string) ([]*gnmipb.PathElem, error) {
	if s == "/" {
		// Root entry: Junos streams container-level subtrees such as
		// /system/state with an empty prefix and absolute update paths.
		return nil, nil
	}
	s = strings.Trim(s, "/")
	if s == "" {
		return nil, errors.New("empty path")
	}
	var elems []*gnmipb.PathElem
	for _, part := range strings.Split(s, "/") {
		name := part
		var keys map[string]string
		if i := strings.IndexByte(part, '['); i >= 0 {
			name = part[:i]
			rest := part[i:]
			keys = map[string]string{}
			for rest != "" {
				if rest[0] != '[' {
					return nil, fmt.Errorf("path %q: bad key syntax at %q", s, rest)
				}
				end := strings.IndexByte(rest, ']')
				if end < 0 {
					return nil, fmt.Errorf("path %q: unterminated key", s)
				}
				kv := rest[1:end]
				eq := strings.IndexByte(kv, '=')
				if eq <= 0 {
					return nil, fmt.Errorf("path %q: key %q lacks '='", s, kv)
				}
				keys[kv[:eq]] = kv[eq+1:]
				rest = rest[end+1:]
			}
		}
		if name == "" {
			return nil, fmt.Errorf("path %q: empty element", s)
		}
		elems = append(elems, &gnmipb.PathElem{Name: name, Key: keys})
	}
	return elems, nil
}

// loadEmbeddedGnmiCatalogs parses every resources/<slug>/gnmi.json
// compiled into the binary, keyed by slug.
func loadEmbeddedGnmiCatalogs() (map[string]*gnmiCatalog, error) {
	out := map[string]*gnmiCatalog{}
	entries, err := fs.ReadDir(embeddedGnmiCatalogFS, "resources")
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return out, nil
		}
		return nil, fmt.Errorf("gnmi catalog: embedded read: %w", err)
	}
	for _, e := range entries {
		// Skip "_"-prefixed dirs (placeholders, shared data), as the scan does.
		if !e.IsDir() || strings.HasPrefix(e.Name(), "_") {
			continue
		}
		p := "resources/" + e.Name() + "/" + gnmiCatalogFileName
		data, err := embeddedGnmiCatalogFS.ReadFile(p)
		if err != nil {
			continue
		}
		c, err := parseGnmiCatalog(data, "<embedded "+p+">")
		if err != nil {
			return nil, err
		}
		out[e.Name()] = c
	}
	return out, nil
}

func loadGnmiCatalogFile(path string) (*gnmiCatalog, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("gnmi catalog: reading %q: %w", path, err)
	}
	return parseGnmiCatalog(data, path)
}

// scanPerTypeGnmiCatalogs overlays resourceDir/<slug>/gnmi.json files
// on `base` (the embedded set). A directory file replaces the embedded
// catalogue for its slug; slugs with neither do not appear.
func scanPerTypeGnmiCatalogs(resourceDir string, base map[string]*gnmiCatalog) (map[string]*gnmiCatalog, error) {
	out := make(map[string]*gnmiCatalog, len(base))
	for k, v := range base {
		out[k] = v
	}
	entries, err := os.ReadDir(resourceDir)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) || errors.Is(err, fs.ErrPermission) {
			log.Printf("gnmi catalog scan: resource dir %q unreadable (%v); per-type overrides disabled", resourceDir, err)
			return out, nil
		}
		return nil, fmt.Errorf("gnmi catalog scan: reading %q: %w", resourceDir, err)
	}
	for _, e := range entries {
		if !e.IsDir() || strings.HasPrefix(e.Name(), "_") {
			continue
		}
		p := filepath.Join(resourceDir, e.Name(), gnmiCatalogFileName)
		if _, err := os.Stat(p); err != nil {
			continue
		}
		c, err := loadGnmiCatalogFile(p)
		if err != nil {
			return nil, err
		}
		out[e.Name()] = c
	}
	return out, nil
}

// LoadGnmiCatalogs populates gnmiCatalogsByType. overridePath, when
// non-empty, replaces every type's catalogue with that one file.
func (sm *SimulatorManager) LoadGnmiCatalogs(overridePath, resourceDir string) error {
	if overridePath != "" {
		c, err := loadGnmiCatalogFile(overridePath)
		if err != nil {
			return err
		}
		sm.gnmiCatalogsByType = map[string]*gnmiCatalog{"*": c}
		log.Printf("gNMI catalog: %s overrides every device type", overridePath)
		return nil
	}
	embedded, err := loadEmbeddedGnmiCatalogs()
	if err != nil {
		return err
	}
	byType, err := scanPerTypeGnmiCatalogs(resourceDir, embedded)
	if err != nil {
		return err
	}
	sm.gnmiCatalogsByType = byType
	for slug, c := range byType {
		log.Printf("gNMI catalog: %s serves %d subtrees (%s)", slug, len(c.Subtrees), c.Vendor)
	}
	return nil
}

// gnmiCatalogFor returns the catalogue for d's type, or nil.
func (sm *SimulatorManager) gnmiCatalogFor(d *DeviceSimulator) *gnmiCatalog {
	if sm == nil || sm.gnmiCatalogsByType == nil {
		return nil
	}
	if c, ok := sm.gnmiCatalogsByType["*"]; ok {
		return c
	}
	return sm.gnmiCatalogsByType[resourceDirName(d.resourceFile)]
}
