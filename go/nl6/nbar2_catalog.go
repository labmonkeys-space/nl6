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
	"math/rand"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
)

// NBAR2 application catalog: the third instance of the shape the trap and
// syslog catalogs already have. A universal set is compiled in from
// resources/_common/nbar2.json, resources/<slug>/nbar2.json overlays it per
// device type with the same `extends` semantic, and -nbar2-catalog replaces
// the whole surface. Loaded once at startup; there is no per-device catalog
// path on the REST surface (a REST-settable path is an arbitrary-file-read
// primitive, the ca_pem lesson) and no runtime reload.
//
// What the loader produces is what the Plan A encoder consumes: one immutable
// avcCatalog per resolved type and ONE IPFIXAVCEncoder built over it, shared
// by every device of that type (spec section 3). The draw tables the
// application-first generator uses live beside them, so a device's records
// and its application table cannot disagree about which applications exist.

//go:embed resources/_common/nbar2.json
var embeddedNbar2CatalogFS embed.FS

const embeddedNbar2CatalogPath = "resources/_common/nbar2.json"

// nbar2CatalogFileName is the per-type overlay basename under resources/<slug>/.
const nbar2CatalogFileName = "nbar2.json"

// RFC 6759 section 4.1 classification engine ids the evidence base
// established (testdata/cisco-avc/NOTES.md): 3 IANA-L4 (port-based, selector
// is the port), 6 USER-Defined, 13 PANA-L7 (NBAR2 layer-7).
const (
	avcEngineIANAL4  = 3
	avcEngineUser    = 6
	avcEnginePANAL7  = 13
	avcSelectorMax   = 0xFFFFFF
	avcNameMaxLen    = ipfixApplicationNameLen        // 24, the fixed applicationName width
	avcDescMaxLen    = ipfixApplicationDescriptionLen // 55, the fixed applicationDescription width
	avcValueMaxLen   = 65535                          // RFC 7011 section 7 variable-length ceiling
	nbar2DefaultWght = 1
)

// nbar2ValueJSON is one weighted host or URI value.
type nbar2ValueJSON struct {
	Value  string `json:"value"`
	Weight int    `json:"weight,omitempty"`
}

// nbar2Proto accepts "tcp", "udp", "icmp" or an integer 0..255 and
// canonicalises to the IP protocol number at decode time, so every rule
// below sees a number.
type nbar2Proto uint8

func (p *nbar2Proto) UnmarshalJSON(b []byte) error {
	var n int
	if err := json.Unmarshal(b, &n); err == nil {
		if n < 0 || n > 255 {
			return fmt.Errorf("proto %d out of range 0..255", n)
		}
		*p = nbar2Proto(n)
		return nil
	}
	var s string
	if err := json.Unmarshal(b, &s); err != nil {
		return fmt.Errorf("proto must be tcp, udp, icmp or an integer 0..255, got %s", string(b))
	}
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "tcp":
		*p = 6
	case "udp":
		*p = 17
	case "icmp":
		*p = 1
	default:
		if n, err := strconv.Atoi(s); err == nil && n >= 0 && n <= 255 {
			*p = nbar2Proto(n)
			return nil
		}
		return fmt.Errorf("proto must be tcp, udp, icmp or an integer 0..255, got %q", s)
	}
	return nil
}

// nbar2EntryJSON is the on-disk shape of one application. engine and
// selector are separate on purpose: the loader packs them with
// avcApplicationID, and can validate the engine only if it sees it.
type nbar2EntryJSON struct {
	Name        string `json:"name"`
	Description string `json:"description"`
	Engine      int    `json:"engine"`
	Selector    int64  `json:"selector"`
	// proto and dst_port are POINTERS so an absent key is distinguishable
	// from 0: an entry that omitted proto used to compile to IP protocol 0
	// and go on the wire that way (review of PR #673).
	Proto   *nbar2Proto      `json:"proto"`
	DstPort *int             `json:"dst_port"`
	Weight  int              `json:"weight,omitempty"`
	Hosts   []nbar2ValueJSON `json:"hosts,omitempty"`
	URIs    []nbar2ValueJSON `json:"uris,omitempty"`
}

// nbar2CatalogJSON is the whole file. Both `comment` (the trap catalog's
// spelling) and `_comment` (the resource parts' spelling) are accepted so an
// author can annotate either way; everything else unknown is rejected.
type nbar2CatalogJSON struct {
	Comment  string           `json:"comment,omitempty"`
	UComment string           `json:"_comment,omitempty"`
	Extends  *bool            `json:"extends,omitempty"`
	Entries  []nbar2EntryJSON `json:"entries"`
}

// nbar2Value is one parsed weighted host or URI.
type nbar2Value struct {
	Value  string
	Weight int
}

// nbar2Entry is one parsed application.
type nbar2Entry struct {
	Name        string
	Description string
	Engine      uint8
	Selector    uint32
	ID          uint32 // avcApplicationID(Engine, Selector)
	Proto       uint8
	DstPort     uint16
	Weight      int
	Hosts       []nbar2Value
	URIs        []nbar2Value

	// oversized marks an entry whose worst-case record cannot fit an empty
	// datagram at the configured MTU. It stays in the catalog, is excluded
	// from the generation draw AND from the application table, and is named
	// once at startup. Disabled rather than rejected because the budget
	// follows -datagram-mtu, and a low MTU must not refuse to boot on nl6's
	// own shipped catalog (the trap loader's reasoning).
	oversized bool
}

// nbar2Catalog is a parsed and finalised catalog. Immutable after load; one
// instance is shared by every device of a type and by the encoder.
type nbar2Catalog struct {
	Entries []*nbar2Entry
	ByName  map[string]*nbar2Entry
	Extends bool

	// Derived by finalize over the USABLE (non-oversized) entries, in
	// catalog order. usable[i] is avc index i+1.
	usable  []*nbar2Entry
	avc     *avcCatalog
	enc     *IPFIXAVCEncoder
	cumW    []int // cumulative application weight over usable
	totalW  int
	hostCum [][]int // per usable entry: cumulative host weights
	hostTot []int
	uriCum  [][]int
	uriTot  []int

	// Oversized names the disabled entries with the size, the gap and the
	// MTU that would admit each, for the startup log and the status endpoint.
	Oversized []string
}

// LoadEmbeddedNbar2Catalog parses the universal catalog compiled into the
// binary.
func LoadEmbeddedNbar2Catalog() (*nbar2Catalog, error) {
	data, err := embeddedNbar2CatalogFS.ReadFile(embeddedNbar2CatalogPath)
	if err != nil {
		return nil, fmt.Errorf("nbar2 catalog: embedded read failed: %w", err)
	}
	return parseNbar2Catalog(data, "<embedded "+embeddedNbar2CatalogPath+">")
}

// LoadNbar2CatalogFromFile parses an operator file. As the -nbar2-catalog
// target it replaces the universal AND every per-type overlay.
func LoadNbar2CatalogFromFile(path string) (*nbar2Catalog, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("nbar2 catalog: reading %q: %w", path, err)
	}
	return parseNbar2Catalog(data, path)
}

// parseNbar2Catalog decodes and validates one file. Every rule names the
// file, the entry and the rule, so an operator can fix the line. The catalog
// returned is NOT finalised: the caller merges overlays and applies the size
// budget first, then calls finalize.
func parseNbar2Catalog(data []byte, source string) (*nbar2Catalog, error) {
	var doc nbar2CatalogJSON
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&doc); err != nil {
		return nil, fmt.Errorf("nbar2 catalog: parsing %s: %w", source, err)
	}
	if len(doc.Entries) == 0 {
		return nil, fmt.Errorf("nbar2 catalog: %s has no entries", source)
	}
	cat := &nbar2Catalog{
		Entries: make([]*nbar2Entry, 0, len(doc.Entries)),
		ByName:  make(map[string]*nbar2Entry, len(doc.Entries)),
		Extends: doc.Extends == nil || *doc.Extends,
	}
	byID := make(map[uint32]string, len(doc.Entries))
	for i, raw := range doc.Entries {
		e, err := compileNbar2Entry(raw, source, i)
		if err != nil {
			return nil, err
		}
		if _, dup := cat.ByName[e.Name]; dup {
			return nil, fmt.Errorf("nbar2 catalog: %s entry %d: duplicate name %q", source, i, e.Name)
		}
		if other, dup := byID[e.ID]; dup {
			return nil, fmt.Errorf("nbar2 catalog: %s entry %d (%q): applicationId %#x (engine %d, selector %d) is already used by %q",
				source, i, e.Name, e.ID, e.Engine, e.Selector, other)
		}
		cat.Entries = append(cat.Entries, e)
		cat.ByName[e.Name] = e
		byID[e.ID] = e.Name
	}
	return cat, nil
}

// compileNbar2Entry applies every per-entry rule.
func compileNbar2Entry(raw nbar2EntryJSON, source string, i int) (*nbar2Entry, error) {
	fail := func(format string, args ...any) (*nbar2Entry, error) {
		return nil, fmt.Errorf("nbar2 catalog: %s entry %d (%q): %s", source, i, raw.Name, fmt.Sprintf(format, args...))
	}
	if strings.TrimSpace(raw.Name) == "" {
		return fail("name is required")
	}
	if len(raw.Name) > avcNameMaxLen {
		return fail("name is %d bytes, over the %d-byte applicationName field", len(raw.Name), avcNameMaxLen)
	}
	if len(raw.Description) > avcDescMaxLen {
		return fail("description is %d bytes, over the %d-byte applicationDescription field", len(raw.Description), avcDescMaxLen)
	}
	switch raw.Engine {
	case avcEngineIANAL4, avcEngineUser, avcEnginePANAL7:
	default:
		return fail("engine %d is not one of the RFC 6759 section 4.1 ids accepted here: %d (IANA-L4), %d (USER-Defined), %d (PANA-L7)",
			raw.Engine, avcEngineIANAL4, avcEngineUser, avcEnginePANAL7)
	}
	if raw.Selector < 0 || raw.Selector > avcSelectorMax {
		return fail("selector %d out of range 0..%d (24 bits)", raw.Selector, avcSelectorMax)
	}
	if raw.Proto == nil {
		return fail("proto is required (tcp, udp, icmp or an integer 0..255)")
	}
	proto := uint8(*raw.Proto)
	if raw.DstPort == nil && proto != 1 {
		return fail("dst_port is required for proto %d (only icmp may omit it)", proto)
	}
	dstPort := 0
	if raw.DstPort != nil {
		dstPort = *raw.DstPort
	}
	if dstPort < 0 || dstPort > 65535 {
		return fail("dst_port %d out of range 0..65535", dstPort)
	}
	if proto == 1 && dstPort != 0 {
		return fail("proto icmp carries no port; dst_port must be 0, got %d", dstPort)
	}
	if raw.Weight < 0 {
		return fail("weight must be positive, got %d", raw.Weight)
	}
	weight := raw.Weight
	if weight == 0 {
		weight = nbar2DefaultWght
	}
	hosts, err := compileNbar2Values(raw.Hosts, "hosts")
	if err != nil {
		return fail("%v", err)
	}
	uris, err := compileNbar2Values(raw.URIs, "uris")
	if err != nil {
		return fail("%v", err)
	}
	return &nbar2Entry{
		Name:        raw.Name,
		Description: raw.Description,
		Engine:      uint8(raw.Engine),
		Selector:    uint32(raw.Selector),
		ID:          avcApplicationID(uint8(raw.Engine), uint32(raw.Selector)),
		Proto:       proto,
		DstPort:     uint16(dstPort),
		Weight:      weight,
		Hosts:       hosts,
		URIs:        uris,
	}, nil
}

func compileNbar2Values(raw []nbar2ValueJSON, field string) ([]nbar2Value, error) {
	out := make([]nbar2Value, 0, len(raw))
	for j, v := range raw {
		if v.Value == "" {
			return nil, fmt.Errorf("%s[%d]: value is required", field, j)
		}
		if len(v.Value) > avcValueMaxLen {
			return nil, fmt.Errorf("%s[%d]: value is %d bytes, over the RFC 7011 variable-length ceiling of %d", field, j, len(v.Value), avcValueMaxLen)
		}
		if v.Weight < 0 {
			return nil, fmt.Errorf("%s[%d]: weight must be positive, got %d", field, j, v.Weight)
		}
		w := v.Weight
		if w == 0 {
			w = nbar2DefaultWght
		}
		out = append(out, nbar2Value{Value: v.Value, Weight: w})
	}
	return out, nil
}

// MergeOverlay returns a new catalog: overlay entries replace same-name
// universal entries in place, new names are appended, and untouched universal
// entries carry through. Neither input is mutated. Overlay.Extends is not
// consulted here; the caller decides. A packed-id collision across the two
// files is an error, since both would advertise one id for two applications.
func (c *nbar2Catalog) MergeOverlay(overlay *nbar2Catalog, source string) (*nbar2Catalog, error) {
	merged := &nbar2Catalog{
		Entries: make([]*nbar2Entry, 0, len(c.Entries)+len(overlay.Entries)),
		ByName:  make(map[string]*nbar2Entry, len(c.Entries)+len(overlay.Entries)),
		Extends: overlay.Extends,
	}
	for _, e := range c.Entries {
		if o, ok := overlay.ByName[e.Name]; ok {
			cp := *o
			merged.Entries = append(merged.Entries, &cp)
			merged.ByName[e.Name] = &cp
			continue
		}
		cp := *e
		merged.Entries = append(merged.Entries, &cp)
		merged.ByName[e.Name] = &cp
	}
	for _, o := range overlay.Entries {
		if _, ok := merged.ByName[o.Name]; ok {
			continue
		}
		cp := *o
		merged.Entries = append(merged.Entries, &cp)
		merged.ByName[o.Name] = &cp
	}
	byID := make(map[uint32]string, len(merged.Entries))
	for _, e := range merged.Entries {
		if other, dup := byID[e.ID]; dup {
			return nil, fmt.Errorf("nbar2 catalog: %s: after merging the overlay, applicationId %#x is used by both %q and %q",
				source, e.ID, other, e.Name)
		}
		byID[e.ID] = e.Name
	}
	return merged, nil
}

// ScanPerTypeNbar2Catalogs walks resourceDir for <slug>/nbar2.json and returns
// the MERGED catalog per slug, layered on universal under `extends: true` or
// standing alone under `extends: false`. Slugs without a file are absent;
// callers fall through to the universal. Mirrors ScanPerTypeTrapCatalogs,
// including the `_`-prefix skip and the one-line permission log.
func ScanPerTypeNbar2Catalogs(universal *nbar2Catalog, resourceDir string) (map[string]*nbar2Catalog, error) {
	result := make(map[string]*nbar2Catalog)
	entries, err := os.ReadDir(resourceDir)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			log.Printf("nbar2 catalog scan: resource dir %q not found; per-type overlays disabled", resourceDir)
			return result, nil
		}
		if errors.Is(err, fs.ErrPermission) {
			log.Printf("nbar2 catalog scan: permission denied reading %q; per-type overlays disabled", resourceDir)
			return result, nil
		}
		return nil, fmt.Errorf("nbar2 catalog scan: reading %q: %w", resourceDir, err)
	}
	permissionLogged := false
	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}
		slug := strings.ToLower(entry.Name())
		if strings.HasPrefix(slug, "_") {
			continue
		}
		path := filepath.Join(resourceDir, entry.Name(), nbar2CatalogFileName)
		info, err := os.Stat(path)
		if err != nil {
			if errors.Is(err, fs.ErrPermission) && !permissionLogged {
				log.Printf("nbar2 catalog scan: permission denied on %q; per-type overlay for %q skipped (further permission errors this scan suppressed)", path, slug)
				permissionLogged = true
			}
			continue
		}
		if info.IsDir() {
			continue
		}
		perType, err := LoadNbar2CatalogFromFile(path)
		if err != nil {
			return nil, fmt.Errorf("per-type nbar2 catalog %q: %w", slug, err)
		}
		if perType.Extends {
			merged, err := universal.MergeOverlay(perType, path)
			if err != nil {
				return nil, err
			}
			result[slug] = merged
		} else {
			result[slug] = perType
		}
	}
	return result, nil
}

// nbar2CatalogsAgreeOnNames checks that no two catalogs give one wire
// applicationId two different names. The scenario report labels an
// application row from a fleet-wide id → name table built first-seen over
// the participants' catalogs (ScenarioController.participantAppNames), which
// is only a safe rule while this holds for every catalog a fleet can
// resolve. The error names the id, both catalogs and both names; nil when
// every shared id agrees. Catalogs are visited in sorted key order so the
// reported pair is deterministic.
func nbar2CatalogsAgreeOnNames(cats map[string]*nbar2Catalog) error {
	slugs := make([]string, 0, len(cats))
	for s := range cats {
		slugs = append(slugs, s)
	}
	sort.Strings(slugs)
	type seen struct{ slug, name string }
	first := make(map[uint32]seen)
	for _, slug := range slugs {
		for _, e := range cats[slug].Entries {
			if prev, ok := first[e.ID]; ok {
				if prev.name != e.Name {
					return fmt.Errorf("nbar2 catalogs disagree on applicationId %d (%#x): %s names it %q, %s names it %q",
						e.ID, e.ID, prev.slug, prev.name, slug, e.Name)
				}
				continue
			}
			first[e.ID] = seen{slug, e.Name}
		}
	}
	return nil
}

// ApplySizeBudget dry-renders every entry's worst-case record through the
// production encoder against an empty data-only datagram of `budget` bytes
// and marks the ones that cannot fit. Returns the names, sized, for the
// startup log. Entries are DISABLED, never rejected (see nbar2Entry.oversized).
//
// The worst case is the entry's longest host and its longest URI; the hit
// count is size-neutral (always two bytes). The verdict comes from the same
// EncodeMeasured that Tick calls, not from arithmetic that agreed with it on
// the day it was written.
func (c *nbar2Catalog) ApplySizeBudget(budget int, source string) []string {
	if c == nil || budget <= 0 {
		return nil
	}
	var disabled []string
	buf := make([]byte, budget)
	scratch := make([]byte, 3*avcValueMaxLen)
	for _, e := range c.Entries {
		probe := newAVCCatalog([]avcApplication{{ID: e.ID, Name: e.Name, Description: e.Description,
			Proto: e.Proto, DstPort: e.DstPort, Hosts: []string{longestNbar2Value(e.Hosts)}, URIs: []string{longestNbar2Value(e.URIs)}}})
		enc := NewIPFIXAVCEncoder(probe)
		rec := FlowRecord{Protocol: e.Proto, DstPort: e.DstPort, AVC: avcRef{App: 1, Host: 1, URI: 1}}
		if len(e.Hosts) == 0 {
			rec.AVC.Host = 0
		}
		if len(e.URIs) == 0 {
			rec.AVC.URI = 0
		}
		_, _, dropped, err := enc.EncodeMeasured(0, 0, 0, []FlowRecord{rec}, false, buf)
		if err == nil && dropped == 0 {
			continue
		}
		e.oversized = true
		// Measure the record on a scratch large enough for anything the
		// loader admits so the operator sees the real size and the MTU that
		// would carry it (the trap loader's shape).
		next, ok := enc.encodeRecord(scratch, 0, rec, 0)
		size := ipfixHeaderSize + ipfixDataSetHdrSize + next
		if !ok {
			disabled = append(disabled, fmt.Sprintf("%s/%s (does not encode at any size; budget %d B)", source, e.Name, budget))
			continue
		}
		disabled = append(disabled, fmt.Sprintf(
			"%s/%s (%d B, over the %d B budget by %d B; needs -datagram-mtu >= %d)",
			source, e.Name, size, budget, size-budget, size+ipv4HeaderBytes+udpHeaderBytes))
	}
	c.Oversized = disabled
	return disabled
}

func longestNbar2Value(vs []nbar2Value) string {
	longest := ""
	for _, v := range vs {
		if len(v.Value) > len(longest) {
			longest = v.Value
		}
	}
	return longest
}

// finalize builds the encoder-facing avcCatalog, the shared encoder and the
// draw tables from the usable entries. Called once at load, after overlays
// are merged and the size budget applied. A catalog with zero usable entries
// finalises to an empty avcCatalog; attach refuses it with a reason.
func (c *nbar2Catalog) finalize() {
	c.usable = c.usable[:0]
	apps := make([]avcApplication, 0, len(c.Entries))
	c.cumW, c.totalW = c.cumW[:0], 0
	c.hostCum, c.hostTot = c.hostCum[:0], c.hostTot[:0]
	c.uriCum, c.uriTot = c.uriCum[:0], c.uriTot[:0]
	for _, e := range c.Entries {
		if e.oversized {
			continue
		}
		c.usable = append(c.usable, e)
		app := avcApplication{ID: e.ID, Name: e.Name, Description: e.Description, Proto: e.Proto, DstPort: e.DstPort}
		hostCum, hostTot := make([]int, len(e.Hosts)), 0
		for i, h := range e.Hosts {
			app.Hosts = append(app.Hosts, h.Value)
			hostTot += h.Weight
			hostCum[i] = hostTot
		}
		uriCum, uriTot := make([]int, len(e.URIs)), 0
		for i, u := range e.URIs {
			app.URIs = append(app.URIs, u.Value)
			uriTot += u.Weight
			uriCum[i] = uriTot
		}
		apps = append(apps, app)
		c.totalW += e.Weight
		c.cumW = append(c.cumW, c.totalW)
		c.hostCum, c.hostTot = append(c.hostCum, hostCum), append(c.hostTot, hostTot)
		c.uriCum, c.uriTot = append(c.uriCum, uriCum), append(c.uriTot, uriTot)
	}
	c.avc = newAVCCatalog(apps)
	c.enc = NewIPFIXAVCEncoder(c.avc)
}

// Usable is the number of entries the device can emit.
func (c *nbar2Catalog) Usable() int {
	if c == nil {
		return 0
	}
	return len(c.usable)
}

// Encoder is the one IPFIXAVCEncoder every device of this type shares.
func (c *nbar2Catalog) Encoder() *IPFIXAVCEncoder {
	if c == nil {
		return nil
	}
	return c.enc
}

// draw picks an application by weight, then a host and a URI by weight,
// returning the record's index triple plus the application's protocol and
// port. It consumes EXACTLY three RNG values on every call, including for an
// application with no hosts or no URIs: a branch-dependent draw makes the
// RNG call count flow-dependent and desynchronises a seeded stream
// (nl6#462's rule; TestNbar2DrawIsUnconditional pins it). Requires
// Usable() > 0.
func (c *nbar2Catalog) draw(rng *rand.Rand) (ref avcRef, proto uint8, port uint16) {
	i := weightedIndex(c.cumW, c.totalW, rng)
	h := weightedIndex(c.hostCum[i], c.hostTot[i], rng)
	u := weightedIndex(c.uriCum[i], c.uriTot[i], rng)
	e := c.usable[i]
	ref = avcRef{App: uint16(i + 1)}
	if c.hostTot[i] > 0 {
		ref.Host = uint16(h + 1)
	}
	if c.uriTot[i] > 0 {
		ref.URI = uint16(u + 1)
	}
	return ref, e.Proto, e.DstPort
}

// weightedIndex draws one RNG value and returns the index whose cumulative
// weight covers it. With no weights it still draws (from [0,1)) and returns
// 0, so the caller's draw count does not depend on the data.
func weightedIndex(cum []int, total int, rng *rand.Rand) int {
	if total <= 0 {
		_ = rng.Int63() // one draw, discarded: the count must not depend on the data
		return 0
	}
	v := rng.Intn(total)
	for i, w := range cum {
		if v < w {
			return i
		}
	}
	return len(cum) - 1
}

// nbar2CatalogSource labels a resolved catalog for the status endpoint.
func nbar2CatalogSource(slug, catalogFlagPath string) string {
	if catalogFlagPath != "" {
		return "override:" + catalogFlagPath
	}
	if slug == universalCatalogKey {
		return "embedded"
	}
	return fmt.Sprintf("file:%s/%s/%s", trapCatalogResourceDir, slug, nbar2CatalogFileName)
}

// Nbar2CatalogConfig is what StartNbar2Catalogs needs: the override path and
// the payload budget, passed explicitly after SetLinkMTU has run so the size
// check can never silently run against the default MTU.
type Nbar2CatalogConfig struct {
	CatalogPath   string
	PayloadBudget int
	// ResourceDir is where per-type overlays are scanned from; empty means
	// the shipped resources tree. A seam so a test can plant overlays.
	ResourceDir string
}

// StartNbar2Catalogs loads the universal catalog and the per-type overlays
// (or the override), applies the size budget, finalises each, and publishes
// them on the manager. Called once at startup beside the trap and syslog
// loaders.
func (sm *SimulatorManager) StartNbar2Catalogs(cfg Nbar2CatalogConfig) error {
	if cfg.PayloadBudget <= 0 {
		return fmt.Errorf("nbar2 catalog: PayloadBudget must be positive (got %d); pass the IPv4 flow payload budget after SetLinkMTU has run", cfg.PayloadBudget)
	}
	var universal *nbar2Catalog
	var err error
	if cfg.CatalogPath == "" {
		universal, err = LoadEmbeddedNbar2Catalog()
	} else {
		universal, err = LoadNbar2CatalogFromFile(cfg.CatalogPath)
	}
	if err != nil {
		return err
	}
	byType := map[string]*nbar2Catalog{universalCatalogKey: universal}
	if cfg.CatalogPath == "" {
		dir := cfg.ResourceDir
		if dir == "" {
			dir = trapCatalogResourceDir
		}
		perType, scanErr := ScanPerTypeNbar2Catalogs(universal, dir)
		if scanErr != nil {
			return fmt.Errorf("nbar2 catalog: scanning per-type catalogs: %w", scanErr)
		}
		for slug, c := range perType {
			byType[slug] = c
		}
	}
	// One name per wire id across every catalog a fleet can resolve: the
	// scenario report labels a row from a first-seen id -> name table over
	// the participants' catalogs, which is only honest if this holds. A
	// catalog-author error, refused at load like a duplicate name.
	if err := nbar2CatalogsAgreeOnNames(byType); err != nil {
		return err
	}
	for slug, c := range byType {
		for _, msg := range c.ApplySizeBudget(cfg.PayloadBudget, slug) {
			log.Printf("nbar2 catalog: %s exceeds the datagram budget and is DISABLED "+
				"(it will not be generated and is absent from the application table); "+
				"shorten its hosts or URIs or raise -datagram-mtu", msg)
		}
		c.finalize()
	}
	sm.mu.Lock()
	sm.nbar2CatalogsByType = byType
	sm.nbar2CatalogPath = cfg.CatalogPath
	sm.mu.Unlock()
	return nil
}

// Nbar2CatalogFor resolves the catalog for a device type: its slug's overlay
// when one loaded, else the universal, else nil when the loader never ran
// (tests that construct a bare manager).
func (sm *SimulatorManager) Nbar2CatalogFor(resourceFile string) *nbar2Catalog {
	sm.mu.RLock()
	defer sm.mu.RUnlock()
	if sm.nbar2CatalogsByType == nil {
		return nil
	}
	if c, ok := sm.nbar2CatalogsByType[resourceDirName(resourceFile)]; ok {
		return c
	}
	return sm.nbar2CatalogsByType[universalCatalogKey]
}
