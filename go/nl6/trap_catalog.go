/*
 * Copyright 2026 Ronny Trommer <ronny@no42.org>
 * SPDX-License-Identifier: Apache-2.0
 */

// SNMP trap catalog loader and selector.
//
// Resolves the two catalog open questions from design.md:
//   - OQ #1: weighted-random selection with per-entry `weight` (default 1).
//     Universal catalog weights: linkDown=40, linkUp=40, authenticationFailure=10,
//     coldStart=5, warmStart=5.
//   - OQ #3: embedded catalog path is resources/_common/traps.json.

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
	"strings"
	"text/template"
)

//go:embed resources/_common/traps.json
var embeddedCatalogFS embed.FS

const embeddedCatalogPath = "resources/_common/traps.json"

// Reserved OIDs that the encoder prepends automatically to every trap.
// Catalog authors MUST NOT include them in body varbinds.
//   - `sysUpTime.0` and `snmpTrapOID.0` are prepended unconditionally (design.md §D10).
//   - `snmpTrapEnterprise.0` is prepended when the catalog entry sets the
//     optional `snmpTrapEnterprise` field (follow-up issue #100).
const (
	oidSysUpTime0          = "1.3.6.1.2.1.1.3.0"
	oidSnmpTrapOID0        = "1.3.6.1.6.3.1.1.4.1.0"
	oidSnmpTrapEnterprise0 = "1.3.6.1.6.3.1.1.4.3.0"
)

// Catalog entry roles (correlate-state-notifications). A role-tagged entry is
// fired by an oper-status transition for the matching direction and is excluded
// from the scheduler's weighted-random Pick. Empty role = untagged (today's
// behavior: scheduler-driven, never state-driven). Shared by trap + syslog.
const (
	roleLinkDown = "link-down"
	roleLinkUp   = "link-up"

	// Optical threshold roles (#347). Four rather than two, because a raise
	// and its clear are SEPARATE catalog entries here.
	//
	// The link roles above pair one OID with another: linkDown and linkUp are
	// distinct notifications. Ciena models an optical alarm the other way
	// round — ONE notification type (wsLinkStateAlarmNotification) whose
	// varbinds carry the condition state — so raise and clear share a trap OID
	// and differ only in the severity and condition-flag values. Reusing a
	// two-role pairing would have forced either a fabricated second OID or a
	// clear that a collector could not distinguish from a raise.
	roleOpticalSDRaise = "optical-sd-raise"
	roleOpticalSDClear = "optical-sd-clear"
	roleOpticalSFRaise = "optical-sf-raise"
	roleOpticalSFClear = "optical-sf-clear"
)

// opticalRoleFor maps an evaluator transition onto the catalog role that
// publishes it. Keeping the mapping here, next to the constants, means the
// detection side never has to know catalog vocabulary.
func opticalRoleFor(cond opticalCondition, raised bool) string {
	switch {
	case cond == opticalCondSD && raised:
		return roleOpticalSDRaise
	case cond == opticalCondSD:
		return roleOpticalSDClear
	case raised:
		return roleOpticalSFRaise
	default:
		return roleOpticalSFClear
	}
}

// validRole reports whether a catalog `role` value is recognized. Empty is
// valid (untagged). Used by both trap and syslog catalog loaders.
func validRole(role string) bool {
	switch role {
	case "", roleLinkDown, roleLinkUp,
		roleOpticalSDRaise, roleOpticalSDClear, roleOpticalSFRaise, roleOpticalSFClear:
		return true
	}
	return false
}

// linkTrapOIDs are the well-known linkDown/linkUp snmpTrapOIDs, used only to
// warn when an entry looks link-related but was not given a `role`.
var linkTrapOIDs = map[string]struct{}{
	"1.3.6.1.6.3.1.1.5.3": {}, // linkDown
	"1.3.6.1.6.3.1.1.5.4": {}, // linkUp
}

// allowedTemplateFields enumerates the eleven-field unified template
// vocabulary shared between trap and syslog catalogs. Any other
// {{.Name}} reference in OID or value strings is rejected at catalog
// load time.
//
// Class 1 device-context fields (SysName, Model, Serial, ChassisID,
// IfName) are populated per fire from FieldResolver; the remaining
// four are per-fire scalars from the scheduler/exporter.
//
// Class 2 random-per-fire fields (PeerIP, User, SourceIP, RuleName, …)
// are explicitly deferred to a future change and remain rejected.
var allowedTemplateFields = map[string]struct{}{
	"IfIndex":   {},
	"IfName":    {},
	"Uptime":    {},
	"Now":       {},
	"DeviceIP":  {},
	"SysName":   {},
	"Model":     {},
	"Serial":    {},
	"ChassisID": {},
	// NowLocal is the fire time as a human-readable local timestamp
	// ("2006-01-02 15:04:05"). Added for CIENA-WS DateAndTime varbinds,
	// whose MIB type is a DisplayString date — {{.Now}} (epoch seconds)
	// there would hand collectors an opaque integer where real hardware
	// puts a date.
	"NowLocal": {},
	// Detail is a per-fire free-form measurement SUFFIX (e.g. " (OSNR 11.20
	// dB)"), empty unless the firing site supplies it via overrides — so
	// templates use a bare {{.Detail}} and render cleanly when absent. The
	// override value carries its own leading separator because the catalog
	// validator (rightly) forbids {{if}} conditionals; a state-driven alarm
	// can thus carry the measurement that triggered it without a
	// per-quantity field explosion.
	"Detail": {},
}

// TrapVarbindType identifies the ASN.1 application type used when encoding
// a varbind's value on the wire. Parsed from the catalog JSON "type" field.
type TrapVarbindType string

const (
	TrapVTInteger     TrapVarbindType = "integer"
	TrapVTOctetString TrapVarbindType = "octet-string"
	TrapVTOID         TrapVarbindType = "oid"
	TrapVTCounter32   TrapVarbindType = "counter32"
	TrapVTGauge32     TrapVarbindType = "gauge32"
	TrapVTTimeTicks   TrapVarbindType = "timeticks"
	TrapVTCounter64   TrapVarbindType = "counter64"
	TrapVTIPAddress   TrapVarbindType = "ipaddress"
)

// trapVarbindJSON is the on-disk shape of a single catalog varbind entry.
// Templates in `oid` and `value` are resolved per-fire.
type trapVarbindJSON struct {
	OID   string          `json:"oid"`
	Type  TrapVarbindType `json:"type"`
	Value string          `json:"value"`
}

// catalogEntryJSON is the on-disk shape of one trap catalog entry.
type catalogEntryJSON struct {
	Name               string            `json:"name"`
	SnmpTrapOID        string            `json:"snmpTrapOID"`
	SnmpTrapEnterprise string            `json:"snmpTrapEnterprise,omitempty"`
	Weight             int               `json:"weight"`
	Role               string            `json:"role,omitempty"`
	Varbinds           []trapVarbindJSON `json:"varbinds"`
}

// trapCatalogJSON is the on-disk shape of the whole catalog file.
// The "comment" field (if present) is ignored so authors can annotate files.
// The "extends" field is meaningful only on per-type catalog files — it
// controls whether the per-type catalog merges on top of the universal
// fallback (nil/true) or fully replaces it for that device type (false).
// Universal catalogs ignore this field.
type trapCatalogJSON struct {
	Comment string             `json:"comment,omitempty"`
	Extends *bool              `json:"extends,omitempty"`
	Traps   []catalogEntryJSON `json:"traps"`
}

// VarbindTemplate is one parsed, template-compiled varbind. Templates for OID
// and Value are pre-compiled at catalog load so Resolve runs in microseconds
// even under 30k-device / 1000 tps load.
type VarbindTemplate struct {
	Type     TrapVarbindType
	OIDTmpl  *template.Template
	ValTmpl  *template.Template
	rawOID   string // for error messages
	rawValue string
}

// CatalogEntry is one parsed trap in the catalog. Weight defaults to 1 when
// omitted from JSON; Pick is weight-biased random selection.
//
// SnmpTrapEnterprise is the OPTIONAL value for the `snmpTrapEnterprise.0`
// varbind (OID 1.3.6.1.6.3.1.1.4.3.0) from SNMPv2-MIB §10. When non-empty,
// the encoder auto-prepends this varbind after the two mandatory
// (`sysUpTime.0`, `snmpTrapOID.0`) and before the body varbinds. Empty
// means the varbind is not emitted — backward-compatible with catalogs
// authored before this field existed.
type CatalogEntry struct {
	Name               string
	SnmpTrapOID        string
	SnmpTrapEnterprise string
	Weight             int
	Role               string // "" | link-down | link-up (correlate-state-notifications)
	Varbinds           []VarbindTemplate

	// fromOverlay marks an entry that came from a per-type overlay (set in
	// MergeOverlay). EntriesByRole uses it for vendor-wins selection: when a
	// device's catalog has overlay entries for a role, the universal (base)
	// entries for that role are suppressed.
	fromOverlay bool
}

// Catalog is the whole parsed trap catalog plus cached weight metadata for Pick.
// Immutable after load; safe for concurrent read from every device.
//
// Extends is meaningful only on per-type catalogs: true (the default when
// the JSON field is absent) means "merge on top of universal"; false means
// "replace universal for this type entirely". Universal catalogs carry this
// field but the value is not consulted by the caller.
type Catalog struct {
	Entries     []*CatalogEntry
	ByName      map[string]*CatalogEntry
	Extends     bool
	cumulativeW []int // cumulativeW[i] = sum(Weight[0..i]) over ALL entries; load-validation
	totalWeight int

	// Schedulable subset: untagged entries only. Role-tagged entries fire from
	// state transitions, never the Poisson scheduler, so Pick draws from these.
	// schedTotalWeight MAY be zero (an all-role-tagged catalog) without making
	// the catalog invalid — Pick simply returns nil (a no-op tick).
	schedEntries     []*CatalogEntry
	schedCumulativeW []int
	schedTotalWeight int
}

// TemplateCtx is the data handed to text/template when Resolve evaluates
// per-fire. Matches the eleven-field vocabulary in allowedTemplateFields.
// Shared field set with SyslogTemplateCtx (design.md §D3 — unified vocab).
type TemplateCtx struct {
	IfIndex   int
	IfName    string // ifDescr.<IfIndex> or synthesised `GigabitEthernet0/<N>`
	Uptime    uint32 // 1/100s ticks since device start
	Now       int64  // Unix epoch seconds
	DeviceIP  string // dotted-quad
	SysName   string // device's sysName.0
	Model     string // human-readable model from slug → label
	Serial    string // `SN<hex>` synthesised from device IP
	ChassisID string // MAC-style chassis ID synthesised from device IP
	NowLocal  string // fire time, local "2006-01-02 15:04:05"
	Detail    string // per-fire self-delimiting measurement suffix; empty unless overridden
}

// Varbind is one resolved (templates evaluated) varbind ready for the encoder.
type Varbind struct {
	OID   string
	Type  TrapVarbindType
	Value string
}

// LoadEmbeddedCatalog parses the universal catalog compiled into the binary
// via //go:embed. The feature works out-of-box — no -trap-catalog flag or
// filesystem access is needed for the default catalog.
func LoadEmbeddedCatalog() (*Catalog, error) {
	data, err := embeddedCatalogFS.ReadFile(embeddedCatalogPath)
	if err != nil {
		return nil, fmt.Errorf("trap catalog: embedded read failed: %w", err)
	}
	return parseCatalog(data, "<embedded "+embeddedCatalogPath+">")
}

// LoadCatalogFromFile parses a user-supplied catalog file. When used as the
// `-trap-catalog` override target, this replaces the entire catalog surface
// (universal + any per-type overlays) for all devices.
func LoadCatalogFromFile(path string) (*Catalog, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("trap catalog: reading %q: %w", path, err)
	}
	return parseCatalog(data, path)
}

// ScanPerTypeTrapCatalogs walks resourceDir for `<slug>/traps.json` files and
// returns a map keyed by device-type slug. Each map value is the MERGED
// catalog for that slug — already layered on top of `universal` when the
// per-type file declares (or defaults to) `extends: true`, or a pure
// replacement when `extends: false`. Slugs without a `traps.json` file do not
// appear in the returned map; callers fall through to the universal fallback
// for those.
//
// Returns a non-nil empty map when resourceDir does not exist; that state is
// not an error (matches the existing SNMP-resource loader's tolerance of
// missing per-type directories).
func ScanPerTypeTrapCatalogs(universal *Catalog, resourceDir string) (map[string]*Catalog, error) {
	result := make(map[string]*Catalog)
	entries, err := os.ReadDir(resourceDir)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			// Missing resource tree is only a no-op when nothing else
			// in the simulator cares about it (e.g. fully-embedded
			// scenarios). Log a warning so operators running out of a
			// directory that expected `resources/` aren't left
			// wondering why per-type overlays never load.
			log.Printf("trap catalog scan: resource dir %q not found — per-type overlays disabled",
				resourceDir)
			return result, nil
		}
		if errors.Is(err, fs.ErrPermission) {
			log.Printf("trap catalog scan: permission denied reading %q — per-type overlays disabled",
				resourceDir)
			return result, nil
		}
		return nil, fmt.Errorf("trap catalog scan: reading %q: %w", resourceDir, err)
	}
	// permissionLoggedThisScan caps the inner permission-denied log to
	// one line per scan. If an operator has a systematic perms mismatch
	// (e.g., every resources/<slug>/ owned by another user) the naive
	// per-entry log would spam 28+ lines at startup per feature.
	permissionLoggedThisScan := false
	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}
		// Normalise to lowercase so the catalog key matches what
		// `resourceDirName` (used by deviceTypesByIP) produces. The
		// repo ships lowercase dir names today but we don't want a
		// mixed-case addition to silently miss the overlay.
		slug := strings.ToLower(entry.Name())
		// Skip the reserved _common dir — its content is embedded via go:embed
		// and must not be reloaded from disk as a per-type overlay.
		if strings.HasPrefix(slug, "_") {
			continue
		}
		path := filepath.Join(resourceDir, entry.Name(), "traps.json")
		info, err := os.Stat(path)
		if err != nil {
			// Permission-denied is operator-visible — log it so a
			// misconfigured per-type file doesn't silently fall back
			// to the universal catalog without any signal. Log once
			// per scan to avoid spam when the whole tree is locked.
			if errors.Is(err, fs.ErrPermission) && !permissionLoggedThisScan {
				log.Printf("trap catalog scan: permission denied on %q — per-type overlay for %q skipped (further permission errors this scan suppressed)",
					path, slug)
				permissionLoggedThisScan = true
			}
			continue
		}
		if info.IsDir() {
			continue
		}
		perType, err := LoadCatalogFromFile(path)
		if err != nil {
			return nil, fmt.Errorf("per-type trap catalog %q: %w", slug, err)
		}
		if perType.Extends {
			result[slug] = universal.MergeOverlay(perType)
		} else {
			result[slug] = perType
		}
	}
	return result, nil
}

// parseCatalog is the shared body of the two Load* helpers. Source is used
// in error messages only.
func parseCatalog(data []byte, source string) (*Catalog, error) {
	var doc trapCatalogJSON
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&doc); err != nil {
		return nil, fmt.Errorf("trap catalog: parsing %s: %w", source, err)
	}
	if len(doc.Traps) == 0 {
		return nil, fmt.Errorf("trap catalog: %s has no entries", source)
	}

	cat := &Catalog{
		Entries: make([]*CatalogEntry, 0, len(doc.Traps)),
		ByName:  make(map[string]*CatalogEntry, len(doc.Traps)),
		Extends: doc.Extends == nil || *doc.Extends, // default true when JSON omits the field
	}
	for i, raw := range doc.Traps {
		entry, err := compileEntry(raw, source, i)
		if err != nil {
			return nil, err
		}
		if _, dup := cat.ByName[entry.Name]; dup {
			return nil, fmt.Errorf("trap catalog: %s entry %d: duplicate name %q", source, i, entry.Name)
		}
		cat.Entries = append(cat.Entries, entry)
		cat.ByName[entry.Name] = entry
	}

	if err := cat.recomputeWeights(); err != nil {
		return nil, fmt.Errorf("trap catalog: %s %w", source, err)
	}
	return cat, nil
}

// recomputeWeights rebuilds cumulativeW and totalWeight from the current
// Entries slice. Called at parse time and after MergeOverlay. Returns an
// error when the total weight is non-positive (catalog contains no pickable
// entries) because Pick would infinitely select nothing otherwise.
func (c *Catalog) recomputeWeights() error {
	running := 0
	c.cumulativeW = make([]int, len(c.Entries))
	for i, e := range c.Entries {
		running += e.Weight
		c.cumulativeW[i] = running
	}
	c.totalWeight = running
	if c.totalWeight <= 0 {
		return fmt.Errorf("total weight must be > 0")
	}
	// Build the schedulable subset (untagged entries). A zero schedulable total
	// is allowed — an all-role-tagged catalog still loads; its link entries fire
	// from state transitions and Pick is a no-op.
	c.schedEntries = c.schedEntries[:0]
	c.schedCumulativeW = c.schedCumulativeW[:0]
	sched := 0
	for _, e := range c.Entries {
		if e.Role != "" {
			continue
		}
		sched += e.Weight
		c.schedEntries = append(c.schedEntries, e)
		c.schedCumulativeW = append(c.schedCumulativeW, sched)
	}
	c.schedTotalWeight = sched
	return nil
}

// EntriesByRole returns the entries a state transition of the given role SHALL
// fire, applying vendor-wins-per-role: if the catalog has any per-type overlay
// entries for the role, only those are returned (the universal entries for that
// role are suppressed); otherwise the base (universal) entries are returned.
// Returns nil for an empty role or no match.
func (c *Catalog) EntriesByRole(role string) []*CatalogEntry {
	if c == nil || role == "" {
		return nil
	}
	var overlay, base []*CatalogEntry
	for _, e := range c.Entries {
		if e.Role != role {
			continue
		}
		if e.fromOverlay {
			overlay = append(overlay, e)
		} else {
			base = append(base, e)
		}
	}
	if len(overlay) > 0 {
		return overlay
	}
	return base
}

// MergeOverlay returns a new Catalog that is the name-based overlay of `overlay`
// on top of `c` (the universal base). Entries whose names appear in `overlay`
// replace the same-named entries in `c`; entries whose names are unique to
// `overlay` are appended; entries present only in `c` carry through unchanged.
// The returned catalog's weight metadata is recomputed across the merged set.
//
// Neither `c` nor `overlay` is mutated — both remain valid standalone catalogs
// after the call. `overlay.Extends` is not consulted here; callers decide
// whether to merge based on that flag before invoking MergeOverlay.
func (c *Catalog) MergeOverlay(overlay *Catalog) *Catalog {
	if c == nil {
		return overlay
	}
	if overlay == nil || len(overlay.Entries) == 0 {
		// Return a shallow copy so callers can treat the result as an
		// independent catalog (same semantics as the merge path).
		out := &Catalog{
			Entries: append([]*CatalogEntry(nil), c.Entries...),
			ByName:  make(map[string]*CatalogEntry, len(c.Entries)),
			Extends: true,
		}
		for _, e := range out.Entries {
			out.ByName[e.Name] = e
		}
		if err := out.recomputeWeights(); err != nil {
			// The base catalog (`c`) already passed parseCatalog's
			// weight check, so this is essentially impossible. Log
			// defensively rather than silently emit a dud catalog
			// that would trip Pick on division-by-zero.
			log.Printf("trap catalog: MergeOverlay(empty overlay) produced invalid weights: %v", err)
		}
		return out
	}

	merged := &Catalog{
		Entries: make([]*CatalogEntry, 0, len(c.Entries)+len(overlay.Entries)),
		ByName:  make(map[string]*CatalogEntry, len(c.Entries)+len(overlay.Entries)),
		Extends: true,
	}
	// Walk the base first so base ordering is preserved for same-name
	// overrides; then append overlay-only entries.
	for _, e := range c.Entries {
		if override, replaced := overlay.ByName[e.Name]; replaced {
			override.fromOverlay = true
			merged.Entries = append(merged.Entries, override)
			merged.ByName[override.Name] = override
		} else {
			merged.Entries = append(merged.Entries, e)
			merged.ByName[e.Name] = e
		}
	}
	for _, e := range overlay.Entries {
		if _, already := merged.ByName[e.Name]; already {
			continue
		}
		e.fromOverlay = true
		merged.Entries = append(merged.Entries, e)
		merged.ByName[e.Name] = e
	}
	if err := merged.recomputeWeights(); err != nil {
		// A merged total-weight of zero means Pick would infinitely
		// select nothing (or panic on rand.Intn(0)). Both base and
		// overlay passed load-time validation individually, so this
		// can only happen with pathological same-name overrides that
		// replace every positive-weight entry with zero-weight ones.
		// Surface it rather than ship a silently broken catalog.
		log.Printf("trap catalog: MergeOverlay produced invalid weights: %v", err)
	}
	return merged
}

// compileEntry validates and compiles one catalog entry. Rejects reserved
// varbind OIDs (design.md §D10) and templates that reference fields outside
// the allowed four (spec: "Unknown template field rejected").
func compileEntry(raw catalogEntryJSON, source string, idx int) (*CatalogEntry, error) {
	if raw.Name == "" {
		return nil, fmt.Errorf("trap catalog: %s entry %d: name is required", source, idx)
	}
	if raw.SnmpTrapOID == "" {
		return nil, fmt.Errorf("trap catalog: %s entry %q: snmpTrapOID is required", source, raw.Name)
	}
	weight := raw.Weight
	if weight == 0 {
		weight = 1 // OQ#1: default weight = 1
	}
	if weight < 0 {
		return nil, fmt.Errorf("trap catalog: %s entry %q: weight must be non-negative", source, raw.Name)
	}

	if !validRole(raw.Role) {
		return nil, fmt.Errorf("trap catalog: %s entry %q: unknown role %q (allowed: link-down, link-up)",
			source, raw.Name, raw.Role)
	}
	entry := &CatalogEntry{
		Name:        raw.Name,
		SnmpTrapOID: strings.TrimPrefix(raw.SnmpTrapOID, "."),
		Weight:      weight,
		Role:        raw.Role,
		Varbinds:    make([]VarbindTemplate, 0, len(raw.Varbinds)),
	}
	// Warn (non-fatal) when an entry looks link-related but carries no role —
	// such an entry keeps firing from the scheduler AND won't be state-driven,
	// which is the double-emit hazard the role tag exists to prevent.
	if raw.Role == "" {
		if _, isLink := linkTrapOIDs[entry.SnmpTrapOID]; isLink {
			log.Printf("trap catalog: %s entry %q has a linkDown/linkUp snmpTrapOID but no \"role\" — "+
				"it will fire from the scheduler and NOT be state-driven; add \"role\":\"link-down\"/\"link-up\" to correlate it",
				source, raw.Name)
		}
	}
	// The optional snmpTrapEnterprise.0 value must be a well-formed dotted-
	// decimal OID and must not collide with OIDs the encoder auto-prepends.
	// Format check runs first so the operator sees a specific message about
	// the format gap (".", whitespace, single-arc, trailing-dot, etc.) rather
	// than a reserved-OID error that never fires for malformed input.
	if raw.SnmpTrapEnterprise != "" {
		entry.SnmpTrapEnterprise = strings.TrimPrefix(raw.SnmpTrapEnterprise, ".")
		if err := validateDottedOID(entry.SnmpTrapEnterprise, raw.Name, "snmpTrapEnterprise"); err != nil {
			return nil, fmt.Errorf("trap catalog: %s %w", source, err)
		}
		switch entry.SnmpTrapEnterprise {
		case oidSysUpTime0, oidSnmpTrapOID0, oidSnmpTrapEnterprise0:
			return nil, fmt.Errorf("trap catalog: %s entry %q: snmpTrapEnterprise value %s "+
				"is a reserved OID — the field should hold an enterprise OID reflecting "+
				"the notification type, typically the parent of snmpTrapOID",
				source, raw.Name, raw.SnmpTrapEnterprise)
		}
	}
	for j, vb := range raw.Varbinds {
		if err := validateVarbindOID(vb.OID, raw.Name, j); err != nil {
			return nil, err
		}
		if vb.Type == "" {
			return nil, fmt.Errorf("trap catalog: %s entry %q varbind %d: type is required", source, raw.Name, j)
		}
		switch vb.Type {
		case TrapVTInteger, TrapVTOctetString, TrapVTOID,
			TrapVTCounter32, TrapVTGauge32, TrapVTTimeTicks,
			TrapVTCounter64, TrapVTIPAddress:
			// ok
		default:
			return nil, fmt.Errorf("trap catalog: %s entry %q varbind %d: unknown type %q",
				source, raw.Name, j, vb.Type)
		}
		if err := validateTemplateFields(vb.OID, raw.Name, j, "oid"); err != nil {
			return nil, err
		}
		if err := validateTemplateFields(vb.Value, raw.Name, j, "value"); err != nil {
			return nil, err
		}

		oidTmpl, err := template.New(raw.Name + ".vb" + fmt.Sprint(j) + ".oid").Parse(vb.OID)
		if err != nil {
			return nil, fmt.Errorf("trap catalog: %s entry %q varbind %d: oid template parse: %w",
				source, raw.Name, j, err)
		}
		valTmpl, err := template.New(raw.Name + ".vb" + fmt.Sprint(j) + ".value").Parse(vb.Value)
		if err != nil {
			return nil, fmt.Errorf("trap catalog: %s entry %q varbind %d: value template parse: %w",
				source, raw.Name, j, err)
		}

		entry.Varbinds = append(entry.Varbinds, VarbindTemplate{
			Type:     vb.Type,
			OIDTmpl:  oidTmpl,
			ValTmpl:  valTmpl,
			rawOID:   vb.OID,
			rawValue: vb.Value,
		})
	}
	return entry, nil
}

// validateVarbindOID rejects the reserved OIDs that the encoder prepends
// automatically. Accepts templates (anything containing "{{") as a pass — the
// reserved OIDs are literal strings, so a template'd OID cannot collide.
//
// snmpTrapEnterprise.0 is rejected in body varbinds because it has its own
// top-level catalog field (`snmpTrapEnterprise`); including it in body
// varbinds would produce a duplicate on the wire.
func validateVarbindOID(raw, entryName string, idx int) error {
	if strings.Contains(raw, "{{") {
		return nil
	}
	norm := strings.TrimPrefix(raw, ".")
	switch norm {
	case oidSysUpTime0, oidSnmpTrapOID0:
		return fmt.Errorf("trap catalog: entry %q varbind %d: OID %s is reserved "+
			"(sysUpTime.0 and snmpTrapOID.0 are prepended automatically by the encoder)",
			entryName, idx, raw)
	case oidSnmpTrapEnterprise0:
		return fmt.Errorf("trap catalog: entry %q varbind %d: OID %s is reserved — "+
			"use the entry-level `snmpTrapEnterprise` field instead of a body varbind",
			entryName, idx, raw)
	}
	return nil
}

// maxDottedOIDLen caps the length of top-level literal OID fields (currently
// only snmpTrapEnterprise). Well under the UDP MTU budget and comfortably
// larger than any real enterprise OID.
const maxDottedOIDLen = 256

// validateDottedOID rejects malformed literal dotted-decimal OIDs:
// empty strings, strings over maxDottedOIDLen, single-arc, trailing dot,
// empty arcs (consecutive dots), and non-numeric characters. Used on
// literal-OID fields (snmpTrapEnterprise); body varbinds use a template
// grammar and go through validateVarbindOID instead.
func validateDottedOID(oid, entryName, field string) error {
	if oid == "" {
		return fmt.Errorf("entry %q %s: OID is empty", entryName, field)
	}
	if len(oid) > maxDottedOIDLen {
		return fmt.Errorf("entry %q %s: OID length %d exceeds max %d",
			entryName, field, len(oid), maxDottedOIDLen)
	}
	if strings.HasSuffix(oid, ".") {
		return fmt.Errorf("entry %q %s: OID %q has trailing dot", entryName, field, oid)
	}
	arcs := strings.Split(oid, ".")
	if len(arcs) < 2 {
		return fmt.Errorf("entry %q %s: OID %q must have at least two arcs",
			entryName, field, oid)
	}
	for _, arc := range arcs {
		if arc == "" {
			return fmt.Errorf("entry %q %s: OID %q has an empty arc",
				entryName, field, oid)
		}
		for _, r := range arc {
			if r < '0' || r > '9' {
				return fmt.Errorf("entry %q %s: OID %q contains non-numeric character %q",
					entryName, field, oid, r)
			}
		}
	}
	return nil
}

// validateTemplateFields finds every {{.Name}} reference in s and rejects any
// Name that isn't in allowedTemplateFields. The check runs at catalog load,
// BEFORE text/template parses — we want a clearer error message than the
// undefined-variable error text/template would produce at evaluation time.
func validateTemplateFields(s, entryName string, vbIdx int, which string) error {
	// Scan for `{{.Ident}}` tokens. We intentionally accept only the simple
	// field-access form; pipelines, functions, and ranges are out of grammar.
	rest := s
	for {
		open := strings.Index(rest, "{{")
		if open < 0 {
			return nil
		}
		close := strings.Index(rest[open:], "}}")
		if close < 0 {
			return fmt.Errorf("trap catalog: entry %q varbind %d %s: unterminated %q",
				entryName, vbIdx, which, "{{")
		}
		expr := strings.TrimSpace(rest[open+2 : open+close])
		if !strings.HasPrefix(expr, ".") {
			return fmt.Errorf("trap catalog: entry %q varbind %d %s: only simple field "+
				"access is allowed (e.g. {{.IfIndex}}); got %q",
				entryName, vbIdx, which, expr)
		}
		field := strings.TrimPrefix(expr, ".")
		if strings.ContainsAny(field, " \t\n|(){}") {
			return fmt.Errorf("trap catalog: entry %q varbind %d %s: only simple field "+
				"access is allowed (e.g. {{.IfIndex}}); got %q",
				entryName, vbIdx, which, expr)
		}
		if _, ok := allowedTemplateFields[field]; !ok {
			return fmt.Errorf("trap catalog: entry %q varbind %d %s: unknown template field "+
				"%q (allowed: IfIndex, IfName, Uptime, Now, DeviceIP, SysName, Model, Serial, ChassisID)",
				entryName, vbIdx, which, field)
		}
		rest = rest[open+close+2:]
	}
}

// Pick selects a catalog entry via weighted-random draw. rnd must be non-nil.
func (c *Catalog) Pick(rnd *rand.Rand) *CatalogEntry {
	if c == nil || c.schedTotalWeight <= 0 {
		return nil // empty or all-role-tagged → no scheduler-driven trap
	}
	// Linear scan over the schedulable (untagged) subset: role-tagged entries
	// fire from state transitions, not the scheduler. Catalog sizes are small.
	r := rnd.Intn(c.schedTotalWeight)
	for i, cum := range c.schedCumulativeW {
		if r < cum {
			return c.schedEntries[i]
		}
	}
	return c.schedEntries[len(c.schedEntries)-1]
}

// Resolve evaluates the entry's templates against ctx and overrides, producing
// Varbinds ready for the PDU encoder. overrides, when non-nil, replace the
// corresponding fields in ctx (e.g. "IfIndex": "7" pins that field for the
// POST /api/v1/devices/{ip}/trap use-case).
func (e *CatalogEntry) Resolve(ctx TemplateCtx, overrides map[string]string) ([]Varbind, error) {
	if len(overrides) > 0 {
		if v, ok := overrides["IfIndex"]; ok {
			n, err := parseIntField(v, "IfIndex")
			if err != nil {
				return nil, err
			}
			ctx.IfIndex = n
		}
		if v, ok := overrides["Uptime"]; ok {
			n, err := parseIntField(v, "Uptime")
			if err != nil {
				return nil, err
			}
			ctx.Uptime = uint32(n)
		}
		if v, ok := overrides["Now"]; ok {
			n, err := parseIntField(v, "Now")
			if err != nil {
				return nil, err
			}
			ctx.Now = int64(n)
		}
		if v, ok := overrides["DeviceIP"]; ok {
			ctx.DeviceIP = v
		}
		if v, ok := overrides["IfName"]; ok {
			ctx.IfName = v
		}
		if v, ok := overrides["SysName"]; ok {
			ctx.SysName = v
		}
		if v, ok := overrides["Model"]; ok {
			ctx.Model = v
		}
		if v, ok := overrides["Serial"]; ok {
			ctx.Serial = v
		}
		if v, ok := overrides["ChassisID"]; ok {
			ctx.ChassisID = v
		}
		if v, ok := overrides["NowLocal"]; ok {
			ctx.NowLocal = v
		}
		if v, ok := overrides["Detail"]; ok {
			ctx.Detail = v
		}
		for k := range overrides {
			if _, ok := allowedTemplateFields[k]; !ok {
				return nil, fmt.Errorf("trap varbind override: unknown field %q", k)
			}
		}
	}

	out := make([]Varbind, 0, len(e.Varbinds))
	var buf bytes.Buffer
	for i, vt := range e.Varbinds {
		buf.Reset()
		if err := vt.OIDTmpl.Execute(&buf, ctx); err != nil {
			return nil, fmt.Errorf("trap %q varbind %d oid resolve: %w", e.Name, i, err)
		}
		oid := buf.String()
		buf.Reset()
		if err := vt.ValTmpl.Execute(&buf, ctx); err != nil {
			return nil, fmt.Errorf("trap %q varbind %d value resolve: %w", e.Name, i, err)
		}
		out = append(out, Varbind{
			OID:   oid,
			Type:  vt.Type,
			Value: buf.String(),
		})
	}
	return out, nil
}

func parseIntField(s, name string) (int, error) {
	// Tolerant parse: the HTTP body ships overrides as strings, but the
	// template fields are integers.
	var n int
	if _, err := fmt.Sscanf(s, "%d", &n); err != nil {
		return 0, fmt.Errorf("trap varbind override %s: expected integer, got %q", name, s)
	}
	return n, nil
}
