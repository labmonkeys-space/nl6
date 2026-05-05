/*
 * © 2025 Labmonkeys Space
 *
 * Layer 8 Ecosystem is licensed under the Apache License, Version 2.0.
 * You may obtain a copy of the License at:
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

// Syslog catalog loader and selector.
//
// Mirrors the shape of trap_catalog.go — same embedded FS pattern, same
// weighted-random Pick, same strict text/template field validation. Key
// differences from the trap catalog:
//   - entries carry RFC 5424 / 3164 metadata (facility, severity, appName,
//     msgId, structuredData) instead of SNMP varbinds
//   - the "varbind template" vocabulary is six fields instead of four
//     (adds SysName, IfName)
//   - an MTU-safety dry-render at load time rejects catalog entries whose
//     rendered output could exceed 1400 bytes (design.md §D12)

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
	"text/template"
	"time"
)

//go:embed resources/_common/syslog.json
var embeddedSyslogCatalogFS embed.FS

const embeddedSyslogCatalogPath = "resources/_common/syslog.json"

// maxSyslogMessageBytes is the dry-render ceiling enforced at catalog load
// time (design.md §D12). 1400 leaves headroom below the typical 1500-byte
// Ethernet MTU for IP + UDP headers and any small collector-side framing.
const maxSyslogMessageBytes = 1400

// allowedSyslogTemplateFields enumerates the nine-field unified template
// vocabulary shared with the trap subsystem (design.md §D3 unified vocab
// decision). Any other {{.Name}} reference in `template` / `hostname` /
// `structuredData` value strings is rejected at catalog load time.
//
// Class 1 device-context fields (SysName, Model, Serial, ChassisID,
// IfName) are populated per fire from FieldResolver; the existing four
// are per-fire scalars from the scheduler/exporter.
var allowedSyslogTemplateFields = map[string]struct{}{
	"DeviceIP":  {},
	"SysName":   {},
	"IfIndex":   {},
	"IfName":    {},
	"Now":       {},
	"Uptime":    {},
	"Model":     {},
	"Serial":    {},
	"ChassisID": {},
}

// SyslogFacility is an RFC 5424 facility value (0..23). We store the numeric
// form post-parse; the catalog JSON accepts either canonical names or ints.
type SyslogFacility uint8

// SyslogSeverity is an RFC 5424 severity value (0..7).
type SyslogSeverity uint8

// Canonical facility names per RFC 5424 Table 1. The map is used to translate
// the catalog's string form into the numeric form stored on parsed entries.
var syslogFacilityNames = map[string]SyslogFacility{
	"kern":     0,
	"user":     1,
	"mail":     2,
	"daemon":   3,
	"auth":     4,
	"syslog":   5,
	"lpr":      6,
	"news":     7,
	"uucp":     8,
	"cron":     9,
	"authpriv": 10,
	"ftp":      11,
	"ntp":      12,
	"audit":    13,
	"alert":    14,
	"clock":    15,
	"local0":   16,
	"local1":   17,
	"local2":   18,
	"local3":   19,
	"local4":   20,
	"local5":   21,
	"local6":   22,
	"local7":   23,
}

// Canonical severity names per RFC 5424 Table 2. Keys are lowercase so the
// catalog accepts "error" and "err" interchangeably.
var syslogSeverityNames = map[string]SyslogSeverity{
	"emerg":   0,
	"alert":   1,
	"crit":    2,
	"err":     3,
	"error":   3,
	"warning": 4,
	"warn":    4,
	"notice":  5,
	"info":    6,
	"debug":   7,
}

// syslogFacilityJSON is the JSON-friendly form of a facility value: accepts
// either an integer (0..23) or a canonical string name. We implement
// UnmarshalJSON rather than forcing the catalog author to pick one form.
type syslogFacilityJSON struct {
	value SyslogFacility
	set   bool
}

func (f *syslogFacilityJSON) UnmarshalJSON(data []byte) error {
	var asInt int
	if err := json.Unmarshal(data, &asInt); err == nil {
		if asInt < 0 || asInt > 23 {
			return fmt.Errorf("facility integer %d out of range (0..23)", asInt)
		}
		f.value = SyslogFacility(asInt)
		f.set = true
		return nil
	}
	var asStr string
	if err := json.Unmarshal(data, &asStr); err != nil {
		return fmt.Errorf("facility must be a string name or integer (got %s)", string(data))
	}
	v, ok := syslogFacilityNames[strings.ToLower(asStr)]
	if !ok {
		return fmt.Errorf("unknown facility name %q (valid: kern, user, mail, daemon, auth, "+
			"syslog, lpr, news, uucp, cron, authpriv, ftp, ntp, audit, alert, clock, "+
			"local0..local7)", asStr)
	}
	f.value = v
	f.set = true
	return nil
}

// syslogSeverityJSON mirrors syslogFacilityJSON for severities (0..7).
type syslogSeverityJSON struct {
	value SyslogSeverity
	set   bool
}

func (s *syslogSeverityJSON) UnmarshalJSON(data []byte) error {
	var asInt int
	if err := json.Unmarshal(data, &asInt); err == nil {
		if asInt < 0 || asInt > 7 {
			return fmt.Errorf("severity integer %d out of range (0..7)", asInt)
		}
		s.value = SyslogSeverity(asInt)
		s.set = true
		return nil
	}
	var asStr string
	if err := json.Unmarshal(data, &asStr); err != nil {
		return fmt.Errorf("severity must be a string name or integer (got %s)", string(data))
	}
	v, ok := syslogSeverityNames[strings.ToLower(asStr)]
	if !ok {
		return fmt.Errorf("unknown severity name %q (valid: emerg, alert, crit, err/error, "+
			"warning/warn, notice, info, debug)", asStr)
	}
	s.value = v
	s.set = true
	return nil
}

// syslogCatalogEntryJSON is the on-disk shape of one catalog entry.
type syslogCatalogEntryJSON struct {
	Name           string              `json:"name"`
	Weight         int                 `json:"weight"`
	Facility       syslogFacilityJSON  `json:"facility"`
	Severity       syslogSeverityJSON  `json:"severity"`
	AppName        string              `json:"appName"`
	MsgID          string              `json:"msgId"`
	StructuredData map[string]string   `json:"structuredData"`
	Hostname       string              `json:"hostname"`
	Template       string              `json:"template"`
}

// syslogCatalogJSON is the on-disk shape of the whole catalog file. The
// "comment" field is ignored so authors can annotate files. The "extends"
// field is meaningful only on per-type catalog files — it controls whether
// the per-type catalog merges on top of the universal fallback (nil/true)
// or fully replaces it for that device type (false).
type syslogCatalogJSON struct {
	Comment string                   `json:"comment,omitempty"`
	Extends *bool                    `json:"extends,omitempty"`
	Entries []syslogCatalogEntryJSON `json:"entries"`
}

// syslogSDEntry is one pre-compiled structured-data key/value pair. `Tmpl`
// is non-nil when the source value contained a template directive; in that
// case `Raw` is kept only for error messages. When `Tmpl` is nil the source
// was a literal and `Raw` is used verbatim. Order is fixed at catalog load
// so RFC 5424 output is deterministic across renders.
type syslogSDEntry struct {
	Key  string
	Tmpl *template.Template
	Raw  string
}

// SyslogCatalogEntry is one parsed catalog entry. `TemplateTmpl` and
// `HostnameTmpl` are nil when the corresponding source string was empty;
// callers must check before invoking Execute.
type SyslogCatalogEntry struct {
	Name           string
	Weight         int
	Facility       SyslogFacility
	Severity       SyslogSeverity
	AppName        string
	MsgID          string
	StructuredData []syslogSDEntry // sorted by Key; pre-compiled
	Hostname       string          // raw source — empty means "use default derivation"
	HostnameTmpl   *template.Template
	Template       string // raw source — may be empty
	TemplateTmpl   *template.Template
}

// SyslogCatalog is the whole parsed catalog plus cached weight metadata for
// Pick. Immutable after load; safe for concurrent read.
//
// Concurrency note: the catalog is safe to share across goroutines, but
// the `*rand.Rand` argument to `Pick` is NOT — math/rand's Rand is not
// concurrency-safe. Scheduler code must own a per-goroutine Rand or
// protect a shared one with a mutex.
type SyslogCatalog struct {
	Entries     []*SyslogCatalogEntry
	ByName      map[string]*SyslogCatalogEntry
	Extends     bool
	cumulativeW []int
	totalWeight int
}

// SyslogTemplateCtx is the data passed to text/template at fire time.
// Matches the nine-field unified vocabulary in
// `allowedSyslogTemplateFields` exactly.
type SyslogTemplateCtx struct {
	DeviceIP  string
	SysName   string
	IfIndex   int
	IfName    string
	Now       int64  // Unix epoch seconds
	Uptime    uint32 // 1/100s ticks since device start
	Model     string // human-readable model from slug → label
	Serial    string // `SN<hex>` synthesised from device IP
	ChassisID string // MAC-style chassis ID synthesised from device IP
}

// SyslogResolved is a catalog entry rendered against a concrete context. It
// is the direct input to the wire encoders in syslog_wire.go.
type SyslogResolved struct {
	Facility       SyslogFacility
	Severity       SyslogSeverity
	AppName        string
	MsgID          string
	Hostname       string // empty means "caller derives from SysName/DeviceIP"
	StructuredData []SyslogSDPair
	Message        string
}

// SyslogSDPair is one structured-data key/value after template resolution.
type SyslogSDPair struct {
	Key   string
	Value string
}

// LoadEmbeddedSyslogCatalog parses the universal catalog compiled into the
// binary via //go:embed. The feature works out-of-box — no -syslog-catalog
// flag or filesystem access is needed for the default catalog.
func LoadEmbeddedSyslogCatalog() (*SyslogCatalog, error) {
	data, err := embeddedSyslogCatalogFS.ReadFile(embeddedSyslogCatalogPath)
	if err != nil {
		return nil, fmt.Errorf("syslog catalog: embedded read failed: %w", err)
	}
	return parseSyslogCatalog(data, "<embedded "+embeddedSyslogCatalogPath+">")
}

// LoadSyslogCatalogFromFile parses a user-supplied catalog file. Replaces the
// embedded catalog entirely — there is no merge (design.md §D11).
func LoadSyslogCatalogFromFile(path string) (*SyslogCatalog, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("syslog catalog: reading %q: %w", path, err)
	}
	return parseSyslogCatalog(data, path)
}

func parseSyslogCatalog(data []byte, source string) (*SyslogCatalog, error) {
	var doc syslogCatalogJSON
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&doc); err != nil {
		return nil, fmt.Errorf("syslog catalog: parsing %s: %w", source, err)
	}
	if len(doc.Entries) == 0 {
		return nil, fmt.Errorf("syslog catalog: %s has no entries", source)
	}

	cat := &SyslogCatalog{
		Entries: make([]*SyslogCatalogEntry, 0, len(doc.Entries)),
		ByName:  make(map[string]*SyslogCatalogEntry, len(doc.Entries)),
		Extends: doc.Extends == nil || *doc.Extends, // default true when field absent
	}
	for i, raw := range doc.Entries {
		entry, err := compileSyslogEntry(raw, source, i)
		if err != nil {
			return nil, err
		}
		if _, dup := cat.ByName[entry.Name]; dup {
			return nil, fmt.Errorf("syslog catalog: %s entry %d: duplicate name %q", source, i, entry.Name)
		}
		cat.Entries = append(cat.Entries, entry)
		cat.ByName[entry.Name] = entry
	}

	if err := cat.recomputeWeights(); err != nil {
		return nil, fmt.Errorf("syslog catalog: %s %w", source, err)
	}
	return cat, nil
}

// recomputeWeights rebuilds cumulativeW and totalWeight from Entries. Used
// at parse time and after MergeOverlay.
func (c *SyslogCatalog) recomputeWeights() error {
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
	return nil
}

// MergeOverlay returns a new SyslogCatalog that overlays `overlay` on `c`
// (the universal base). Same-named entries in overlay replace c's; unique
// entries append; c-only entries carry through. Weights recomputed over
// the merged set. Neither input is mutated.
func (c *SyslogCatalog) MergeOverlay(overlay *SyslogCatalog) *SyslogCatalog {
	if c == nil {
		return overlay
	}
	if overlay == nil || len(overlay.Entries) == 0 {
		out := &SyslogCatalog{
			Entries: append([]*SyslogCatalogEntry(nil), c.Entries...),
			ByName:  make(map[string]*SyslogCatalogEntry, len(c.Entries)),
			Extends: true,
		}
		for _, e := range out.Entries {
			out.ByName[e.Name] = e
		}
		if err := out.recomputeWeights(); err != nil {
			log.Printf("syslog catalog: MergeOverlay(empty overlay) produced invalid weights: %v", err)
		}
		return out
	}
	merged := &SyslogCatalog{
		Entries: make([]*SyslogCatalogEntry, 0, len(c.Entries)+len(overlay.Entries)),
		ByName:  make(map[string]*SyslogCatalogEntry, len(c.Entries)+len(overlay.Entries)),
		Extends: true,
	}
	for _, e := range c.Entries {
		if override, replaced := overlay.ByName[e.Name]; replaced {
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
		merged.Entries = append(merged.Entries, e)
		merged.ByName[e.Name] = e
	}
	if err := merged.recomputeWeights(); err != nil {
		log.Printf("syslog catalog: MergeOverlay produced invalid weights: %v", err)
	}
	return merged
}

// ScanPerTypeSyslogCatalogs walks resourceDir for `<slug>/syslog.json` files
// and returns a map keyed by device-type slug. Each value is the merged
// catalog (on top of `universal` when extends=true, or a replacement when
// extends=false). Symmetric with ScanPerTypeTrapCatalogs.
func ScanPerTypeSyslogCatalogs(universal *SyslogCatalog, resourceDir string) (map[string]*SyslogCatalog, error) {
	result := make(map[string]*SyslogCatalog)
	entries, err := os.ReadDir(resourceDir)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			log.Printf("syslog catalog scan: resource dir %q not found — per-type overlays disabled",
				resourceDir)
			return result, nil
		}
		if errors.Is(err, fs.ErrPermission) {
			log.Printf("syslog catalog scan: permission denied reading %q — per-type overlays disabled",
				resourceDir)
			return result, nil
		}
		return nil, fmt.Errorf("syslog catalog scan: reading %q: %w", resourceDir, err)
	}
	// Mirror the log-once-per-scan pattern on the trap side so a
	// systematic perms mismatch doesn't spam N lines at startup.
	permissionLoggedThisScan := false
	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}
		// Lowercase to match resourceDirName (used by deviceTypesByIP).
		slug := strings.ToLower(entry.Name())
		if strings.HasPrefix(slug, "_") {
			continue
		}
		path := filepath.Join(resourceDir, entry.Name(), "syslog.json")
		info, err := os.Stat(path)
		if err != nil {
			if errors.Is(err, fs.ErrPermission) && !permissionLoggedThisScan {
				log.Printf("syslog catalog scan: permission denied on %q — per-type overlay for %q skipped (further permission errors this scan suppressed)",
					path, slug)
				permissionLoggedThisScan = true
			}
			continue
		}
		if info.IsDir() {
			continue
		}
		perType, err := LoadSyslogCatalogFromFile(path)
		if err != nil {
			return nil, fmt.Errorf("per-type syslog catalog %q: %w", slug, err)
		}
		if perType.Extends {
			result[slug] = universal.MergeOverlay(perType)
		} else {
			result[slug] = perType
		}
	}
	return result, nil
}

func compileSyslogEntry(raw syslogCatalogEntryJSON, source string, idx int) (*SyslogCatalogEntry, error) {
	if raw.Name == "" {
		return nil, fmt.Errorf("syslog catalog: %s entry %d: name is required", source, idx)
	}
	if !raw.Facility.set {
		return nil, fmt.Errorf("syslog catalog: %s entry %q: facility is required", source, raw.Name)
	}
	if !raw.Severity.set {
		return nil, fmt.Errorf("syslog catalog: %s entry %q: severity is required", source, raw.Name)
	}
	if raw.AppName == "" {
		return nil, fmt.Errorf("syslog catalog: %s entry %q: appName is required "+
			"(RFC 3164 has no NILVALUE — every entry must name the emitting app)",
			source, raw.Name)
	}
	weight := raw.Weight
	// weight == 0 is coerced to 1 for consistency with trap_catalog.go behaviour.
	// Operators who want "never pick" should omit the entry rather than set weight 0.
	if weight == 0 {
		weight = 1
	}
	if weight < 0 {
		return nil, fmt.Errorf("syslog catalog: %s entry %q: weight must be non-negative", source, raw.Name)
	}

	entry := &SyslogCatalogEntry{
		Name:     raw.Name,
		Weight:   weight,
		Facility: raw.Facility.value,
		Severity: raw.Severity.value,
		AppName:  raw.AppName,
		MsgID:    raw.MsgID,
		Hostname: raw.Hostname,
		Template: raw.Template,
	}

	// Validate template fields in every templatable string before parsing
	// the templates themselves. This gives a clearer error than
	// text/template's "undefined variable" message at evaluation time.
	for _, pair := range []struct {
		value string
		which string
	}{
		{raw.Template, "template"},
		{raw.Hostname, "hostname"},
	} {
		if pair.value == "" {
			continue
		}
		if err := validateSyslogTemplateFields(pair.value, raw.Name, pair.which); err != nil {
			return nil, err
		}
	}

	if raw.Template != "" {
		tmpl, err := template.New(raw.Name + ".template").Parse(raw.Template)
		if err != nil {
			return nil, fmt.Errorf("syslog catalog: %s entry %q template parse: %w", source, raw.Name, err)
		}
		entry.TemplateTmpl = tmpl
	}
	if raw.Hostname != "" {
		tmpl, err := template.New(raw.Name + ".hostname").Parse(raw.Hostname)
		if err != nil {
			return nil, fmt.Errorf("syslog catalog: %s entry %q hostname parse: %w", source, raw.Name, err)
		}
		entry.HostnameTmpl = tmpl
	}

	// Structured-data: validate each key against RFC 5424 §6.3.3 SD-NAME,
	// field-validate the value, and pre-compile its template at load time
	// (spec Requirement "Varbind templating" — templates parsed once at
	// catalog load, not at every fire).
	if len(raw.StructuredData) > 0 {
		entry.StructuredData = make([]syslogSDEntry, 0, len(raw.StructuredData))
		keys := make([]string, 0, len(raw.StructuredData))
		for k := range raw.StructuredData {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		for _, k := range keys {
			if err := validateSyslogSDName(k, raw.Name); err != nil {
				return nil, err
			}
			v := raw.StructuredData[k]
			if err := validateSyslogTemplateFields(v, raw.Name, "structuredData."+k); err != nil {
				return nil, err
			}
			sd := syslogSDEntry{Key: k, Raw: v}
			if strings.Contains(v, "{{") {
				tmpl, err := template.New(raw.Name + ".sd." + k).Parse(v)
				if err != nil {
					return nil, fmt.Errorf("syslog catalog: %s entry %q structuredData[%s] parse: %w",
						source, raw.Name, k, err)
				}
				sd.Tmpl = tmpl
			}
			entry.StructuredData = append(entry.StructuredData, sd)
		}
	}

	// MTU-safety dry-render (design.md §D12). Render with worst-case values
	// for every template field using the *actual* 5424 encoder — an earlier
	// implementation used an approximation that underestimated in two ways
	// (SD-value escape expansion was ignored; per-SD-pair leading space
	// wasn't counted). Running the real encoder gives an exact upper bound
	// for the worst-case context, which is what the spec requires.
	if err := validateSyslogEntrySize(entry, source); err != nil {
		return nil, err
	}
	return entry, nil
}

// validateSyslogSDName rejects SD-NAME values that violate RFC 5424 §6.3.3.
// SD-NAME = 1*32PRINTUSASCII excluding `=`, SP, `]`, `"`.
func validateSyslogSDName(name, entryName string) error {
	if len(name) == 0 || len(name) > 32 {
		return fmt.Errorf("syslog catalog: entry %q structuredData key %q: length %d "+
			"violates RFC 5424 §6.3.3 (SD-NAME must be 1..32 characters)",
			entryName, name, len(name))
	}
	for i := 0; i < len(name); i++ {
		c := name[i]
		if c < 33 || c > 126 || c == '=' || c == ']' || c == '"' {
			return fmt.Errorf("syslog catalog: entry %q structuredData key %q: invalid "+
				"character %q at position %d (RFC 5424 §6.3.3 SD-NAME excludes "+
				"SP, `=`, `]`, `\"` and non-printable ASCII)",
				entryName, name, string(c), i)
		}
	}
	return nil
}

// validateSyslogTemplateFields scans s for `{{.Ident}}` tokens and rejects
// any Ident outside the approved six fields. Pipelines, functions, and
// ranges are out of grammar.
func validateSyslogTemplateFields(s, entryName, which string) error {
	rest := s
	for {
		open := strings.Index(rest, "{{")
		if open < 0 {
			return nil
		}
		closeIdx := strings.Index(rest[open:], "}}")
		if closeIdx < 0 {
			return fmt.Errorf("syslog catalog: entry %q %s: unterminated %q", entryName, which, "{{")
		}
		expr := strings.TrimSpace(rest[open+2 : open+closeIdx])
		if !strings.HasPrefix(expr, ".") {
			return fmt.Errorf("syslog catalog: entry %q %s: only simple field access is allowed "+
				"(e.g. {{.IfIndex}}); got %q", entryName, which, expr)
		}
		field := strings.TrimPrefix(expr, ".")
		if strings.ContainsAny(field, " \t\n|(){}") {
			return fmt.Errorf("syslog catalog: entry %q %s: only simple field access is allowed "+
				"(e.g. {{.IfIndex}}); got %q", entryName, which, expr)
		}
		if _, ok := allowedSyslogTemplateFields[field]; !ok {
			return fmt.Errorf("syslog catalog: entry %q %s: unknown template field %q "+
				"(allowed: DeviceIP, SysName, IfIndex, IfName, Now, Uptime, Model, Serial, ChassisID)",
				entryName, which, field)
		}
		rest = rest[open+closeIdx+2:]
	}
}

// validateSyslogEntrySize renders the entry against a worst-case context
// using the actual 5424 encoder and rejects it if the encoded size exceeds
// maxSyslogMessageBytes. Using the real encoder (not an approximation)
// means the check accounts for SD-value escape expansion, per-pair
// leading spaces, header token sanitisation, and every other format
// detail the encoder performs.
func validateSyslogEntrySize(entry *SyslogCatalogEntry, source string) error {
	worst := SyslogTemplateCtx{
		DeviceIP:  "255.255.255.255",
		SysName:   strings.Repeat("H", 64),
		IfIndex:   65535,
		IfName:    strings.Repeat("X", 32),
		Now:       9999999999,
		Uptime:    0xFFFFFFFF,
		Model:     strings.Repeat("M", 48), // longest realistic: "NVIDIA DGX A100" → 15 chars; 48 is a comfortable upper bound
		Serial:    "SNFFFFFFFF",             // max-width synthesised format
		ChassisID: "02:42:ff:ff:ff:ff",      // max-width synthesised format
	}
	resolved, err := entry.resolveAgainst(worst, nil)
	if err != nil {
		return fmt.Errorf("syslog catalog: %s entry %q dry-render: %w", source, entry.Name, err)
	}
	// When the catalog entry has no hostname template, simulate the
	// exporter-level fallback to sysName so the worst-case bytes include
	// a realistic HOSTNAME.
	if resolved.Hostname == "" {
		resolved.Hostname = worst.SysName
	}

	var buf bytes.Buffer
	enc := &RFC5424Encoder{}
	// Use a fixed worst-case timestamp — the exact value doesn't matter,
	// TIMESTAMP width is constant for the 5424 format.
	if err := enc.Encode(&buf, resolved, time.Unix(worst.Now, 0).UTC()); err != nil {
		// The encoder itself enforces MaxMessageSize; surface that error
		// with the catalog context so operators know which entry tripped.
		return fmt.Errorf("syslog catalog: %s entry %q: dry-encoded size exceeds MTU-safety "+
			"ceiling (%w) — shorten the template or structured-data fields",
			source, entry.Name, err)
	}
	if buf.Len() > maxSyslogMessageBytes {
		return fmt.Errorf("syslog catalog: %s entry %q: dry-rendered size %d exceeds MTU-safety "+
			"ceiling of %d bytes — shorten the template or structured-data fields",
			source, entry.Name, buf.Len(), maxSyslogMessageBytes)
	}
	return nil
}

// Pick selects a catalog entry via weighted-random draw. rnd must be non-nil.
func (c *SyslogCatalog) Pick(rnd *rand.Rand) *SyslogCatalogEntry {
	if c == nil || len(c.Entries) == 0 || c.totalWeight <= 0 {
		return nil
	}
	r := rnd.Intn(c.totalWeight)
	for i, cum := range c.cumulativeW {
		if r < cum {
			return c.Entries[i]
		}
	}
	return c.Entries[len(c.Entries)-1]
}

// Resolve evaluates the entry's templates against ctx and overrides, producing
// a SyslogResolved ready for the wire encoder. overrides, when non-nil,
// replace the corresponding fields in ctx — used by the on-demand HTTP
// endpoint to pin specific template values for CI/test-harness fires.
func (e *SyslogCatalogEntry) Resolve(ctx SyslogTemplateCtx, overrides map[string]string) (SyslogResolved, error) {
	if len(overrides) > 0 {
		if v, ok := overrides["DeviceIP"]; ok {
			ctx.DeviceIP = v
		}
		if v, ok := overrides["SysName"]; ok {
			ctx.SysName = v
		}
		if v, ok := overrides["IfIndex"]; ok {
			n, err := parseIntFieldSyslog(v, "IfIndex")
			if err != nil {
				return SyslogResolved{}, err
			}
			ctx.IfIndex = n
		}
		if v, ok := overrides["IfName"]; ok {
			ctx.IfName = v
		}
		if v, ok := overrides["Now"]; ok {
			n, err := parseIntFieldSyslog(v, "Now")
			if err != nil {
				return SyslogResolved{}, err
			}
			ctx.Now = int64(n)
		}
		if v, ok := overrides["Uptime"]; ok {
			n, err := parseIntFieldSyslog(v, "Uptime")
			if err != nil {
				return SyslogResolved{}, err
			}
			ctx.Uptime = uint32(n)
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
		for k := range overrides {
			if _, ok := allowedSyslogTemplateFields[k]; !ok {
				return SyslogResolved{}, fmt.Errorf("syslog template override: unknown field %q", k)
			}
		}
	}
	return e.resolveAgainst(ctx, nil)
}

// resolveAgainst does the template-execute pass. It is separate from Resolve
// so the catalog-load MTU check can reuse it with the worst-case context
// without re-applying overrides.
func (e *SyslogCatalogEntry) resolveAgainst(ctx SyslogTemplateCtx, _ map[string]string) (SyslogResolved, error) {
	out := SyslogResolved{
		Facility: e.Facility,
		Severity: e.Severity,
		AppName:  e.AppName,
		MsgID:    e.MsgID,
	}
	var buf bytes.Buffer
	if e.TemplateTmpl != nil {
		buf.Reset()
		if err := e.TemplateTmpl.Execute(&buf, ctx); err != nil {
			return SyslogResolved{}, fmt.Errorf("syslog %q template: %w", e.Name, err)
		}
		out.Message = buf.String()
	}
	if e.HostnameTmpl != nil {
		buf.Reset()
		if err := e.HostnameTmpl.Execute(&buf, ctx); err != nil {
			return SyslogResolved{}, fmt.Errorf("syslog %q hostname: %w", e.Name, err)
		}
		out.Hostname = buf.String()
	}
	if len(e.StructuredData) > 0 {
		out.StructuredData = make([]SyslogSDPair, 0, len(e.StructuredData))
		for _, sd := range e.StructuredData {
			if sd.Tmpl == nil {
				out.StructuredData = append(out.StructuredData, SyslogSDPair{Key: sd.Key, Value: sd.Raw})
				continue
			}
			buf.Reset()
			if err := sd.Tmpl.Execute(&buf, ctx); err != nil {
				return SyslogResolved{}, fmt.Errorf("syslog %q structuredData[%s]: %w", e.Name, sd.Key, err)
			}
			out.StructuredData = append(out.StructuredData, SyslogSDPair{Key: sd.Key, Value: buf.String()})
		}
	}
	return out, nil
}

// parseIntFieldSyslog is a strict decimal-integer parser for HTTP override
// payloads. Unlike `fmt.Sscanf("%d")`, which accepts trailing non-numeric
// bytes silently (`"3abc"` → 3), `strconv.Atoi` requires the entire string
// to be a well-formed integer.
func parseIntFieldSyslog(s, name string) (int, error) {
	n, err := strconv.Atoi(s)
	if err != nil {
		return 0, fmt.Errorf("syslog template override %s: expected integer, got %q", name, s)
	}
	return n, nil
}
