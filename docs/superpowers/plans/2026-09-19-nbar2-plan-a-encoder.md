# NBAR2 Plan A: AVC Encoder and Application Table Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** An IPFIX encoder that emits Cisco AVC style records (the 19 existing IEs plus `applicationId` and the two PEN 9 layer-7 fields) with RFC 7011 variable-length encoding and measured pagination, a `Tick` that counts and re-queues on the encoder's consumed count, and an application-table options datagram; all driven from a test-constructed catalog. Nothing in this plan is reachable from the REST API or flags yet; Plan B wires it.

**Architecture:** A new `IPFIXAVCEncoder` type in `ipfix_avc.go` holds a pointer to an immutable `avcCatalog` and implements `FlowEncoder` plus two type-asserted seams: `measuredFlowEncoder` (returns how many records it emitted; `Tick` re-queues the rest) and `appTableEncoder` (emits the RFC 6759 §4.3 options template). `FlowRecord` gains a 6-byte `AVC` index triple resolved against the catalog at encode time. The plain `IPFIXEncoder` is untouched, so non-AVC output is byte-identical by construction.

**Tech Stack:** Go 1.26, `encoding/binary`, existing test helpers (`testUDPListener`, `testSender`, `tickWithEncoder`, `fillExpiredFlows`, `decodeIPFIXPacket`).

**Spec:** `docs/superpowers/specs/2026-09-18-nbar2-ipfix-l7-export-design.md` sections 2 and 3, and section 1 "Outcome of unit 1". Evidence: `go/nl6/testdata/cisco-avc/{elements.tsv,NOTES.md}`, `go/nl6/testdata/rfc/rfc6759-application-information.txt`.

## Global Constraints

- New Go files carry the fork's SPDX short header, year 2026, no `Created by`:
  ```go
  /*
   * Copyright 2026 Ronny Trommer <ronny@no42.org>
   * SPDX-License-Identifier: Apache-2.0
   */
  ```
- Every IE number, PEN and fixed length the encoder emits is a named constant whose value a test reads back out of `testdata/cisco-avc/elements.tsv` (Task 1). No literal IE number appears anywhere else.
- Template IDs: 256 plain data (existing), 257 interface options (existing), **258 AVC data, 259 application table**. This resolves spec open question 5; both options tables may coexist on one device.
- Variable-length fields follow RFC 7011 §7: length under 255 is one byte; otherwise the byte `255` then a 2-byte big-endian length. The template declares length `0xFFFF`.
- Enterprise-specific field specifier (RFC 7011 §3.2): IE id with bit 15 set (2 bytes), field length (2 bytes), PEN (4 bytes). PEN 9 is Cisco.
- IE 42125 layout (spec §1 caveat, decided here): records are `URI\0` followed by a 2-byte **big-endian** hit count, repeated, with **no trailing delimiter**. Big-endian follows RFC 7011 §6.1.1's network byte order for integers; the encoding example `{URI\0countURI\0count}` governs over the prose format line. Both decisions are stated in a code comment beside the constant and in `docs/reference/flow-export.md`.
- A record the encoder cannot fit into an EMPTY datagram is dropped, counted once in `FlowTickStats.SendFailures`, and logged through the exporter's `sync.Once`-gated `logFirstEncodeErr`.
- `Tick` counts as sent exactly the records the encoder reports consumed, never `len(batch)`, on the measured path.
- Non-AVC encoders are not modified. `IPFIXEncoder`, `NetFlow9Encoder`, `NetFlow5Encoder`, `SFlowEncoder` keep every existing test green unchanged.
- Markdown one sentence per line, no em-dashes or en-dashes. Commits: Conventional Commits, `git commit -s`, `Assisted-by: ClaudeCode:<model>` immediately above `Signed-off-by`.
- Tests run from `go/`: `cd go && go test ./nl6/ -run <Name> -v`. Raise `minimumTestFunctions` in `test_inventory_test.go` by the number of `Test*` functions each task adds (Task 8 sets the final value).
- Work in a worktree on a branch off `main` (`feat/nbar2-plan-a-encoder`).

## Not in this plan

Plan B (catalog loader, embedded + per-type overlay, `-nbar2-catalog`, the load-time dry render that disables oversized entries and excludes them from the application table, application-first flow generation, the `nbar2` config field and its three rejections, the curated capability set, the byte-identity digest for non-AVC devices) and Plan C (ground-truth key extension, `l7_values[]`, IPFIXcol2 interop gate, veth capture). Each is written after the previous plan lands, so its types are real rather than placeholders.

---

### Task 1: Evidence-derived constants and the extract joins

**Files:**
- Create: `go/nl6/ipfix_avc.go` (constants only in this task)
- Test: `go/nl6/ipfix_avc_test.go`
- Modify: `go/nl6/cisco_avc_extract_test.go` (add the RFC join test)

**Interfaces:**
- Produces: constants `ciscoPEN`, `ipfixApplicationID`, `ipfixApplicationName`, `ipfixApplicationDescription`, `ciscoHTTPHost`, `ciscoHTTPURIStatistics`, `ipfixApplicationNameLen`, `ipfixApplicationDescriptionLen`, `ipfixAVCTemplateID`, `ipfixAppTableTemplateID`, `ipfixEnterpriseBit`.
- Consumes: `loadCiscoAVCExtract` from `cisco_avc_extract_test.go`.

- [ ] **Step 1: Write the failing tests**

Create `go/nl6/ipfix_avc_test.go`:

```go
/*
 * Copyright 2026 Ronny Trommer <ronny@no42.org>
 * SPDX-License-Identifier: Apache-2.0
 */

package main

import (
	"strconv"
	"testing"
)

// The encoder's IE table is DERIVED from testdata/cisco-avc/elements.tsv
// (spec section 1): a constant that disagrees with the extract fails by
// name here. This test cannot show the extract is right; it shows the code
// did not drift from it.
func TestIPFIXAVCConstantsMatchEvidence(t *testing.T) {
	_, elements := loadCiscoAVCExtract(t)
	want := map[string]struct {
		pen, id int
		got     int
	}{
		"applicationId":          {0, 95, ipfixApplicationID},
		"applicationName":        {0, 96, ipfixApplicationName},
		"applicationDescription": {0, 94, ipfixApplicationDescription},
		"HTTP Host":              {9, 45003, ciscoHTTPHost},
		"HTTP URI statistics":    {9, 42125, ciscoHTTPURIStatistics},
	}
	seen := map[string]bool{}
	for _, e := range elements {
		w, ok := want[e.Name]
		if !ok {
			continue
		}
		seen[e.Name] = true
		pen, _ := strconv.Atoi(e.PEN)
		id, _ := strconv.Atoi(e.ID)
		if pen != w.pen || id != w.id {
			t.Fatalf("test table for %q says pen=%d id=%d, extract says pen=%d id=%d: fix the test table only if the extract changed", e.Name, w.pen, w.id, pen, id)
		}
		if w.got != id {
			t.Errorf("constant for %q = %d, extract says %d", e.Name, w.got, id)
		}
		if e.Status == "unresolved" {
			t.Errorf("%q is unresolved in the extract and must not be encoded", e.Name)
		}
		switch e.Name {
		case "applicationName":
			if n, _ := strconv.Atoi(e.Length); n != ipfixApplicationNameLen {
				t.Errorf("applicationName length constant = %d, extract says %d", ipfixApplicationNameLen, n)
			}
		case "applicationDescription":
			if n, _ := strconv.Atoi(e.Length); n != ipfixApplicationDescriptionLen {
				t.Errorf("applicationDescription length constant = %d, extract says %d", ipfixApplicationDescriptionLen, n)
			}
		}
	}
	for name := range want {
		if !seen[name] {
			t.Errorf("extract has no row named %q", name)
		}
	}
	if ciscoPEN != 9 {
		t.Errorf("ciscoPEN = %d, want 9", ciscoPEN)
	}
	if ipfixAVCTemplateID != 258 || ipfixAppTableTemplateID != 259 {
		t.Errorf("template ids = %d/%d, want 258/259 (plan A global constraint)", ipfixAVCTemplateID, ipfixAppTableTemplateID)
	}
}
```

Append to `go/nl6/cisco_avc_extract_test.go`:

```go
// Every rfc6759-sourced element must appear in the checked-in RFC extract
// as `ElementId: <id>`. This is the join the final review of unit 1 asked
// for: without it a transposed IE number in elements.tsv passes every test.
func TestCiscoAVCExtract_RFC6759RowsJoinTheExtract(t *testing.T) {
	data, err := os.ReadFile(filepath.Join("testdata", "rfc", "rfc6759-application-information.txt"))
	if err != nil {
		t.Fatal(err)
	}
	text := string(data)
	_, elements := loadCiscoAVCExtract(t)
	joined := 0
	for _, e := range elements {
		cites := false
		for _, s := range e.Sources {
			if strings.TrimSpace(s) == "rfc6759" {
				cites = true
			}
		}
		if !cites {
			continue
		}
		joined++
		if !strings.Contains(text, "ElementId: "+e.ID) {
			t.Errorf("element %s/%s cites rfc6759 but the extract has no 'ElementId: %s'", e.PEN, e.ID, e.ID)
		}
		if !strings.Contains(text, e.Name) {
			t.Errorf("element %s/%s (%s) cites rfc6759 but the extract never names it", e.PEN, e.ID, e.Name)
		}
	}
	if joined < 3 {
		t.Fatalf("only %d rfc6759-sourced rows joined; expected at least applicationId, applicationName, applicationDescription", joined)
	}
}
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `cd go && go test ./nl6/ -run 'TestIPFIXAVCConstantsMatchEvidence|TestCiscoAVCExtract_RFC6759RowsJoinTheExtract' -v`
Expected: build failure `undefined: ipfixApplicationID` (and the other constants). The join test cannot run until the package builds, which is fine.

- [ ] **Step 3: Write the constants**

Create `go/nl6/ipfix_avc.go`:

```go
/*
 * Copyright 2026 Ronny Trommer <ronny@no42.org>
 * SPDX-License-Identifier: Apache-2.0
 */

package main

// Cisco AVC (NBAR2) export over IPFIX. Every number below is DERIVED from
// testdata/cisco-avc/elements.tsv and pinned by TestIPFIXAVCConstantsMatchEvidence;
// the provenance of each row is in testdata/cisco-avc/NOTES.md. Do not add an
// IE here without a row there.
const (
	// ciscoPEN is Cisco's IANA Private Enterprise Number.
	ciscoPEN = 9

	// IANA-registered application identity IEs (RFC 6759 sections 7.1.1 to 7.1.3).
	ipfixApplicationID          = 95 // applicationId: engine id (8 bits) + selector (24 bits)
	ipfixApplicationName        = 96 // applicationName, fixed 24 bytes in Cisco's option application-table
	ipfixApplicationDescription = 94 // applicationDescription, fixed 55 bytes in Cisco's option application-table

	// Cisco enterprise-specific layer-7 IEs (PEN 9), IPFIX only.
	ciscoHTTPHost          = 45003 // collect application http host; variable-length string
	ciscoHTTPURIStatistics = 42125 // collect application http uri statistics; see ipfixURIStatsLayout

	// Fixed lengths Cisco's 2015 AVC guide gives for option application-table.
	ipfixApplicationNameLen        = 24
	ipfixApplicationDescriptionLen = 55

	// Template ids. 256 is the plain data template and 257 the interface
	// option table (both existing); the AVC pair sits beside them so one
	// device can carry all four.
	ipfixAVCTemplateID      = 258
	ipfixAppTableTemplateID = 259

	// ipfixEnterpriseBit marks an enterprise-specific IE in a template field
	// specifier (RFC 7011 section 3.2); the 4-byte PEN follows the length.
	ipfixEnterpriseBit = 0x8000

	// ipfixVarLen is the template length that declares a variable-length
	// field (RFC 7011 section 7).
	ipfixVarLen = 0xFFFF
)

// ipfixURIStatsLayout documents the two decisions unit 1 left to the encoder
// for IE 42125 (testdata/cisco-avc/NOTES.md, "HTTP URI statistics (42125)
// layout"). Cisco's text gives "NULL (\0) is the delimiter." and the encoding
// example {URI\0countURI\0count}; it states no byte order and its prose
// format line shows a trailing delimiter its encoding example does not.
//
// Decision 1: the 2-byte hit count is BIG-ENDIAN, RFC 7011 section 6.1.1's
// network byte order for integers. Decision 2: the encoding example governs,
// so a record is `URI\0` + count, repeated, with NO trailing delimiter.
// Neither is Cisco-sourced; a capture from a real IOS-XE box would settle
// both, and the spec's fidelity exit rule applies to them until then.
const ipfixURIStatsLayout = "URI\\0 + uint16 big-endian count, repeated, no trailing delimiter"
```

- [ ] **Step 4: Run the tests to verify they pass**

Run: `cd go && go test ./nl6/ -run 'TestIPFIXAVCConstantsMatchEvidence|TestCiscoAVCExtract' -v`
Expected: PASS for all five tests.

- [ ] **Step 5: Verify detection power**

Temporarily change `ciscoHTTPHost = 45003` to `45030`, run `TestIPFIXAVCConstantsMatchEvidence`, confirm it fails naming "HTTP Host". Revert. Temporarily change elements.tsv row `0/95` id to `59`, run `TestCiscoAVCExtract_RFC6759RowsJoinTheExtract`, confirm it fails with `no 'ElementId: 59'`. Revert.

- [ ] **Step 6: Commit**

```bash
git add go/nl6/ipfix_avc.go go/nl6/ipfix_avc_test.go go/nl6/cisco_avc_extract_test.go
git commit -s -m "feat(nbar2): derive the AVC IE constants from the evidence extract" -m "Adds the extract-to-TSV join on ElementId that unit 1's final review named as the missing content check." -m "Assisted-by: ClaudeCode:<model>"
```

---

### Task 2: RFC 7011 §7 variable-length field writer

**Files:**
- Modify: `go/nl6/ipfix_avc.go`
- Test: `go/nl6/ipfix_avc_test.go`

**Interfaces:**
- Produces: `func putIPFIXVarLen(buf []byte, pos int, v []byte) (int, bool)` returning the new position and whether it fit; `func ipfixVarLenSize(n int) int` returning the on-wire size of an n-byte value including its length prefix.

- [ ] **Step 1: Write the failing test**

Append to `go/nl6/ipfix_avc_test.go`:

```go
// RFC 7011 section 7: a value shorter than 255 bytes carries a 1-byte length;
// otherwise the byte 255 then a 2-byte big-endian length. 254, 255 and 256
// are the boundary where variable-length encoders break.
func TestIPFIXVarLenBoundary(t *testing.T) {
	for _, n := range []int{0, 1, 254, 255, 256, 1000} {
		v := make([]byte, n)
		for i := range v {
			v[i] = byte('a' + i%26)
		}
		buf := make([]byte, n+3)
		pos, ok := putIPFIXVarLen(buf, 0, v)
		if !ok {
			t.Fatalf("n=%d: did not fit in %d bytes", n, len(buf))
		}
		if pos != ipfixVarLenSize(n) {
			t.Fatalf("n=%d: wrote %d bytes, ipfixVarLenSize says %d", n, pos, ipfixVarLenSize(n))
		}
		var gotLen, hdr int
		if buf[0] < 255 {
			gotLen, hdr = int(buf[0]), 1
		} else {
			gotLen, hdr = int(buf[1])<<8|int(buf[2]), 3
		}
		if n < 255 && hdr != 1 || n >= 255 && hdr != 3 {
			t.Fatalf("n=%d: header form %d bytes", n, hdr)
		}
		if gotLen != n || string(buf[hdr:pos]) != string(v) {
			t.Fatalf("n=%d: decoded length %d, payload mismatch=%v", n, gotLen, string(buf[hdr:pos]) != string(v))
		}
	}
	// Does not fit, one byte short in each length form: 253 bytes need 254;
	// 255 bytes need 258.
	if _, ok := putIPFIXVarLen(make([]byte, 253), 0, make([]byte, 253)); ok {
		t.Fatal("253-byte value needs 254 bytes and must not fit in 253")
	}
	if _, ok := putIPFIXVarLen(make([]byte, 257), 0, make([]byte, 255)); ok {
		t.Fatal("255-byte value needs 258 bytes and must not fit in 257")
	}
	// Too long to represent at all.
	if _, ok := putIPFIXVarLen(make([]byte, 70000), 0, make([]byte, 65536)); ok {
		t.Fatal("65536-byte value cannot be represented in a 2-byte length")
	}
}
```

- [ ] **Step 2: Run the test to verify it fails**

Run: `cd go && go test ./nl6/ -run TestIPFIXVarLenBoundary -v`
Expected: build failure `undefined: putIPFIXVarLen`.

- [ ] **Step 3: Implement**

Append to `go/nl6/ipfix_avc.go`:

```go
import "encoding/binary"

// ipfixVarLenSize is the on-wire size of an n-byte variable-length value
// including its RFC 7011 section 7 length prefix.
func ipfixVarLenSize(n int) int {
	if n < 255 {
		return 1 + n
	}
	return 3 + n
}

// putIPFIXVarLen writes v at pos as an RFC 7011 section 7 variable-length
// field and returns the new position. ok is false, and buf is untouched,
// when the value does not fit; the caller decides what a non-fit means.
// Values longer than 65535 bytes cannot be represented and never fit.
func putIPFIXVarLen(buf []byte, pos int, v []byte) (int, bool) {
	n := len(v)
	if n > 0xFFFF || pos+ipfixVarLenSize(n) > len(buf) {
		return pos, false
	}
	if n < 255 {
		buf[pos] = byte(n)
		pos++
	} else {
		buf[pos] = 255
		binary.BigEndian.PutUint16(buf[pos+1:], uint16(n))
		pos += 3
	}
	copy(buf[pos:], v)
	return pos + n, true
}
```

(Merge the import into the file's single import block.)

- [ ] **Step 4: Run the test to verify it passes**

Run: `cd go && go test ./nl6/ -run TestIPFIXVarLenBoundary -v`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add go/nl6/ipfix_avc.go go/nl6/ipfix_avc_test.go
git commit -s -m "feat(nbar2): add the RFC 7011 §7 variable-length field writer" -m "Assisted-by: ClaudeCode:<model>"
```

---

### Task 3: Catalog value types and the record's index triple

**Files:**
- Modify: `go/nl6/ipfix_avc.go`
- Modify: `go/nl6/flow_cache.go:26-49` (`FlowRecord`)
- Test: `go/nl6/ipfix_avc_test.go`

**Interfaces:**
- Produces:
  ```go
  type avcApplication struct {
      ID          uint32   // engine id << 24 | selector, as the wire carries it
      Name        string   // applicationName (truncated to 24 bytes on the wire)
      Description string   // applicationDescription (truncated to 55)
      Proto       uint8    // L4 protocol the application implies (Plan B uses it)
      DstPort     uint16   // destination port the application implies (Plan B uses it)
      Hosts       []string // HTTP host values; empty for non-HTTP applications
      URIs        []string // URI values used for HTTP URI statistics; empty for non-HTTP
  }
  type avcCatalog struct { apps []avcApplication }
  func newAVCCatalog(apps []avcApplication) *avcCatalog   // copies; immutable after
  func (c *avcCatalog) App(idx uint16) (*avcApplication, bool) // idx is 1-based; 0 = none
  func (c *avcCatalog) Len() int
  func avcApplicationID(engine uint8, selector uint32) uint32
  type avcRef struct { App, Host, URI uint16 } // all 1-based; 0 = absent
  ```
- `FlowRecord` gains `AVC avcRef` as its last field. The zero value means "no application", so every existing record and test is unchanged.

- [ ] **Step 1: Write the failing test**

Append to `go/nl6/ipfix_avc_test.go`:

```go
func testAVCCatalog() *avcCatalog {
	return newAVCCatalog([]avcApplication{
		{ID: avcApplicationID(13, 80), Name: "http", Description: "HTTP", Proto: 6, DstPort: 80,
			Hosts: []string{"www.example.com", "cdn.example.net"}, URIs: []string{"/index.html", "/api/v1/items"}},
		{ID: avcApplicationID(13, 443), Name: "ssl", Description: "Secure Socket Layer", Proto: 6, DstPort: 443},
		{ID: avcApplicationID(3, 53), Name: "dns", Description: "Domain Name System", Proto: 17, DstPort: 53},
	})
}

func TestAVCCatalogIndexing(t *testing.T) {
	c := testAVCCatalog()
	if c.Len() != 3 {
		t.Fatalf("Len = %d, want 3", c.Len())
	}
	if _, ok := c.App(0); ok {
		t.Fatal("index 0 must mean absent")
	}
	if _, ok := c.App(4); ok {
		t.Fatal("index past the end must be absent")
	}
	app, ok := c.App(1)
	if !ok || app.Name != "http" {
		t.Fatalf("App(1) = %+v ok=%v, want http", app, ok)
	}
	if got := avcApplicationID(13, 80); got != 13<<24|80 {
		t.Fatalf("avcApplicationID(13,80) = %#x, want %#x", got, 13<<24|80)
	}
	if got := avcApplicationID(13, 0x1FFFFFF); got&0xFFFFFF != 0xFFFFFF || got>>24 != 13 {
		t.Fatalf("selector must be masked to 24 bits, got %#x", got)
	}
	var r FlowRecord
	if r.AVC != (avcRef{}) {
		t.Fatal("zero FlowRecord must carry no application")
	}
}
```

- [ ] **Step 2: Run the test to verify it fails**

Run: `cd go && go test ./nl6/ -run TestAVCCatalogIndexing -v`
Expected: build failure `undefined: newAVCCatalog`.

- [ ] **Step 3: Implement the types**

Append to `go/nl6/ipfix_avc.go`:

```go
// avcApplication is one NBAR2 application as the encoder needs it. Plan B's
// catalog loader produces these; here they are constructed directly.
type avcApplication struct {
	ID          uint32
	Name        string
	Description string
	Proto       uint8
	DstPort     uint16
	Hosts       []string
	URIs        []string
}

// avcCatalog is an immutable, 1-based indexed set of applications. Index 0
// means "no application" so a zero avcRef on a FlowRecord is a plain record.
// FlowRecords carry INDICES into this catalog rather than strings (spec
// section 3): at 30k devices x 256 flows the strings would cost ~300 MB.
type avcCatalog struct {
	apps []avcApplication
}

func newAVCCatalog(apps []avcApplication) *avcCatalog {
	c := &avcCatalog{apps: make([]avcApplication, len(apps))}
	copy(c.apps, apps)
	return c
}

// App returns the application at 1-based idx, or false for 0 or out of range.
func (c *avcCatalog) App(idx uint16) (*avcApplication, bool) {
	if c == nil || idx == 0 || int(idx) > len(c.apps) {
		return nil, false
	}
	return &c.apps[idx-1], true
}

func (c *avcCatalog) Len() int {
	if c == nil {
		return 0
	}
	return len(c.apps)
}

// avcApplicationID packs RFC 6759 section 4.1's applicationId: the
// classification engine id in the top 8 bits and the selector in the low 24.
func avcApplicationID(engine uint8, selector uint32) uint32 {
	return uint32(engine)<<24 | selector&0xFFFFFF
}

// avcRef is the per-record application reference: 1-based indices into the
// device's avcCatalog (App) and into that application's Hosts and URIs
// slices. 0 means absent. Six bytes per record, resolved at encode time.
type avcRef struct {
	App, Host, URI uint16
}
```

Edit `go/nl6/flow_cache.go`: add to the end of `FlowRecord` the field `AVC avcRef // NBAR2 application reference; zero = plain record (ipfix_avc.go)`.

- [ ] **Step 4: Run the test and the whole package**

Run: `cd go && go test ./nl6/ -run TestAVCCatalogIndexing -v && go test ./nl6/ 2>&1 | tail -1`
Expected: PASS, then `ok` for the package (the new field is zero-valued everywhere).

- [ ] **Step 5: Commit**

```bash
git add go/nl6/ipfix_avc.go go/nl6/ipfix_avc_test.go go/nl6/flow_cache.go
git commit -s -m "feat(nbar2): add the AVC catalog value types and the record index triple" -m "Assisted-by: ClaudeCode:<model>"
```

---

### Task 4: AVC data template set and the test decoder's enterprise support

**Files:**
- Modify: `go/nl6/ipfix_avc.go`
- Modify: `go/nl6/ipfix_test.go:96-110` (template decoding) and the data-set branch
- Test: `go/nl6/ipfix_avc_test.go`

**Interfaces:**
- Produces: `var ipfixAVCFields []ipfixFieldSpec`, `type ipfixFieldSpec struct{ id, length uint16; pen uint32 }`, `func buildIPFIXAVCTemplateSet() []byte`, `var ipfixAVCTemplateSetBytes []byte` (built in `init`).
- Test decoder: `ipfixTemplateField` gains `PEN uint32`; `decodeIPFIXPacket` reads 8-byte specifiers when bit 15 is set and records data sets it cannot fix-decode (id != 256) as raw `RawSets map[uint16][]byte` instead of misreading them as 54-byte records.

- [ ] **Step 1: Write the failing test**

Append to `go/nl6/ipfix_avc_test.go`:

```go
// The AVC template is the 19 existing IEs, then applicationId, then the two
// PEN 9 layer-7 fields as variable-length enterprise specifiers. Enterprise
// specifiers are 8 bytes (RFC 7011 section 3.2), so the set length is
// computed, not the plain template's 84.
func TestIPFIXAVCTemplateSet(t *testing.T) {
	set := buildIPFIXAVCTemplateSet()
	wantLen := 4 + 4 + 20*4 + 2*8
	if len(set) != wantLen {
		t.Fatalf("template set length = %d, want %d", len(set), wantLen)
	}
	if got := int(set[2])<<8 | int(set[3]); got != wantLen {
		t.Fatalf("declared set length = %d, want %d", got, wantLen)
	}
	msg := append([]byte{0, 10, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0}, set...)
	msg[2], msg[3] = byte(len(msg)>>8), byte(len(msg))
	pkt := decodeIPFIXPacket(t, msg)
	if len(pkt.Templates) != 1 || pkt.Templates[0].TemplateID != ipfixAVCTemplateID {
		t.Fatalf("templates = %+v", pkt.Templates)
	}
	f := pkt.Templates[0].Fields
	if len(f) != 22 {
		t.Fatalf("field count = %d, want 22", len(f))
	}
	for i := 0; i < 19; i++ {
		if f[i].IEID != ipfixFields[i][0] || f[i].IELength != ipfixFields[i][1] || f[i].PEN != 0 {
			t.Fatalf("field %d = %+v, want the plain template's %v", i, f[i], ipfixFields[i])
		}
	}
	if f[19] != (ipfixTemplateField{IEID: ipfixApplicationID, IELength: 4}) {
		t.Fatalf("field 19 = %+v, want applicationId/4", f[19])
	}
	if f[20] != (ipfixTemplateField{IEID: ciscoHTTPHost, IELength: ipfixVarLen, PEN: ciscoPEN}) {
		t.Fatalf("field 20 = %+v, want httpHost var PEN 9", f[20])
	}
	if f[21] != (ipfixTemplateField{IEID: ciscoHTTPURIStatistics, IELength: ipfixVarLen, PEN: ciscoPEN}) {
		t.Fatalf("field 21 = %+v, want httpUriStatistics var PEN 9", f[21])
	}
}
```

- [ ] **Step 2: Run the test to verify it fails**

Run: `cd go && go test ./nl6/ -run TestIPFIXAVCTemplateSet -v`
Expected: build failure `undefined: buildIPFIXAVCTemplateSet` (and `PEN` on `ipfixTemplateField`).

- [ ] **Step 3: Implement the template builder**

Append to `go/nl6/ipfix_avc.go`:

```go
// ipfixFieldSpec is one template field specifier; pen 0 means IANA.
type ipfixFieldSpec struct {
	id, length uint16
	pen        uint32
}

// ipfixAVCFields is the AVC data template: the plain template's 19 IEs in
// the same order, then applicationId, then the two Cisco layer-7 fields.
// Keeping the plain prefix identical means a collector's decoder for 256
// reads the first 54 bytes of a 258 record unchanged.
var ipfixAVCFields = func() []ipfixFieldSpec {
	out := make([]ipfixFieldSpec, 0, len(ipfixFields)+3)
	for _, f := range ipfixFields {
		out = append(out, ipfixFieldSpec{id: f[0], length: f[1]})
	}
	return append(out,
		ipfixFieldSpec{id: ipfixApplicationID, length: 4},
		ipfixFieldSpec{id: ciscoHTTPHost, length: ipfixVarLen, pen: ciscoPEN},
		ipfixFieldSpec{id: ciscoHTTPURIStatistics, length: ipfixVarLen, pen: ciscoPEN},
	)
}()

// ipfixAVCTemplateSetBytes is the pre-encoded AVC Template Set, read-only
// after init.
var ipfixAVCTemplateSetBytes = buildIPFIXAVCTemplateSet()

// buildIPFIXAVCTemplateSet encodes the Template Set for ipfixAVCFields. An
// enterprise specifier is id|0x8000 (2) + length (2) + PEN (4), so the set
// length is computed from the field list rather than fixed.
func buildIPFIXAVCTemplateSet() []byte {
	length := 4 + 4
	for _, f := range ipfixAVCFields {
		if f.pen != 0 {
			length += 8
		} else {
			length += 4
		}
	}
	buf := make([]byte, length)
	pos := 0
	binary.BigEndian.PutUint16(buf[pos:], ipfixSetIDTemplate)
	pos += 2
	binary.BigEndian.PutUint16(buf[pos:], uint16(length))
	pos += 2
	binary.BigEndian.PutUint16(buf[pos:], ipfixAVCTemplateID)
	pos += 2
	binary.BigEndian.PutUint16(buf[pos:], uint16(len(ipfixAVCFields)))
	pos += 2
	for _, f := range ipfixAVCFields {
		id := f.id
		if f.pen != 0 {
			id |= ipfixEnterpriseBit
		}
		binary.BigEndian.PutUint16(buf[pos:], id)
		pos += 2
		binary.BigEndian.PutUint16(buf[pos:], f.length)
		pos += 2
		if f.pen != 0 {
			binary.BigEndian.PutUint32(buf[pos:], f.pen)
			pos += 4
		}
	}
	return buf
}
```

- [ ] **Step 4: Extend the test decoder**

In `go/nl6/ipfix_test.go`, change `ipfixTemplateField` to `struct { IEID, IELength uint16; PEN uint32 }` and, in the Template Set loop, after reading `ieID` and `ieLen`: if `ieID&0x8000 != 0`, read a 4-byte PEN, clear the bit (`ieID &^= 0x8000`), and advance `tmplPos` by 8 instead of 4. Add `RawSets map[uint16][]byte` to `ipfixPacket`; in the data-set branch, decode fixed 54-byte records only when `setID == ipfixTemplateID` (256), otherwise store `setData[4:]` under `pkt.RawSets[setID]` (Task 5 adds the AVC record decoder). Update the existing `TestIPFIXEncodePacket_WithTemplate` comparison if the struct literal form changed (it compares fields individually; verify with the run).

- [ ] **Step 5: Run the tests**

Run: `cd go && go test ./nl6/ -run 'TestIPFIXAVCTemplateSet|TestIPFIX' -v 2>&1 | grep -E '^(--- FAIL|ok|FAIL)'`
Expected: `ok`; every pre-existing IPFIX test still passes.

- [ ] **Step 6: Commit**

```bash
git add go/nl6/ipfix_avc.go go/nl6/ipfix_avc_test.go go/nl6/ipfix_test.go
git commit -s -m "feat(nbar2): build the AVC data template with enterprise field specifiers" -m "Assisted-by: ClaudeCode:<model>"
```

---

### Task 5: `IPFIXAVCEncoder` with measured pagination and a consumed count

**Files:**
- Modify: `go/nl6/ipfix_avc.go`
- Modify: `go/nl6/ipfix_test.go` (AVC record decoder)
- Test: `go/nl6/ipfix_avc_test.go`

**Interfaces:**
- Produces:
  ```go
  type IPFIXAVCEncoder struct{ cat *avcCatalog }
  func NewIPFIXAVCEncoder(cat *avcCatalog) *IPFIXAVCEncoder
  // FlowEncoder:
  func (e *IPFIXAVCEncoder) EncodePacket(domainID, seqNo, uptimeMs uint32, records []FlowRecord, includeTemplate bool, buf []byte) (int, error)
  func (e *IPFIXAVCEncoder) PacketSizes() (int, int, int)   // header+set hdr, template set len, 0
  func (e *IPFIXAVCEncoder) SeqIncrement(n int) int          // n (RFC 7011 §3.1)
  func (e *IPFIXAVCEncoder) MaxRecordSize() int              // ipfixRecordSize + 4 + ipfixVarLenSize(maxHost) + ipfixVarLenSize(maxURIStats) over the catalog
  func (e *IPFIXAVCEncoder) TrailingPadBytes(n int) int      // 0: pad is measured inside EncodeMeasured
  func (e *IPFIXAVCEncoder) MaxRecordsPerDatagram() int      // 0
  // measured seam:
  type measuredFlowEncoder interface {
      EncodeMeasured(domainID, seqNo, uptimeMs uint32, records []FlowRecord, includeTemplate bool, buf []byte) (n, consumed, dropped int, err error)
  }
  ```
  `EncodeMeasured` writes as many leading records as fit (template included when asked), returns bytes written, records consumed, and `dropped` = 1 when the FIRST record cannot fit an otherwise empty datagram (that record is skipped and consumed counts it, so the caller does not retry it forever). `EncodePacket` calls `EncodeMeasured` and ignores consumed, so the plain interface still works.
- Test decoder: `decodeIPFIXAVCRecords(t, raw []byte) []ipfixDecodedAVCRecord` with fields `Base ipfixDecodedRecord; AppID uint32; Host string; URIStats []byte`.

- [ ] **Step 1: Write the failing tests**

Append to `go/nl6/ipfix_avc_test.go`:

```go
import ("net"; "strings")

func avcRecord(app, host, uri uint16, srcPort uint16) FlowRecord {
	return FlowRecord{
		SrcIP: net.ParseIP("10.0.0.1").To4(), DstIP: net.ParseIP("10.0.0.2").To4(),
		NextHop: net.IPv4(0, 0, 0, 0).To4(), SrcPort: srcPort, DstPort: 80, Protocol: 6,
		Bytes: 100, Packets: 1, AVC: avcRef{App: app, Host: host, URI: uri},
	}
}

// Round trip through the test decoder: template + records; applicationId,
// host and URI statistics come back as written; a record with no
// application carries applicationId 0 and two zero-length fields.
func TestIPFIXAVCEncodeRoundTrip(t *testing.T) {
	enc := NewIPFIXAVCEncoder(testAVCCatalog())
	buf := make([]byte, 1472)
	recs := []FlowRecord{avcRecord(1, 2, 1, 50000), avcRecord(2, 0, 0, 50001), avcRecord(0, 0, 0, 50002)}
	n, consumed, dropped, err := enc.EncodeMeasured(1, 7, 1000, recs, true, buf)
	if err != nil || consumed != 3 || dropped != 0 {
		t.Fatalf("n=%d consumed=%d dropped=%d err=%v", n, consumed, dropped, err)
	}
	pkt := decodeIPFIXPacket(t, buf[:n])
	if len(pkt.Templates) != 1 || pkt.Templates[0].TemplateID != ipfixAVCTemplateID {
		t.Fatalf("templates = %+v", pkt.Templates)
	}
	if pkt.Header.SequenceNumber != 7 || int(pkt.Header.Length) != n {
		t.Fatalf("header = %+v, n=%d", pkt.Header, n)
	}
	got := decodeIPFIXAVCRecords(t, pkt.RawSets[ipfixAVCTemplateID])
	if len(got) != 3 {
		t.Fatalf("decoded %d records, want 3", len(got))
	}
	if got[0].AppID != avcApplicationID(13, 80) || got[0].Host != "cdn.example.net" {
		t.Fatalf("record 0 = %+v", got[0])
	}
	want := append([]byte("/index.html\x00"), 0, 1)
	if string(got[0].URIStats) != string(want) {
		t.Fatalf("record 0 uri stats = %q, want %q (URI, NUL, uint16 BE count 1)", got[0].URIStats, want)
	}
	if got[1].AppID != avcApplicationID(13, 443) || got[1].Host != "" || len(got[1].URIStats) != 0 {
		t.Fatalf("record 1 (ssl, no host) = %+v", got[1])
	}
	if got[2].AppID != 0 || got[2].Host != "" || got[2].Base.SrcPort != 50002 {
		t.Fatalf("record 2 (no application) = %+v", got[2])
	}
	if n%4 != 0 {
		t.Fatalf("message length %d is not 4-byte aligned", n)
	}
}

// Host lengths at the RFC 7011 section 7 boundary survive the round trip.
func TestIPFIXAVCEncodeHostLengthBoundary(t *testing.T) {
	for _, hl := range []int{1, 254, 255, 256} {
		cat := newAVCCatalog([]avcApplication{{ID: avcApplicationID(13, 80), Name: "http", Hosts: []string{strings.Repeat("h", hl)}}})
		enc := NewIPFIXAVCEncoder(cat)
		buf := make([]byte, 1472)
		n, consumed, _, err := enc.EncodeMeasured(1, 0, 0, []FlowRecord{avcRecord(1, 1, 0, 1)}, false, buf)
		if err != nil || consumed != 1 {
			t.Fatalf("hl=%d: consumed=%d err=%v", hl, consumed, err)
		}
		got := decodeIPFIXAVCRecords(t, decodeIPFIXPacket(t, buf[:n]).RawSets[ipfixAVCTemplateID])
		if len(got) != 1 || len(got[0].Host) != hl {
			t.Fatalf("hl=%d: decoded host length %d", hl, len(got[0].Host))
		}
	}
}

// Measured pagination: with a small budget the encoder consumes only what
// fits, and the count it reports is exactly the number of records on the
// wire. Then a record that fits no empty datagram is dropped and reported.
func TestIPFIXAVCEncodeMeasuredConsumesWhatFits(t *testing.T) {
	enc := NewIPFIXAVCEncoder(testAVCCatalog())
	recs := make([]FlowRecord, 10)
	for i := range recs {
		recs[i] = avcRecord(1, 1, 1, uint16(50000+i))
	}
	// Each record is 54 + 4 + (1+15) + (1+14) = 89 bytes; header 16 + set 4.
	buf := make([]byte, 20+89*3+2)
	n, consumed, dropped, err := enc.EncodeMeasured(1, 0, 0, recs, false, buf)
	if err != nil || dropped != 0 {
		t.Fatalf("err=%v dropped=%d", err, dropped)
	}
	if consumed != 3 {
		t.Fatalf("consumed = %d, want 3", consumed)
	}
	if got := len(decodeIPFIXAVCRecords(t, decodeIPFIXPacket(t, buf[:n]).RawSets[ipfixAVCTemplateID])); got != consumed {
		t.Fatalf("%d records on the wire, consumed reports %d", got, consumed)
	}
	// Too small for even one record: dropped=1, consumed=1, nothing written.
	tiny := make([]byte, 20+50)
	n, consumed, dropped, err = enc.EncodeMeasured(1, 0, 0, recs[:1], false, tiny)
	if err != nil || n != 0 || consumed != 1 || dropped != 1 {
		t.Fatalf("oversize: n=%d consumed=%d dropped=%d err=%v; want 0,1,1,nil", n, consumed, dropped, err)
	}
	// Template-only message when nothing is given.
	n, consumed, dropped, err = enc.EncodeMeasured(1, 0, 0, nil, true, buf)
	if err != nil || consumed != 0 || dropped != 0 || n != 16+len(ipfixAVCTemplateSetBytes) {
		t.Fatalf("template-only: n=%d consumed=%d dropped=%d err=%v", n, consumed, dropped, err)
	}
}
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `cd go && go test ./nl6/ -run 'TestIPFIXAVCEncode' -v`
Expected: build failure `undefined: NewIPFIXAVCEncoder`.

- [ ] **Step 3: Implement the encoder**

Append to `go/nl6/ipfix_avc.go` (add `"fmt"`, `"math"`, `"time"` to the import block):

```go
// IPFIXAVCEncoder emits the AVC data template (258) and records that
// resolve their avcRef against ONE catalog. It is constructed per catalog,
// not shared fleet-wide like IPFIXEncoder, because the record's indices
// are meaningless without the catalog they were drawn from (spec section 3).
// The catalog is immutable, so one encoder is still safe across goroutines.
type IPFIXAVCEncoder struct {
	cat *avcCatalog
}

func NewIPFIXAVCEncoder(cat *avcCatalog) *IPFIXAVCEncoder {
	return &IPFIXAVCEncoder{cat: cat}
}

// measuredFlowEncoder is the seam for encoders whose record size is not
// fixed. Tick hands it the whole expired slice and takes back how many
// records it emitted; the rest ride the next datagram. dropped is 1 when the
// first record could not fit an otherwise empty datagram: it is skipped,
// counted in consumed so the caller cannot retry it forever, and the caller
// counts it as a send failure. Like flowOptionsEncoder it is reached by
// type assertion, so fixed-size encoders are untouched.
type measuredFlowEncoder interface {
	EncodeMeasured(domainID, seqNo, uptimeMs uint32, records []FlowRecord, includeTemplate bool, buf []byte) (n, consumed, dropped int, err error)
}

func (e *IPFIXAVCEncoder) PacketSizes() (int, int, int) {
	return ipfixHeaderSize + ipfixDataSetHdrSize, len(ipfixAVCTemplateSetBytes), 0
}
func (e *IPFIXAVCEncoder) SeqIncrement(n int) int  { return n }
func (e *IPFIXAVCEncoder) TrailingPadBytes(int) int { return 0 }
func (e *IPFIXAVCEncoder) MaxRecordsPerDatagram() int { return 0 }

// MaxRecordSize is the worst case over the catalog: the fixed prefix plus the
// longest host and the longest single-URI statistics value. Tick uses it only
// as a sanity bound; pagination is measured in EncodeMeasured.
func (e *IPFIXAVCEncoder) MaxRecordSize() int {
	maxHost, maxURI := 0, 0
	for i := 0; i < e.cat.Len(); i++ {
		app, _ := e.cat.App(uint16(i + 1))
		for _, h := range app.Hosts {
			if len(h) > maxHost {
				maxHost = len(h)
			}
		}
		for _, u := range app.URIs {
			if len(u)+3 > maxURI {
				maxURI = len(u) + 3 // URI + NUL + uint16 count
			}
		}
	}
	return ipfixRecordSize + 4 + ipfixVarLenSize(maxHost) + ipfixVarLenSize(maxURI)
}

// EncodePacket satisfies FlowEncoder for callers that do not use the measured
// seam; consumed is discarded, which is why Tick must use EncodeMeasured.
func (e *IPFIXAVCEncoder) EncodePacket(domainID, seqNo, uptimeMs uint32, records []FlowRecord, includeTemplate bool, buf []byte) (int, error) {
	n, _, _, err := e.EncodeMeasured(domainID, seqNo, uptimeMs, records, includeTemplate, buf)
	return n, err
}

// EncodeMeasured writes the message header, the AVC template when asked, and
// as many leading records as fit, padding the data Set to 4 bytes. Sizing is
// measured per record, never predicted: every bug in this family was a
// predicted size disagreeing with an emitted one.
func (e *IPFIXAVCEncoder) EncodeMeasured(domainID, seqNo, uptimeMs uint32, records []FlowRecord, includeTemplate bool, buf []byte) (int, int, int, error) {
	if len(records) == 0 && !includeTemplate {
		return 0, 0, 0, nil
	}
	nowMs := time.Now().UnixMilli()
	deviceStartMs := nowMs - int64(uptimeMs)
	if deviceStartMs < 0 {
		deviceStartMs = 0
	}
	overhead := ipfixHeaderSize
	if includeTemplate {
		overhead += len(ipfixAVCTemplateSetBytes)
	}
	if len(buf) < overhead {
		return 0, 0, 0, fmt.Errorf("ipfix avc: buffer too small (%d bytes), need at least %d", len(buf), overhead)
	}
	pos := 0
	binary.BigEndian.PutUint16(buf[pos:], ipfixVersion)
	pos += 2
	lengthOffset := pos
	pos += 2
	binary.BigEndian.PutUint32(buf[pos:], uint32(nowMs/1000))
	pos += 4
	binary.BigEndian.PutUint32(buf[pos:], seqNo)
	pos += 4
	binary.BigEndian.PutUint32(buf[pos:], domainID)
	pos += 4
	if includeTemplate {
		copy(buf[pos:], ipfixAVCTemplateSetBytes)
		pos += len(ipfixAVCTemplateSetBytes)
	}
	if len(records) == 0 {
		binary.BigEndian.PutUint16(buf[lengthOffset:], uint16(pos))
		return pos, 0, 0, nil
	}
	// Data Set: header now, length backfilled. A record is written into the
	// remaining space minus the worst-case pad (3 bytes); if it does not fit,
	// the write position is rewound and the loop stops.
	setStart := pos
	binary.BigEndian.PutUint16(buf[pos:], ipfixAVCTemplateID)
	pos += 4
	consumed := 0
	for _, r := range records {
		limit := len(buf) - 3
		if limit < pos {
			break
		}
		next, ok := e.encodeRecord(buf[:limit], pos, r, deviceStartMs)
		if !ok {
			break
		}
		pos = next
		consumed++
	}
	if consumed == 0 {
		// Nothing fit. If the datagram was otherwise empty this record can
		// never be sent: report it dropped and consumed so the caller moves on.
		if !includeTemplate {
			return 0, 1, 1, nil
		}
		// Template-carrying message with no room for a record: send the
		// template alone and let the caller retry the record in a data-only
		// datagram, which has more room.
		binary.BigEndian.PutUint16(buf[lengthOffset:], uint16(setStart))
		return setStart, 0, 0, nil
	}
	if rem := (pos - setStart) % 4; rem != 0 {
		for i := 0; i < 4-rem; i++ {
			buf[pos] = 0
			pos++
		}
	}
	binary.BigEndian.PutUint16(buf[setStart+2:], uint16(pos-setStart))
	binary.BigEndian.PutUint16(buf[lengthOffset:], uint16(pos))
	return pos, consumed, 0, nil
}

// encodeRecord writes the plain 54-byte prefix (reusing encodeIPFIXRecord so
// the two templates cannot drift), then applicationId and the two
// variable-length fields. Returns false, with nothing counted, when the
// record does not fit in buf.
func (e *IPFIXAVCEncoder) encodeRecord(buf []byte, pos int, r FlowRecord, deviceStartMs int64) (int, bool) {
	if pos+ipfixRecordSize+4 > len(buf) {
		return pos, false
	}
	start := pos
	pos = encodeIPFIXRecord(buf, pos, r, deviceStartMs)
	var appID uint32
	var host, uriStats []byte
	if app, ok := e.cat.App(r.AVC.App); ok {
		appID = app.ID
		if h := int(r.AVC.Host); h > 0 && h <= len(app.Hosts) {
			host = []byte(app.Hosts[h-1])
		}
		if u := int(r.AVC.URI); u > 0 && u <= len(app.URIs) {
			uriStats = uriStatsValue(app.URIs[u-1], 1)
		}
	}
	binary.BigEndian.PutUint32(buf[pos:], appID)
	pos += 4
	var ok bool
	if pos, ok = putIPFIXVarLen(buf, pos, host); !ok {
		return start, false
	}
	if pos, ok = putIPFIXVarLen(buf, pos, uriStats); !ok {
		return start, false
	}
	return pos, true
}

// uriStatsValue renders one IE 42125 entry per ipfixURIStatsLayout: the URI,
// a NUL, then the hit count as uint16 big-endian, with no trailing delimiter.
// count is clamped to Cisco's stated maximum of 65535.
func uriStatsValue(uri string, count uint32) []byte {
	if count > math.MaxUint16 {
		count = math.MaxUint16
	}
	out := make([]byte, 0, len(uri)+3)
	out = append(out, uri...)
	out = append(out, 0, byte(count>>8), byte(count))
	return out
}

var _ FlowEncoder = (*IPFIXAVCEncoder)(nil)
var _ measuredFlowEncoder = (*IPFIXAVCEncoder)(nil)
```

Fix one arithmetic detail before running: `binary.BigEndian.PutUint16(buf[pos:], ipfixAVCTemplateID); pos += 4` skips the length slot correctly (it is backfilled), but write a zero into `buf[pos+2:pos+4]` first so a decoder reading a partially written buffer in a test never sees stale bytes.

- [ ] **Step 4: Add the AVC record decoder to the test file**

Append to `go/nl6/ipfix_test.go`:

```go
type ipfixDecodedAVCRecord struct {
	Base     ipfixDecodedRecord
	AppID    uint32
	Host     string
	URIStats []byte
}

// decodeIPFIXAVCRecords parses a 258 data set body (after the 4-byte set
// header) written by IPFIXAVCEncoder: the plain 54-byte record, then
// applicationId, then two RFC 7011 section 7 variable-length values. Stops
// at padding (fewer than 58 bytes left).
func decodeIPFIXAVCRecords(t *testing.T, raw []byte) []ipfixDecodedAVCRecord {
	t.Helper()
	var out []ipfixDecodedAVCRecord
	pos := 0
	readVar := func() []byte {
		if pos >= len(raw) {
			t.Fatalf("avc: truncated at variable-length prefix, pos %d", pos)
		}
		n := int(raw[pos])
		pos++
		if n == 255 {
			n = int(binary.BigEndian.Uint16(raw[pos:]))
			pos += 2
		}
		if pos+n > len(raw) {
			t.Fatalf("avc: variable-length value of %d overruns the set at pos %d", n, pos)
		}
		v := raw[pos : pos+n]
		pos += n
		return v
	}
	for pos+ipfixRecordSize+4 <= len(raw) {
		rec := ipfixDecodedAVCRecord{}
		rec.Base = decodeOneIPFIXRecord(raw[pos:])
		pos += ipfixRecordSize
		rec.AppID = binary.BigEndian.Uint32(raw[pos:])
		pos += 4
		rec.Host = string(readVar())
		rec.URIStats = append([]byte(nil), readVar()...)
		out = append(out, rec)
	}
	return out
}
```

Refactor the existing 54-byte record parsing in `decodeIPFIXPacket` into `func decodeOneIPFIXRecord(b []byte) ipfixDecodedRecord` (pure extraction: same field reads, no behaviour change) and call it from both places.

- [ ] **Step 5: Run the tests**

Run: `cd go && go test ./nl6/ -run 'TestIPFIXAVC|TestIPFIX|TestAVC' -v 2>&1 | grep -E '^(--- FAIL|ok|FAIL)|_test.go:'`
Expected: `ok`. If `TestIPFIXAVCEncodeMeasuredConsumesWhatFits` disagrees on the per-record size (89), recompute from the actual catalog strings rather than adjusting the encoder.

- [ ] **Step 6: Verify by mutation**

Change `putIPFIXVarLen`'s threshold `n < 255` to `n <= 255`, run `TestIPFIXAVCEncodeHostLengthBoundary`, confirm the 255 case fails. Revert. Change `consumed++` to run before the fit check, run `TestIPFIXAVCEncodeMeasuredConsumesWhatFits`, confirm "on the wire, consumed reports" fails. Revert.

- [ ] **Step 7: Commit**

```bash
git add go/nl6/ipfix_avc.go go/nl6/ipfix_avc_test.go go/nl6/ipfix_test.go
git commit -s -m "feat(nbar2): add IPFIXAVCEncoder with measured pagination and a consumed count" -m "Assisted-by: ClaudeCode:<model>"
```

---

### Task 6: `Tick` re-queues on the encoder's consumed count

**Files:**
- Modify: `go/nl6/flow_exporter.go` (the flow loop, around the `if sfe, ok := encoder.(SFlowEncoder)` branch)
- Test: `go/nl6/ipfix_avc_test.go`

**Interfaces:**
- Consumes: `measuredFlowEncoder` from Task 5; `fe.logFirstEncodeErr` does not exist yet on `FlowExporter`: add `firstEncodeErr sync.Once` and `func (fe *FlowExporter) logFirstEncodeErr(err error)` mirroring `logFirstOptionsErr`.
- Produces: on the measured path, `batch` is the encoder's reported prefix of `expired`, `stats.RecordsSent` and the scenario ledger count `consumed`, a dropped record increments `stats.SendFailures` once and is logged once per exporter.

- [ ] **Step 1: Write the failing test**

Append to `go/nl6/ipfix_avc_test.go` (add `"time"`, `"sync"` as needed):

```go
// Through the real Tick: 120 AVC records with varied host lengths paginate
// across several datagrams, every record reaches the wire exactly once,
// RecordsSent equals the wire count, and the sequence numbers are the
// running record count (RFC 7011 section 3.1).
func TestIPFIXAVCTickRequeuesOnConsumed(t *testing.T) {
	ln, ch := testUDPListener(t)
	defer ln.Close()
	conn := testSender(t)
	defer conn.Close()
	addr := ln.LocalAddr().(*net.UDPAddr)

	cat := newAVCCatalog([]avcApplication{{ID: avcApplicationID(13, 80), Name: "http",
		Hosts: []string{"a.example", strings.Repeat("b", 200), strings.Repeat("c", 300)}, URIs: []string{"/x"}}})
	enc := NewIPFIXAVCEncoder(cat)
	prof := *mtuTestProfile()
	prof.ConcurrentFlows = 0
	fe := newTestFlowExporter(testDevice("10.1.2.50"), &prof, 10*time.Minute, 5*time.Minute, 10*time.Minute)
	past := time.Now().Add(-time.Hour)
	for i := 0; i < 120; i++ {
		fe.cache.Add(avcRecord(1, uint16(i%3+1), 1, uint16(49152+i)), past)
	}
	stats := tickWithEncoder(fe, time.Now(), enc, conn, addr, testPool())
	if stats.PacketsSent < 3 {
		t.Fatalf("expected several datagrams, got %d", stats.PacketsSent)
	}
	seen := map[uint16]bool{}
	var running uint32
	for i := 0; i < int(stats.PacketsSent); i++ {
		pkt := receivePacket(ch)
		if pkt == nil {
			t.Fatalf("datagram %d missing", i)
		}
		if len(pkt) > maxFlowPayloadIPv4 {
			t.Fatalf("datagram %d is %d bytes, over the %d budget", i, len(pkt), maxFlowPayloadIPv4)
		}
		dec := decodeIPFIXPacket(t, pkt)
		if dec.Header.SequenceNumber != running {
			t.Fatalf("datagram %d sequence %d, want %d", i, dec.Header.SequenceNumber, running)
		}
		recs := decodeIPFIXAVCRecords(t, dec.RawSets[ipfixAVCTemplateID])
		for _, r := range recs {
			if seen[r.Base.SrcPort] {
				t.Fatalf("record with src port %d arrived twice", r.Base.SrcPort)
			}
			seen[r.Base.SrcPort] = true
		}
		running += uint32(len(recs))
	}
	if len(seen) != 120 || stats.RecordsSent != 120 || fe.seqNo != 120 {
		t.Fatalf("wire=%d RecordsSent=%d seqNo=%d, want 120 each", len(seen), stats.RecordsSent, fe.seqNo)
	}
	if stats.SendFailures != 0 {
		t.Fatalf("SendFailures = %d, want 0", stats.SendFailures)
	}
}

// A record that fits no datagram is dropped once, counted once, and does
// not block the records behind it.
func TestIPFIXAVCTickDropsUnsendableRecord(t *testing.T) {
	ln, ch := testUDPListener(t)
	defer ln.Close()
	conn := testSender(t)
	defer conn.Close()
	addr := ln.LocalAddr().(*net.UDPAddr)

	cat := newAVCCatalog([]avcApplication{{ID: avcApplicationID(13, 80), Name: "http",
		Hosts: []string{"ok.example", strings.Repeat("z", 1500)}}})
	enc := NewIPFIXAVCEncoder(cat)
	prof := *mtuTestProfile()
	prof.ConcurrentFlows = 0
	fe := newTestFlowExporter(testDevice("10.1.2.51"), &prof, 10*time.Minute, 5*time.Minute, 10*time.Minute)
	fe.lastTempl = time.Now() // data-only tick
	past := time.Now().Add(-time.Hour)
	fe.cache.Add(avcRecord(1, 2, 0, 49152), past) // 1500-byte host: never fits
	fe.cache.Add(avcRecord(1, 1, 0, 49153), past)
	stats := tickWithEncoder(fe, time.Now(), enc, conn, addr, testPool())
	if stats.SendFailures != 1 || stats.RecordsSent != 1 || stats.PacketsSent != 1 {
		t.Fatalf("stats = %+v, want SendFailures 1, RecordsSent 1, PacketsSent 1", stats)
	}
	pkt := receivePacket(ch)
	if pkt == nil {
		t.Fatal("the sendable record never arrived")
	}
	recs := decodeIPFIXAVCRecords(t, decodeIPFIXPacket(t, pkt).RawSets[ipfixAVCTemplateID])
	if len(recs) != 1 || recs[0].Host != "ok.example" {
		t.Fatalf("wire records = %+v", recs)
	}
	if fe.seqNo != 1 {
		t.Fatalf("seqNo = %d, want 1 (dropped record never counted as sent)", fe.seqNo)
	}
}
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `cd go && go test ./nl6/ -run 'TestIPFIXAVCTick' -v 2>&1 | grep -E '^(--- FAIL|ok|FAIL)|_test.go:'`
Expected: FAIL. `Tick` uses `MaxRecordSize()` as a divisor and hands the encoder a batch it counts as `len(batch)`; the first test fails on "arrived twice" or on RecordsSent, and the second fails because the oversize record blocks or is counted as sent.

- [ ] **Step 3: Implement the measured branch in `Tick`**

In `go/nl6/flow_exporter.go`, inside the `for {` flow loop, before `var batch []FlowRecord`, add the measured path. The final structure of the loop body's batch selection and encode becomes:

```go
		var batch []FlowRecord
		var n int
		var err error
		if me, ok := encoder.(measuredFlowEncoder); ok {
			// Measured path: the encoder decides how many of `expired` fit.
			// Capacity is not predicted from MaxRecordSize (a worst case
			// that collapses per-datagram volume, and can be larger than the
			// budget on a template tick, which would send nothing forever).
			var consumed, dropped int
			n, consumed, dropped, err = me.EncodeMeasured(fe.domainID, fe.seqNo, uptimeMs, expired, sendTemplate, buf)
			if err != nil {
				fe.logFirstEncodeErr(err)
				break
			}
			if dropped > 0 {
				// The first record fits no empty datagram. It is gone from
				// the queue (consumed counts it) and is a send failure, never
				// a sent record; nothing was written for it.
				fe.logFirstEncodeErr(fmt.Errorf("record for %s exceeds the datagram budget of %d bytes and was dropped", domainIDtoIP(fe.domainID), len(buf)))
				stats.SendFailures += uint64(dropped)
				if scenActive {
					part.ledger.emitted.Add(uint64(dropped))
					part.ledger.sendFailures.Add(uint64(dropped))
				}
				expired = expired[consumed:]
				if len(expired) == 0 && !sendTemplate {
					break
				}
				continue
			}
			batch = expired[:consumed]
			expired = expired[consumed:]
			if n == 0 {
				break
			}
		} else {
			// Fixed-size path: unchanged.
			perRec := recSize
			... (existing capacity arithmetic and batch slicing, verbatim)
			if len(batch) == 0 && !sendTemplate {
				break
			}
			if sfe, ok := encoder.(SFlowEncoder); ok {
				... (existing sFlow branch, verbatim)
			} else {
				n, err = encoder.EncodePacket(fe.domainID, fe.seqNo, uptimeMs, batch, sendTemplate, buf)
			}
			if err != nil || n == 0 {
				break
			}
		}
```

Everything after the encode (write, ledger, stats, `fe.seqNo += uint32(encoder.SeqIncrement(len(batch)))`, template bookkeeping, `if len(expired) == 0 { break }`) is unchanged and now sees `batch` as exactly the consumed prefix on the measured path. Add to `FlowExporter`: `firstEncodeErr sync.Once` and

```go
// logFirstEncodeErr logs at most one encode-path error per exporter, the
// sync.Once shape trap and options already use: ungated this was ~1,000
// lines per second at 30k devices for a defect present since startup.
func (fe *FlowExporter) logFirstEncodeErr(err error) {
	fe.firstEncodeErr.Do(func() {
		log.Printf("flow export: encode error for %s (further occurrences suppressed): %v", domainIDtoIP(fe.domainID), err)
	})
}
```

Do not move, rename or reformat the fixed-size branch; the diff of that branch must be indentation only, which the reviewer will check.

- [ ] **Step 4: Run the tests, then the whole package**

Run: `cd go && go test ./nl6/ -run 'TestIPFIXAVCTick|TestFlowExporter|TestFlowTick|TestFlowDatagramsFitMTU|TestIPFIXSequence|TestNetFlow' -v 2>&1 | grep -E '^(--- FAIL|ok|FAIL)|_test.go:'` then `go test ./nl6/ 2>&1 | tail -1`
Expected: `ok` both times. The fixed-size encoders never enter the new branch.

- [ ] **Step 5: Verify by mutation**

Change `batch = expired[:consumed]` to `batch = expired[:len(expired)]` (the old `len(batch)` counting), run `TestIPFIXAVCTickRequeuesOnConsumed`, confirm RecordsSent or "arrived twice" fails. Revert.

- [ ] **Step 6: Commit**

```bash
git add go/nl6/flow_exporter.go go/nl6/ipfix_avc_test.go
git commit -s -m "feat(nbar2): let Tick count and re-queue on the measured encoder's consumed count" -m "A record that fits no datagram is dropped into send_failures once, not retried forever and never counted as sent." -m "Assisted-by: ClaudeCode:<model>"
```

---

### Task 7: Application-table options datagram (RFC 6759 §4.3, template 259)

**Files:**
- Modify: `go/nl6/ipfix_avc.go`
- Modify: `go/nl6/flow_exporter.go` (emit after the interface options block)
- Modify: `go/nl6/flow_options_test.go` (decoder: `decodeIPFIXOptionsDatagram` must accept template 259 with a 4-byte scope and two string fields; check how it is written and generalise by reading the template's field lengths rather than assuming 257's)
- Test: `go/nl6/ipfix_avc_test.go`

**Interfaces:**
- Produces:
  ```go
  type appTableEncoder interface {
      EncodeAppTableDatagram(domainID, seqNo uint32, apps []avcApplication, buf []byte) (n, consumed int, err error)
  }
  func (e *IPFIXAVCEncoder) EncodeAppTableDatagram(...)
  func (e *IPFIXAVCEncoder) Applications() []avcApplication // the catalog's apps, for Tick
  var ipfixAppTableTemplateSetBytes []byte // Set ID 3, template 259, scope count 1, scope applicationId/4, options applicationName/24 + applicationDescription/55
  const ipfixAppTableRecSize = 4 + ipfixApplicationNameLen + ipfixApplicationDescriptionLen // 83; the set is padded to 4 bytes
  ```
- `Tick`: when `encoder.(appTableEncoder)` holds and `emitOptions` (the template-refresh condition already captured for interface options) is true, emit the application table after the interface option table, paginating on `consumed`, advancing `fe.seqNo` by `encoder.SeqIncrement(consumed)`, counting packets and bytes but not `RecordsSent`.

- [ ] **Step 1: Write the failing test**

Append to `go/nl6/ipfix_avc_test.go`:

```go
// The application table is an Options Template (Set ID 3, template 259)
// with scope applicationId and non-scope applicationName (24 bytes) and
// applicationDescription (55 bytes), per RFC 6759 section 4.3 and Cisco's
// option application-table lengths. Records are 83 bytes, so the set pads.
func TestIPFIXAVCAppTableDatagram(t *testing.T) {
	cat := testAVCCatalog()
	enc := NewIPFIXAVCEncoder(cat)
	buf := make([]byte, 1472)
	n, consumed, err := enc.EncodeAppTableDatagram(1, 42, enc.Applications(), buf)
	if err != nil || consumed != 3 {
		t.Fatalf("n=%d consumed=%d err=%v", n, consumed, err)
	}
	if n%4 != 0 {
		t.Fatalf("message length %d not 4-byte aligned", n)
	}
	dg := decodeIPFIXOptionsDatagram(t, buf[:n])
	if dg.SequenceNo != 42 || dg.Template == nil || dg.Template.TemplateID != ipfixAppTableTemplateID {
		t.Fatalf("datagram = %+v", dg)
	}
	if dg.Template.ScopeCount != 1 || len(dg.Template.Fields) != 3 {
		t.Fatalf("template = %+v", dg.Template)
	}
	if f := dg.Template.Fields; f[0].IEID != ipfixApplicationID || f[0].IELength != 4 ||
		f[1].IEID != ipfixApplicationName || f[1].IELength != ipfixApplicationNameLen ||
		f[2].IEID != ipfixApplicationDescription || f[2].IELength != ipfixApplicationDescriptionLen {
		t.Fatalf("template fields = %+v", f)
	}
	if len(dg.Records) != 3 {
		t.Fatalf("records = %d, want 3", len(dg.Records))
	}
	if dg.Records[0].Scope != avcApplicationID(13, 80) || dg.Records[0].Strings[0] != "http" || dg.Records[0].Strings[1] != "HTTP" {
		t.Fatalf("record 0 = %+v", dg.Records[0])
	}
	// Pagination: a buffer holding two records consumes two.
	small := make([]byte, 16+len(ipfixAppTableTemplateSetBytes)+4+2*ipfixAppTableRecSize+3)
	_, consumed, err = enc.EncodeAppTableDatagram(1, 0, enc.Applications(), small)
	if err != nil || consumed != 2 {
		t.Fatalf("small buffer: consumed=%d err=%v, want 2", consumed, err)
	}
}

// Through Tick: on a template-refresh tick an AVC device emits the data
// template, the interface option table (257) AND the application table
// (259); the two options tables coexist and the application table advances
// the sequence by its record count.
func TestIPFIXAVCTickEmitsApplicationTable(t *testing.T) {
	ln, ch := testUDPListener(t)
	defer ln.Close()
	conn := testSender(t)
	defer conn.Close()
	addr := ln.LocalAddr().(*net.UDPAddr)

	enc := NewIPFIXAVCEncoder(testAVCCatalog())
	prof := *mtuTestProfile()
	prof.ConcurrentFlows = 0
	fe := newTestFlowExporter(testDevice("10.1.2.52"), &prof, 10*time.Minute, 5*time.Minute, 10*time.Minute)
	fe.optionShape = flowOptionShapeIfScoped
	fe.optionIfaces = []flowOptionIface{{ifIndex: 1, name: "Gi0/1"}}
	fe.cache.Add(avcRecord(1, 1, 1, 49152), time.Now().Add(-time.Hour))
	stats := tickWithEncoder(fe, time.Now(), enc, conn, addr, testPool())
	if stats.PacketsSent != 3 || stats.RecordsSent != 1 {
		t.Fatalf("stats = %+v, want 3 datagrams (data, if-options, app-table) and 1 record", stats)
	}
	var seqs []uint32
	templates := map[uint16]bool{}
	for i := 0; i < 3; i++ {
		pkt := receivePacket(ch)
		if pkt == nil {
			t.Fatalf("datagram %d missing", i)
		}
		seqs = append(seqs, binary.BigEndian.Uint32(pkt[8:]))
		setID := binary.BigEndian.Uint16(pkt[16:])
		if setID == ipfixSetIDOptionsTemplate {
			templates[binary.BigEndian.Uint16(pkt[20:])] = true
		} else {
			templates[binary.BigEndian.Uint16(pkt[20:])] = true // data template id from the template set
		}
	}
	for _, id := range []uint16{ipfixAVCTemplateID, ipfixOptionsTemplateID, ipfixAppTableTemplateID} {
		if !templates[id] {
			t.Fatalf("template %d not seen; saw %v", id, templates)
		}
	}
	// data (1 record) at 0; interface options (1 record) at 1; app table (3 records) at 2; final 5.
	if seqs[0] != 0 || seqs[1] != 1 || seqs[2] != 2 || fe.seqNo != 5 {
		t.Fatalf("sequences = %v, seqNo = %d; want [0 1 2] and 5", seqs, fe.seqNo)
	}
}
```

(Add `"encoding/binary"` to the test imports.)

- [ ] **Step 2: Run the tests to verify they fail**

Run: `cd go && go test ./nl6/ -run 'TestIPFIXAVCAppTable|TestIPFIXAVCTickEmitsApplicationTable' -v 2>&1 | grep -E '^(--- FAIL|ok|FAIL)|_test.go:'`
Expected: build failure `undefined: EncodeAppTableDatagram`.

- [ ] **Step 3: Implement the options datagram**

Append to `go/nl6/ipfix_avc.go`:

```go
// ipfixAppTableRecSize is one application-table option data record: the
// 4-byte applicationId scope, then the two fixed-width strings Cisco's
// option application-table emits.
const ipfixAppTableRecSize = 4 + ipfixApplicationNameLen + ipfixApplicationDescriptionLen

// ipfixAppTableTemplateSetBytes is the RFC 6759 section 4.3 options
// template: scope applicationId, non-scope applicationName and
// applicationDescription, at Cisco's fixed lengths. Built once, read-only.
var ipfixAppTableTemplateSetBytes = buildIPFIXAppTableTemplateSet()

func buildIPFIXAppTableTemplateSet() []byte {
	length := 4 + 6 + 3*4 // set hdr + (id, field count, scope count) + 3 specifiers = 22
	if rem := length % 4; rem != 0 {
		length += 4 - rem
	}
	buf := make([]byte, length)
	pos := 0
	binary.BigEndian.PutUint16(buf[pos:], ipfixSetIDOptionsTemplate)
	pos += 2
	binary.BigEndian.PutUint16(buf[pos:], uint16(length))
	pos += 2
	binary.BigEndian.PutUint16(buf[pos:], ipfixAppTableTemplateID)
	pos += 2
	binary.BigEndian.PutUint16(buf[pos:], 3) // field count incl. scope
	pos += 2
	binary.BigEndian.PutUint16(buf[pos:], 1) // scope field count
	pos += 2
	for _, f := range [][2]uint16{
		{ipfixApplicationID, 4},
		{ipfixApplicationName, ipfixApplicationNameLen},
		{ipfixApplicationDescription, ipfixApplicationDescriptionLen},
	} {
		binary.BigEndian.PutUint16(buf[pos:], f[0])
		pos += 2
		binary.BigEndian.PutUint16(buf[pos:], f[1])
		pos += 2
	}
	return buf
}

// appTableEncoder is the seam Tick uses to emit the application table on
// the template-refresh cadence, beside the interface option table.
type appTableEncoder interface {
	Applications() []avcApplication
	EncodeAppTableDatagram(domainID, seqNo uint32, apps []avcApplication, buf []byte) (n, consumed int, err error)
}

// Applications returns the catalog's applications in index order. The slice
// is the catalog's own and must not be modified.
func (e *IPFIXAVCEncoder) Applications() []avcApplication { return e.cat.apps }

// EncodeAppTableDatagram writes a self-contained message: header, the
// options template, and as many application records as fit. consumed <
// len(apps) means the caller re-invokes with the remainder. The set is padded
// to 4 bytes because 83-byte records are not aligned.
func (e *IPFIXAVCEncoder) EncodeAppTableDatagram(domainID, seqNo uint32, apps []avcApplication, buf []byte) (int, int, error) {
	if len(apps) == 0 {
		return 0, 0, nil
	}
	overhead := ipfixHeaderSize + len(ipfixAppTableTemplateSetBytes) + ipfixDataSetHdrSize
	if len(buf) < overhead+ipfixAppTableRecSize+3 {
		return 0, 0, fmt.Errorf("ipfix avc: buffer too small (%d bytes) for an application-table datagram, need at least %d", len(buf), overhead+ipfixAppTableRecSize+3)
	}
	pos := 0
	binary.BigEndian.PutUint16(buf[pos:], ipfixVersion)
	pos += 2
	lengthOffset := pos
	pos += 2
	binary.BigEndian.PutUint32(buf[pos:], uint32(time.Now().Unix()))
	pos += 4
	binary.BigEndian.PutUint32(buf[pos:], seqNo)
	pos += 4
	binary.BigEndian.PutUint32(buf[pos:], domainID)
	pos += 4
	copy(buf[pos:], ipfixAppTableTemplateSetBytes)
	pos += len(ipfixAppTableTemplateSetBytes)

	setStart := pos
	binary.BigEndian.PutUint16(buf[pos:], ipfixAppTableTemplateID)
	pos += 4
	maxFit := (len(buf) - pos - 3) / ipfixAppTableRecSize
	consumed := len(apps)
	if consumed > maxFit {
		consumed = maxFit
	}
	for _, app := range apps[:consumed] {
		binary.BigEndian.PutUint32(buf[pos:], app.ID)
		pos += 4
		pos = putFixedString(buf, pos, app.Name, ipfixApplicationNameLen)
		pos = putFixedString(buf, pos, app.Description, ipfixApplicationDescriptionLen)
	}
	if rem := (pos - setStart) % 4; rem != 0 {
		for i := 0; i < 4-rem; i++ {
			buf[pos] = 0
			pos++
		}
	}
	binary.BigEndian.PutUint16(buf[setStart+2:], uint16(pos-setStart))
	binary.BigEndian.PutUint16(buf[lengthOffset:], uint16(pos))
	return pos, consumed, nil
}

// putFixedString writes s into a fixed-width NUL-padded field of n bytes,
// truncating at n, and returns the new position. putPaddedString is the
// 32-byte special case used by the interface option table.
func putFixedString(buf []byte, pos int, s string, n int) int {
	c := copy(buf[pos:pos+n], s)
	for i := pos + c; i < pos+n; i++ {
		buf[i] = 0
	}
	return pos + n
}

var _ appTableEncoder = (*IPFIXAVCEncoder)(nil)
```

- [ ] **Step 4: Emit it from `Tick`**

In `go/nl6/flow_exporter.go`, directly after the `if emitOptions { ... }` interface-options block, add:

```go
	// The application table (RFC 6759 section 4.3) rides the same
	// template-refresh cadence as the interface option table. An AVC device
	// may carry both; template ids 257 and 259 keep them apart. Its records
	// are Data Records under RFC 7011 section 3.1, so the sequence advances
	// by consumed; they are metadata, not flows, so RecordsSent is untouched.
	if ate, ok := encoder.(appTableEncoder); ok && emitOptionsCadence {
		remaining := ate.Applications()
		for len(remaining) > 0 {
			n, consumed, err := ate.EncodeAppTableDatagram(fe.domainID, fe.seqNo, remaining, buf)
			if err != nil {
				fe.logFirstOptionsErr(err)
				break
			}
			if n == 0 || consumed == 0 {
				break
			}
			if err := fe.writeDatagram(writeConn, buf[:n], collectorAddr); err != nil {
				fe.logFirstWriteErr(err)
			}
			stats.PacketsSent++
			stats.BytesSent += uint64(n)
			fe.seqNo += uint32(encoder.SeqIncrement(consumed))
			remaining = remaining[consumed:]
		}
	}
```

`emitOptions` today is `sendTemplate && fe.optionShape != ""` captured before the flow loop (read the exact expression at its definition). Split it: capture `emitOptionsCadence := sendTemplate` (the refresh condition alone) beside it, and keep `emitOptions := emitOptionsCadence && fe.optionShape != ""` for the interface table, so the application table emits on every refresh tick regardless of whether an interface table is configured.

- [ ] **Step 5: Generalise the options test decoder**

In `go/nl6/flow_options_test.go`, make `decodeIPFIXOptionsDatagram` read the options template's field specifiers and derive the record layout from them (scope width from field 0's length; each following field as a string of its declared length), exposing `ScopeCount` on the template and `Scope uint32` plus `Strings []string` on each record, instead of assuming template 257's shapes. Keep the existing 257 tests green; they read the same values.

- [ ] **Step 6: Run the tests, then the whole package**

Run: `cd go && go test ./nl6/ -run 'TestIPFIXAVC|TestFlowOptions|TestIPFIXSequence' -v 2>&1 | grep -E '^(--- FAIL|ok|FAIL)|_test.go:'` then `go test ./nl6/ 2>&1 | tail -1`
Expected: `ok` both times.

- [ ] **Step 7: Verify by mutation**

Change `fe.seqNo += uint32(encoder.SeqIncrement(consumed))` in the new block to `fe.seqNo++`, run `TestIPFIXAVCTickEmitsApplicationTable`, confirm `seqNo = 3, want 5` fails. Revert.

- [ ] **Step 8: Commit**

```bash
git add go/nl6/ipfix_avc.go go/nl6/ipfix_avc_test.go go/nl6/flow_exporter.go go/nl6/flow_options_test.go
git commit -s -m "feat(nbar2): emit the RFC 6759 application-table options datagram on the refresh cadence" -m "Assisted-by: ClaudeCode:<model>"
```

---

### Task 8: MTU coverage, docs, and the test-count floor

**Files:**
- Modify: `go/nl6/flow_mtu_test.go` (`TestFlowDatagramsFitMTU` table)
- Modify: `go/nl6/test_inventory_test.go:121`
- Modify: `CLAUDE.md` (protocol table: one row for the AVC template)
- Modify: `docs/reference/flow-export.md` (a short "NBAR2 / AVC records" section stating the template ids, the variable-length rule, the 42125 byte-order and delimiter decisions, and that nothing enables it yet)

- [ ] **Step 1: Add the AVC case to the MTU test**

In `TestFlowDatagramsFitMTU`'s case table add an entry `{name: "ipfix-avc", protocol: "ipfix", encoder: NewIPFIXAVCEncoder(testAVCCatalog()), tightlyPacked: false}` (read the table's actual field names first and match them). The fixture's `fillExpiredFlows` records carry a zero `AVC`, so also fill 60 records via `avcRecord(1, 1, 1, port)` with distinct ports so the variable-length path is exercised; do this inside the case when `name == "ipfix-avc"`.

Run: `cd go && go test ./nl6/ -run TestFlowDatagramsFitMTU -v 2>&1 | grep -E '^(--- |ok|FAIL)'`
Expected: PASS, including the new subtest; every datagram at or under 1472 bytes.

- [ ] **Step 2: Docs**

CLAUDE.md protocol table: add a row `ipfix (AVC template 258)` with header 16B, record `54B fixed prefix + applicationId 4B + two variable-length PEN 9 fields`, template yes (258, plus application table 259 on the refresh cadence), and a Notes cell: "NBAR2 layer-7 export; constants derive from `testdata/cisco-avc/elements.tsv`; IE 42125 hit count is big-endian with no trailing delimiter (an nl6 decision, see `ipfixURIStatsLayout`); not reachable from config until Plan B."

`docs/reference/flow-export.md`: add `## NBAR2 application records (IPFIX only)` with five to eight one-sentence lines covering the same facts, the RFC 7011 §7 length rule, and the "not yet enabled" statement.

- [ ] **Step 3: Floor**

Count the new `Test*` functions added by Tasks 1 to 8 (`grep -c '^func Test' go/nl6/ipfix_avc_test.go` plus the one added to `cisco_avc_extract_test.go`) and set `minimumTestFunctions` to `1576 + that count`.

Run: `cd go && go test ./nl6/ -run 'TestPackageTestInventoryHasNotShrunk|TestLoadBearingGuardsArePresent' -v 2>&1 | grep -E '^(--- |ok|FAIL)'`
Expected: PASS.

- [ ] **Step 4: Full suite, format, vet**

Run: `cd go && test -z "$(gofmt -l ./nl6)" && go vet ./nl6/ && go test ./... 2>&1 | grep -E '^(ok|FAIL)'`
Expected: `ok` for both packages.

- [ ] **Step 5: Commit**

```bash
git add go/nl6/flow_mtu_test.go go/nl6/test_inventory_test.go CLAUDE.md docs/reference/flow-export.md
git commit -s -m "test(nbar2): cover the AVC template in the MTU sweep; document the record format" -m "Assisted-by: ClaudeCode:<model>"
```
