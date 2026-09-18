# NBAR2 Unit 1: Evidence Sourcing Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Produce the checked-in, test-validated evidence base (`go/nl6/testdata/cisco-avc/`) that every IE number, type and template shape in the NBAR2 encoder will derive from, and record what stays unverified.

**Architecture:** Two TSV files (elements and sources) plus a notes file hold the pinned reading; a Go test validates their schema and referential integrity so a row cannot cite nothing. An RFC 6759 extract joins the existing `testdata/rfc/` directory. No production code changes in this unit.

**Tech Stack:** Go 1.26 test package `nl6`, TSV, Markdown. No new dependencies.

**Spec:** `docs/superpowers/specs/2026-09-18-nbar2-ipfix-l7-export-design.md` (section 1, Evidence contract; Work units, item 1).

## Global Constraints

- New Go files carry the fork's SPDX short header, year 2026, no `Created by` line:
  ```go
  /*
   * Copyright 2026 Ronny Trommer <ronny@no42.org>
   * SPDX-License-Identifier: Apache-2.0
   */
  ```
- Primary source is Cisco documentation, cited by title, revision and URL. RFCs are primary for what they define.
- CESNET libfds is consulted as a data file only (`config/system/elements/cisco.xml`), never copied into the repo, and its C sources are not read. ElastiFlow is not consulted at all.
- The extract is a factual table, never a copy of a Cisco document's text. Quote at most one sentence per element for a definition.
- A row's `status` is `verified` only when a Cisco document or an RFC names the number. Otherwise `contested` (sources disagree) or `unresolved` (no authoritative source found).
- Markdown in the repo is one sentence per line, no em-dashes.
- Commits are Conventional Commits, made with `git commit -s`, with `Assisted-by: ClaudeCode:<model>` immediately followed by the `Signed-off-by` line (no blank line between).
- Tests run from `go/`: `cd go && go test ./nl6/ -run <Name> -v`.
- This unit changes no production code. If a task seems to need one, stop and report.

---

### Task 1: Extract format and schema test

**Files:**
- Create: `go/nl6/testdata/cisco-avc/sources.tsv`
- Create: `go/nl6/testdata/cisco-avc/elements.tsv`
- Create: `go/nl6/testdata/cisco-avc/NOTES.md`
- Test: `go/nl6/cisco_avc_extract_test.go`

**Interfaces:**
- Produces: `loadCiscoAVCExtract(t *testing.T) (sources map[string]avcSource, elements []avcElement)` in the test file, used by every later task's test and by unit 2's encoder-constant test.
- Produces: the TSV column contracts below, which unit 2 parses.

`sources.tsv` columns (tab separated, header row, `#` comments allowed):

```
id	title	revision	url	fetched
```

`elements.tsv` columns:

```
pen	id	name	type	length	status	source	note
```

`pen` is the enterprise number (`0` for IANA), `id` the IE number, `type` the IPFIX abstract data type (`unsigned32`, `string`, `octetArray`), `length` a byte count or `var`, `status` one of `verified|contested|unresolved`, `source` a comma-separated list of `sources.tsv` ids, `note` free text.

- [ ] **Step 1: Write the failing test**

```go
/*
 * Copyright 2026 Ronny Trommer <ronny@no42.org>
 * SPDX-License-Identifier: Apache-2.0
 */

package main

import (
	"bufio"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// The Cisco AVC extract is the evidence base for every IE number the NBAR2
// encoder emits (spec section 1). These tests make a row unable to cite
// nothing: every element names a source that exists, every source carries a
// URL and a fetch date, and status is one of three spelled values. They do
// not, and cannot, check that the extract is RIGHT; only sourcing can.

type avcSource struct {
	ID, Title, Revision, URL, Fetched string
}

type avcElement struct {
	PEN, ID, Name, Type, Length, Status, Note string
	Sources                                   []string
}

func readTSV(t *testing.T, path string, want int) [][]string {
	t.Helper()
	f, err := os.Open(path)
	if err != nil {
		t.Fatalf("open %s: %v", path, err)
	}
	defer f.Close()
	var rows [][]string
	sc := bufio.NewScanner(f)
	line := 0
	for sc.Scan() {
		line++
		s := sc.Text()
		if strings.TrimSpace(s) == "" || strings.HasPrefix(s, "#") {
			continue
		}
		cols := strings.Split(s, "\t")
		if len(cols) != want {
			t.Fatalf("%s:%d: %d columns, want %d", path, line, len(cols), want)
		}
		rows = append(rows, cols)
	}
	if err := sc.Err(); err != nil {
		t.Fatalf("scan %s: %v", path, err)
	}
	if len(rows) < 2 {
		t.Fatalf("%s: no data rows", path)
	}
	return rows[1:] // drop header
}

func loadCiscoAVCExtract(t *testing.T) (map[string]avcSource, []avcElement) {
	t.Helper()
	dir := filepath.Join("testdata", "cisco-avc")
	sources := map[string]avcSource{}
	for _, r := range readTSV(t, filepath.Join(dir, "sources.tsv"), 5) {
		s := avcSource{r[0], r[1], r[2], r[3], r[4]}
		if _, dup := sources[s.ID]; dup {
			t.Fatalf("sources.tsv: duplicate id %q", s.ID)
		}
		sources[s.ID] = s
	}
	var elements []avcElement
	for _, r := range readTSV(t, filepath.Join(dir, "elements.tsv"), 8) {
		elements = append(elements, avcElement{
			PEN: r[0], ID: r[1], Name: r[2], Type: r[3], Length: r[4],
			Status: r[5], Sources: strings.Split(r[6], ","), Note: r[7],
		})
	}
	return sources, elements
}

func TestCiscoAVCExtract_SourcesAreComplete(t *testing.T) {
	sources, _ := loadCiscoAVCExtract(t)
	for id, s := range sources {
		if s.Title == "" || s.Revision == "" || s.Fetched == "" {
			t.Errorf("source %q: title, revision and fetched are all required", id)
		}
		if !strings.HasPrefix(s.URL, "https://") {
			t.Errorf("source %q: url %q must be https", id, s.URL)
		}
	}
}

func TestCiscoAVCExtract_EveryElementCitesAKnownSource(t *testing.T) {
	sources, elements := loadCiscoAVCExtract(t)
	valid := map[string]bool{"verified": true, "contested": true, "unresolved": true}
	seen := map[string]bool{}
	for _, e := range elements {
		key := e.PEN + "/" + e.ID
		if seen[key] {
			t.Errorf("elements.tsv: duplicate element %s", key)
		}
		seen[key] = true
		if !valid[e.Status] {
			t.Errorf("element %s: status %q not in verified|contested|unresolved", key, e.Status)
		}
		for _, src := range e.Sources {
			if _, ok := sources[strings.TrimSpace(src)]; !ok {
				t.Errorf("element %s: cites unknown source %q", key, src)
			}
		}
		if e.Status == "contested" && len(e.Sources) < 2 {
			t.Errorf("element %s: contested needs at least two sources", key)
		}
	}
}
```

- [ ] **Step 2: Run the test to verify it fails**

Run: `cd go && go test ./nl6/ -run 'TestCiscoAVCExtract' -v`
Expected: FAIL with `open testdata/cisco-avc/sources.tsv: no such file or directory`

- [ ] **Step 3: Create the sources file with what has already been consulted**

Create `go/nl6/testdata/cisco-avc/sources.tsv`:

```
id	title	revision	url	fetched
cisco-avc-fdg-2015	Cisco Application Visibility and Control Field Definition Guide for Third-Party Customers, AVC Metric Definitions	Revised March 26, 2015	https://www.cisco.com/c/en/us/td/docs/routers/access/ISRG2/AVC/api/guide/AVC_Metric_Definition_Guide/5_AVC_Metric_Def.html	2026-09-18
libfds-cisco-xml	CESNET libfds system element definitions, cisco.xml (PEN 9). Corroborating data file only; BSD-3-Clause/GPLv2+; not copied	master as of fetch date	https://github.com/CESNET/libfds/blob/master/config/system/elements/cisco.xml	2026-09-18
```

- [ ] **Step 4: Create the elements file with the four rows established so far**

Create `go/nl6/testdata/cisco-avc/elements.tsv`:

```
pen	id	name	type	length	status	source	note
0	95	applicationId	octetArray	4	verified	cisco-avc-fdg-2015	engine-id (8 bits) + selector (24 bits); CLI collect application name; exportable under v9 and IPFIX
0	96	applicationName	string	24	verified	cisco-avc-fdg-2015	carried by option application-table, not in data records
9	45003	HTTP Host	string	var	contested	cisco-avc-fdg-2015,libfds-cisco-xml	Cisco 2015 guide: 45003, IPFIX only, max 512 chars IOS / 2 KB IOS XE; libfds defines appHTTPHost as 12235; see NOTES.md
9	42125	HTTP URI statistics	octetArray	var	verified	cisco-avc-fdg-2015	concatenated URIs each followed by a 2-byte hit count; IPFIX only; wire layout to be pinned in Task 5
```

- [ ] **Step 5: Create the notes file**

Create `go/nl6/testdata/cisco-avc/NOTES.md`:

```markdown
# Cisco AVC extract: notes

This directory is the evidence base for the NBAR2 IPFIX encoder.
Read `docs/superpowers/specs/2026-09-18-nbar2-ipfix-l7-export-design.md`, section 1, before editing.
`elements.tsv` is a factual table of IE numbers.
It is not a copy of any Cisco document.

## Reference policy

Primary: Cisco documentation and RFCs, cited by title, revision and URL.
Corroborating: CESNET libfds `cisco.xml`, a BSD-licensed data file, never copied here; libfds and IPFIXcol2 C sources are not read.
Excluded: ElastiFlow, on licence grounds (object-code EULA; legacy repo under a non-OSI commercial-use restriction).

## Contested

### HTTP Host: 45003 or 12235

Cisco's 2015 Field Definition Guide (ISR G2, ASR 1000) gives 45003.
libfds gives 12235 under the name `appHTTPHost`.
Resolution: pending Task 3.

## Unverified

TLS SNI or certificate common name as an exported string: no Cisco PEN 9 element found yet.
Resolution: pending Task 4.
```

- [ ] **Step 6: Run the test to verify it passes**

Run: `cd go && go test ./nl6/ -run 'TestCiscoAVCExtract' -v`
Expected: PASS for both tests.

- [ ] **Step 7: Verify the test has detection power**

Temporarily change `45003`'s source column to `nosuch` in `elements.tsv`, run the test, confirm `cites unknown source "nosuch"` fails. Revert the edit.

Run: `cd go && go test ./nl6/ -run 'TestCiscoAVCExtract_EveryElementCitesAKnownSource' -v`
Expected: FAIL naming element `9/45003`, then PASS after revert.

- [ ] **Step 8: Commit**

```bash
git add go/nl6/testdata/cisco-avc go/nl6/cisco_avc_extract_test.go
git commit -s -m "test(nbar2): add the Cisco AVC evidence extract and its schema test" -m "Pins the four IE rows established during design and records the 45003 vs 12235 HTTP host discrepancy as contested. No production code." -m "Assisted-by: ClaudeCode:claude-fable-5-1"
```

Verify the trailer block: `git log -1 --format=%B | tail -3` must show `Assisted-by` immediately above `Signed-off-by`.

---

### Task 2: RFC 6759 extract (applicationId engine IDs and the application table)

**Files:**
- Create: `go/nl6/testdata/rfc/rfc6759-application-information.txt`
- Modify: `go/nl6/testdata/cisco-avc/sources.tsv`
- Modify: `go/nl6/testdata/cisco-avc/elements.tsv`
- Modify: `go/nl6/testdata/cisco-avc/NOTES.md`
- Test: `go/nl6/cisco_avc_extract_test.go`

**Interfaces:**
- Consumes: `loadCiscoAVCExtract` from Task 1.
- Produces: the engine-id table and options-template shape unit 2 encodes from.

- [ ] **Step 1: Look at the existing RFC extract header form**

Run: `ls go/nl6/testdata/rfc/ && head -20 go/nl6/testdata/rfc/$(ls go/nl6/testdata/rfc/ | head -1)`
Expected: one or more RFC 3414 extract files with a leading comment naming the RFC, sections and source URL. Match that header form in Step 3.

- [ ] **Step 2: Write the failing test**

Append to `go/nl6/cisco_avc_extract_test.go`:

```go
// RFC 6759 is the IETF publication of Cisco's applicationId export. Its
// engine-id table decides which classification engine a collector resolves
// an applicationId against, so the values the encoder uses must be read from
// the checked-in extract, never recalled.
func TestCiscoAVCExtract_RFC6759EngineIDsArePinned(t *testing.T) {
	data, err := os.ReadFile(filepath.Join("testdata", "rfc", "rfc6759-application-information.txt"))
	if err != nil {
		t.Fatalf("read extract: %v", err)
	}
	text := string(data)
	for _, want := range []string{
		"IANA-L4", "USER-Defined", "PANA-L7",
		"applicationName", "applicationDescription",
		"Section 4.3",
	} {
		if !strings.Contains(text, want) {
			t.Errorf("rfc6759 extract is missing %q", want)
		}
	}
	sources, elements := loadCiscoAVCExtract(t)
	if _, ok := sources["rfc6759"]; !ok {
		t.Fatal("sources.tsv has no rfc6759 row")
	}
	var have94 bool
	for _, e := range elements {
		if e.PEN == "0" && e.ID == "94" {
			have94 = true
		}
	}
	if !have94 {
		t.Error("elements.tsv has no applicationDescription (IE 94) row")
	}
}
```

- [ ] **Step 3: Run the test to verify it fails**

Run: `cd go && go test ./nl6/ -run 'TestCiscoAVCExtract_RFC6759' -v`
Expected: FAIL with `read extract: open testdata/rfc/rfc6759-application-information.txt: no such file or directory`

- [ ] **Step 4: Fetch RFC 6759 and write the extract**

Run: `curl -sSL https://www.rfc-editor.org/rfc/rfc6759.txt -o /tmp/rfc6759.txt` (use the session scratchpad directory if one is configured).

Create `go/nl6/testdata/rfc/rfc6759-application-information.txt` with, in this order: a header in the form found in Step 1 naming `RFC 6759, Cisco Systems Export of Application Information in IP Flow Information Export (IPFIX), November 2012, https://www.rfc-editor.org/rfc/rfc6759.txt, fetched 2026-09-18`; then the verbatim text of Section 4.1 (`applicationId`) including the Classification Engine ID table; then Section 4.2 (`applicationName`, `applicationDescription`); then Section 4.3 (the options template for the application table). Copy from the fetched file; do not paraphrase inside the extract.

- [ ] **Step 5: Add the source row and the element rows**

Append to `sources.tsv`:

```
rfc6759	RFC 6759: Cisco Systems Export of Application Information in IPFIX (Claise, Aitken, Ben-Dvora)	November 2012	https://www.rfc-editor.org/rfc/rfc6759.txt	2026-09-18
```

Append to `elements.tsv`:

```
0	94	applicationDescription	string	var	verified	rfc6759	non-scope field of the application-table options template (RFC 6759 section 4.3)
```

Edit the existing `95` and `96` rows so `source` reads `cisco-avc-fdg-2015,rfc6759` and the `95` note ends with `; engine ids per RFC 6759 section 4.1: 3 IANA-L4 (port based), 6 USER-Defined (custom), 13 PANA-L7 (NBAR2 layer 7)`.

- [ ] **Step 6: Record the options-template shape in NOTES.md**

Append to `NOTES.md`:

```markdown
## Application table options template (RFC 6759 section 4.3)

Scope field: `applicationId` (IE 95).
Non-scope fields: `applicationName` (IE 96), `applicationDescription` (IE 94).
Cisco's 2015 guide gives `applicationName` a fixed length of 24 bytes in `option application-table`.
Whether `applicationDescription` is emitted by IOS-XE `option application-table`, and at what length, is checked in Task 3 alongside the platform reading.

## applicationId engine ids (RFC 6759 section 4.1)

| engine id | name | selector | nl6 use |
|-----------|------|----------|---------|
| 3 | IANA-L4 | 2 bytes, well-known port | port-based catalog entries |
| 6 | USER-Defined | 3 bytes | custom applications |
| 13 | PANA-L7 | 3 bytes | NBAR2 layer-7 applications |

The selector values for PANA-L7 are Cisco's NBAR2 registry and are not published as a table; a catalog entry records the selector it uses and the reading it came from.
```

- [ ] **Step 7: Run all extract tests**

Run: `cd go && go test ./nl6/ -run 'TestCiscoAVCExtract' -v`
Expected: PASS for all three tests.

- [ ] **Step 8: Commit**

```bash
git add go/nl6/testdata/rfc/rfc6759-application-information.txt go/nl6/testdata/cisco-avc go/nl6/cisco_avc_extract_test.go
git commit -s -m "test(nbar2): pin RFC 6759 engine ids and the application-table shape" -m "Assisted-by: ClaudeCode:claude-fable-5-1"
```

---

### Task 3: Resolve the HTTP host number (45003 vs 12235) for the in-scope platforms

**Files:**
- Modify: `go/nl6/testdata/cisco-avc/sources.tsv`
- Modify: `go/nl6/testdata/cisco-avc/elements.tsv`
- Modify: `go/nl6/testdata/cisco-avc/NOTES.md`

**Interfaces:**
- Produces: a `verified` or `unresolved` status on row `9/45003` and, if a second number is confirmed for a platform, a separate row for it. Unit 2 encodes only `verified` rows.

- [ ] **Step 1: Read what libfds says about 12235**

Open https://github.com/CESNET/libfds/blob/master/config/system/elements/cisco.xml in a browser and find the `appHTTPHost` element. Record in `NOTES.md` under "Contested": the exact `<name>`, `<id>`, `<dataType>` and any `<source>` or comment the file gives for that element. Do not copy the surrounding file.

- [ ] **Step 2: Search Cisco documentation for the IOS-XE 17.x field list**

Check, in order, and record each as a `sources.tsv` row whether or not it names the field:

1. `https://www.cisco.com/c/en/us/td/docs/routers/access/ISRG2/AVC/api/guide/AVC_Metric_Definition_Guide.pdf` (the full PDF; confirm the HTML reading of 45003 and look for a platform column).
2. Cisco "Application Visibility and Control Configuration Guide, Cisco IOS XE 17.x", chapter "Flexible NetFlow and AVC", section listing `collect application http host` and its export field ID. Search cisco.com for `"collect application http host" "IOS XE 17"`.
3. Cisco "Catalyst 9000 Application Visibility and Control" configuration guide, any release 17.x, section on exported fields. Search cisco.com for `Catalyst 9500 AVC "http host" flow record`.
4. Cisco Wireless (WLC / Catalyst 9800) AVC field list, because WLC numbering is where a second number most plausibly comes from.

For each document, record title, revision, URL, fetch date, and in `NOTES.md` a one-line statement of what it says about HTTP host (number, or "does not list").

- [ ] **Step 3: Decide the status by the rule**

Apply the Global Constraint: `verified` only when a Cisco document names the number for the platform.

- If a Cisco IOS-XE 17.x or Catalyst 9000 document names 45003: set row `9/45003` to `verified`, cite it, and add a `NOTES.md` line saying 12235 is not confirmed by any Cisco document and where it appears.
- If a Cisco document names 12235 for a platform: add a row `9	12235	appHTTPHost	string	var	verified	<source>	<platform>` and keep 45003 `verified` for its platforms, with `NOTES.md` explaining both.
- If no 17.x document names either: leave `contested`, and write in `NOTES.md` which platforms 45003 is confirmed for (ISR G2, ASR 1000 per the 2015 guide) and that Catalyst 9500 is unconfirmed.

- [ ] **Step 4: Run the extract tests**

Run: `cd go && go test ./nl6/ -run 'TestCiscoAVCExtract' -v`
Expected: PASS. A `contested` row still needs two sources; a `verified` row needs one.

- [ ] **Step 5: Commit**

```bash
git add go/nl6/testdata/cisco-avc
git commit -s -m "docs(nbar2): record the HTTP host IE reading for IOS-XE platforms" -m "Assisted-by: ClaudeCode:claude-fable-5-1"
```

---

### Task 4: Widen the TLS SNI / common-name search

**Files:**
- Modify: `go/nl6/testdata/cisco-avc/sources.tsv`
- Modify: `go/nl6/testdata/cisco-avc/elements.tsv` (only if a field is found)
- Modify: `go/nl6/testdata/cisco-avc/NOTES.md`

**Interfaces:**
- Produces: either a `verified` row for a TLS string export, or an "Unverified" entry in `NOTES.md` stating the search that was done. The spec's TLS scope decision reads this.

- [ ] **Step 1: Check the documents, recording each as a source row**

1. The Task 3 documents (already fetched): search each for `ssl`, `tls`, `sni`, `common name`, `server name`.
2. Cisco "NBAR2 Protocol Pack" release notes for the current pack (search cisco.com `NBAR2 protocol pack release notes "extracted fields"`).
3. Cisco "AVC Field Definition Guide" chapter "New Exported Fields": `https://www.cisco.com/c/en/us/td/docs/routers/access/ISRG2/AVC/api/guide/AVC_Metric_Definition_Guide/avc_app_exported_fields.html`.
4. Cisco Catalyst 9800 (WLC) AVC and "Encrypted Traffic Analytics" export documentation, since ETA exports TLS metadata.
5. libfds `cisco.xml`: search for `ssl`, `tls`, `sni`, `commonName`. Record what, if anything, it defines; corroboration only.

- [ ] **Step 2: Record the outcome**

If a Cisco document names a PEN 9 element exporting SNI or CN as a string: add a `verified` row and a `NOTES.md` paragraph naming the platform and CLI.

If not: replace the "Unverified" TLS entry in `NOTES.md` with:

```markdown
## Unverified: TLS SNI / common name

Searched on 2026-09-18 (sources: <list ids>).
No Cisco PEN 9 element exporting a TLS SNI or certificate common name as a string was found on ISR G2, ASR 1000, IOS-XE 17.x, Catalyst 9000 or Catalyst 9800.
NBAR2 consumes SNI and CN for classification (`ip nbar custom ... ssl unique-name`); the export product is an applicationId selector.
Consequence for the spec: TLS-classified traffic is represented by applicationId and the application table, with no SNI string on the wire.
```

- [ ] **Step 3: Run the extract tests and commit**

Run: `cd go && go test ./nl6/ -run 'TestCiscoAVCExtract' -v`
Expected: PASS.

```bash
git add go/nl6/testdata/cisco-avc
git commit -s -m "docs(nbar2): record the TLS SNI/common-name export search" -m "Assisted-by: ClaudeCode:claude-fable-5-1"
```

---

### Task 5: Pin the HTTP URI statistics (42125) wire layout

**Files:**
- Modify: `go/nl6/testdata/cisco-avc/NOTES.md`
- Modify: `go/nl6/testdata/cisco-avc/elements.tsv`

**Interfaces:**
- Produces: the byte layout unit 2 encodes for IE 42125, or a `NOTES.md` statement that it stays unpinned and the field leaves scope.

- [ ] **Step 1: Read the Cisco definition**

From `cisco-avc-fdg-2015` (Task 1 source) and the full PDF (Task 3 source 1), record verbatim into `NOTES.md` under a new heading `## HTTP URI statistics (42125) layout` the guide's one-sentence definition, and then in your own words: element order, whether the URI is length-prefixed or delimiter-terminated, the hit-count width and byte order, and the maximum URI length per platform.

- [ ] **Step 2: Corroborate against libfds**

Record what `cisco.xml` gives for element 9357 `appHTTPUriStatistics` (data type only). If the data type disagrees with Cisco's description, say so; Cisco governs.

- [ ] **Step 3: Update the element row**

Set the `9/42125` note to the layout summary from Step 1 (one line). If the layout could not be established from Cisco text, set `status` to `unresolved` and add to `NOTES.md` "Unverified": `HTTP URI statistics layout not pinned; the field leaves unit 2 scope until it is.`

- [ ] **Step 4: Run the extract tests and commit**

Run: `cd go && go test ./nl6/ -run 'TestCiscoAVCExtract' -v`
Expected: PASS.

```bash
git add go/nl6/testdata/cisco-avc
git commit -s -m "docs(nbar2): pin the HTTP URI statistics wire layout" -m "Assisted-by: ClaudeCode:claude-fable-5-1"
```

---

### Task 6: Fold the outcomes into the spec and choose the exit

**Files:**
- Modify: `docs/superpowers/specs/2026-09-18-nbar2-ipfix-l7-export-design.md` (section 1 "What has been established so far", "Two unresolved findings", and "Open questions" 1 to 4)

**Interfaces:**
- Consumes: the final state of `elements.tsv` and `NOTES.md`.
- Produces: the spec state the units 2 to 7 plan is written from.

- [ ] **Step 1: Update section 1's table**

Replace the four-row table with one row per `verified` element in `elements.tsv`, same columns, and add RFC 6759 as a cited source beside the Cisco guide.

- [ ] **Step 2: Rewrite "Two unresolved findings" as outcomes**

For HTTP host: state the final status and platforms, in two sentences.
For TLS: state whether a field was found, in two sentences, and name the scope consequence.

- [ ] **Step 3: Apply the exit rule and state which branch was taken**

Under a new heading `### Outcome of unit 1`, write exactly one of:

- `All fields in scope are verified. The claim stays "Cisco-faithful". Units 2 to 7 proceed.`
- `The following fields are unverified and leave scope: <list>. The claim stays "Cisco-faithful" for the remaining fields. Units 2 to 7 proceed on those.`
- `<Field> cannot be verified and is required. The claim downgrades to "conformant and interop-tested against open decoders"; docs/ will say so in those words. Units 2 to 7 proceed under the downgraded claim.`

- [ ] **Step 4: Mark open questions 1 to 4 resolved**

Each of the four lines becomes `Resolved: <one sentence>` pointing at `testdata/cisco-avc/NOTES.md`.

- [ ] **Step 5: Check style and commit**

Run: `grep -cP '\x{2014}|\x{2013}' docs/superpowers/specs/2026-09-18-nbar2-ipfix-l7-export-design.md`
Expected: `0` (no em-dash or en-dash; the repo's prose rule).

```bash
git add docs/superpowers/specs/2026-09-18-nbar2-ipfix-l7-export-design.md
git commit -s -m "docs(nbar2): record unit 1 sourcing outcomes and the fidelity exit taken" -m "Assisted-by: ClaudeCode:claude-fable-5-1"
```

- [ ] **Step 6: Report**

State to the owner, in this order: the outcome branch from Step 3, the final `elements.tsv` row list with statuses, and the sentence from `NOTES.md` that describes the TLS result. Then request the plan for units 2 to 7.
