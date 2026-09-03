/*
 * Copyright 2026 Ronny Trommer <ronny@no42.org>
 * SPDX-License-Identifier: Apache-2.0
 */

package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
	"time"
)

// nl6#98, first half: the three seams an SNMPv3 notification encoder needs, with
// NO second caller yet.
//
// THE WHOLE POINT OF THIS FILE IS THE FOUR DIGESTS, AND WHAT MAKES THEM WORTH
// ANYTHING IS WHERE THEY WERE MEASURED. Each constant below was computed by
// running this test's digest half in a worktree at the BASELINE COMMIT — before
// any seam was lifted — and copied here. A digest read off the new tree and
// pasted back proves only that the new tree agrees with itself, which is exactly
// the failure mode this change is split out to avoid. Same standard, and the
// same worktree procedure, as TestV2cOutputUnchangedByV1Encoder (nl6#97).
//
// HOW THEY WERE DERIVED, exactly:
//
//	git worktree add /tmp/nl6-baseline-98 449280dd022424ea88258af1025286780823aac8
//	# in the worktree: add `var usmPrivSaltRead = rand.Read` to snmpv3_crypto.go
//	# and point the two `rand.Read(salt)` calls at it, then copy this file in
//	# and DELETE FROM THE "seam properties" BANNER DOWN — the digest half above
//	# it is the part that compiles against the baseline.
//	# Then run goimports -w on the copy. Six imports (errors, go/ast, go/parser,
//	# go/token, os, path/filepath) are used ONLY below the banner, so a copy
//	# truncated without fixing them does not compile and the baseline cannot be
//	# measured at all. Keep: bytes, crypto/sha256, encoding/hex, fmt, sort,
//	# strings, testing, time.
//	cd /tmp/nl6-baseline-98/go && go test ./nl6/ \
//	    -run 'UnchangedBy(PDU|Envelope)Extraction' -count=1 -v
//
// The salt seam is the ONE production difference between the tree those were
// measured in and the tree before this change: an authPriv message is random by
// construction, so without pinning that input its bytes cannot be compared
// across commits at all. Everything else in the digest half is baseline code.
//
// WHAT THE CORPUS IS, precisely, because the digests mean nothing without it.
// Catalogs are loaded the way production loads them — the embedded universal
// plus ScanPerTypeTrapCatalogs, which SKIPS the `_`-prefixed slugs and APPLIES
// MergeOverlay, so each per-type row is the effective catalog a device of that
// type fires from. What is NOT applied is ApplySizeBudget: that runs only in
// StartTrapSubsystem against an operator-settable MTU, so entries production
// would mark oversized and refuse to fire are encoded here anyway. That is
// deliberate — the subject is the encoders, and a corpus that shrank whenever
// -datagram-mtu moved would make these digests a function of a flag.
//
// IF ONE OF THESE MOVES, the extraction changed the wire. Do not re-pin it
// without saying which path's output changed and why.

// ── the shipped notification corpus ─────────────────────────────────────────

// pduExtractionCtx is the fixed template context every row renders against.
// Fixed rather than synthesised so the digests are a property of the corpus and
// the encoders, not of the clock.
var pduExtractionCtx = TemplateCtx{
	IfIndex: 7, IfName: "GigabitEthernet0/7", Uptime: 123456, Now: 1770000000,
	DeviceIP: "10.42.0.9", SysName: "sim-9", Model: "Cisco ISR 4451",
	Serial: "SN0a2a0009", ChassisID: "02:42:0a:2a:00:09",
	NowLocal: "2026-08-04 11:22:33", Detail: "OSNR=12.5dB",
}

// notificationRow is one resolved catalog entry, ready to encode.
type notificationRow struct {
	label      string
	trapOID    string
	enterprise string
	varbinds   []Varbind
	// mustRefuse marks a row every notification encoder is required to REFUSE.
	// Without at least one, the refusal branches below are unreachable and the
	// fast encoder's fault-parity arm never runs: the shipped corpus refuses
	// nothing, so a digest built from it alone pins the success path only.
	mustRefuse bool
}

// syntheticRefusalRows are the deliberately unencodable rows.
//
// nl6#540 is the defect they stand in for: an OID the encoder cannot represent
// used to go out as the degenerate `06 00` — a binding no manager can match,
// with no log line and no counter. encodeNotificationPDU refuses at FOUR
// positions — trapOID, enterpriseOID, the varbind OID and encodeVarbindTyped —
// and each gets a row, because a refusal that moved from one position to
// another would otherwise be invisible.
//
// THE ENTERPRISE ROW WAS MISSING and its absence was not visible from either
// side: the other three all carry a valid enterprise, so that branch
// contributed to no digest and reached no fault-parity arm, while the comment
// here said "each of the three positions" and read as complete.
//
// A single-arc OID is the trigger: encodeOID answers `06 00` for it, which is
// exactly what encodableAsOID tests for.
var syntheticRefusalRows = []notificationRow{
	{
		label:      "_synthetic/unencodable-trapOID",
		trapOID:    "1",
		enterprise: "1.3.6.1.4.1.9",
		varbinds:   []Varbind{{OID: "1.3.6.1.2.1.1.5.0", Type: TrapVTOctetString, Value: "sim-9"}},
		mustRefuse: true,
	},
	{
		// The trapOID is a STANDARD trap deliberately. RFC 3584 §3.2 honours a
		// declared snmpTrapEnterprise only for a standard trap, so this is the
		// one shape in which the enterprise reaches the v1 encoder as well as
		// the two v2c ones — a vendor trapOID would derive its enterprise from
		// itself and leave the v1 row silently unexercised.
		label:      "_synthetic/unencodable-enterprise-OID",
		trapOID:    "1.3.6.1.6.3.1.1.5.3",
		enterprise: "1",
		varbinds:   []Varbind{{OID: "1.3.6.1.2.1.1.5.0", Type: TrapVTOctetString, Value: "sim-9"}},
		mustRefuse: true,
	},
	{
		label:      "_synthetic/unencodable-varbind-OID",
		trapOID:    "1.3.6.1.6.3.1.1.5.3",
		enterprise: "1.3.6.1.4.1.9",
		varbinds:   []Varbind{{OID: "2", Type: TrapVTOctetString, Value: "sim-9"}},
		mustRefuse: true,
	},
	{
		label:      "_synthetic/unencodable-OID-value",
		trapOID:    "1.3.6.1.6.3.1.1.5.3",
		enterprise: "1.3.6.1.4.1.9",
		varbinds:   []Varbind{{OID: "1.3.6.1.2.1.1.2.0", Type: TrapVTOID, Value: "3"}},
		mustRefuse: true,
	},
}

// shippedNotificationRows is how many effective catalog entries the corpus walk
// resolves: the embedded universal plus every per-type overlay, merged the way
// production merges them.
//
// ASSERTED EXACTLY, NOT FLOORED, and the reason is what the three catalog
// digests SAY when they fail. Each of them names a cause — "lifting
// encodeNotificationPDU must not move one byte" — and that sentence is false if
// what actually moved was a catalog DATA edit: a new vendor entry, a reworded
// template, an entry removed. A floor cannot tell the two apart, so a data edit
// would present as an encoder regression and be re-pinned as one. With the
// census exact, a data edit fails HERE first, with a message that says so, and
// the digests below stay a statement about the encoders.
//
// Raise or lower it when the shipped catalogs change, in the same commit, and
// re-measure the three digests at the baseline the header names.
const shippedNotificationRows = 38

// syntheticNotificationRows is the refusal set's size, pinned separately so a
// deleted synthetic row cannot be absorbed by a catalog gaining an entry. It is
// also what wantRefusals must equal on every pass.
const syntheticNotificationRows = 4

// notificationCorpus is every shipped catalog entry plus the synthetic
// refusals.
//
// LOADED THE WAY PRODUCTION LOADS THEM. An earlier cut globbed
// resources/*/traps.json, which matched _common/traps.json and digested the five
// universal entries a second time under a second label — while production skips
// `_`-prefixed slugs (trap_catalog.go) and reaches the universal only through
// the embedded copy. ScanPerTypeTrapCatalogs is the same scanner
// SimulatorManager uses and the same one TestV2cOutputUnchangedByV1Encoder
// uses, so the corpus is now the set of effective catalogs the fleet fires
// from.
func notificationCorpus(t *testing.T) []notificationRow {
	t.Helper()

	universal, err := LoadEmbeddedCatalog()
	if err != nil {
		t.Fatalf("LoadEmbeddedCatalog: %v", err)
	}
	perType, err := ScanPerTypeTrapCatalogs(universal, "resources")
	if err != nil {
		t.Fatalf("ScanPerTypeTrapCatalogs: %v", err)
	}
	if len(perType) == 0 {
		t.Fatal("no per-type trap catalogs found — every digest below would be near-vacuous")
	}

	catalogs := map[string]*Catalog{"_universal": universal}
	for slug, c := range perType {
		if strings.HasPrefix(slug, "_") {
			t.Fatalf("ScanPerTypeTrapCatalogs returned the reserved slug %q; the universal catalog "+
				"must reach this corpus exactly once, through LoadEmbeddedCatalog", slug)
		}
		catalogs[slug] = c
	}

	names := make([]string, 0, len(catalogs))
	for n := range catalogs {
		names = append(names, n)
	}
	sort.Strings(names)

	var rows []notificationRow
	for _, catName := range names {
		entries := append([]*CatalogEntry(nil), catalogs[catName].Entries...)
		sort.Slice(entries, func(a, b int) bool { return entries[a].Name < entries[b].Name })
		for _, e := range entries {
			vbs, err := e.Resolve(pduExtractionCtx, nil)
			if err != nil {
				t.Fatalf("%s/%s: Resolve: %v", catName, e.Name, err)
			}
			rows = append(rows, notificationRow{
				label:      catName + "/" + e.Name,
				trapOID:    e.SnmpTrapOID,
				enterprise: e.SnmpTrapEnterprise,
				varbinds:   vbs,
			})
		}
	}
	if len(rows) != shippedNotificationRows {
		t.Fatalf("the corpus walk resolved %d shipped catalog entries, want %d.\n"+
			"THIS IS A CATALOG DATA CHANGE, NOT AN ENCODER CHANGE. The three digests below will "+
			"move too, and their failure messages blame the extraction — which would be the wrong "+
			"diagnosis. Update shippedNotificationRows and re-measure those digests at the baseline "+
			"commit named in this file's header, in a worktree, against the NEW catalogs",
			len(rows), shippedNotificationRows)
	}
	if len(syntheticRefusalRows) != syntheticNotificationRows {
		t.Fatalf("%d synthetic refusal rows, want %d; encodeNotificationPDU refuses at four "+
			"positions and each needs one, or a branch contributes to no digest",
			len(syntheticRefusalRows), syntheticNotificationRows)
	}
	return append(rows, syntheticRefusalRows...)
}

// wantRefusals is how many rows every notification encoder must refuse, per
// pass over the corpus. Asserted rather than merely counted: a refusal branch
// nothing reaches is a digest contribution that pins nothing.
func wantRefusals(rows []notificationRow) int {
	n := 0
	for _, r := range rows {
		if r.mustRefuse {
			n++
		}
	}
	return n
}

// ── row 1 and 2: the SNMPv2c reference encoder, TRAP and INFORM ─────────────

// TestV2cNotificationOutputUnchangedByPDUExtraction is the matrix's first row.
//
// It covers BOTH -trap-mode values, because the PDU tag is the only thing that
// distinguishes them and lifting the PDU builder is precisely a change to where
// that tag is written.
func TestV2cNotificationOutputUnchangedByPDUExtraction(t *testing.T) {
	rows := notificationCorpus(t)
	enc := SNMPv2cEncoder{}
	buf := make([]byte, 8192)

	h := sha256.New()
	encoded, refused := 0, 0
	for _, r := range rows {
		for _, mode := range []struct {
			name string
			fn   func(string, uint32, string, string, uint32, []Varbind, []byte) (int, error)
		}{
			{"trap", enc.EncodeTrap},
			{"inform", enc.EncodeInform},
		} {
			n, err := mode.fn("public", 42, r.trapOID, r.enterprise, pduExtractionCtx.Uptime, r.varbinds, buf)
			if (err != nil) != r.mustRefuse {
				t.Errorf("%s/%s: err = %v, mustRefuse = %v", r.label, mode.name, err, r.mustRefuse)
			}
			if err != nil {
				// The refusal is part of the behaviour under test, so it is
				// digested too — an extraction that turned a refusal into a
				// message, or the reverse, moves this digest.
				h.Write([]byte(r.label + "/" + mode.name + ":REFUSED"))
				refused++
				continue
			}
			h.Write([]byte(r.label + "/" + mode.name + ":"))
			h.Write(buf[:n])
			encoded++
		}
	}
	if encoded < 40 {
		t.Fatalf("only %d messages encoded (%d refused); the walk collapsed", encoded, refused)
	}
	if want := wantRefusals(rows) * 2; refused != want {
		t.Errorf("%d refusals, want %d; the refusal branch of this digest is not being exercised",
			refused, want)
	}

	const want = "788e75e09e93dbcb6f5615269004d0d4924ba1034f1b6a28e1701202077cf79b"
	if got := hex.EncodeToString(h.Sum(nil)); got != want {
		t.Errorf("the SNMPv2c encoding of %d shipped notifications (%d refusals) digests to %s, "+
			"measured at the baseline commit as %s.\nshippedNotificationRows fires ahead of this on a "+
			"catalog DATA edit, so a failure here is the ENCODERS: lifting encodeNotificationPDU out "+
			"of encodeV2cNotification must not move one byte of v2c output. If this moved "+
			"deliberately, say which v2c behaviour changed and why", encoded, refused, got, want)
	}
}

// TestFastV2cNotificationOutputUnchangedByPDUExtraction is the matrix's second
// row. The fast encoder is READ-ONLY in this change, so its digest moving means
// a shared primitive underneath it moved.
//
// It also re-asserts parity with the reference here rather than relying on
// TestFastEncoderMatchesLegacy_ShippedCatalogs alone: parity holding while BOTH
// sides moved together is the one way two green digests can still be wrong, and
// only the pair of pinned digests rules it out.
func TestFastV2cNotificationOutputUnchangedByPDUExtraction(t *testing.T) {
	rows := notificationCorpus(t)
	enc := SNMPv2cEncoder{}
	ref := make([]byte, 8192)
	var fast []byte

	h := sha256.New()
	encoded, refused := 0, 0
	for _, r := range rows {
		for _, tc := range []struct {
			name string
			tag  byte
			mode TrapMode
		}{
			{"trap", ASN1_TRAP_V2C, TrapModeTrap},
			{"inform", ASN1_INFORM_REQUEST, TrapModeInform},
		} {
			var err error
			fast, err = enc.EncodeNotificationFast(fast, tc.mode, "public", 42, nil,
				r.trapOID, r.enterprise, pduExtractionCtx.Uptime, r.varbinds)

			n, refErr := encodeV2cNotification(tc.tag, "public", 42, r.trapOID, r.enterprise,
				pduExtractionCtx.Uptime, r.varbinds, ref)

			// FAULT-FOR-FAULT, not just byte-for-byte: a pair that agrees on
			// output while disagreeing on which inputs they refuse ships a
			// message one of them would not send (nl6#540's lesson). The
			// synthetic rows are what make this arm reachable at all.
			if (err == nil) != (refErr == nil) {
				t.Errorf("%s/%s: fast err=%v, reference err=%v — the two must refuse the same inputs",
					r.label, tc.name, err, refErr)
				continue
			}
			if (err != nil) != r.mustRefuse {
				t.Errorf("%s/%s: err = %v, mustRefuse = %v", r.label, tc.name, err, r.mustRefuse)
			}
			if err != nil {
				h.Write([]byte("fast/" + r.label + "/" + tc.name + ":REFUSED"))
				refused++
				continue
			}
			if !bytes.Equal(fast, ref[:n]) {
				t.Errorf("%s/%s: fast and reference encoders disagree\nfast: % x\nref:  % x",
					r.label, tc.name, fast, ref[:n])
				continue
			}
			h.Write([]byte("fast/" + r.label + "/" + tc.name + ":"))
			h.Write(fast)
			encoded++
		}
	}
	if encoded < 40 {
		t.Fatalf("only %d messages encoded; the walk collapsed", encoded)
	}
	if want := wantRefusals(rows) * 2; refused != want {
		t.Errorf("%d refusals, want %d; the fault-parity arm is not being exercised", refused, want)
	}

	const want = "9153d4cfa67073f4f7027a805585943261cffbbfc88156973ab2ef8842bb3233"
	if got := hex.EncodeToString(h.Sum(nil)); got != want {
		t.Errorf("the fast encoder's output over %d shipped notifications digests to %s, measured at "+
			"the baseline commit as %s.\nshippedNotificationRows fires ahead of this on a catalog DATA "+
			"edit, so a failure here is the encoders: encodeV2cNotificationFast is untouched by this "+
			"change, and a move is a shared primitive moving underneath it", encoded, got, want)
	}
}

// ── row 3: the SNMPv1 trap path ─────────────────────────────────────────────

// TestV1NotificationOutputUnchangedByPDUExtraction is the matrix's third row.
//
// The v1 encoder builds its OWN PDU — a Trap-PDU has no request-id, no
// error-status and none of the three prepended varbinds — so it does not call
// encodeNotificationPDU at all. It is digested anyway because it shares
// encodeVarbindTyped and the OID encoder with the code that moved.
func TestV1NotificationOutputUnchangedByPDUExtraction(t *testing.T) {
	rows := notificationCorpus(t)
	enc := SNMPv1Encoder{AgentAddr: "10.42.0.9"}
	buf := make([]byte, 8192)

	h := sha256.New()
	encoded, refused := 0, 0
	for _, r := range rows {
		n, err := enc.EncodeTrap("public", 42, r.trapOID, r.enterprise, pduExtractionCtx.Uptime, r.varbinds, buf)
		if (err != nil) != r.mustRefuse {
			t.Errorf("%s: err = %v, mustRefuse = %v", r.label, err, r.mustRefuse)
		}
		if err != nil {
			h.Write([]byte(r.label + ":REFUSED"))
			refused++
			continue
		}
		h.Write([]byte(r.label + ":"))
		h.Write(buf[:n])
		encoded++
	}
	if encoded < 20 {
		t.Fatalf("only %d v1 traps encoded (%d refused); the walk collapsed", encoded, refused)
	}
	if want := wantRefusals(rows); refused != want {
		t.Errorf("%d refusals, want %d", refused, want)
	}

	const want = "19f91e2e7df38b63e1148c2cc8836d232fb3211321e513805650b72735fe7a34"
	if got := hex.EncodeToString(h.Sum(nil)); got != want {
		t.Errorf("the SNMPv1 encoding of %d shipped notifications (%d refusals) digests to %s, "+
			"measured at the baseline commit as %s.\nshippedNotificationRows fires ahead of this on a "+
			"catalog DATA edit, so a failure here is encodeVarbindTyped or the OID encoder moving "+
			"beneath a path that builds its own PDU", encoded, refused, got, want)
	}
}

// ── row 4: the SNMPv3 poll path, at every security level ────────────────────

// v3ExtractionServer builds a v3 server whose output is REPRODUCIBLE.
//
// Two things vary in a v3 message and both are pinned here. engineTime is
// seconds since boot, so bootedAt is zeroed AFTER the sync.Once derivation runs
// — engineTimeSeconds() answers exactly 0 for a zero bootedAt, which is the only
// value of it that does not depend on how long the test took. The privacy salt
// is pinned by the caller via pinPrivSalt.
//
// The auth and privacy passwords differ, so a derivation that reads the wrong
// one is visible in the digest rather than invisible behind a shared secret.
func v3ExtractionServer(t *testing.T, auth, priv int) *SNMPServer {
	t.Helper()
	s := newTestServer(map[string]string{
		".1.3.6.1.2.1.1.1.0":        "nl6 extraction probe",
		".1.3.6.1.2.1.1.3.0":        "123456",
		".1.3.6.1.4.1.99999.1.0":    "probe",
		".1.3.6.1.2.1.31.1.1.1.6.1": "8589934592",
	})
	s.v3Config = &SNMPv3Config{
		Enabled:      true,
		EngineID:     "0x8000123401020304",
		Username:     "testuser",
		Password:     "authpassword",
		PrivPassword: "privpassword",
		AuthProtocol: auth,
		PrivProtocol: priv,
	}
	u := s.usmState() // force the once.Do so bootedAt can be pinned afterwards
	u.bootedAt = time.Time{}
	if u.engineTimeSeconds() != 0 {
		t.Fatalf("engineTimeSeconds() = %d with a zero bootedAt, want 0; the digest below would be "+
			"a function of how long this test took", u.engineTimeSeconds())
	}
	return s
}

// pinPrivSalt substitutes the USM privacy salt source for the duration of one
// test and restores it afterwards.
//
// THE CONSTRAINT IS PACKAGE-WIDE, NOT FILE-WIDE. usmPrivSaltRead is PRODUCTION
// state at package scope, so what must not overlap this is any test ANYWHERE in
// the package that reaches an authPriv encode — not merely the ones in this
// file. A parallel test overlapping one that pinned it would not fail: it would
// hand an authPriv encode a DIFFERENT salt and change a digest, or worse, hand a
// test that meant to use the real generator a fixed one and quietly turn an
// entropy assertion into a tautology (TestPrivSaltDefaultsToCryptoRand is
// exactly such a test, and it lives here). No test in this package calls
// t.Parallel() today and the whole-package `-race` run is clean because of it;
// keep it that way.
//
// EVERY MUTATION OF usmPrivSaltRead GOES THROUGH HERE, which is why it takes the
// filler rather than hardcoding one. The failure test used to save and restore
// the var inline, so two places mutated production state and only one of them
// carried this warning.
func pinPrivSalt(t *testing.T, read func([]byte) (int, error)) {
	t.Helper()
	saved := usmPrivSaltRead
	usmPrivSaltRead = read
	t.Cleanup(func() { usmPrivSaltRead = saved })
}

// fixedSalt is the reproducible filler every digest below pins the salt with.
// Its bytes are arbitrary; what matters is that they are the same on both sides
// of the baseline comparison, since an authPriv message is random by
// construction and could not otherwise be compared across commits at all.
func fixedSalt(b []byte) (int, error) {
	for i := range b {
		b[i] = byte(0x5A + i)
	}
	return len(b), nil
}

// v3ExtractionLevels is the matrix's v3 row expanded: noAuthNoPriv, authNoPriv
// under both hashes, and authPriv under both ciphers crossed with both hashes.
//
// BOTH HASHES ARE CROSSED WITH BOTH CIPHERS deliberately. nl6#624 found the two
// privacy derivations hardcoding OPPOSITE hashes, so md5+des and sha1+aes128
// were accidentally right while the other two were wrong — a set that tested
// only the diagonal saw nothing.
var v3ExtractionLevels = []struct {
	name  string
	auth  int
	priv  int
	flags byte
}{
	{"noAuthNoPriv", SNMPV3_AUTH_NONE, SNMPV3_PRIV_NONE, 0},
	{"authNoPriv/md5", SNMPV3_AUTH_MD5, SNMPV3_PRIV_NONE, SNMPV3_MSG_FLAG_AUTH},
	{"authNoPriv/sha1", SNMPV3_AUTH_SHA1, SNMPV3_PRIV_NONE, SNMPV3_MSG_FLAG_AUTH},
	{"authPriv/md5+des", SNMPV3_AUTH_MD5, SNMPV3_PRIV_DES, SNMPV3_MSG_FLAG_AUTH | SNMPV3_MSG_FLAG_PRIV},
	{"authPriv/md5+aes", SNMPV3_AUTH_MD5, SNMPV3_PRIV_AES128, SNMPV3_MSG_FLAG_AUTH | SNMPV3_MSG_FLAG_PRIV},
	{"authPriv/sha1+des", SNMPV3_AUTH_SHA1, SNMPV3_PRIV_DES, SNMPV3_MSG_FLAG_AUTH | SNMPV3_MSG_FLAG_PRIV},
	{"authPriv/sha1+aes", SNMPV3_AUTH_SHA1, SNMPV3_PRIV_AES128, SNMPV3_MSG_FLAG_AUTH | SNMPV3_MSG_FLAG_PRIV},
}

// v3ExtractionRequest builds a request message carrying a real inbound scoped
// PDU, so extractRequestIDFromScopedPDU has something to read.
//
// The scoped PDU is assembled from the BER primitives here rather than through
// wrapInScopedPDU, so this test compiles and runs unchanged at the baseline
// commit — which is the only way its digest can be measured there.
func v3ExtractionRequest(msgID int, flags byte, requestID int) *SNMPv3Message {
	var pduContents []byte
	pduContents = append(pduContents, encodeInteger(requestID)...)
	pduContents = append(pduContents, encodeInteger(0)...)
	pduContents = append(pduContents, encodeInteger(0)...)
	pduContents = append(pduContents, encodeSequence(encodeVarBind(".1.3.6.1.2.1.1.1.0", encodeNull()))...)

	pdu := []byte{ASN1_GET_REQUEST}
	pdu = append(pdu, encodeLength(len(pduContents))...)
	pdu = append(pdu, pduContents...)

	var scoped []byte
	scoped = append(scoped, encodeOctetString("\x80\x00\x12\x34\x01\x02\x03\x04")...)
	scoped = append(scoped, encodeOctetString("")...)
	scoped = append(scoped, pdu...)

	return &SNMPv3Message{
		Version:        SNMPV3_VERSION,
		GlobalData:     SNMPv3GlobalData{MsgID: msgID, MsgFlags: flags, MsgSecurityModel: SNMPV3_SECURITY_MODEL_USM},
		SecurityParams: SNMPv3SecurityParams{UserName: "testuser"},
		ScopedPDU:      encodeSequence(scoped),
	}
}

// v3ExtractionWritesPerRequest is how many byte strings the sweep below hashes
// for each (security level, request) pair: the single-binding response, the
// multi-binding SCOPED PDU on its own, the multi-binding response, and the two
// Report responses. The scoped PDU is hashed separately because it is
// wrapInScopedPDU's own output, and a change confined to the envelope around it
// would otherwise be indistinguishable from a change inside it.
const v3ExtractionWritesPerRequest = 5

// TestV3PollOutputUnchangedByEnvelopeExtraction is the matrix's fourth row and
// the riskiest one: splitting wrapScopedPDUInV3Message and lifting
// wrapInScopedPDU both sit directly on the shipped poll path.
//
// It digests SINGLE-binding, MULTI-binding and REPORT responses at every
// security level, because the three reach the envelope by different routes —
// and the Report is the only one that reaches createDiscoveryScopedPDU, whose
// own copy of the scoped-PDU envelope drifted from this one once already
// (nl6#624: the hex spelling of the engine ID against its octets).
func TestV3PollOutputUnchangedByEnvelopeExtraction(t *testing.T) {
	pinPrivSalt(t, fixedSalt)

	h := sha256.New()
	writes := 0
	for _, lvl := range v3ExtractionLevels {
		s := v3ExtractionServer(t, lvl.auth, lvl.priv)

		// A request with a readable scoped PDU, and one without: the request-id
		// is derived from the former and falls back to 1 for the latter, and
		// both paths reach the same envelope.
		reqs := []struct {
			name string
			msg  *SNMPv3Message
		}{
			{"withScoped", v3ExtractionRequest(0x2A2A, lvl.flags, 4242)},
			{"bareRequest", &SNMPv3Message{
				GlobalData:     SNMPv3GlobalData{MsgID: 7, MsgFlags: lvl.flags},
				SecurityParams: SNMPv3SecurityParams{UserName: "testuser"},
			}},
		}

		for _, req := range reqs {
			single, err := s.createSNMPv3Response(".1.3.6.1.2.1.1.1.0", "nl6 extraction probe", req.msg)
			if err != nil {
				t.Fatalf("%s/%s: createSNMPv3Response: %v", lvl.name, req.name, err)
			}
			h.Write([]byte(lvl.name + "/" + req.name + "/single:"))
			h.Write(single)
			writes++

			scoped, err := s.createScopedPDUMulti(
				[]string{".1.3.6.1.2.1.1.1.0", ".1.3.6.1.2.1.1.3.0", ".1.3.6.1.2.1.31.1.1.1.6.1"},
				[]string{"nl6 extraction probe", "123456", "8589934592"}, req.msg)
			if err != nil {
				t.Fatalf("%s/%s: createScopedPDUMulti: %v", lvl.name, req.name, err)
			}
			h.Write([]byte(lvl.name + "/" + req.name + "/scoped:"))
			h.Write(scoped)
			writes++

			multi, err := s.wrapScopedPDUInV3Message(scoped, req.msg)
			if err != nil {
				t.Fatalf("%s/%s: wrapScopedPDUInV3Message: %v", lvl.name, req.name, err)
			}
			h.Write([]byte(lvl.name + "/" + req.name + "/multi:"))
			h.Write(multi)
			writes++

			for _, sign := range []bool{false, true} {
				report := s.createSNMPv3ReportResponseSigned(oidUsmStatsWrongDigests, req.msg, sign)
				if len(report) == 0 {
					t.Fatalf("%s/%s: Report response is empty (sign=%v)", lvl.name, req.name, sign)
				}
				h.Write([]byte(fmt.Sprintf("%s/%s/report/%v:", lvl.name, req.name, sign)))
				h.Write(report)
				writes++
			}
		}
	}
	if want := len(v3ExtractionLevels) * 2 * v3ExtractionWritesPerRequest; writes != want {
		t.Fatalf("digested %d v3 writes, want %d; the sweep collapsed", writes, want)
	}

	const want = "f9ea0e6761e4b3e6047ab1455292918d4e6e9d6b35dd83088b56c7d0662ace26"
	if got := hex.EncodeToString(h.Sum(nil)); got != want {
		t.Errorf("the SNMPv3 poll path over %d writes digests to %s, measured at the baseline commit "+
			"as %s.\nwrapInScopedPDU and wrapScopedPDUInV3MessageWith are pure refactors of the shipped "+
			"poll path; a move here means a polled device's response changed", writes, got, want)
	}
}

// ── the two seam properties the deferred half depends on ────────────────────

// TestWrapInScopedPDUCarriesANotificationPDU is the matrix's fifth row and the
// reason wrapInScopedPDU exists at all.
//
// createScopedPDUMulti structurally cannot carry a notification: it hardcodes
// ASN1_GET_RESPONSE, derives its request-id from an inbound PDU, and types
// values by OID prefix rather than by Varbind.Type. So the property under test
// is that the wrapper is INDIFFERENT to what it wraps — a 0xA7 PDU comes out the
// far side byte for byte, at an arbitrary engine ID and an arbitrary context
// name.
//
// BOTH NOTIFICATION TAGS ARE SWEPT. "An arbitrary pre-encoded PDU" was asserted
// over 0xA7 alone, which proves nothing about arbitrariness — an implementation
// that special-cased that one tag would pass. The deferred nl6#98 half needs
// 0xA6 as well, since an SNMPv3 INFORM is a notification the originator retries
// against an ack.
//
// The emptyEngineID case pins TODAY'S PERMISSIVE BEHAVIOUR and nothing more.
// Whether a notification ORIGINATOR may send a zero-length
// contextEngineID/msgAuthoritativeEngineID is an nl6#98 question — RFC 3411
// wants 5-32 octets, and usmState already substitutes a default rather than
// emit nothing — and it is deliberately not decided here.
func TestWrapInScopedPDUCarriesANotificationPDU(t *testing.T) {
	for _, pt := range []struct {
		name string
		tag  byte
	}{
		{"trap", ASN1_TRAP_V2C},
		{"inform", ASN1_INFORM_REQUEST},
	} {
		t.Run(pt.name, func(t *testing.T) {
			pdu, err := encodeNotificationPDU(pt.tag, 42, "1.3.6.1.6.3.1.1.5.3", "1.3.6.1.4.1.9",
				123456, []Varbind{
					{OID: "1.3.6.1.2.1.2.2.1.1.7", Type: TrapVTInteger, Value: "7"},
					{OID: "1.3.6.1.2.1.1.5.0", Type: TrapVTOctetString, Value: "sim-9"},
				})
			if err != nil {
				t.Fatalf("encodeNotificationPDU: %v", err)
			}
			if pdu[0] != pt.tag {
				t.Fatalf("encodeNotificationPDU emitted tag 0x%02X, want 0x%02X", pdu[0], pt.tag)
			}

			for _, tc := range []struct {
				name        string
				engineID    []byte
				contextName string
			}{
				{"defaultContext", []byte{0x80, 0x00, 0x12, 0x34, 0x01, 0x02, 0x03, 0x04}, ""},
				{"namedContext", []byte{0x80, 0x00, 0xFF, 0xFF}, "vrf-red"},
				{"emptyEngineID", nil, ""},
			} {
				t.Run(tc.name, func(t *testing.T) {
					scoped := wrapInScopedPDU(tc.engineID, tc.contextName, pdu)

					// Decoded with the independent BER reader from
					// trap_v1_test.go, not with nl6's own parser: a reader that
					// shares code with the encoder lets one misreading satisfy
					// both sides.
					body, rest := v1TLV(t, scoped, ASN1_SEQUENCE, "scoped PDU")
					if len(rest) != 0 {
						t.Fatalf("trailing bytes after the scoped PDU: % x", rest)
					}
					gotEngine, body := v1OctetString(t, body, "contextEngineID")
					if gotEngine != string(tc.engineID) {
						t.Errorf("contextEngineID = % x, want % x. It goes on the wire as OCTETS, never "+
							"as its hex spelling (nl6#624)", gotEngine, tc.engineID)
					}
					gotContext, body := v1OctetString(t, body, "contextName")
					if gotContext != tc.contextName {
						t.Errorf("contextName = %q, want %q", gotContext, tc.contextName)
					}
					if !bytes.Equal(body, pdu) {
						t.Errorf("the wrapped PDU is not the PDU handed in.\ngot:  % x\nwant: % x\n"+
							"wrapInScopedPDU must carry an arbitrary PDU — including the 0x%02X the "+
							"nl6#98 notification encoder will hand it — through untouched",
							body, pdu, pt.tag)
					}
				})
			}
		})
	}
}

// TestInnerEnvelopeFormReproducesTheAdapter is the matrix's sixth row: the
// property the deferred half is built on.
//
// A notification originator has no request to echo, so it must be able to supply
// msgID, the flag byte and the user name directly and get the SAME message the
// request-derived form produces. Byte equality at every security level, with the
// salt pinned so authPriv is comparable at all.
func TestInnerEnvelopeFormReproducesTheAdapter(t *testing.T) {
	pinPrivSalt(t, fixedSalt)

	for _, lvl := range v3ExtractionLevels {
		t.Run(lvl.name, func(t *testing.T) {
			s := v3ExtractionServer(t, lvl.auth, lvl.priv)
			req := v3ExtractionRequest(0x2A2A, lvl.flags, 4242)

			scoped, err := s.createScopedPDU(".1.3.6.1.4.1.99999.1.0", "probe", req)
			if err != nil {
				t.Fatalf("createScopedPDU: %v", err)
			}

			viaAdapter, err := s.wrapScopedPDUInV3Message(scoped, req)
			if err != nil {
				t.Fatalf("wrapScopedPDUInV3Message: %v", err)
			}
			viaInner, err := s.wrapScopedPDUInV3MessageWith(scoped,
				req.GlobalData.MsgID, req.GlobalData.MsgFlags, req.SecurityParams.UserName)
			if err != nil {
				t.Fatalf("wrapScopedPDUInV3MessageWith: %v", err)
			}
			if !bytes.Equal(viaAdapter, viaInner) {
				t.Errorf("the inner envelope form does not reproduce the adapter for the same inputs.\n"+
					"adapter: % x\ninner:   % x\nThe adapter must be a thin projection of the inner "+
					"form; if it is not, the nl6#98 trap encoder gets a second envelope that can drift",
					viaAdapter, viaInner)
			}

			// Each of the three inputs must actually REACH the message, or
			// "reproduces the adapter" is satisfied by a form that ignores all
			// three and emits one fixed envelope.
			arms := []struct {
				what             string
				msgID            int
				flags            byte
				user             string
				expectDifference bool
			}{
				{"msgID", 0x1234, req.GlobalData.MsgFlags, "testuser", true},
				{"userName", req.GlobalData.MsgID, req.GlobalData.MsgFlags, "otheruser", true},
				{"reportBitCleared", req.GlobalData.MsgID,
					req.GlobalData.MsgFlags | SNMPV3_MSG_FLAG_REPORT, "testuser", false},
			}
			// THE REPORT-BIT ARM ALONE DOES NOT PIN msgFlags: it asserts NO
			// difference, which a form ignoring the argument entirely also
			// satisfies. This arm is the one that fails such a form — dropping
			// the security level to noAuthNoPriv must change the message, since
			// it removes the digest and, at authPriv, the encryption.
			if lvl.flags != 0 {
				arms = append(arms, struct {
					what             string
					msgID            int
					flags            byte
					user             string
					expectDifference bool
				}{"flagsZeroed", req.GlobalData.MsgID, 0, "testuser", true})
			}

			for _, m := range arms {
				other, err := s.wrapScopedPDUInV3MessageWith(scoped, m.msgID, m.flags, m.user)
				if err != nil {
					t.Fatalf("%s: %v", m.what, err)
				}
				if same := bytes.Equal(other, viaInner); same == m.expectDifference {
					if m.expectDifference {
						t.Errorf("changing %s produced an identical message, so the inner form ignores "+
							"that argument", m.what)
					} else {
						t.Errorf("setting the reportable bit changed the message; the emitted msgFlags " +
							"must have it cleared (RFC 3412 §6.4)")
					}
				}
			}
		})
	}
}

// ── the extraction itself: one implementation, not two ──────────────────────

// TestExtractedPDUIsWhatTheV2cEncoderEmits pins the lift STRUCTURALLY: the
// bytes encodeNotificationPDU returns must be exactly the PDU region of the
// message encodeV2cNotification emits.
//
// Without this, the two could drift into agreement-by-coincidence on the shipped
// corpus while disagreeing on anything the corpus does not carry — which is the
// whole reason the v3 path must reuse this builder rather than grow its own.
func TestExtractedPDUIsWhatTheV2cEncoderEmits(t *testing.T) {
	rows := notificationCorpus(t)
	buf := make([]byte, 8192)
	checked := 0

	for _, r := range rows {
		for _, tag := range []byte{ASN1_TRAP_V2C, ASN1_INFORM_REQUEST} {
			n, err := encodeV2cNotification(tag, "public", 42, r.trapOID, r.enterprise,
				pduExtractionCtx.Uptime, r.varbinds, buf)
			pdu, pduErr := encodeNotificationPDU(tag, 42, r.trapOID, r.enterprise,
				pduExtractionCtx.Uptime, r.varbinds)
			if (err == nil) != (pduErr == nil) {
				t.Errorf("%s: encodeV2cNotification err=%v but encodeNotificationPDU err=%v — the "+
					"envelope must not add or swallow a refusal", r.label, err, pduErr)
				continue
			}
			if err != nil {
				continue
			}

			// Strip the community envelope with the independent reader.
			body, rest := v1TLV(t, buf[:n], ASN1_SEQUENCE, "outer message")
			if len(rest) != 0 {
				t.Fatalf("%s: trailing bytes after the outer SEQUENCE", r.label)
			}
			version, body := v1Int(t, body, "version")
			if version != 1 {
				t.Fatalf("%s: version = %d, want 1 (v2c)", r.label, version)
			}
			community, body := v1OctetString(t, body, "community")
			if community != "public" {
				t.Fatalf("%s: community = %q", r.label, community)
			}
			if !bytes.Equal(body, pdu) {
				t.Errorf("%s: the PDU region of the v2c message is not what encodeNotificationPDU "+
					"returns.\nmessage PDU: % x\nextracted:   % x", r.label, body, pdu)
			}
			checked++
		}
	}
	if checked < 40 {
		t.Fatalf("only %d messages checked; the walk collapsed", checked)
	}
}

// ── source scans: the callers call, and nobody else re-implements ───────────

// pduExtractionFunc is one top-level function of the production package.
type pduExtractionFunc struct {
	file string
	recv string // receiver type name, "" for a free function
	name string
	decl *ast.FuncDecl
}

// String names a function the way the tables below spell it.
func (f pduExtractionFunc) String() string {
	if f.recv == "" {
		return f.name
	}
	return f.recv + "." + f.name
}

// pduExtractionParse parses Go source into the package's top-level functions.
//
// AST rather than string search, and that is not pedantry: the first cut of
// these guards located a function with strings.Index on its signature and ended
// it at the first column-0 `}`, so it matched the first TEXTUAL occurrence —
// a mention in a doc comment would satisfy it, and a body containing a raw
// string with a `}` at column 0 would truncate it. go/parser is already the
// in-package precedent (snmpv3_usm_conformance_test.go).
func pduExtractionParse(t *testing.T, filename, src string) []pduExtractionFunc {
	t.Helper()
	fset := token.NewFileSet()
	f, err := parser.ParseFile(fset, filename, src, parser.SkipObjectResolution)
	if err != nil {
		t.Fatalf("parse %s: %v", filename, err)
	}
	var out []pduExtractionFunc
	for _, d := range f.Decls {
		fn, ok := d.(*ast.FuncDecl)
		if !ok || fn.Body == nil {
			continue
		}
		recv := ""
		if fn.Recv != nil && len(fn.Recv.List) == 1 {
			switch e := fn.Recv.List[0].Type.(type) {
			case *ast.StarExpr:
				if id, ok := e.X.(*ast.Ident); ok {
					recv = id.Name
				}
			case *ast.Ident:
				recv = e.Name
			}
		}
		out = append(out, pduExtractionFunc{file: filename, recv: recv, name: fn.Name.Name, decl: fn})
	}
	return out
}

// pduExtractionProductionFuncs parses every non-test file of this package.
func pduExtractionProductionFuncs(t *testing.T) []pduExtractionFunc {
	t.Helper()
	entries, err := os.ReadDir(".")
	if err != nil {
		t.Fatalf("read package dir: %v", err)
	}
	var names []string
	for _, e := range entries {
		n := e.Name()
		if e.IsDir() || !strings.HasSuffix(n, ".go") || strings.HasSuffix(n, "_test.go") {
			continue
		}
		names = append(names, n)
	}
	sort.Strings(names)
	if len(names) < 50 {
		t.Fatalf("only %d production files found; the scan below would be near-vacuous", len(names))
	}

	var out []pduExtractionFunc
	for _, n := range names {
		src, err := os.ReadFile(filepath.Join(".", n)) // #nosec G304 -- this package's own sources
		if err != nil {
			t.Fatalf("read %s: %v", n, err)
		}
		out = append(out, pduExtractionParse(t, n, string(src))...)
	}
	return out
}

// pduExtractionCalls is the set of function names a body calls.
func pduExtractionCalls(fn *ast.FuncDecl) map[string]bool {
	out := map[string]bool{}
	ast.Inspect(fn.Body, func(n ast.Node) bool {
		call, ok := n.(*ast.CallExpr)
		if !ok {
			return true
		}
		switch f := call.Fun.(type) {
		case *ast.Ident:
			out[f.Name] = true
		case *ast.SelectorExpr:
			out[f.Sel.Name] = true
		}
		return true
	})
	return out
}

// pduExtractionMentions is the set of identifier names a body references,
// selector fields included.
func pduExtractionMentions(fn *ast.FuncDecl) map[string]bool {
	out := map[string]bool{}
	ast.Inspect(fn.Body, func(n ast.Node) bool {
		switch x := n.(type) {
		case *ast.Ident:
			out[x.Name] = true
		case *ast.SelectorExpr:
			out[x.Sel.Name] = true
		}
		return true
	})
	return out
}

// encodesAnEngineIDAsAnOctetString reports whether a body hands an engine ID
// straight to encodeOctetString.
//
// THAT IS THE SCOPED-PDU ENVELOPE'S FINGERPRINT and it is deliberately narrow.
// It does not fire on encodeUSMSecurityParameters, which encodes
// params.AuthoritativeEngineID rather than an `engineID`, nor on
// wrapScopedPDUInV3MessageWith, which reads usm.engineID but passes it on
// instead of encoding it.
func encodesAnEngineIDAsAnOctetString(fn *ast.FuncDecl) bool {
	// STRUCTURAL, NOT BY NAME. This used to require an identifier or selector
	// literally called `engineID`, and a reviewer defeated it by planting a
	// complete second copy of the envelope whose local was called `eid` --
	// both scans stayed green. Matching a spelling means the guard is one
	// rename away from useless, which is how its predecessor let
	// createDiscoveryScopedPDU through.
	//
	// The fingerprint that survives renaming is the SHAPE of an RFC 3412 §6
	// ScopedPDU: a contextName encoded from an EMPTY STRING LITERAL, wrapped
	// in a SEQUENCE. encodeUSMSecurityParameters also calls encodeOctetString
	// several times and encodeSequence once, but every argument is a variable,
	// so the literal is what separates them. The name check is kept as a
	// second net for a variant that builds the context name some other way.
	emptyLiteralOctetString, sequence, namedEngineID := false, false, false
	ast.Inspect(fn.Body, func(n ast.Node) bool {
		call, ok := n.(*ast.CallExpr)
		if !ok {
			return true
		}
		id, ok := call.Fun.(*ast.Ident)
		if !ok {
			return true
		}
		switch id.Name {
		case "encodeSequence":
			sequence = true
		case "encodeOctetString", "appendOctetString":
			for _, a := range call.Args {
				if lit, isLit := a.(*ast.BasicLit); isLit && lit.Kind == token.STRING &&
					(lit.Value == `""` || lit.Value == "``") {
					emptyLiteralOctetString = true
				}
				ast.Inspect(a, func(m ast.Node) bool {
					switch x := m.(type) {
					case *ast.Ident:
						if x.Name == "engineID" {
							namedEngineID = true
						}
					case *ast.SelectorExpr:
						if x.Sel.Name == "engineID" {
							namedEngineID = true
						}
					}
					return true
				})
			}
		}
		return true
	})
	return (emptyLiteralOctetString && sequence) || (namedEngineID && sequence)
}

// TestExtractedSeamsHaveExactlyOneImplementation is the forward half: the named
// callers still CALL the extracted helpers.
//
// A byte digest CANNOT see a call site reverted to an exact local copy — it
// emits the same bytes and every digest above stays green, and the copy becomes
// visible only once one of the two drifts, which is the day it is a defect
// rather than the day it is introduced.
func TestExtractedSeamsHaveExactlyOneImplementation(t *testing.T) {
	funcs := pduExtractionProductionFuncs(t)
	byName := map[string]pduExtractionFunc{}
	for _, f := range funcs {
		byName[f.String()] = f
	}

	for _, tc := range []struct {
		caller string
		callee string
		why    string
	}{
		{"SNMPServer.createScopedPDUMulti", "wrapInScopedPDU",
			"the scoped-PDU envelope must exist once; the nl6#98 trap encoder wraps a 0xA7 PDU with it"},
		{"SNMPServer.createDiscoveryScopedPDU", "wrapInScopedPDU",
			"the Report path's own copy of this envelope drifted from the response path's once already " +
				"(nl6#624: the engine ID's hex spelling against its octets), and no in-package test " +
				"compared the two"},
		{"SNMPServer.wrapScopedPDUInV3Message", "wrapScopedPDUInV3MessageWith",
			"the request-derived form must be a thin adapter, not a second envelope"},
		{"encodeV2cNotification", "encodeNotificationPDU",
			"the notification PDU body is identical under v2c and v3 and must not exist twice"},
	} {
		f, ok := byName[tc.caller]
		if !ok {
			t.Errorf("%s not found. If it was renamed, this guard has to be renamed with it, not "+
				"deleted", tc.caller)
			continue
		}
		if !pduExtractionCalls(f.decl)[tc.callee] {
			t.Errorf("%s (%s) no longer calls %s.\n%s", tc.caller, f.file, tc.callee, tc.why)
		}
	}
}

// pduExtractionReimplementers applies the three re-implementation rules to a set
// of functions and returns the offenders, each with the rule it broke.
//
// Split out from the test so a positive control can drive it over synthetic
// source: a scan that reports zero cannot fail on its own, so something has to
// prove it is capable of reporting at all.
func pduExtractionReimplementers(funcs []pduExtractionFunc) map[string]string {
	// Each allowance carries a reason. A new entry is a decision someone has to
	// write down, which is the whole mechanism.
	scopedPDUEnvelope := map[string]string{
		"wrapInScopedPDU": "IS the envelope",
	}
	v3Envelope := map[string]string{
		"SNMPServer.wrapScopedPDUInV3MessageWith": "IS the envelope",
		"SNMPServer.createSNMPv3ReportResponseSigned": "a Report is a deliberately different envelope: " +
			"its own msgFlags rule (reportFlags), never encrypted, and a user name that depends on " +
			"whether it is signed — empty for an unsigned discovery Report, the REQUEST'S user name " +
			"for a signed one, which a manager matches against the request it sent",
	}
	notificationTags := map[string]string{
		"encodeNotificationPDU":       "IS the notification PDU builder, and validates the tag",
		"SNMPv2cEncoder.EncodeTrap":   "selects the TRAP tag for the reference encoder",
		"SNMPv2cEncoder.EncodeInform": "selects the INFORM tag for the reference encoder",
		"SNMPv2cEncoder.EncodeNotificationFast": "selects the tag for the fast encoder, which keeps its " +
			"own PDU region by decision (see encodeV2cNotification)",
		"Catalog.ApplySizeBudget": "dry-renders each entry at the TRAP tag to size it",
	}

	out := map[string]string{}
	for _, f := range funcs {
		name := f.String()
		if encodesAnEngineIDAsAnOctetString(f.decl) {
			if _, ok := scopedPDUEnvelope[name]; !ok {
				out[name] = "builds a scoped-PDU envelope itself (encodes an engineID as an OCTET " +
					"STRING) instead of calling wrapInScopedPDU"
			}
		}
		if pduExtractionCalls(f.decl)["encodeSNMPv3Message"] {
			if _, ok := v3Envelope[name]; !ok {
				out[name] = "assembles an SNMPv3 message envelope itself instead of going through " +
					"wrapScopedPDUInV3MessageWith"
			}
		}
		m := pduExtractionMentions(f.decl)
		if m["ASN1_TRAP_V2C"] || m["ASN1_INFORM_REQUEST"] {
			if _, ok := notificationTags[name]; !ok {
				out[name] = "names a notification PDU tag; a new one means a second place that decides " +
					"what a notification is"
			}
		}
	}
	return out
}

// TestNothingReimplementsTheExtractedSeams is the complementary half, and it
// exists because the forward scan above MISSED A LIVE RE-IMPLEMENTATION:
// createDiscoveryScopedPDU hand-built the scoped-PDU envelope while not being
// one of the named callers, so asserting that the callers call proved nothing
// about who else builds.
func TestNothingReimplementsTheExtractedSeams(t *testing.T) {
	// The control comes first. A guard that asserts ZERO of something cannot
	// fail on its own; this is what makes it able to.
	t.Run("control", func(t *testing.T) {
		const planted = `package main

func plantedScopedPDU(engineID []byte, pdu []byte) []byte {
	var c []byte
	c = append(c, encodeOctetString(string(engineID))...)
	c = append(c, encodeOctetString("")...)
	c = append(c, pdu...)
	return encodeSequence(c)
}

func plantedV3Envelope(s *SNMPServer, msg *SNMPv3Message, usmParams []byte) ([]byte, error) {
	return s.encodeSNMPv3Message(msg, usmParams)
}

func plantedNotification(mode TrapMode) byte {
	if mode == TrapModeInform {
		return ASN1_INFORM_REQUEST
	}
	return ASN1_TRAP_V2C
}

func plantedInnocent(a, b int) int { return a + b }
`
		found := pduExtractionReimplementers(pduExtractionParse(t, "planted.go", planted))
		for _, want := range []string{"plantedScopedPDU", "plantedV3Envelope", "plantedNotification"} {
			if _, ok := found[want]; !ok {
				t.Errorf("the rule did not report %s; it cannot detect a re-implementation, so the "+
					"zero it reports over the real package means nothing", want)
			}
		}
		if _, ok := found["plantedInnocent"]; ok {
			t.Errorf("the rule reported an unrelated function; it is too broad to be useful")
		}
	})

	for name, why := range pduExtractionReimplementers(pduExtractionProductionFuncs(t)) {
		t.Errorf("%s %s.\nIf this is a deliberate second implementation, add it to the allowance table "+
			"in pduExtractionReimplementers WITH A REASON — the table is the record of that decision",
			name, why)
	}
}

// ── the salt seam ───────────────────────────────────────────────────────────

// TestPrivSaltDefaultsToCryptoRand pins the seam's PRODUCTION value.
//
// A reviewer replaced the default with a zero-filler and the whole package
// stayed green: every authPriv digest above pins the salt itself, so none of
// them can see the default at all. A predictable salt is a real SNMPv3 privacy
// break — under DES the IV is salt XOR pre-IV, so a fixed salt makes the IV a
// constant and identical plaintext encrypts identically forever.
//
// Asserted through BEHAVIOUR rather than by comparing the func value against
// rand.Read, following TestInterfaceStateClockDefaultsToWallClock: function
// values are not comparable in Go, and pinning the identity would make an
// equivalent refactor a failure.
// TestPrivSaltSeamIsInitialisedFromCryptoRand asserts what the seam's own
// comment claims and what CLAUDE.md asserts: that the production value IS
// crypto/rand.Read.
//
// THE BEHAVIOURAL TEST BELOW CANNOT DO THIS, and a reviewer proved it. Pointing
// usmPrivSaltRead at ONE seeded math/rand generator reused across calls left
// the entire package green -- every digest (they all call pinPrivSalt and
// overwrite the default first), the race suite, the net-snmp interop gate, and
// TestPrivSaltDefaultsToCryptoRand itself, because a seeded PRNG produces 64
// distinct non-zero draws and two differing ciphertexts. Distinctness is a
// property of any non-repeating stream, not of a CSPRNG. Meanwhile the DES IV
// (salt XOR pre-IV) becomes predictable and identical plaintext encrypts
// identically -- the exact break the seam's comment names.
//
// So this asserts the DECLARATION, not the behaviour: the initializer must be
// the identifier `Read` selected from the package imported as `crypto/rand`.
// gosec cannot cover it either -- the repo excludes G404 with a written
// rationale that crypto/rand "is used where it matters (SNMPv3 IV)".
func TestPrivSaltSeamIsInitialisedFromCryptoRand(t *testing.T) {
	assertSaltInitialiser(t, "snmpv3_crypto.go", true)

	// Positive control: a rule reporting zero cannot fail on its own. Plant a
	// math/rand initializer in a temp copy and require it to be REJECTED.
	dir := t.TempDir()
	planted := filepath.Join(dir, "planted.go")
	if err := os.WriteFile(planted, []byte(`package main

import mrand "math/rand"

var usmPrivSaltRead = mrand.New(mrand.NewSource(1)).Read
`), 0o600); err != nil {
		t.Fatalf("write control: %v", err)
	}
	assertSaltInitialiser(t, planted, false)
}

// assertSaltInitialiser requires (or forbids) that path declares
// usmPrivSaltRead initialised from the crypto/rand package's Read.
func assertSaltInitialiser(t *testing.T, path string, wantCryptoRand bool) {
	t.Helper()
	src, err := os.ReadFile(path) // #nosec G304 -- test-local path over this package's own sources
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	fset := token.NewFileSet()
	file, err := parser.ParseFile(fset, path, src, parser.SkipObjectResolution)
	if err != nil {
		t.Fatalf("parse %s: %v", path, err)
	}

	// Resolve the local name of the crypto/rand import, so an aliased import
	// is handled and a math/rand alias cannot masquerade as it.
	cryptoRandName := ""
	for _, imp := range file.Imports {
		if imp.Path == nil || imp.Path.Value != `"crypto/rand"` {
			continue
		}
		cryptoRandName = "rand"
		if imp.Name != nil {
			cryptoRandName = imp.Name.Name
		}
	}

	found := false
	ok := false
	for _, decl := range file.Decls {
		gen, isGen := decl.(*ast.GenDecl)
		if !isGen || gen.Tok != token.VAR {
			continue
		}
		for _, spec := range gen.Specs {
			vs, isVS := spec.(*ast.ValueSpec)
			if !isVS {
				continue
			}
			for i, name := range vs.Names {
				if name.Name != "usmPrivSaltRead" || i >= len(vs.Values) {
					continue
				}
				found = true
				sel, isSel := vs.Values[i].(*ast.SelectorExpr)
				if !isSel || sel.Sel.Name != "Read" {
					continue
				}
				pkg, isIdent := sel.X.(*ast.Ident)
				ok = isIdent && cryptoRandName != "" && pkg.Name == cryptoRandName
			}
		}
	}

	if !found {
		t.Fatalf("%s declares no usmPrivSaltRead var with an initializer", filepath.Base(path))
	}
	if ok != wantCryptoRand {
		if wantCryptoRand {
			t.Errorf("usmPrivSaltRead in %s is NOT initialised from crypto/rand.Read.\n"+
				"The SNMPv3 privacy salt would be whatever that expression yields; a seeded "+
				"generator passes every other test in this package. Either restore the "+
				"crypto/rand initializer or correct the claim in CLAUDE.md.", filepath.Base(path))
		} else {
			t.Error("the control was ACCEPTED: a math/rand initializer satisfied this rule, so " +
				"the rule cannot report the defect it exists for")
		}
	}
}

func TestPrivSaltDefaultsToCryptoRand(t *testing.T) {
	// Deliberately NO pinPrivSalt here: the production default is the subject.
	const draws = 64
	seen := map[string]bool{}
	for i := 0; i < draws; i++ {
		b := make([]byte, 8)
		n, err := usmPrivSaltRead(b)
		if err != nil || n != len(b) {
			t.Fatalf("usmPrivSaltRead: n=%d err=%v", n, err)
		}
		if bytes.Equal(b, make([]byte, 8)) {
			t.Fatalf("draw %d is eight zero bytes; the default is not a random source", i)
		}
		seen[string(b)] = true
	}
	if len(seen) != draws {
		t.Errorf("%d distinct values out of %d draws; the default salt repeats and is not "+
			"crypto/rand.Read", len(seen), draws)
	}

	// And at the level a peer actually sees: two authPriv messages carrying the
	// same plaintext must differ, which is exactly what a constant salt breaks.
	for _, priv := range []struct {
		name  string
		proto int
	}{{"des", SNMPV3_PRIV_DES}, {"aes128", SNMPV3_PRIV_AES128}} {
		s := v3ExtractionServer(t, SNMPV3_AUTH_MD5, priv.proto)
		req := v3ExtractionRequest(0x2A2A, SNMPV3_MSG_FLAG_AUTH|SNMPV3_MSG_FLAG_PRIV, 4242)
		first, err := s.createSNMPv3Response(".1.3.6.1.4.1.99999.1.0", "probe", req)
		if err != nil {
			t.Fatalf("%s: %v", priv.name, err)
		}
		second, err := s.createSNMPv3Response(".1.3.6.1.4.1.99999.1.0", "probe", req)
		if err != nil {
			t.Fatalf("%s: %v", priv.name, err)
		}
		if bytes.Equal(first, second) {
			t.Errorf("%s: two authPriv responses to the same request are byte-identical, so the salt "+
				"is a constant. Under a fixed salt the IV is fixed and the ciphertext leaks plaintext "+
				"equality", priv.name)
		}
	}
}

// TestPrivSaltFailureIsFatalToTheMessage covers the branch the seam made
// reachable for the first time.
//
// crypto/rand.Read errors only on a misconfigured kernel entropy source, so
// before the seam this was dead code that no test could enter. The property is
// that it fails LOUDLY: encryption under a zero or partial salt would produce a
// predictable IV, which is worse than sending nothing.
func TestPrivSaltFailureIsFatalToTheMessage(t *testing.T) {
	sentinel := errors.New("entropy source unavailable")
	pinPrivSalt(t, func(_ []byte) (int, error) { return 0, sentinel })

	plaintext := []byte("scoped pdu stand-in, padded by the cipher")
	for _, priv := range []struct {
		name  string
		proto int
	}{{"des", SNMPV3_PRIV_DES}, {"aes128", SNMPV3_PRIV_AES128}} {
		t.Run(priv.name, func(t *testing.T) {
			s := v3ExtractionServer(t, SNMPV3_AUTH_MD5, priv.proto)

			ct, salt, err := s.encryptScopedPDUAt(plaintext, 1, 0)
			if err == nil {
				t.Fatalf("encryption succeeded with no entropy; it emitted %d ciphertext bytes under a "+
					"predictable IV", len(ct))
			}
			// errors.Is ALONE. Both salt sites wrap with %w, so a substring
			// fallback would accept a %v that formats the cause away and
			// discards the chain — which is the state the AES site was in
			// until this change, and a fallback is what made that invisible.
			if !errors.Is(err, sentinel) {
				t.Errorf("the error does not WRAP the entropy failure (errors.Is is false): %v", err)
			}
			if ct != nil || salt != nil {
				t.Errorf("ciphertext/salt returned alongside the error: % x / % x", ct, salt)
			}

			// And the whole message must fail rather than go out unencrypted.
			req := v3ExtractionRequest(0x2A2A, SNMPV3_MSG_FLAG_AUTH|SNMPV3_MSG_FLAG_PRIV, 4242)
			if msg, err := s.createSNMPv3Response(".1.3.6.1.4.1.99999.1.0", "probe", req); err == nil {
				t.Errorf("a %d-byte response was assembled despite the entropy failure; an authPriv "+
					"message must not fall back to sending the scoped PDU in the clear", len(msg))
			}
		})
	}
}
