/*
 * Copyright 2026 Ronny Trommer <ronny@no42.org>
 * SPDX-License-Identifier: Apache-2.0
 */

// Per-catalog-entry BER precomputation.
//
// A catalog entry is immutable once loaded, so the parts of its notification
// that do not vary between fires can be encoded once instead of ~60,000 times a
// second. Profiling the trap path at saturation put encodeOID at 9.3 % of all
// CPU and its strings.Split at 16 % of all allocation — for OIDs that are
// literal constants in a JSON file.
//
// What is constant, and what is not:
//
//	sysUpTime.0        OID constant, value varies (device uptime)
//	snmpTrapOID.0      ENTIRELY constant — OID and value both fixed per entry
//	snmpTrapEnterprise ENTIRELY constant when the entry sets one
//	body varbind OID   constant ONLY when the OID template has no actions;
//	                   e.g. "1.3.6.1.2.1.2.2.1.1.{{.IfIndex}}" is not
//	body varbind value never — that is the point of the templates
//
// Templating is detected from the raw source text rather than by walking the
// parsed template tree, and deliberately errs toward "not constant": a false
// negative costs one inline encodeOID, whereas a false positive would pin a
// stale OID onto every fire. See preEncodedEntry.varbindOID.

package main

import "strings"

// preEncodedEntry holds the BER fragments of a CatalogEntry that never change.
// Built once by precomputeEntry at catalog load and read-only thereafter, so it
// is safe to share across the worker pool without synchronisation.
type preEncodedEntry struct {
	// sysUpTimeOID is the OID TLV for sysUpTime.0 (the TimeTicks value that
	// follows it is per-fire and is not stored here).
	sysUpTimeOID []byte
	// trapOIDVB is the complete VarBind SEQUENCE for snmpTrapOID.0.
	trapOIDVB []byte
	// enterpriseVB is the complete VarBind SEQUENCE for snmpTrapEnterprise.0,
	// or nil when the entry declares no enterprise OID.
	enterpriseVB []byte
	// varbindOID is parallel to CatalogEntry.Varbinds: element i holds the
	// pre-encoded OID TLV for body varbind i, or nil when that varbind's OID
	// is templated and must be encoded per fire.
	varbindOID [][]byte
	// usesNowLocal reports whether any template in the entry references
	// {{.NowLocal}}. When false the fire path skips a time.Time.Format call
	// that showed up as ~1 % of allocation for a field almost no entry uses.
	usesNowLocal bool
}

// precomputeEntry builds the entry's immutable BER fragments. Called from
// compileEntry, so every construction path (embedded catalog, -trap-catalog
// override, per-type overlay) gets one; MergeOverlay carries entry pointers
// through unchanged, so merged catalogs inherit it.
func precomputeEntry(e *CatalogEntry) *preEncodedEntry {
	pre := &preEncodedEntry{
		sysUpTimeOID: appendOID(nil, oidSysUpTime0),
		varbindOID:   make([][]byte, len(e.Varbinds)),
	}

	// snmpTrapOID.0 — a complete varbind, both halves constant.
	vb, m := beginTLV(nil)
	vb = appendOID(vb, oidSnmpTrapOID0)
	vb = appendOID(vb, e.SnmpTrapOID)
	pre.trapOIDVB = endTLV(vb, m, ASN1_SEQUENCE)

	if e.SnmpTrapEnterprise != "" {
		ent, em := beginTLV(nil)
		ent = appendOID(ent, oidSnmpTrapEnterprise0)
		ent = appendOID(ent, e.SnmpTrapEnterprise)
		pre.enterpriseVB = endTLV(ent, em, ASN1_SEQUENCE)
	}

	for i, vt := range e.Varbinds {
		if !isTemplated(vt.rawOID) {
			pre.varbindOID[i] = appendOID(nil, vt.rawOID)
		}
		if referencesNowLocal(vt.rawOID) || referencesNowLocal(vt.rawValue) {
			pre.usesNowLocal = true
		}
	}
	return pre
}

// isTemplated reports whether a raw template string contains any action. The
// check is intentionally coarse: anything containing "{{" is treated as
// dynamic, so a constant-folding opportunity is missed rather than a dynamic
// OID being frozen.
func isTemplated(raw string) bool {
	return strings.Contains(raw, "{{")
}

// referencesNowLocal reports whether a raw template string mentions the
// NowLocal field. Same conservative direction as isTemplated — a false positive
// only costs the formatting work the legacy path did unconditionally.
func referencesNowLocal(raw string) bool {
	return strings.Contains(raw, "NowLocal")
}
