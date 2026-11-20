/*
 * Copyright 2026 Ronny Trommer <ronny@no42.org>
 * SPDX-License-Identifier: Apache-2.0
 */

package main

import (
	"strings"
	"testing"
	"time"
)

// Four HOST-RESOURCES-MIB columns go out at their MIB type (nl6#1057). Until
// this change oidTypeTable had no HOST-RESOURCES entry, so every value went out
// as whatever it parsed as, and 17 instances in 5 profiles had the wrong tag:
//
//	hrSystemUptime.0     TimeTicks          was INTEGER       nvidia_dgx_a100, nvidia_dgx_h100, nvidia_hgx_h200
//	hrSystemNumUsers.0   Gauge32            was INTEGER       the same three
//	hrSystemProcesses.0  Gauge32            was INTEGER       the same three
//	hrStorageType.N      OBJECT IDENTIFIER  was OCTET STRING  nvidia_dgx_h100, nvidia_hgx_h200,
//	                                                          dell_poweredge_r750, hpe_proliant_dl380 (2 rows each)
//
// The change is the type table alone. No resource value moves: every shipped
// value already encodes at its MIB type, so the link has no value view, and
// the only names it adds are the three hrStorageType values, which become OID
// names once the column is typed.
//
// Decisions (nl6#1057). Only the four columns a shipped profile serves are
// typed; another HOST-RESOURCES column gets typed when a profile ships it.
// hrSystemUptime.0 stays a static value here and becomes live from the boot
// instant in a follow-up. Partial hrStorage rows are a separate data question.
//
// MIB citation. The column numbers and syntaxes were read with net-snmp
// 5.6.2.1 from its own copy, cited by LAST-UPDATED and by the SHA-256 of the
// file read (the nl6#599 provenance convention):
//
//	HOST-RESOURCES-MIB  200003060000Z  0406b893dcfacc370a1ae04ccfe6ffdecb15f93e3377a1a5ded2bbde5d944165
//
// Reproduce with:
//
//	snmptranslate -m +HOST-RESOURCES-MIB -On HOST-RESOURCES-MIB::hrStorageType
//	snmptranslate -Td -m ALL -M /usr/share/snmp/mibs .1.3.6.1.2.1.25.2.3.1.2
//	shasum -a 256 /usr/share/snmp/mibs/HOST-RESOURCES-MIB.txt

const (
	hostResSystemUptimeColumn    = ".1.3.6.1.2.1.25.1.1"
	hostResSystemNumUsersColumn  = ".1.3.6.1.2.1.25.1.5"
	hostResSystemProcessesColumn = ".1.3.6.1.2.1.25.1.6"
	hostResStorageTypeColumn     = ".1.3.6.1.2.1.25.2.3.1.2"
)

// hostResTypedColumns are the columns this link types, with the tag each one
// must go out as.
var hostResTypedColumns = []oidTypeEntry{
	{hostResSystemUptimeColumn, ASN1_TIMETICKS},
	{hostResSystemNumUsersColumn, ASN1_GAUGE32},
	{hostResSystemProcessesColumn, ASN1_GAUGE32},
	{hostResStorageTypeColumn, ASN1_OBJECT_ID},
}

func hostResTypedColumnPrefixes() []string {
	out := make([]string, len(hostResTypedColumns))
	for i, c := range hostResTypedColumns {
		out[i] = c.prefix
	}
	return out
}

// TestHostResourcesColumnsGoOutAtTheirMIBType checks both serving paths
// independently, because a GET answers through findResponseAt and a walk
// through findNextOIDWithServed, and the two can disagree (nl6#1056). The GETs
// are driven by the shipped rows of the four columns, the walk by the walk
// itself, so an instance the walk skips is caught by the walk count and a
// wrong tag on either path by the encode check. Both counts pin the 17
// instances the issue measured.
func TestHostResourcesColumnsGoOutAtTheirMIBType(t *testing.T) {
	boot := time.Now().Add(-time.Hour)
	tagFor := func(oid string) (byte, bool) {
		for _, c := range hostResTypedColumns {
			if inColumns(oid, []string{c.prefix}) {
				return c.tag, true
			}
		}
		return 0, false
	}
	devices := map[string]*SNMPServer{}
	device := func(profile string) *SNMPServer {
		if s, ok := devices[profile]; ok {
			return s
		}
		s := bootedShippedDevice(t, profile, boot, nil)
		devices[profile] = s
		return s
	}

	got := 0
	for _, e := range shippedSNMPEntries(t) {
		want, typed := tagFor(e.OID)
		if !typed {
			continue
		}
		got++
		v := device(e.Profile).findResponse(e.OID)
		if enc := encodeTypedValue(e.OID, v); len(enc) < 2 || enc[0] != want {
			t.Errorf("%s GET %s = %q encodes as % X, want tag %#02x", e.Profile, e.OID, v, enc, want)
		}
	}

	walked := 0
	for _, profile := range shippedProfileNames(t) {
		s := device(profile)
		cur := ".1.3.6.1.2.1.25"
		for i := 0; i < 10000; i++ {
			oid, val := s.findNextOID(cur)
			if !strings.HasPrefix(oid, ".1.3.6.1.2.1.25.") {
				break
			}
			cur = oid
			want, typed := tagFor(oid)
			if !typed {
				continue
			}
			walked++
			if enc := encodeTypedValue(oid, val); len(enc) < 2 || enc[0] != want {
				t.Errorf("%s walk %s = %q encodes as % X, want tag %#02x", profile, oid, val, enc, want)
			}
		}
	}
	if got != 17 || walked != 17 {
		t.Errorf("checked %d GET instances from the shipped rows and %d walked instances of the four columns, want 17 each", got, walked)
	}
}

// hostResTypesParentRevision is main at branch time; the digests below were
// taken there and are NOT re-derived from the new tree.
const hostResTypesParentRevision = "9d62d2a"

const (
	shippedTagDigestBeforeHostResTypes         = "154e029d64874b240297039bceba4dc0e40ad4f4a52fcdeda3c16d906f3a71c9"
	shippedOIDEncodingDigestBeforeHostResTypes = "c21837407f314e5a08634384f65df4b3698286a6be97bd577b9e077c316f74ee"
)

// hostResTypedColumnNames are the OID names that entered the set only because
// hrStorageType became typed: its three values, hrStorageRam,
// hrStorageVirtualMemory and hrStorageFixedDisk, none of which is a name for
// another reason. Measured at this link as the tree's names minus the parent
// tree's (6494 against 6491, nothing removed). It is a literal on purpose:
// recomputing it from a later tree would fold that link's edits into this one.
var hostResTypedColumnNames = []string{
	"1.3.6.1.2.1.25.2.1.2",
	"1.3.6.1.2.1.25.2.1.3",
	"1.3.6.1.2.1.25.2.1.4",
}

// hostResTypesNamesBefore reverses the OID-name view: the typed column's
// values leave the set, and nothing else moved.
func hostResTypesNamesBefore(t *testing.T, names []string) []string {
	t.Helper()
	return reverseOIDNameEdits(t, names, "nl6#1057 typed columns", hostResTypedColumnNames, nil)
}

func TestHostResTypesReproduceTheParentCorpus(t *testing.T) {
	got := corpusTagDigestAt(t, corpusValuesAt(t, hostResTypesParentRevision), hostResTypesParentRevision)
	if got != shippedTagDigestBeforeHostResTypes {
		t.Errorf("reversing nl6#1057 gives tag digest %s, want %s", got, shippedTagDigestBeforeHostResTypes)
	}
}

func TestHostResTypesRePinIsOnlyTheTyping(t *testing.T) {
	restored := restoreCorpusOIDNamesTo(t, collectShippedOIDs(t), hostResTypesParentRevision)
	if got := corpusOIDNameDigest(restored); got != shippedOIDEncodingDigestBeforeHostResTypes {
		t.Errorf("reversing nl6#1057 gives OID-name digest %s, want %s", got, shippedOIDEncodingDigestBeforeHostResTypes)
	}
}
