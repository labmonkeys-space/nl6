/*
 * Copyright 2026 Ronny Trommer <ronny@no42.org>
 * SPDX-License-Identifier: Apache-2.0
 */

package main

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"testing"
)

// nl6#576 re-homed the NVIDIA GPU telemetry arc from 1.3.6.1.4.1.53246 to
// 1.3.6.1.4.1.5703.
//
// 53246 is not NVIDIA's. The IANA enterprise-numbers registry (fetched
// 2026-09-01, self-dated 2026-08-28) allocates it to Mailteck, S.A., a Spanish
// company with no connection to GPUs, so a collector doing vendor detection on a
// simulated DGX resolved it as Mailteck. 5703 is NVIDIA Corporation's real PEN.
// Every sub-identifier BELOW the PEN is preserved exactly, so this is a prefix
// swap at every site and nothing else: the per-model sysObjectID suffixes
// .1.2.1 / .1.2.2 / .1.2.3 stay distinct and in the same order, and no object was
// added, removed or renumbered.
//
// WHAT THIS DOES NOT FIX, and it is recorded rather than glossed: NVIDIA
// publishes no SNMP GPU MIB at all — its GPU telemetry story is DCGM/Prometheus —
// so the objects below 5703 remain nl6's own invention. Under 53246 that
// fabrication was unattributed; under 5703 it is attributed to NVIDIA, which a
// collector may treat as authoritative. That is the nl6#569 class narrowed to the
// object layer and it is accepted deliberately, which is why the two parts of
// each nvidia_* profile that carry the arc — the _snmp_gpu and _snmp_system
// parts, six files in all — now carry a _comment saying so. The other five parts
// per profile hold no arc OID and are untouched. Do not "complete" the model to
// look more like a published MIB: there is none to converge on.
//
// ── why there is a ledger at all ────────────────────────────────────────────
//
// A prefix change moves BOTH golden corpus digests, and the honest question is
// whether each moved for only the intended reason:
//
//   - shippedTagDigest is keyed on (profile, OID, emitted tag). The tags are
//     untouched (oidTypeTable has no row under either arc, so snmpTypeTag returns
//     0 for every one of these OIDs and the encoder takes the same branch), but
//     every OID STRING changed, so the digest moves.
//   - shippedOIDEncodingDigest hashes each distinct shipped OID NAME against its
//     BER encoding. 74 names per profile changed, and so did the three
//     sysObjectID VALUES, which collectShippedOIDs also gathers because an
//     OID-typed response reaches encodeOID.
//
// The reversal below answers both mechanically: apply the inverse of this change
// to today's corpus and the PARENT revision's digest must come back byte for
// byte. Every recorded oidBefore and oldValue was read OUT OF GIT at
// 1bca8e8db72e3ca2ddc70aa39ea92a7a56b0625b (v0.28.0, the revision this branch
// forked from) rather than retyped from the new tree —
// TestNvidiaArcLedgerValuesMatchTheParentRevision pins that, so the table cannot
// be "fixed" into agreeing with itself. That is the nl6#573 lesson.
//
// This ledger is the NEWEST link in the chain. The three older ledgers each
// reverse to their own parent starting from today's corpus, so each of them now
// begins by undoing this rename: the chain reads
// today -> 1bca8e8 -> ec4700f -> 3a69927 -> 44ef67f.

var nl6576RenamedGPUOIDs = []struct{ profile, oidBefore, oidAfter, value string }{
	{"nvidia_dgx_a100.json", ".1.3.6.1.4.1.53246.1.1.1.0.1.0", ".1.3.6.1.4.1.5703.1.1.1.0.1.0", "8"},
	{"nvidia_dgx_a100.json", ".1.3.6.1.4.1.53246.1.1.1.0.2.0", ".1.3.6.1.4.1.5703.1.1.1.0.2.0", "3.1.8"},
	{"nvidia_dgx_a100.json", ".1.3.6.1.4.1.53246.1.1.1.1.1.0", ".1.3.6.1.4.1.5703.1.1.1.1.1.0", "NVIDIA A100-SXM4-80GB"},
	{"nvidia_dgx_a100.json", ".1.3.6.1.4.1.53246.1.1.1.1.2.0", ".1.3.6.1.4.1.5703.1.1.1.1.2.0", "GPU-a1b2c3d4-e5f6-7890-abcd-ef1234567800"},
	{"nvidia_dgx_a100.json", ".1.3.6.1.4.1.53246.1.1.1.1.3.0", ".1.3.6.1.4.1.5703.1.1.1.1.3.0", "132042200001ABC"},
	{"nvidia_dgx_a100.json", ".1.3.6.1.4.1.53246.1.1.1.1.4.0", ".1.3.6.1.4.1.5703.1.1.1.1.4.0", "00000000:07:00.0"},
	{"nvidia_dgx_a100.json", ".1.3.6.1.4.1.53246.1.1.1.1.13.0", ".1.3.6.1.4.1.5703.1.1.1.1.13.0", "525.105.17"},
	{"nvidia_dgx_a100.json", ".1.3.6.1.4.1.53246.1.1.1.1.14.0", ".1.3.6.1.4.1.5703.1.1.1.1.14.0", "12.0"},
	{"nvidia_dgx_a100.json", ".1.3.6.1.4.1.53246.1.1.1.1.15.0", ".1.3.6.1.4.1.5703.1.1.1.1.15.0", "0"},
	{"nvidia_dgx_a100.json", ".1.3.6.1.4.1.53246.1.1.1.1.16.0", ".1.3.6.1.4.1.5703.1.1.1.1.16.0", "0"},
	{"nvidia_dgx_a100.json", ".1.3.6.1.4.1.53246.1.1.1.1.17.0", ".1.3.6.1.4.1.5703.1.1.1.1.17.0", "6"},
	{"nvidia_dgx_a100.json", ".1.3.6.1.4.1.53246.1.1.1.1.1.1", ".1.3.6.1.4.1.5703.1.1.1.1.1.1", "NVIDIA A100-SXM4-80GB"},
	{"nvidia_dgx_a100.json", ".1.3.6.1.4.1.53246.1.1.1.1.2.1", ".1.3.6.1.4.1.5703.1.1.1.1.2.1", "GPU-b2c3d4e5-f6a7-8901-bcde-f12345678011"},
	{"nvidia_dgx_a100.json", ".1.3.6.1.4.1.53246.1.1.1.1.3.1", ".1.3.6.1.4.1.5703.1.1.1.1.3.1", "132042210101ABC"},
	{"nvidia_dgx_a100.json", ".1.3.6.1.4.1.53246.1.1.1.1.4.1", ".1.3.6.1.4.1.5703.1.1.1.1.4.1", "00000000:0B:00.0"},
	{"nvidia_dgx_a100.json", ".1.3.6.1.4.1.53246.1.1.1.1.13.1", ".1.3.6.1.4.1.5703.1.1.1.1.13.1", "525.105.17"},
	{"nvidia_dgx_a100.json", ".1.3.6.1.4.1.53246.1.1.1.1.14.1", ".1.3.6.1.4.1.5703.1.1.1.1.14.1", "12.0"},
	{"nvidia_dgx_a100.json", ".1.3.6.1.4.1.53246.1.1.1.1.15.1", ".1.3.6.1.4.1.5703.1.1.1.1.15.1", "0"},
	{"nvidia_dgx_a100.json", ".1.3.6.1.4.1.53246.1.1.1.1.16.1", ".1.3.6.1.4.1.5703.1.1.1.1.16.1", "0"},
	{"nvidia_dgx_a100.json", ".1.3.6.1.4.1.53246.1.1.1.1.17.1", ".1.3.6.1.4.1.5703.1.1.1.1.17.1", "6"},
	{"nvidia_dgx_a100.json", ".1.3.6.1.4.1.53246.1.1.1.1.1.2", ".1.3.6.1.4.1.5703.1.1.1.1.1.2", "NVIDIA A100-SXM4-80GB"},
	{"nvidia_dgx_a100.json", ".1.3.6.1.4.1.53246.1.1.1.1.2.2", ".1.3.6.1.4.1.5703.1.1.1.1.2.2", "GPU-c3d4e5f6-a7b8-9012-cdef-123456780022"},
	{"nvidia_dgx_a100.json", ".1.3.6.1.4.1.53246.1.1.1.1.3.2", ".1.3.6.1.4.1.5703.1.1.1.1.3.2", "132042220201ABC"},
	{"nvidia_dgx_a100.json", ".1.3.6.1.4.1.53246.1.1.1.1.4.2", ".1.3.6.1.4.1.5703.1.1.1.1.4.2", "00000000:47:00.0"},
	{"nvidia_dgx_a100.json", ".1.3.6.1.4.1.53246.1.1.1.1.13.2", ".1.3.6.1.4.1.5703.1.1.1.1.13.2", "525.105.17"},
	{"nvidia_dgx_a100.json", ".1.3.6.1.4.1.53246.1.1.1.1.14.2", ".1.3.6.1.4.1.5703.1.1.1.1.14.2", "12.0"},
	{"nvidia_dgx_a100.json", ".1.3.6.1.4.1.53246.1.1.1.1.15.2", ".1.3.6.1.4.1.5703.1.1.1.1.15.2", "0"},
	{"nvidia_dgx_a100.json", ".1.3.6.1.4.1.53246.1.1.1.1.16.2", ".1.3.6.1.4.1.5703.1.1.1.1.16.2", "0"},
	{"nvidia_dgx_a100.json", ".1.3.6.1.4.1.53246.1.1.1.1.17.2", ".1.3.6.1.4.1.5703.1.1.1.1.17.2", "6"},
	{"nvidia_dgx_a100.json", ".1.3.6.1.4.1.53246.1.1.1.1.1.3", ".1.3.6.1.4.1.5703.1.1.1.1.1.3", "NVIDIA A100-SXM4-80GB"},
	{"nvidia_dgx_a100.json", ".1.3.6.1.4.1.53246.1.1.1.1.2.3", ".1.3.6.1.4.1.5703.1.1.1.1.2.3", "GPU-d4e5f6a7-b8c9-0123-defa-123456780033"},
	{"nvidia_dgx_a100.json", ".1.3.6.1.4.1.53246.1.1.1.1.3.3", ".1.3.6.1.4.1.5703.1.1.1.1.3.3", "132042230301ABC"},
	{"nvidia_dgx_a100.json", ".1.3.6.1.4.1.53246.1.1.1.1.4.3", ".1.3.6.1.4.1.5703.1.1.1.1.4.3", "00000000:4E:00.0"},
	{"nvidia_dgx_a100.json", ".1.3.6.1.4.1.53246.1.1.1.1.13.3", ".1.3.6.1.4.1.5703.1.1.1.1.13.3", "525.105.17"},
	{"nvidia_dgx_a100.json", ".1.3.6.1.4.1.53246.1.1.1.1.14.3", ".1.3.6.1.4.1.5703.1.1.1.1.14.3", "12.0"},
	{"nvidia_dgx_a100.json", ".1.3.6.1.4.1.53246.1.1.1.1.15.3", ".1.3.6.1.4.1.5703.1.1.1.1.15.3", "0"},
	{"nvidia_dgx_a100.json", ".1.3.6.1.4.1.53246.1.1.1.1.16.3", ".1.3.6.1.4.1.5703.1.1.1.1.16.3", "0"},
	{"nvidia_dgx_a100.json", ".1.3.6.1.4.1.53246.1.1.1.1.17.3", ".1.3.6.1.4.1.5703.1.1.1.1.17.3", "6"},
	{"nvidia_dgx_a100.json", ".1.3.6.1.4.1.53246.1.1.1.1.1.4", ".1.3.6.1.4.1.5703.1.1.1.1.1.4", "NVIDIA A100-SXM4-80GB"},
	{"nvidia_dgx_a100.json", ".1.3.6.1.4.1.53246.1.1.1.1.2.4", ".1.3.6.1.4.1.5703.1.1.1.1.2.4", "GPU-e5f6a7b8-c9d0-1234-efab-123456780044"},
	{"nvidia_dgx_a100.json", ".1.3.6.1.4.1.53246.1.1.1.1.3.4", ".1.3.6.1.4.1.5703.1.1.1.1.3.4", "132042240401ABC"},
	{"nvidia_dgx_a100.json", ".1.3.6.1.4.1.53246.1.1.1.1.4.4", ".1.3.6.1.4.1.5703.1.1.1.1.4.4", "00000000:87:00.0"},
	{"nvidia_dgx_a100.json", ".1.3.6.1.4.1.53246.1.1.1.1.13.4", ".1.3.6.1.4.1.5703.1.1.1.1.13.4", "525.105.17"},
	{"nvidia_dgx_a100.json", ".1.3.6.1.4.1.53246.1.1.1.1.14.4", ".1.3.6.1.4.1.5703.1.1.1.1.14.4", "12.0"},
	{"nvidia_dgx_a100.json", ".1.3.6.1.4.1.53246.1.1.1.1.15.4", ".1.3.6.1.4.1.5703.1.1.1.1.15.4", "0"},
	{"nvidia_dgx_a100.json", ".1.3.6.1.4.1.53246.1.1.1.1.16.4", ".1.3.6.1.4.1.5703.1.1.1.1.16.4", "0"},
	{"nvidia_dgx_a100.json", ".1.3.6.1.4.1.53246.1.1.1.1.17.4", ".1.3.6.1.4.1.5703.1.1.1.1.17.4", "6"},
	{"nvidia_dgx_a100.json", ".1.3.6.1.4.1.53246.1.1.1.1.1.5", ".1.3.6.1.4.1.5703.1.1.1.1.1.5", "NVIDIA A100-SXM4-80GB"},
	{"nvidia_dgx_a100.json", ".1.3.6.1.4.1.53246.1.1.1.1.2.5", ".1.3.6.1.4.1.5703.1.1.1.1.2.5", "GPU-f6a7b8c9-d0e1-2345-fabc-123456780055"},
	{"nvidia_dgx_a100.json", ".1.3.6.1.4.1.53246.1.1.1.1.3.5", ".1.3.6.1.4.1.5703.1.1.1.1.3.5", "132042250501ABC"},
	{"nvidia_dgx_a100.json", ".1.3.6.1.4.1.53246.1.1.1.1.4.5", ".1.3.6.1.4.1.5703.1.1.1.1.4.5", "00000000:8E:00.0"},
	{"nvidia_dgx_a100.json", ".1.3.6.1.4.1.53246.1.1.1.1.13.5", ".1.3.6.1.4.1.5703.1.1.1.1.13.5", "525.105.17"},
	{"nvidia_dgx_a100.json", ".1.3.6.1.4.1.53246.1.1.1.1.14.5", ".1.3.6.1.4.1.5703.1.1.1.1.14.5", "12.0"},
	{"nvidia_dgx_a100.json", ".1.3.6.1.4.1.53246.1.1.1.1.15.5", ".1.3.6.1.4.1.5703.1.1.1.1.15.5", "0"},
	{"nvidia_dgx_a100.json", ".1.3.6.1.4.1.53246.1.1.1.1.16.5", ".1.3.6.1.4.1.5703.1.1.1.1.16.5", "0"},
	{"nvidia_dgx_a100.json", ".1.3.6.1.4.1.53246.1.1.1.1.17.5", ".1.3.6.1.4.1.5703.1.1.1.1.17.5", "6"},
	{"nvidia_dgx_a100.json", ".1.3.6.1.4.1.53246.1.1.1.1.1.6", ".1.3.6.1.4.1.5703.1.1.1.1.1.6", "NVIDIA A100-SXM4-80GB"},
	{"nvidia_dgx_a100.json", ".1.3.6.1.4.1.53246.1.1.1.1.2.6", ".1.3.6.1.4.1.5703.1.1.1.1.2.6", "GPU-a7b8c9d0-e1f2-3456-abcd-123456780066"},
	{"nvidia_dgx_a100.json", ".1.3.6.1.4.1.53246.1.1.1.1.3.6", ".1.3.6.1.4.1.5703.1.1.1.1.3.6", "132042260601ABC"},
	{"nvidia_dgx_a100.json", ".1.3.6.1.4.1.53246.1.1.1.1.4.6", ".1.3.6.1.4.1.5703.1.1.1.1.4.6", "00000000:C7:00.0"},
	{"nvidia_dgx_a100.json", ".1.3.6.1.4.1.53246.1.1.1.1.13.6", ".1.3.6.1.4.1.5703.1.1.1.1.13.6", "525.105.17"},
	{"nvidia_dgx_a100.json", ".1.3.6.1.4.1.53246.1.1.1.1.14.6", ".1.3.6.1.4.1.5703.1.1.1.1.14.6", "12.0"},
	{"nvidia_dgx_a100.json", ".1.3.6.1.4.1.53246.1.1.1.1.15.6", ".1.3.6.1.4.1.5703.1.1.1.1.15.6", "0"},
	{"nvidia_dgx_a100.json", ".1.3.6.1.4.1.53246.1.1.1.1.16.6", ".1.3.6.1.4.1.5703.1.1.1.1.16.6", "0"},
	{"nvidia_dgx_a100.json", ".1.3.6.1.4.1.53246.1.1.1.1.17.6", ".1.3.6.1.4.1.5703.1.1.1.1.17.6", "6"},
	{"nvidia_dgx_a100.json", ".1.3.6.1.4.1.53246.1.1.1.1.1.7", ".1.3.6.1.4.1.5703.1.1.1.1.1.7", "NVIDIA A100-SXM4-80GB"},
	{"nvidia_dgx_a100.json", ".1.3.6.1.4.1.53246.1.1.1.1.2.7", ".1.3.6.1.4.1.5703.1.1.1.1.2.7", "GPU-b8c9d0e1-f2a3-4567-bcde-123456780077"},
	{"nvidia_dgx_a100.json", ".1.3.6.1.4.1.53246.1.1.1.1.3.7", ".1.3.6.1.4.1.5703.1.1.1.1.3.7", "132042270701ABC"},
	{"nvidia_dgx_a100.json", ".1.3.6.1.4.1.53246.1.1.1.1.4.7", ".1.3.6.1.4.1.5703.1.1.1.1.4.7", "00000000:CE:00.0"},
	{"nvidia_dgx_a100.json", ".1.3.6.1.4.1.53246.1.1.1.1.13.7", ".1.3.6.1.4.1.5703.1.1.1.1.13.7", "525.105.17"},
	{"nvidia_dgx_a100.json", ".1.3.6.1.4.1.53246.1.1.1.1.14.7", ".1.3.6.1.4.1.5703.1.1.1.1.14.7", "12.0"},
	{"nvidia_dgx_a100.json", ".1.3.6.1.4.1.53246.1.1.1.1.15.7", ".1.3.6.1.4.1.5703.1.1.1.1.15.7", "0"},
	{"nvidia_dgx_a100.json", ".1.3.6.1.4.1.53246.1.1.1.1.16.7", ".1.3.6.1.4.1.5703.1.1.1.1.16.7", "0"},
	{"nvidia_dgx_a100.json", ".1.3.6.1.4.1.53246.1.1.1.1.17.7", ".1.3.6.1.4.1.5703.1.1.1.1.17.7", "6"},
	{"nvidia_dgx_h100.json", ".1.3.6.1.4.1.53246.1.1.1.0.1.0", ".1.3.6.1.4.1.5703.1.1.1.0.1.0", "8"},
	{"nvidia_dgx_h100.json", ".1.3.6.1.4.1.53246.1.1.1.0.2.0", ".1.3.6.1.4.1.5703.1.1.1.0.2.0", "3.3.0"},
	{"nvidia_dgx_h100.json", ".1.3.6.1.4.1.53246.1.1.1.1.1.0", ".1.3.6.1.4.1.5703.1.1.1.1.1.0", "NVIDIA H100 80GB HBM3"},
	{"nvidia_dgx_h100.json", ".1.3.6.1.4.1.53246.1.1.1.1.2.0", ".1.3.6.1.4.1.5703.1.1.1.1.2.0", "GPU-d4e8f2a1-7b3c-4d9e-a1f0-8c2d3e4f5a6b"},
	{"nvidia_dgx_h100.json", ".1.3.6.1.4.1.53246.1.1.1.1.3.0", ".1.3.6.1.4.1.5703.1.1.1.1.3.0", "1560833002DEF"},
	{"nvidia_dgx_h100.json", ".1.3.6.1.4.1.53246.1.1.1.1.4.0", ".1.3.6.1.4.1.5703.1.1.1.1.4.0", "00000000:07:00.0"},
	{"nvidia_dgx_h100.json", ".1.3.6.1.4.1.53246.1.1.1.1.13.0", ".1.3.6.1.4.1.5703.1.1.1.1.13.0", "535.129.03"},
	{"nvidia_dgx_h100.json", ".1.3.6.1.4.1.53246.1.1.1.1.14.0", ".1.3.6.1.4.1.5703.1.1.1.1.14.0", "12.2"},
	{"nvidia_dgx_h100.json", ".1.3.6.1.4.1.53246.1.1.1.1.15.0", ".1.3.6.1.4.1.5703.1.1.1.1.15.0", "0"},
	{"nvidia_dgx_h100.json", ".1.3.6.1.4.1.53246.1.1.1.1.16.0", ".1.3.6.1.4.1.5703.1.1.1.1.16.0", "0"},
	{"nvidia_dgx_h100.json", ".1.3.6.1.4.1.53246.1.1.1.1.17.0", ".1.3.6.1.4.1.5703.1.1.1.1.17.0", "18"},
	{"nvidia_dgx_h100.json", ".1.3.6.1.4.1.53246.1.1.1.1.1.1", ".1.3.6.1.4.1.5703.1.1.1.1.1.1", "NVIDIA H100 80GB HBM3"},
	{"nvidia_dgx_h100.json", ".1.3.6.1.4.1.53246.1.1.1.1.2.1", ".1.3.6.1.4.1.5703.1.1.1.1.2.1", "GPU-a3b7c9d1-2e4f-4a8b-b5c6-d7e8f9012345"},
	{"nvidia_dgx_h100.json", ".1.3.6.1.4.1.53246.1.1.1.1.3.1", ".1.3.6.1.4.1.5703.1.1.1.1.3.1", "1560833102DEF"},
	{"nvidia_dgx_h100.json", ".1.3.6.1.4.1.53246.1.1.1.1.4.1", ".1.3.6.1.4.1.5703.1.1.1.1.4.1", "00000000:0A:00.0"},
	{"nvidia_dgx_h100.json", ".1.3.6.1.4.1.53246.1.1.1.1.13.1", ".1.3.6.1.4.1.5703.1.1.1.1.13.1", "535.129.03"},
	{"nvidia_dgx_h100.json", ".1.3.6.1.4.1.53246.1.1.1.1.14.1", ".1.3.6.1.4.1.5703.1.1.1.1.14.1", "12.2"},
	{"nvidia_dgx_h100.json", ".1.3.6.1.4.1.53246.1.1.1.1.15.1", ".1.3.6.1.4.1.5703.1.1.1.1.15.1", "0"},
	{"nvidia_dgx_h100.json", ".1.3.6.1.4.1.53246.1.1.1.1.16.1", ".1.3.6.1.4.1.5703.1.1.1.1.16.1", "0"},
	{"nvidia_dgx_h100.json", ".1.3.6.1.4.1.53246.1.1.1.1.17.1", ".1.3.6.1.4.1.5703.1.1.1.1.17.1", "18"},
	{"nvidia_dgx_h100.json", ".1.3.6.1.4.1.53246.1.1.1.1.1.2", ".1.3.6.1.4.1.5703.1.1.1.1.1.2", "NVIDIA H100 80GB HBM3"},
	{"nvidia_dgx_h100.json", ".1.3.6.1.4.1.53246.1.1.1.1.2.2", ".1.3.6.1.4.1.5703.1.1.1.1.2.2", "GPU-f1e2d3c4-b5a6-4978-8d7c-6b5a4f3e2d1c"},
	{"nvidia_dgx_h100.json", ".1.3.6.1.4.1.53246.1.1.1.1.3.2", ".1.3.6.1.4.1.5703.1.1.1.1.3.2", "1560833202DEF"},
	{"nvidia_dgx_h100.json", ".1.3.6.1.4.1.53246.1.1.1.1.4.2", ".1.3.6.1.4.1.5703.1.1.1.1.4.2", "00000000:0D:00.0"},
	{"nvidia_dgx_h100.json", ".1.3.6.1.4.1.53246.1.1.1.1.13.2", ".1.3.6.1.4.1.5703.1.1.1.1.13.2", "535.129.03"},
	{"nvidia_dgx_h100.json", ".1.3.6.1.4.1.53246.1.1.1.1.14.2", ".1.3.6.1.4.1.5703.1.1.1.1.14.2", "12.2"},
	{"nvidia_dgx_h100.json", ".1.3.6.1.4.1.53246.1.1.1.1.15.2", ".1.3.6.1.4.1.5703.1.1.1.1.15.2", "0"},
	{"nvidia_dgx_h100.json", ".1.3.6.1.4.1.53246.1.1.1.1.16.2", ".1.3.6.1.4.1.5703.1.1.1.1.16.2", "0"},
	{"nvidia_dgx_h100.json", ".1.3.6.1.4.1.53246.1.1.1.1.17.2", ".1.3.6.1.4.1.5703.1.1.1.1.17.2", "18"},
	{"nvidia_dgx_h100.json", ".1.3.6.1.4.1.53246.1.1.1.1.1.3", ".1.3.6.1.4.1.5703.1.1.1.1.1.3", "NVIDIA H100 80GB HBM3"},
	{"nvidia_dgx_h100.json", ".1.3.6.1.4.1.53246.1.1.1.1.2.3", ".1.3.6.1.4.1.5703.1.1.1.1.2.3", "GPU-12345678-abcd-4ef0-9876-543210fedcba"},
	{"nvidia_dgx_h100.json", ".1.3.6.1.4.1.53246.1.1.1.1.3.3", ".1.3.6.1.4.1.5703.1.1.1.1.3.3", "1560833302DEF"},
	{"nvidia_dgx_h100.json", ".1.3.6.1.4.1.53246.1.1.1.1.4.3", ".1.3.6.1.4.1.5703.1.1.1.1.4.3", "00000000:47:00.0"},
	{"nvidia_dgx_h100.json", ".1.3.6.1.4.1.53246.1.1.1.1.13.3", ".1.3.6.1.4.1.5703.1.1.1.1.13.3", "535.129.03"},
	{"nvidia_dgx_h100.json", ".1.3.6.1.4.1.53246.1.1.1.1.14.3", ".1.3.6.1.4.1.5703.1.1.1.1.14.3", "12.2"},
	{"nvidia_dgx_h100.json", ".1.3.6.1.4.1.53246.1.1.1.1.15.3", ".1.3.6.1.4.1.5703.1.1.1.1.15.3", "0"},
	{"nvidia_dgx_h100.json", ".1.3.6.1.4.1.53246.1.1.1.1.16.3", ".1.3.6.1.4.1.5703.1.1.1.1.16.3", "0"},
	{"nvidia_dgx_h100.json", ".1.3.6.1.4.1.53246.1.1.1.1.17.3", ".1.3.6.1.4.1.5703.1.1.1.1.17.3", "18"},
	{"nvidia_dgx_h100.json", ".1.3.6.1.4.1.53246.1.1.1.1.1.4", ".1.3.6.1.4.1.5703.1.1.1.1.1.4", "NVIDIA H100 80GB HBM3"},
	{"nvidia_dgx_h100.json", ".1.3.6.1.4.1.53246.1.1.1.1.2.4", ".1.3.6.1.4.1.5703.1.1.1.1.2.4", "GPU-87654321-dcba-4fe0-1234-abcdef098765"},
	{"nvidia_dgx_h100.json", ".1.3.6.1.4.1.53246.1.1.1.1.3.4", ".1.3.6.1.4.1.5703.1.1.1.1.3.4", "1560833402DEF"},
	{"nvidia_dgx_h100.json", ".1.3.6.1.4.1.53246.1.1.1.1.4.4", ".1.3.6.1.4.1.5703.1.1.1.1.4.4", "00000000:4A:00.0"},
	{"nvidia_dgx_h100.json", ".1.3.6.1.4.1.53246.1.1.1.1.13.4", ".1.3.6.1.4.1.5703.1.1.1.1.13.4", "535.129.03"},
	{"nvidia_dgx_h100.json", ".1.3.6.1.4.1.53246.1.1.1.1.14.4", ".1.3.6.1.4.1.5703.1.1.1.1.14.4", "12.2"},
	{"nvidia_dgx_h100.json", ".1.3.6.1.4.1.53246.1.1.1.1.15.4", ".1.3.6.1.4.1.5703.1.1.1.1.15.4", "0"},
	{"nvidia_dgx_h100.json", ".1.3.6.1.4.1.53246.1.1.1.1.16.4", ".1.3.6.1.4.1.5703.1.1.1.1.16.4", "0"},
	{"nvidia_dgx_h100.json", ".1.3.6.1.4.1.53246.1.1.1.1.17.4", ".1.3.6.1.4.1.5703.1.1.1.1.17.4", "18"},
	{"nvidia_dgx_h100.json", ".1.3.6.1.4.1.53246.1.1.1.1.1.5", ".1.3.6.1.4.1.5703.1.1.1.1.1.5", "NVIDIA H100 80GB HBM3"},
	{"nvidia_dgx_h100.json", ".1.3.6.1.4.1.53246.1.1.1.1.2.5", ".1.3.6.1.4.1.5703.1.1.1.1.2.5", "GPU-aabbccdd-1122-4334-5566-778899aabbcc"},
	{"nvidia_dgx_h100.json", ".1.3.6.1.4.1.53246.1.1.1.1.3.5", ".1.3.6.1.4.1.5703.1.1.1.1.3.5", "1560833502DEF"},
	{"nvidia_dgx_h100.json", ".1.3.6.1.4.1.53246.1.1.1.1.4.5", ".1.3.6.1.4.1.5703.1.1.1.1.4.5", "00000000:4D:00.0"},
	{"nvidia_dgx_h100.json", ".1.3.6.1.4.1.53246.1.1.1.1.13.5", ".1.3.6.1.4.1.5703.1.1.1.1.13.5", "535.129.03"},
	{"nvidia_dgx_h100.json", ".1.3.6.1.4.1.53246.1.1.1.1.14.5", ".1.3.6.1.4.1.5703.1.1.1.1.14.5", "12.2"},
	{"nvidia_dgx_h100.json", ".1.3.6.1.4.1.53246.1.1.1.1.15.5", ".1.3.6.1.4.1.5703.1.1.1.1.15.5", "0"},
	{"nvidia_dgx_h100.json", ".1.3.6.1.4.1.53246.1.1.1.1.16.5", ".1.3.6.1.4.1.5703.1.1.1.1.16.5", "0"},
	{"nvidia_dgx_h100.json", ".1.3.6.1.4.1.53246.1.1.1.1.17.5", ".1.3.6.1.4.1.5703.1.1.1.1.17.5", "18"},
	{"nvidia_dgx_h100.json", ".1.3.6.1.4.1.53246.1.1.1.1.1.6", ".1.3.6.1.4.1.5703.1.1.1.1.1.6", "NVIDIA H100 80GB HBM3"},
	{"nvidia_dgx_h100.json", ".1.3.6.1.4.1.53246.1.1.1.1.2.6", ".1.3.6.1.4.1.5703.1.1.1.1.2.6", "GPU-11223344-5566-4778-99aa-bbccddeeff00"},
	{"nvidia_dgx_h100.json", ".1.3.6.1.4.1.53246.1.1.1.1.3.6", ".1.3.6.1.4.1.5703.1.1.1.1.3.6", "1560833602DEF"},
	{"nvidia_dgx_h100.json", ".1.3.6.1.4.1.53246.1.1.1.1.4.6", ".1.3.6.1.4.1.5703.1.1.1.1.4.6", "00000000:87:00.0"},
	{"nvidia_dgx_h100.json", ".1.3.6.1.4.1.53246.1.1.1.1.13.6", ".1.3.6.1.4.1.5703.1.1.1.1.13.6", "535.129.03"},
	{"nvidia_dgx_h100.json", ".1.3.6.1.4.1.53246.1.1.1.1.14.6", ".1.3.6.1.4.1.5703.1.1.1.1.14.6", "12.2"},
	{"nvidia_dgx_h100.json", ".1.3.6.1.4.1.53246.1.1.1.1.15.6", ".1.3.6.1.4.1.5703.1.1.1.1.15.6", "0"},
	{"nvidia_dgx_h100.json", ".1.3.6.1.4.1.53246.1.1.1.1.16.6", ".1.3.6.1.4.1.5703.1.1.1.1.16.6", "0"},
	{"nvidia_dgx_h100.json", ".1.3.6.1.4.1.53246.1.1.1.1.17.6", ".1.3.6.1.4.1.5703.1.1.1.1.17.6", "18"},
	{"nvidia_dgx_h100.json", ".1.3.6.1.4.1.53246.1.1.1.1.1.7", ".1.3.6.1.4.1.5703.1.1.1.1.1.7", "NVIDIA H100 80GB HBM3"},
	{"nvidia_dgx_h100.json", ".1.3.6.1.4.1.53246.1.1.1.1.2.7", ".1.3.6.1.4.1.5703.1.1.1.1.2.7", "GPU-ffeeddcc-bbaa-4998-8776-554433221100"},
	{"nvidia_dgx_h100.json", ".1.3.6.1.4.1.53246.1.1.1.1.3.7", ".1.3.6.1.4.1.5703.1.1.1.1.3.7", "1560833702DEF"},
	{"nvidia_dgx_h100.json", ".1.3.6.1.4.1.53246.1.1.1.1.4.7", ".1.3.6.1.4.1.5703.1.1.1.1.4.7", "00000000:8A:00.0"},
	{"nvidia_dgx_h100.json", ".1.3.6.1.4.1.53246.1.1.1.1.13.7", ".1.3.6.1.4.1.5703.1.1.1.1.13.7", "535.129.03"},
	{"nvidia_dgx_h100.json", ".1.3.6.1.4.1.53246.1.1.1.1.14.7", ".1.3.6.1.4.1.5703.1.1.1.1.14.7", "12.2"},
	{"nvidia_dgx_h100.json", ".1.3.6.1.4.1.53246.1.1.1.1.15.7", ".1.3.6.1.4.1.5703.1.1.1.1.15.7", "0"},
	{"nvidia_dgx_h100.json", ".1.3.6.1.4.1.53246.1.1.1.1.16.7", ".1.3.6.1.4.1.5703.1.1.1.1.16.7", "0"},
	{"nvidia_dgx_h100.json", ".1.3.6.1.4.1.53246.1.1.1.1.17.7", ".1.3.6.1.4.1.5703.1.1.1.1.17.7", "18"},
	{"nvidia_hgx_h200.json", ".1.3.6.1.4.1.53246.1.1.1.0.1.0", ".1.3.6.1.4.1.5703.1.1.1.0.1.0", "8"},
	{"nvidia_hgx_h200.json", ".1.3.6.1.4.1.53246.1.1.1.0.2.0", ".1.3.6.1.4.1.5703.1.1.1.0.2.0", "3.4.1"},
	{"nvidia_hgx_h200.json", ".1.3.6.1.4.1.53246.1.1.1.1.1.0", ".1.3.6.1.4.1.5703.1.1.1.1.1.0", "NVIDIA H200 141GB HBM3e"},
	{"nvidia_hgx_h200.json", ".1.3.6.1.4.1.53246.1.1.1.1.2.0", ".1.3.6.1.4.1.5703.1.1.1.1.2.0", "GPU-e7a1b2c3-d4e5-4f67-8901-2a3b4c5d6e7f"},
	{"nvidia_hgx_h200.json", ".1.3.6.1.4.1.53246.1.1.1.1.3.0", ".1.3.6.1.4.1.5703.1.1.1.1.3.0", "1780944003GHI"},
	{"nvidia_hgx_h200.json", ".1.3.6.1.4.1.53246.1.1.1.1.4.0", ".1.3.6.1.4.1.5703.1.1.1.1.4.0", "00000000:07:00.0"},
	{"nvidia_hgx_h200.json", ".1.3.6.1.4.1.53246.1.1.1.1.13.0", ".1.3.6.1.4.1.5703.1.1.1.1.13.0", "545.23.08"},
	{"nvidia_hgx_h200.json", ".1.3.6.1.4.1.53246.1.1.1.1.14.0", ".1.3.6.1.4.1.5703.1.1.1.1.14.0", "12.3"},
	{"nvidia_hgx_h200.json", ".1.3.6.1.4.1.53246.1.1.1.1.15.0", ".1.3.6.1.4.1.5703.1.1.1.1.15.0", "0"},
	{"nvidia_hgx_h200.json", ".1.3.6.1.4.1.53246.1.1.1.1.16.0", ".1.3.6.1.4.1.5703.1.1.1.1.16.0", "0"},
	{"nvidia_hgx_h200.json", ".1.3.6.1.4.1.53246.1.1.1.1.17.0", ".1.3.6.1.4.1.5703.1.1.1.1.17.0", "18"},
	{"nvidia_hgx_h200.json", ".1.3.6.1.4.1.53246.1.1.1.1.1.1", ".1.3.6.1.4.1.5703.1.1.1.1.1.1", "NVIDIA H200 141GB HBM3e"},
	{"nvidia_hgx_h200.json", ".1.3.6.1.4.1.53246.1.1.1.1.2.1", ".1.3.6.1.4.1.5703.1.1.1.1.2.1", "GPU-b8c9d0e1-f2a3-4b56-7890-1c2d3e4f5a6b"},
	{"nvidia_hgx_h200.json", ".1.3.6.1.4.1.53246.1.1.1.1.3.1", ".1.3.6.1.4.1.5703.1.1.1.1.3.1", "1780944103GHI"},
	{"nvidia_hgx_h200.json", ".1.3.6.1.4.1.53246.1.1.1.1.4.1", ".1.3.6.1.4.1.5703.1.1.1.1.4.1", "00000000:0A:00.0"},
	{"nvidia_hgx_h200.json", ".1.3.6.1.4.1.53246.1.1.1.1.13.1", ".1.3.6.1.4.1.5703.1.1.1.1.13.1", "545.23.08"},
	{"nvidia_hgx_h200.json", ".1.3.6.1.4.1.53246.1.1.1.1.14.1", ".1.3.6.1.4.1.5703.1.1.1.1.14.1", "12.3"},
	{"nvidia_hgx_h200.json", ".1.3.6.1.4.1.53246.1.1.1.1.15.1", ".1.3.6.1.4.1.5703.1.1.1.1.15.1", "0"},
	{"nvidia_hgx_h200.json", ".1.3.6.1.4.1.53246.1.1.1.1.16.1", ".1.3.6.1.4.1.5703.1.1.1.1.16.1", "0"},
	{"nvidia_hgx_h200.json", ".1.3.6.1.4.1.53246.1.1.1.1.17.1", ".1.3.6.1.4.1.5703.1.1.1.1.17.1", "18"},
	{"nvidia_hgx_h200.json", ".1.3.6.1.4.1.53246.1.1.1.1.1.2", ".1.3.6.1.4.1.5703.1.1.1.1.1.2", "NVIDIA H200 141GB HBM3e"},
	{"nvidia_hgx_h200.json", ".1.3.6.1.4.1.53246.1.1.1.1.2.2", ".1.3.6.1.4.1.5703.1.1.1.1.2.2", "GPU-c3d4e5f6-a7b8-4901-2345-6d7e8f9a0b1c"},
	{"nvidia_hgx_h200.json", ".1.3.6.1.4.1.53246.1.1.1.1.3.2", ".1.3.6.1.4.1.5703.1.1.1.1.3.2", "1780944203GHI"},
	{"nvidia_hgx_h200.json", ".1.3.6.1.4.1.53246.1.1.1.1.4.2", ".1.3.6.1.4.1.5703.1.1.1.1.4.2", "00000000:0D:00.0"},
	{"nvidia_hgx_h200.json", ".1.3.6.1.4.1.53246.1.1.1.1.13.2", ".1.3.6.1.4.1.5703.1.1.1.1.13.2", "545.23.08"},
	{"nvidia_hgx_h200.json", ".1.3.6.1.4.1.53246.1.1.1.1.14.2", ".1.3.6.1.4.1.5703.1.1.1.1.14.2", "12.3"},
	{"nvidia_hgx_h200.json", ".1.3.6.1.4.1.53246.1.1.1.1.15.2", ".1.3.6.1.4.1.5703.1.1.1.1.15.2", "0"},
	{"nvidia_hgx_h200.json", ".1.3.6.1.4.1.53246.1.1.1.1.16.2", ".1.3.6.1.4.1.5703.1.1.1.1.16.2", "0"},
	{"nvidia_hgx_h200.json", ".1.3.6.1.4.1.53246.1.1.1.1.17.2", ".1.3.6.1.4.1.5703.1.1.1.1.17.2", "18"},
	{"nvidia_hgx_h200.json", ".1.3.6.1.4.1.53246.1.1.1.1.1.3", ".1.3.6.1.4.1.5703.1.1.1.1.1.3", "NVIDIA H200 141GB HBM3e"},
	{"nvidia_hgx_h200.json", ".1.3.6.1.4.1.53246.1.1.1.1.2.3", ".1.3.6.1.4.1.5703.1.1.1.1.2.3", "GPU-d5e6f7a8-b9c0-4123-4567-8e9f0a1b2c3d"},
	{"nvidia_hgx_h200.json", ".1.3.6.1.4.1.53246.1.1.1.1.3.3", ".1.3.6.1.4.1.5703.1.1.1.1.3.3", "1780944303GHI"},
	{"nvidia_hgx_h200.json", ".1.3.6.1.4.1.53246.1.1.1.1.4.3", ".1.3.6.1.4.1.5703.1.1.1.1.4.3", "00000000:47:00.0"},
	{"nvidia_hgx_h200.json", ".1.3.6.1.4.1.53246.1.1.1.1.13.3", ".1.3.6.1.4.1.5703.1.1.1.1.13.3", "545.23.08"},
	{"nvidia_hgx_h200.json", ".1.3.6.1.4.1.53246.1.1.1.1.14.3", ".1.3.6.1.4.1.5703.1.1.1.1.14.3", "12.3"},
	{"nvidia_hgx_h200.json", ".1.3.6.1.4.1.53246.1.1.1.1.15.3", ".1.3.6.1.4.1.5703.1.1.1.1.15.3", "0"},
	{"nvidia_hgx_h200.json", ".1.3.6.1.4.1.53246.1.1.1.1.16.3", ".1.3.6.1.4.1.5703.1.1.1.1.16.3", "0"},
	{"nvidia_hgx_h200.json", ".1.3.6.1.4.1.53246.1.1.1.1.17.3", ".1.3.6.1.4.1.5703.1.1.1.1.17.3", "18"},
	{"nvidia_hgx_h200.json", ".1.3.6.1.4.1.53246.1.1.1.1.1.4", ".1.3.6.1.4.1.5703.1.1.1.1.1.4", "NVIDIA H200 141GB HBM3e"},
	{"nvidia_hgx_h200.json", ".1.3.6.1.4.1.53246.1.1.1.1.2.4", ".1.3.6.1.4.1.5703.1.1.1.1.2.4", "GPU-e7f8a9b0-c1d2-4345-6789-0a1b2c3d4e5f"},
	{"nvidia_hgx_h200.json", ".1.3.6.1.4.1.53246.1.1.1.1.3.4", ".1.3.6.1.4.1.5703.1.1.1.1.3.4", "1780944403GHI"},
	{"nvidia_hgx_h200.json", ".1.3.6.1.4.1.53246.1.1.1.1.4.4", ".1.3.6.1.4.1.5703.1.1.1.1.4.4", "00000000:4A:00.0"},
	{"nvidia_hgx_h200.json", ".1.3.6.1.4.1.53246.1.1.1.1.13.4", ".1.3.6.1.4.1.5703.1.1.1.1.13.4", "545.23.08"},
	{"nvidia_hgx_h200.json", ".1.3.6.1.4.1.53246.1.1.1.1.14.4", ".1.3.6.1.4.1.5703.1.1.1.1.14.4", "12.3"},
	{"nvidia_hgx_h200.json", ".1.3.6.1.4.1.53246.1.1.1.1.15.4", ".1.3.6.1.4.1.5703.1.1.1.1.15.4", "0"},
	{"nvidia_hgx_h200.json", ".1.3.6.1.4.1.53246.1.1.1.1.16.4", ".1.3.6.1.4.1.5703.1.1.1.1.16.4", "0"},
	{"nvidia_hgx_h200.json", ".1.3.6.1.4.1.53246.1.1.1.1.17.4", ".1.3.6.1.4.1.5703.1.1.1.1.17.4", "18"},
	{"nvidia_hgx_h200.json", ".1.3.6.1.4.1.53246.1.1.1.1.1.5", ".1.3.6.1.4.1.5703.1.1.1.1.1.5", "NVIDIA H200 141GB HBM3e"},
	{"nvidia_hgx_h200.json", ".1.3.6.1.4.1.53246.1.1.1.1.2.5", ".1.3.6.1.4.1.5703.1.1.1.1.2.5", "GPU-f9a0b1c2-d3e4-4567-8901-2f3a4b5c6d7e"},
	{"nvidia_hgx_h200.json", ".1.3.6.1.4.1.53246.1.1.1.1.3.5", ".1.3.6.1.4.1.5703.1.1.1.1.3.5", "1780944503GHI"},
	{"nvidia_hgx_h200.json", ".1.3.6.1.4.1.53246.1.1.1.1.4.5", ".1.3.6.1.4.1.5703.1.1.1.1.4.5", "00000000:4D:00.0"},
	{"nvidia_hgx_h200.json", ".1.3.6.1.4.1.53246.1.1.1.1.13.5", ".1.3.6.1.4.1.5703.1.1.1.1.13.5", "545.23.08"},
	{"nvidia_hgx_h200.json", ".1.3.6.1.4.1.53246.1.1.1.1.14.5", ".1.3.6.1.4.1.5703.1.1.1.1.14.5", "12.3"},
	{"nvidia_hgx_h200.json", ".1.3.6.1.4.1.53246.1.1.1.1.15.5", ".1.3.6.1.4.1.5703.1.1.1.1.15.5", "0"},
	{"nvidia_hgx_h200.json", ".1.3.6.1.4.1.53246.1.1.1.1.16.5", ".1.3.6.1.4.1.5703.1.1.1.1.16.5", "0"},
	{"nvidia_hgx_h200.json", ".1.3.6.1.4.1.53246.1.1.1.1.17.5", ".1.3.6.1.4.1.5703.1.1.1.1.17.5", "18"},
	{"nvidia_hgx_h200.json", ".1.3.6.1.4.1.53246.1.1.1.1.1.6", ".1.3.6.1.4.1.5703.1.1.1.1.1.6", "NVIDIA H200 141GB HBM3e"},
	{"nvidia_hgx_h200.json", ".1.3.6.1.4.1.53246.1.1.1.1.2.6", ".1.3.6.1.4.1.5703.1.1.1.1.2.6", "GPU-a1b2c3d4-e5f6-4789-0123-4a5b6c7d8e9f"},
	{"nvidia_hgx_h200.json", ".1.3.6.1.4.1.53246.1.1.1.1.3.6", ".1.3.6.1.4.1.5703.1.1.1.1.3.6", "1780944603GHI"},
	{"nvidia_hgx_h200.json", ".1.3.6.1.4.1.53246.1.1.1.1.4.6", ".1.3.6.1.4.1.5703.1.1.1.1.4.6", "00000000:87:00.0"},
	{"nvidia_hgx_h200.json", ".1.3.6.1.4.1.53246.1.1.1.1.13.6", ".1.3.6.1.4.1.5703.1.1.1.1.13.6", "545.23.08"},
	{"nvidia_hgx_h200.json", ".1.3.6.1.4.1.53246.1.1.1.1.14.6", ".1.3.6.1.4.1.5703.1.1.1.1.14.6", "12.3"},
	{"nvidia_hgx_h200.json", ".1.3.6.1.4.1.53246.1.1.1.1.15.6", ".1.3.6.1.4.1.5703.1.1.1.1.15.6", "0"},
	{"nvidia_hgx_h200.json", ".1.3.6.1.4.1.53246.1.1.1.1.16.6", ".1.3.6.1.4.1.5703.1.1.1.1.16.6", "0"},
	{"nvidia_hgx_h200.json", ".1.3.6.1.4.1.53246.1.1.1.1.17.6", ".1.3.6.1.4.1.5703.1.1.1.1.17.6", "18"},
	{"nvidia_hgx_h200.json", ".1.3.6.1.4.1.53246.1.1.1.1.1.7", ".1.3.6.1.4.1.5703.1.1.1.1.1.7", "NVIDIA H200 141GB HBM3e"},
	{"nvidia_hgx_h200.json", ".1.3.6.1.4.1.53246.1.1.1.1.2.7", ".1.3.6.1.4.1.5703.1.1.1.1.2.7", "GPU-b3c4d5e6-f7a8-4901-2345-6b7c8d9e0f1a"},
	{"nvidia_hgx_h200.json", ".1.3.6.1.4.1.53246.1.1.1.1.3.7", ".1.3.6.1.4.1.5703.1.1.1.1.3.7", "1780944703GHI"},
	{"nvidia_hgx_h200.json", ".1.3.6.1.4.1.53246.1.1.1.1.4.7", ".1.3.6.1.4.1.5703.1.1.1.1.4.7", "00000000:8A:00.0"},
	{"nvidia_hgx_h200.json", ".1.3.6.1.4.1.53246.1.1.1.1.13.7", ".1.3.6.1.4.1.5703.1.1.1.1.13.7", "545.23.08"},
	{"nvidia_hgx_h200.json", ".1.3.6.1.4.1.53246.1.1.1.1.14.7", ".1.3.6.1.4.1.5703.1.1.1.1.14.7", "12.3"},
	{"nvidia_hgx_h200.json", ".1.3.6.1.4.1.53246.1.1.1.1.15.7", ".1.3.6.1.4.1.5703.1.1.1.1.15.7", "0"},
	{"nvidia_hgx_h200.json", ".1.3.6.1.4.1.53246.1.1.1.1.16.7", ".1.3.6.1.4.1.5703.1.1.1.1.16.7", "0"},
	{"nvidia_hgx_h200.json", ".1.3.6.1.4.1.53246.1.1.1.1.17.7", ".1.3.6.1.4.1.5703.1.1.1.1.17.7", "18"},
}

var nl6576RehomedSysObjectIDs = []struct{ profile, oid, oldValue, newValue string }{
	{"nvidia_dgx_a100.json", ".1.3.6.1.2.1.1.2.0", "1.3.6.1.4.1.53246.1.2.1", "1.3.6.1.4.1.5703.1.2.1"},
	{"nvidia_dgx_h100.json", ".1.3.6.1.2.1.1.2.0", "1.3.6.1.4.1.53246.1.2.2", "1.3.6.1.4.1.5703.1.2.2"},
	{"nvidia_hgx_h200.json", ".1.3.6.1.2.1.1.2.0", "1.3.6.1.4.1.53246.1.2.3", "1.3.6.1.4.1.5703.1.2.3"},
}

// mailteckArcPrefix is the arc the GPU telemetry used to live under, and it is
// spelled out here ONCE so every assertion about "the old arc" reads the same
// string.
//
// What is ENFORCED about it is narrower than "it appears nowhere else": the
// number is deliberately written down in several places as historical context —
// the six resource _comments, metrics_oids.go's own comment, the three doc pages,
// and the comments on both re-pinned digests. What no shipped string may do is
// NAME it, in an OID key or an OID-typed value, and that is what
// TestNoNvidiaOIDsShipUnderMailteck and TestArcRewriteSeesEveryShippedSpelling
// assert. A prose ban on the digits would be both unenforced and wrong.
const mailteckArcPrefix = ".1.3.6.1.4.1.53246"

// nvidiaArcPrefix is NVIDIA Corporation's IANA-registered PEN. It is a LITERAL
// here on purpose and must not be expressed in terms of nvidiaGPUMetricPrefix:
// TestEveryNvidiaGPUOIDIsAnsweredAtTheNewArc exists to catch a tree whose static
// data was re-homed while metrics_oids.go stayed at 53246, and a test that
// derived its expectation from the production constant would follow the mutation
// instead of reporting it.
const nvidiaArcPrefix = ".1.3.6.1.4.1.5703"

// nvidiaProfiles are the three device types that serve the arc.
var nvidiaProfiles = []string{"nvidia_dgx_a100.json", "nvidia_dgx_h100.json", "nvidia_hgx_h200.json"}

// nl6576DynamicGPUOIDsPerDevice is 8 metrics x 8 GPUs, the block nvidiaGPUOIDs
// builds from one prefix.
const nl6576DynamicGPUOIDsPerDevice = 64

// nl6576StaticArcOIDsPerProfile is the number of arc OIDs each profile ships as
// static JSON: 2 scalars under .1.1.1.0 plus 9 columns x 8 GPUs under .1.1.1.1.
const nl6576StaticArcOIDsPerProfile = 74

// The two "before" digests below live HERE rather than beside the live constants
// they chain onto, which is a break from the pattern snmp_oid_roundtrip_test.go
// uses (its whole historical run — shippedOIDEncodingDigestAt09546c3 and the two
// after it — sits next to the live shippedOIDEncodingDigest). The break is
// deliberate: this transition's ledger is one file, and splitting its digests from
// its tables would be worse. So the cross-reference is written down instead of
// left for a reader to discover.
//
//	live value                  declared in                       reversed by
//	shippedTagDigest            snmp_hc_counter_table_test.go     TestNvidiaArcRehomeReproducesTheParentCorpus
//	shippedOIDEncodingDigest    snmp_oid_roundtrip_test.go        TestNvidiaArcRePinIsOnlyTheRename
//
// Both live constants carry a comment naming this file and these two tests, so
// the chain can be followed from either end.

// nvidiaArcParentRevision is the revision this change forked from and the one its
// two golden digests below were taken at. It is spelled once and read by both the
// tests here and this change's entry in newestFirstReversals.
const nvidiaArcParentRevision = "1bca8e8"

// shippedTagDigestBeforeNvidiaArcRehome is the (profile, OID, emitted tag)
// digest of the corpus at 1bca8e8 — the value shippedTagDigest held before this
// change, NOT re-derived from the re-homed tree.
const shippedTagDigestBeforeNvidiaArcRehome = "ba6e97223bbad5132bac6301b7a106950eb15552fded701a445e01074d5e99cf"

// shippedOIDEncodingDigestBeforeNvidiaArcRehome is the OID-name-to-encoding
// digest at the same revision, and the same rule applies to it. It is also the
// newest entry in snmp_oid_roundtrip_test.go's historical run: the value that
// file's shippedOIDEncodingDigest held before this change.
const shippedOIDEncodingDigestBeforeNvidiaArcRehome = "4dabe3fe5bdec217f4d76da0c4f0a187897435a33538ddbc25adc173c3baa801"

// nl6576ValueDigestAtParent is a SHA-256 over the sorted
// "profile\toidBefore\tvalue" lines of every row this ledger records, as it
// existed at 1bca8e8.
//
// It was computed by reading the six resource parts OUT OF GIT at that revision
// (`git show 1bca8e8:<path>`), never from the tables below, so comparing the
// tables against it compares them with the tree as it actually was. A digest
// derived from the tables would only prove the tables equal themselves — and for
// the 225 recorded oidBefore names and the three recorded old sysObjectID values
// nothing else in the package has anything left to compare against, because the
// rename removed all of them from the tree.
const nl6576ValueDigestAtParent = "1d74846d122175b99fca19eb4b3578caec4838ad776a69ccb020a7cbcdf19a51"

// restoreNl6576NvidiaArc reverses this change against a (profile, OID) -> value
// map, so the map afterwards is the corpus as 1bca8e8 shipped it. Shared with the
// three older ledger reversals, whose own starting point is the tree this one
// reconstructs.
//
// EVERY DISAGREEMENT IS FATAL, deliberately. An earlier cut reported a mismatch
// with t.Errorf and then wrote anyway, so the reconstruction carried on from a
// map it had just called wrong and the caller's digest mismatch — an opaque pair
// of hex strings — arrived on top of the real diagnosis and buried it. There is
// nothing useful to be learned from a reversal that continues past a corpus it
// does not recognise.
func restoreNl6576NvidiaArc(t *testing.T, cur map[[2]string]string) {
	t.Helper()

	for _, r := range nl6576RenamedGPUOIDs {
		after := [2]string{r.profile, r.oidAfter}
		before := [2]string{r.profile, r.oidBefore}
		got, ok := cur[after]
		if !ok {
			t.Fatalf("%s is in the rename ledger but %s no longer ships", r.profile, r.oidAfter)
		}
		if got != r.value {
			t.Fatalf("%s %s ships %q, but the ledger records the value as %q; a rename must not "+
				"change a value", r.profile, r.oidAfter, got, r.value)
		}
		if _, clash := cur[before]; clash {
			t.Fatalf("%s serves %s again, so the old Mailteck arc is back in the corpus",
				r.profile, r.oidBefore)
		}
		delete(cur, after)
		cur[before] = r.value
	}
	for _, s := range nl6576RehomedSysObjectIDs {
		k := [2]string{s.profile, s.oid}
		got, ok := cur[k]
		if !ok {
			t.Fatalf("%s no longer serves %s, which the sysObjectID ledger records", s.profile, s.oid)
		}
		if got != s.newValue {
			t.Fatalf("%s %s ships %q, but the ledger says this change set it to %q",
				s.profile, s.oid, got, s.newValue)
		}
		cur[k] = s.oldValue
	}
}

// nl6576OIDNamesBeforeRehome maps a list of shipped OID NAMES back to the
// spelling they had at 1bca8e8. It is the name-view counterpart of
// restoreNl6576NvidiaArc, used by every reversal of shippedOIDEncodingDigest.
//
// The rewrite is a blanket prefix swap rather than a table lookup, and that is
// sound only because nothing in the corpus used 5703 before this change — pinned
// by TestNvidiaArcLedgerIsNotVacuous, which requires every 5703 name shipped
// today to be accounted for by the ledger.
//
// Names here carry no leading dot: that is the spelling collectShippedOIDs
// gathers, since it reads the raw JSON strings.
//
// It takes a *testing.T and is FATAL when the prefix matches nothing, matching
// the convention every value view already followed. It used to be a t-less pure
// rewrite, so a corpus that had stopped shipping the 5703 arc made it a silent
// no-op and the only symptom was a digest mismatch in whichever ledger chained
// onto it.
func nl6576OIDNamesBeforeRehome(t *testing.T, names []string) []string {
	t.Helper()

	const oldUndotted = "1.3.6.1.4.1.53246."
	const newUndotted = "1.3.6.1.4.1.5703."

	out := make([]string, 0, len(names))
	rewritten := 0
	for _, n := range names {
		if strings.HasPrefix(n, newUndotted) {
			n = oldUndotted + n[len(newUndotted):]
			rewritten++
		}
		out = append(out, n)
	}
	if rewritten == 0 {
		t.Fatalf("the nl6#576 name-view reversal rewrote no name: nothing in the list it was given "+
			"is under %s, so it reverses nothing and the reconstruction is not 1bca8e8's set",
			newUndotted)
	}
	return out
}

// TestNvidiaArcRehomeReproducesTheParentCorpus is the before/after pin for the
// TAG digest: reverse the ledger against today's corpus and 1bca8e8's value must
// come back. A missing row, an extra row, or any other edit to shipped data made
// without recording it here all fail.
//
// Reproducing it also PROVES the claim the re-pin of shippedTagDigest rests on:
// the only difference between the two corpora is the rename. If any tag had
// moved, or an entry had been added or dropped, the reconstruction would not
// land on the parent value.
func TestNvidiaArcRehomeReproducesTheParentCorpus(t *testing.T) {
	cur := map[[2]string]string{}
	for _, e := range shippedSNMPEntries(t) {
		k := [2]string{e.Profile, e.OID}
		if prev, dup := cur[k]; dup && prev != e.Value {
			t.Fatalf("%s serves %s twice with different values (%q, %q); the reconstruction "+
				"cannot be unambiguous", e.Profile, e.OID, prev, e.Value)
		}
		cur[k] = e.Value
	}

	restoreCorpusValuesTo(t, cur, nvidiaArcParentRevision)

	// Same line shape and hash as shippedTypedCorpus.
	seen := map[string]struct{}{}
	for k, v := range cur {
		enc := encodeTypedValue(k[1], v)
		if len(enc) == 0 {
			t.Fatalf("%s %s: encodeTypedValue(%q) emitted nothing", k[0], k[1], v)
		}
		seen[fmt.Sprintf("%s\t%s\t%02X", k[0], k[1], enc[0])] = struct{}{}
	}
	lines := make([]string, 0, len(seen))
	for l := range seen {
		lines = append(lines, l)
	}
	sort.Strings(lines)

	h := sha256.New()
	for _, l := range lines {
		h.Write([]byte(l))
		h.Write([]byte{'\n'})
	}
	got := hex.EncodeToString(h.Sum(nil))

	t.Logf("reversed %d OID renames and %d sysObjectID re-homings; %d (profile, OID, tag) triples "+
		"reconstructed", len(nl6576RenamedGPUOIDs), len(nl6576RehomedSysObjectIDs), len(lines))

	if got != shippedTagDigestBeforeNvidiaArcRehome {
		t.Errorf("reconstructed parent digest = %s, want %s.\n"+
			"The ledger no longer accounts for the difference between 1bca8e8's shipped data and "+
			"this tree's. Either a row is missing from it, or shipped data changed without being "+
			"recorded.", got, shippedTagDigestBeforeNvidiaArcRehome)
	}
}

// TestNvidiaArcRePinIsOnlyTheRename does the same job for the OID-NAME digest,
// which the tag digest cannot see: it hashes (profile, OID, tag) triples, so a
// name that changed to a DIFFERENT name encoding to the same tag is invisible to
// it. Here every distinct shipped name is paired with its actual BER encoding.
func TestNvidiaArcRePinIsOnlyTheRename(t *testing.T) {
	restored := restoreCorpusOIDNamesTo(t, collectShippedOIDs(t), nvidiaArcParentRevision)
	sort.Strings(restored)

	h := sha256.New()
	checked := 0
	for _, oid := range restored {
		if strings.Contains(oid, "{{") {
			continue
		}
		checked++
		// hash.Hash.Write never returns an error, but errcheck cannot know that.
		_, _ = fmt.Fprintf(h, "%s=%x\n", oid, encodeOID(oid))
	}
	got := hex.EncodeToString(h.Sum(nil))

	if got != shippedOIDEncodingDigestBeforeNvidiaArcRehome {
		t.Errorf("un-renaming the arc gives digest %s, want the pre-change value %s over %d OIDs.\n"+
			"So the re-pin of shippedOIDEncodingDigest is NOT explained by this rename alone: "+
			"something else about what a shipped OID puts on the wire has changed.",
			got, shippedOIDEncodingDigestBeforeNvidiaArcRehome, checked)
	}
	t.Logf("%d shipped OID names with the arc un-renamed reproduce the pre-change digest", checked)
}

// TestNvidiaArcLedgerValuesMatchTheParentRevision pins the ledger's recorded
// oidBefore names and values against the tree at 1bca8e8. Without it the 225
// recorded oidBefore spellings and the three old sysObjectID values are
// unfalsifiable: the rename removed every one of them from the tree, so nothing
// else in the package has anything left to compare against.
//
// If it fails after an edit to the tables, the tables are wrong — the parent
// revision cannot change.
func TestNvidiaArcLedgerValuesMatchTheParentRevision(t *testing.T) {
	var lines []string
	for _, r := range nl6576RenamedGPUOIDs {
		lines = append(lines, fmt.Sprintf("%s\t%s\t%s", r.profile, r.oidBefore, r.value))
	}
	for _, s := range nl6576RehomedSysObjectIDs {
		lines = append(lines, fmt.Sprintf("%s\t%s\t%s", s.profile, s.oid, s.oldValue))
	}
	sort.Strings(lines)

	h := sha256.New()
	for _, l := range lines {
		h.Write([]byte(l))
		h.Write([]byte{'\n'})
	}
	got := hex.EncodeToString(h.Sum(nil))

	if got != nl6576ValueDigestAtParent {
		t.Errorf("ledger value digest = %s, want %s (%d rows).\n"+
			"The recorded (profile, OID-before, value) triples no longer match what 1bca8e8 "+
			"shipped. Re-derive with: git show 1bca8e8:go/nl6/resources/nvidia_*/... for the six "+
			"parts, collect the rows this ledger names, and hash sorted "+
			"\"profile\\tOID\\tvalue\" lines. Do not re-pin this constant to match an edited "+
			"table: the parent revision is fixed.", got, nl6576ValueDigestAtParent, len(lines))
	}
	t.Logf("all %d recorded values match the corpus at 1bca8e8", len(lines))
}

// TestNvidiaArcLedgerIsNotVacuous guards the guard, and it carries the "the only
// difference is the rename" claim that the digest reversal alone cannot state in
// so many words. An emptied ledger would make the reversal above pass only if the
// corpus were untouched, so the census is pinned and the SHAPE of every row is
// checked against the claim made about it.
func TestNvidiaArcLedgerIsNotVacuous(t *testing.T) {
	for _, tc := range []struct {
		name string
		got  int
		want int
	}{
		{"renamed GPU OIDs", len(nl6576RenamedGPUOIDs), 222},
		{"re-homed sysObjectIDs", len(nl6576RehomedSysObjectIDs), 3},
		{"total recorded rows", len(nl6576RenamedGPUOIDs) + len(nl6576RehomedSysObjectIDs), 225},
	} {
		if tc.got != tc.want {
			t.Errorf("%s: ledger has %d rows, want %d — the counts are the census quoted in the "+
				"commit body and the docs, so they move together or not at all",
				tc.name, tc.got, tc.want)
		}
	}

	// EVERY SUB-IDENTIFIER BELOW THE PEN IS PRESERVED. This is the whole
	// approach: the change is a prefix swap and nothing else, so a downstream
	// pollaris rule needs only its prefix updated. Asserted per row rather than
	// trusted from the generator, because a single mangled suffix is exactly the
	// kind of edit a digest reversal would report as "the ledger is wrong"
	// without saying which row.
	perProfile := map[string]int{}
	for _, r := range nl6576RenamedGPUOIDs {
		perProfile[r.profile]++
		beforeSuffix, okB := strings.CutPrefix(r.oidBefore, mailteckArcPrefix+".")
		afterSuffix, okA := strings.CutPrefix(r.oidAfter, nvidiaArcPrefix+".")
		switch {
		case !okB:
			t.Errorf("%s: ledger oidBefore %s is not under the Mailteck arc %s",
				r.profile, r.oidBefore, mailteckArcPrefix)
		case !okA:
			t.Errorf("%s: ledger oidAfter %s is not under the NVIDIA arc %s",
				r.profile, r.oidAfter, nvidiaArcPrefix)
		case beforeSuffix != afterSuffix:
			t.Errorf("%s: %s -> %s changes the sub-identifiers below the PEN (%s -> %s). This "+
				"change re-homes an arc; it does not renumber objects",
				r.profile, r.oidBefore, r.oidAfter, beforeSuffix, afterSuffix)
		}
		// A rename must not move a tag. Both sides are put through the ENCODER
		// rather than reasoned about from oidTypeTable, since the encoder is what
		// decides the wire byte.
		encB, encA := encodeTypedValue(r.oidBefore, r.value), encodeTypedValue(r.oidAfter, r.value)
		if len(encB) == 0 || len(encA) == 0 || encB[0] != encA[0] {
			t.Errorf("%s: %q emits % x under %s and % x under %s; a re-homing must be tag-neutral",
				r.profile, r.value, encB, r.oidBefore, encA, r.oidAfter)
		}
	}
	// PER PROFILE, not the total divided by the profile count. 75 / 74 / 73 sums
	// to 222 and divides to exactly 74, so a row misfiled from one profile to
	// another passes an average and fails this. The profile list is the one
	// declared in this file rather than a literal 3, so adding a fourth NVIDIA
	// type is one edit, not two that can disagree.
	if len(perProfile) != len(nvidiaProfiles) {
		t.Errorf("the rename ledger spans %d profiles, want %d", len(perProfile), len(nvidiaProfiles))
	}
	for _, profile := range nvidiaProfiles {
		if got := perProfile[profile]; got != nl6576StaticArcOIDsPerProfile {
			t.Errorf("the ledger records %d renamed OIDs for %s, want %d",
				got, profile, nl6576StaticArcOIDsPerProfile)
		}
		delete(perProfile, profile)
	}
	for profile, n := range perProfile {
		t.Errorf("the ledger records %d renamed OIDs for %s, which is not an NVIDIA profile",
			n, profile)
	}

	// The three sysObjectID suffixes stay DISTINCT and in the same order, which
	// is the point of re-homing rather than deleting: vendor detection has to keep
	// telling the three models apart.
	wantSuffix := map[string]string{
		"nvidia_dgx_a100.json": "1.2.1",
		"nvidia_dgx_h100.json": "1.2.2",
		"nvidia_hgx_h200.json": "1.2.3",
	}
	seenSuffix := map[string]string{}
	for _, s := range nl6576RehomedSysObjectIDs {
		if s.oid != ".1.3.6.1.2.1.1.2.0" {
			t.Errorf("%s: the sysObjectID ledger records %s, which is not sysObjectID.0",
				s.profile, s.oid)
			continue
		}
		oldSuffix, okO := strings.CutPrefix(s.oldValue, strings.TrimPrefix(mailteckArcPrefix, ".")+".")
		newSuffix, okN := strings.CutPrefix(s.newValue, strings.TrimPrefix(nvidiaArcPrefix, ".")+".")
		if !okO || !okN || oldSuffix != newSuffix {
			t.Errorf("%s: sysObjectID %s -> %s is not a bare prefix swap", s.profile, s.oldValue, s.newValue)
			continue
		}
		if want := wantSuffix[s.profile]; newSuffix != want {
			t.Errorf("%s: sysObjectID suffix is %s, want %s — the per-model suffixes must stay "+
				"distinct and in their original order", s.profile, newSuffix, want)
		}
		if other, dup := seenSuffix[newSuffix]; dup {
			t.Errorf("%s and %s both claim sysObjectID suffix %s; a collector could not tell the "+
				"two models apart", other, s.profile, newSuffix)
		}
		seenSuffix[newSuffix] = s.profile
	}

	// NOTHING WAS ADDED AND NOTHING WAS DROPPED. Every use of the NVIDIA arc in
	// the corpus must be accounted for by a ledger row — an unaccounted one would
	// be telemetry this change added, and this change re-homes only.
	//
	// It is also the SOUNDNESS PRECONDITION for nl6576OIDNamesBeforeRehome, which
	// rewrites 5703 back to 53246 blanket, in all six chained reversals. That is
	// sound only while every 5703 string in the corpus is one this change put
	// there. So the census scans OID-typed VALUES as well as names (a sysObjectID
	// response is not an OID key, and vendor detection reads exactly that), and
	// TestArcRewriteSeesEveryShippedSpelling covers the trap-catalog surface and
	// the alternative spellings, which shippedSNMPEntries cannot see at all.
	nameLedger := map[[2]string]struct{}{}
	for _, r := range nl6576RenamedGPUOIDs {
		nameLedger[[2]string{r.profile, r.oidAfter}] = struct{}{}
	}
	valueLedger := map[[2]string]string{}
	for _, s := range nl6576RehomedSysObjectIDs {
		valueLedger[[2]string{s.profile, s.oid}] = s.newValue
	}
	perWhere := map[string]int{}
	for _, h := range entriesTouchingArc(t, nvidiaArcPrefix) {
		perWhere[h.where]++
		switch h.where {
		case "name":
			if _, ok := nameLedger[[2]string{h.profile, h.oid}]; !ok {
				t.Errorf("%s serves %s under the NVIDIA arc, but the ledger does not record it. "+
					"This change re-homes; it does not add telemetry", h.part, h.oid)
			}
		case "value":
			if want, ok := valueLedger[[2]string{h.profile, h.oid}]; !ok || want != h.text {
				t.Errorf("%s: %s answers %q under the NVIDIA arc, which the ledger does not "+
					"record. An unrecorded 5703 string makes nl6576OIDNamesBeforeRehome's blanket "+
					"rewrite unsound: all six chained reversals would silently rewrite it",
					h.part, h.oid, h.text)
			}
		}
	}
	if perWhere["name"] != len(nl6576RenamedGPUOIDs) {
		t.Errorf("%d arc OID names ship, the ledger records %d",
			perWhere["name"], len(nl6576RenamedGPUOIDs))
	}
	if perWhere["value"] != len(nl6576RehomedSysObjectIDs) {
		t.Errorf("%d arc OID-typed values ship, the ledger records %d",
			perWhere["value"], len(nl6576RehomedSysObjectIDs))
	}
}

// TestArcRewriteSeesEveryShippedSpelling closes the gap the census above cannot:
// nl6576OIDNamesBeforeRehome keys on ONE exact prefix string, applied to the list
// collectShippedOIDs gathers, and that list is wider than shippedSNMPEntries — it
// also holds trap-catalog snmpTrapOID / snmpTrapEnterprise values and OID-typed
// responses, in whatever spelling the JSON uses.
//
// Three spellings would be missed silently, and each surfaces only as three
// unexplained digest failures whose documented remedy is to re-pin:
//
//   - a name written WITH a leading dot (no shipped part does today, but the
//     loaders normalise, so nothing stops one)
//   - the bare PEN node with no trailing sub-identifier
//   - a 5703 string reached through the catalog surface rather than the snmp array
//
// So this asserts the property the rewrite actually needs: every shipped string
// that mentions either PEN is spelled exactly the way the rewrite matches, and
// none mentions the Mailteck PEN at all.
func TestArcRewriteSeesEveryShippedSpelling(t *testing.T) {
	const rewriteMatches = "1.3.6.1.4.1.5703." // the literal nl6576OIDNamesBeforeRehome keys on
	bareNvidia := strings.TrimPrefix(nvidiaArcPrefix, ".")
	bareMailteck := strings.TrimPrefix(mailteckArcPrefix, ".")

	rewritable, mentions := 0, 0
	for _, name := range collectShippedOIDs(t) {
		dotted := normaliseOIDKey(name)
		if underArc(dotted, mailteckArcPrefix) {
			t.Errorf("a shipped OID string %q mentions the Mailteck PEN %s. Whatever surface it "+
				"came from — resource name, OID-typed response, or trap catalog — the arc is "+
				"re-homed and no shipped string may name it", name, bareMailteck)
		}
		if !underArc(dotted, nvidiaArcPrefix) {
			continue
		}
		mentions++
		if !strings.HasPrefix(name, rewriteMatches) {
			t.Errorf("a shipped OID string %q sits under the NVIDIA PEN but is not spelled %q..., "+
				"which is the ONE prefix nl6576OIDNamesBeforeRehome matches. It would be left "+
				"un-rewritten by all six chained reversals, and the only symptom would be three "+
				"digest failures with no explanation. Either spell it that way, or teach the "+
				"rewrite this spelling and say so", name, rewriteMatches)
			continue
		}
		rewritable++
	}

	// The rewrite must have something to do, or the assertions above are vacuous:
	// 74 distinct GPU OID names shared by the three profiles, plus one distinct
	// sysObjectID value per profile.
	if want := nl6576StaticArcOIDsPerProfile + len(nvidiaProfiles); mentions != want {
		t.Errorf("%d distinct shipped strings mention the NVIDIA PEN, want %d (%d distinct GPU "+
			"OID names shared across the profiles, plus one sysObjectID value each)",
			mentions, want, nl6576StaticArcOIDsPerProfile)
	}
	if rewritable != mentions {
		t.Errorf("%d of %d are in the spelling the rewrite matches", rewritable, mentions)
	}

	// And the rewrite really does move them, which is what makes "the rewrite
	// matches this spelling" a claim about the function rather than about a
	// constant that happens to sit next to it.
	moved := 0
	for i, back := range nl6576OIDNamesBeforeRehome(t, collectShippedOIDs(t)) {
		if strings.HasPrefix(back, bareMailteck+".") {
			moved++
		}
		if strings.HasPrefix(back, bareNvidia+".") {
			t.Errorf("nl6576OIDNamesBeforeRehome left entry %d as %q, still under the NVIDIA PEN", i, back)
		}
	}
	if moved != mentions {
		t.Errorf("the rewrite moved %d strings, want %d", moved, mentions)
	}
	t.Logf("%d distinct shipped strings mention the NVIDIA PEN; all are rewritable and all move",
		mentions)
}

// TestNoNvidiaOIDsShipUnderMailteck is the absence half, and it is the assertion
// the whole change exists to make true: no profile may serve anything under
// 1.3.6.1.4.1.53246, because that arc belongs to Mailteck, S.A.
//
// A test that requires ZERO of something cannot fail on its own, so it starts
// with a POSITIVE CONTROL: a temp copy of resources/ with TWO 53246 entries
// planted in it, which the same scan must both report.
//
// TWO, not one, and the second is the load-bearing one. The first plants the arc
// as an OID NAME; the second plants it as a sysObjectID.0 RESPONSE VALUE on a
// profile that is not even an NVIDIA one, which is how vendor detection actually
// reads the arc. One planted name cannot prove the value branch works: the
// name-only scan this control replaced passed with a planted sysObjectID value
// sitting in the corpus.
func TestNoNvidiaOIDsShipUnderMailteck(t *testing.T) {
	// The control runs first and in its own scope, because it t.Chdir()s.
	t.Run("positive control", func(t *testing.T) {
		tmp := t.TempDir()
		if err := os.CopyFS(filepath.Join(tmp, "resources"), os.DirFS("resources")); err != nil {
			t.Fatalf("copy resources: %v", err)
		}
		for _, p := range []struct{ dir, file, body string }{
			{"nvidia_dgx_a100", "zzplanted_name_snmp.json",
				`{"snmp":[{"oid":"1.3.6.1.4.1.53246.1.1.1.1.5.0","response":"42"}]}`},
			// A sysObjectID.0 whose RESPONSE is under the arc, on a non-NVIDIA
			// profile. Nothing about the OID key gives this away.
			{"cisco_ios", "zzplanted_value_snmp.json",
				`{"snmp":[{"oid":"1.3.6.1.2.1.1.2.0","response":"1.3.6.1.4.1.53246.1.2.9"}]}`},
		} {
			if err := os.WriteFile(filepath.Join(tmp, "resources", p.dir, p.file),
				[]byte(p.body), 0o644); err != nil {
				t.Fatalf("plant a Mailteck-arc entry: %v", err)
			}
		}
		t.Chdir(tmp)

		got := entriesTouchingArc(t, mailteckArcPrefix)
		byWhere := map[string]int{}
		for _, h := range got {
			byWhere[h.where]++
		}
		if len(got) != 2 || byWhere["name"] != 1 || byWhere["value"] != 1 {
			t.Fatalf("the control plants ONE name and ONE OID-typed VALUE under %s; the scan "+
				"reported %d hits (%v): %+v.\nThe zero asserted below is therefore vacuous. If the "+
				"value hit is missing, the scan reads OID KEYS only — and vendor detection reads "+
				"the sysObjectID RESPONSE, which is the whole reason this arc was re-homed.",
				mailteckArcPrefix, len(got), byWhere, got)
		}
	})

	for _, h := range entriesTouchingArc(t, mailteckArcPrefix) {
		t.Errorf("%s: %s reaches the wire under %s (as an OID %s: %s). 1.3.6.1.4.1.53246 is "+
			"allocated to Mailteck, S.A., not NVIDIA: a collector doing vendor detection resolves "+
			"this device as Mailteck. Re-home it to %s, preserving every sub-identifier",
			h.part, h.oid, mailteckArcPrefix, h.where, h.text, nvidiaArcPrefix)
	}

	// And the NEW arc must actually be served, or this test would also pass on a
	// corpus that had lost the GPU surface entirely — which nl6#576 explicitly
	// rejected as an option, because docs/reference/gpu/pollaris.mdx publishes
	// polling rules against these OIDs.
	//
	// Counted per POSITION, so losing the three sysObjectID values while keeping
	// the 222 names is reported rather than absorbed into one total: those three
	// are the vendor-detection surface.
	served := map[string]int{}
	for _, h := range entriesTouchingArc(t, nvidiaArcPrefix) {
		served[h.where]++
	}
	wantNames := nl6576StaticArcOIDsPerProfile * len(nvidiaProfiles)
	if served["name"] != wantNames {
		t.Errorf("%d OID names sit under %s, want %d. The arc was re-homed, not deleted",
			served["name"], nvidiaArcPrefix, wantNames)
	}
	if served["value"] != len(nvidiaProfiles) {
		t.Errorf("%d OID-typed values sit under %s, want %d — one sysObjectID.0 per NVIDIA "+
			"profile. Vendor detection is the reason the arc was re-homed rather than deleted",
			served["value"], nvidiaArcPrefix, len(nvidiaProfiles))
	}
	t.Logf("%d names and %d OID-typed values sit under %s; none under %s",
		served["name"], served["value"], nvidiaArcPrefix, mailteckArcPrefix)
}

// arcHit is one shipped entry that touches an enterprise arc, and WHERE it
// touches it. The `where` field is the point: an arc reaches the wire from TWO
// positions and only one of them is an OID key.
type arcHit struct {
	profile string // "nvidia_dgx_a100.json"
	oid     string // the entry's own OID, normalised
	part    string // the file to edit
	where   string // "name" or "value"
	text    string // the string that is under the arc
}

// entriesTouchingArc is the rule, as a function so the control can require it to
// REPORT rather than only to stay silent.
//
// IT SCANS NAMES **AND** OID-TYPED VALUES, and the value half is the one that
// matters most here. Vendor detection reads the sysObjectID.0 RESPONSE, not an
// OID key, so an arc restored into a sysObjectID value is exactly the regression
// this guard exists to catch — and a name-only scan is structurally blind to it.
// Measured before the fix: planting 1.3.6.1.4.1.53246.1.2.9 as cisco_ios's
// sysObjectID.0 response left TestNoNvidiaOIDsShipUnderMailteck green, and the
// only tests that fired were five golden digests whose documented remedy is to
// RE-PIN the constant. That is the nl6#541 failure shape (a guard whose blind
// spot is invisible from inside the guard), and it is what the comment on
// TestEveryNvidiaGPUOIDIsAnsweredAtTheNewArc warns about two functions below.
//
// Whether a value is an OID is decided EXACTLY as the production encoder and
// collectShippedOIDs decide it — snmpTypeTag(normaliseOIDKey(name)) ==
// ASN1_OBJECT_ID — and not by a second predicate of this file's own. A predicate
// that agreed on the day it was written is how trap_catalog.go's validateDottedOID
// drifted from the encoder (nl6#539). A string-shape test would be wrong as well:
// an IPv4 address is digits and dots too.
//
// Both spellings of a value are covered, since a response carries no leading dot
// while an OID key does once normalised.
func entriesTouchingArc(t *testing.T, arc string) []arcHit {
	t.Helper()
	return scanArcPositions(t, func(dotted string) bool { return underArc(dotted, arc) })
}

// scanArcPositions is the scan itself, with the arc test as a parameter. It was
// split out of entriesTouchingArc by nl6#588, whose own-vendor guard asks a
// different question of the SAME two positions — "which PEN is this under", not
// "is this under one named arc" — and a second walk would be a second place for
// the value half to go missing. There is ONE scan of the two positions in this
// package and both guards go through it, so narrowing it to names-only fails
// both controls at once.
func scanArcPositions(t *testing.T, keep func(dottedOID string) bool) []arcHit {
	t.Helper()

	var out []arcHit
	for _, e := range shippedSNMPEntries(t) {
		if keep(e.OID) {
			out = append(out, arcHit{e.Profile, e.OID, e.Part, "name", e.OID})
		}
		if snmpTypeTag(normaliseOIDKey(e.OID)) != ASN1_OBJECT_ID {
			continue
		}
		if keep(normaliseOIDKey(e.Value)) {
			out = append(out, arcHit{e.Profile, e.OID, e.Part, "value", e.Value})
		}
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].profile != out[j].profile {
			return out[i].profile < out[j].profile
		}
		if out[i].oid != out[j].oid {
			return out[i].oid < out[j].oid
		}
		return out[i].where < out[j].where
	})
	return out
}

// underArc is true when a dotted OID is the arc node itself or sits below it.
// The arc node is included deliberately: 1.3.6.1.4.1.53246 with no trailing
// sub-identifier is still Mailteck's number, and a test keyed on arc+"." alone
// would walk straight past it (see TestArcRewriteSeesEveryShippedSpelling).
func underArc(dottedOID, arc string) bool {
	return dottedOID == arc || strings.HasPrefix(dottedOID, arc+".")
}

// ── the premise, checked in as data ─────────────────────────────────────────

// ianaPENFixture is the registry extract this change's premise rests on.
const ianaPENFixture = "testdata/iana/enterprise_numbers.tsv"

// ianaPENEntry is one row of it.
type ianaPENEntry struct {
	pen, org, emailDomain, role string
}

// readIANAPENFixture parses the checked-in registry extract. It reads a FILE and
// never the network, for the reason testdata/mibs/*.tsv gives: a test that
// depends on iana.org either fails closed in CI or skips and asserts nothing.
//
// IT REJECTS A DUPLICATE pen OR role HERE, in the reader, rather than leaving
// each caller to check. Every caller indexes these rows into a map — byRole in
// the two premise tests, byPEN in the own-vendor guard — and a Go map assignment
// silently keeps the LAST duplicate, so a second row for the same role would make
// a premise test assert against the wrong registry entry and pass. That is the
// one failure mode a premise pin cannot survive: it exists precisely to be the
// thing nothing else can falsify. The fixture grew from 2 rows to 23 in nl6#588,
// which is where this stopped being hypothetical.
func readIANAPENFixture(t *testing.T) []ianaPENEntry {
	t.Helper()

	raw, err := os.ReadFile(ianaPENFixture)
	if err != nil {
		t.Fatalf("read %s: %v", ianaPENFixture, err)
	}
	type seenAt struct {
		line int
		pen  string
	}
	var out []ianaPENEntry
	penLine := map[string]int{}
	roleLine := map[string]seenAt{}
	for i, line := range strings.Split(string(raw), "\n") {
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		f := strings.Split(line, "\t")
		if len(f) != 4 {
			t.Fatalf("%s:%d: %d tab-separated fields, want 4: %q", ianaPENFixture, i+1, len(f), line)
		}
		e := ianaPENEntry{f[0], f[1], f[2], f[3]}
		if prev, dup := penLine[e.pen]; dup {
			t.Fatalf("%s: PEN %s appears twice, at lines %d and %d. Every reader indexes these rows "+
				"by pen or by role into a map, and a map keeps the LAST duplicate silently — so a "+
				"second row would make a premise assertion compare against the wrong registry entry "+
				"and pass", ianaPENFixture, e.pen, prev, i+1)
		}
		if prev, dup := roleLine[e.role]; dup {
			t.Fatalf("%s: role %q appears twice, at lines %d and %d (PENs %s and %s). A role names "+
				"ONE registry row; two rows sharing one make the premise pins assert against "+
				"whichever came last", ianaPENFixture, e.role, prev.line, i+1, prev.pen, e.pen)
		}
		penLine[e.pen] = i + 1
		roleLine[e.role] = seenAt{i + 1, e.pen}
		out = append(out, e)
	}
	if len(out) == 0 {
		t.Fatalf("%s holds no entries", ianaPENFixture)
	}
	return out
}

// TestArcPrefixesMatchTheIANARegistry is the one assertion in this file that is
// about the WORLD rather than about the corpus, and it is the premise everything
// else assumes: 5703 belongs to NVIDIA and 53246 does not.
//
// Without it, nl6#576's whole justification is a sentence in a commit message.
// Getting it backwards would not fail a single other test in the package: the
// ledger would reverse cleanly, the digests would reproduce, the serve path would
// answer, and the fleet would identify every simulated DGX as some other company
// again. That is precisely the class of claim nl6#541 decided to check in as
// extracted data rather than assert.
//
// It compares the two arc CONSTANTS this file drives every other assertion from
// against the registry rows, so a future edit that changes an arc without
// refreshing the fixture fails here first, with the registry line to look at.
func TestArcPrefixesMatchTheIANARegistry(t *testing.T) {
	const penRoot = ".1.3.6.1.4.1."

	byRole := map[string]ianaPENEntry{}
	for _, e := range readIANAPENFixture(t) {
		if prev, dup := byRole[e.role]; dup {
			t.Fatalf("the fixture gives role %q twice (%s and %s)", e.role, prev.pen, e.pen)
		}
		byRole[e.role] = e
	}

	for _, tc := range []struct {
		role, arc, wantOrg, wantDomain, why string
	}{
		{
			role: "nvidia", arc: nvidiaArcPrefix,
			wantOrg: "NVIDIA Corporation", wantDomain: "nvidia.com",
			why: "this is the arc nl6 serves GPU telemetry under, so sysObjectID identifies a " +
				"simulated DGX by it. If it is not NVIDIA's, vendor detection is wrong and the " +
				"re-homing achieved nothing",
		},
		{
			role: "mailteck", arc: mailteckArcPrefix,
			wantOrg: "Mailteck, S.A.", wantDomain: "mailteck.com",
			why: "this is the arc the telemetry used to sit under, and the reason it moved. If " +
				"this row is not a company unrelated to NVIDIA, the defect nl6#576 reports did " +
				"not exist",
		},
	} {
		e, ok := byRole[tc.role]
		if !ok {
			t.Fatalf("%s carries no row with role %q", ianaPENFixture, tc.role)
		}
		if got := penRoot + e.pen; got != tc.arc {
			t.Errorf("the %s constant is %s, but the registry gives PEN %s for %s (%s). %s",
				tc.role, tc.arc, e.pen, e.org, got, tc.why)
		}
		if e.org != tc.wantOrg {
			t.Errorf("the registry gives PEN %s to %q, and this change was made on the reading "+
				"that it belongs to %q. Re-fetch the registry: %s", e.pen, e.org, tc.wantOrg, tc.why)
		}
		if e.emailDomain != tc.wantDomain {
			t.Errorf("the registry contact for PEN %s is at %q, want %q — the corroborating "+
				"evidence for the organisation string", e.pen, e.emailDomain, tc.wantDomain)
		}
	}

	// The two must be DIFFERENT owners, which is the whole defect in one line.
	if byRole["nvidia"].org == byRole["mailteck"].org {
		t.Errorf("the fixture gives both PENs to %q, so there was nothing to re-home",
			byRole["nvidia"].org)
	}

	// And the production constant must sit under the NVIDIA PEN. This is the one
	// place the two are tied together: everywhere else nvidiaArcPrefix is a test
	// literal precisely so it cannot follow a mutation of the production one.
	if !strings.HasPrefix(nvidiaGPUMetricPrefix, nvidiaArcPrefix+".") {
		t.Errorf("nvidiaGPUMetricPrefix is %s, which is not under the registry-checked NVIDIA "+
			"PEN %s", nvidiaGPUMetricPrefix, nvidiaArcPrefix)
	}
}

// gpuDeviceForProfile builds a device carrying the three things this test needs
// to exercise the arc: the profile's resources, an IfCounterCycler, and the
// per-GPU metric arrays.
//
// The last of those is why it exists rather than reusing deviceForProfile, which
// omits InitGPUMetrics: without it MetricsCycler.GetGPUUtil answers the "0" it
// returns for an out-of-range index, so a test would see every dynamic GPU OID
// "answered" whether the cycler was wired or not.
//
// It is NOT a reproduction of a production creation path. Both of those call
// InitIfCountersWithScenario, which seeds the interface-state engine from the
// profile's ifTable .7 / .8 rows; this calls plain InitIfCounters, because
// interface state has no bearing on an enterprise-arc OID.
func gpuDeviceForProfile(t *testing.T, profile string) *SNMPServer {
	t.Helper()

	sm := &SimulatorManager{resourcesCache: make(map[string]*DeviceResources)}
	res, err := sm.LoadSpecificResources(profile)
	if err != nil {
		t.Fatalf("LoadSpecificResources(%s): %v", profile, err)
	}
	dp := GetDeviceProfile(profile)
	if dp.GPU == nil {
		t.Fatalf("%s has no GPU profile, so this fixture cannot exercise the dynamic OIDs", profile)
	}
	mc := NewMetricsCycler(1, dp)
	mc.InitGPUMetrics(1, dp.GPU)
	mc.InitIfCounters(res, 1)
	return &SNMPServer{device: &DeviceSimulator{
		ID:            "nvidia-arc-pin",
		resources:     res,
		resourceFile:  profile,
		metricsCycler: mc,
	}}
}

// TestEveryNvidiaGPUOIDIsAnsweredAtTheNewArc fires on the DEFECT rather than on a
// digest. Both corpus digests' documented remedy is to RE-PIN, so a tree that
// re-homed the static JSON and left metrics_oids.go at 53246 would show up as
// "update the golden value" — and 64 OIDs per device would have gone quiet with a
// green suite. This is the test that reports that, which is why its expectation
// is the LITERAL new arc and not nvidiaGPUMetricPrefix.
//
// It also covers the other three matrix rows: a static GET returns the value the
// 53246 twin returned, a sysObjectID GET returns the right per-model OID, and the
// old arc answers the RFC 3416 noSuchObject exception rather than a value.
//
// ABSENCE HAS ONE SPELLING HERE, and it is isSNMPExceptionValue. findResponse
// answers a miss with the valueNoSuchObject sentinel and never with "" (nl6#517,
// snmp_handlers.go), so an earlier `got == "" || isSNMPExceptionValue(got)` was
// half dead code and half a hedge that two different absences might both be fine.
// They are not: "" reaching a caller here would be a defect in findResponse, and
// this test would be the wrong place to tolerate it.
//
// The old arc is checked EXHAUSTIVELY on both halves — all 74 statics and all 64
// dynamics per profile. Sampling one static was the earlier shape and it was a
// false economy: the two halves are served by different mechanisms (the static
// oidIndex and the metric-OID map), so a partial re-homing of the JSON is exactly
// the case a single sample can miss.
func TestEveryNvidiaGPUOIDIsAnsweredAtTheNewArc(t *testing.T) {
	staticByProfile := map[string][]struct{ oid, value string }{}
	for _, r := range nl6576RenamedGPUOIDs {
		staticByProfile[r.profile] = append(staticByProfile[r.profile],
			struct{ oid, value string }{r.oidAfter, r.value})
	}
	sysObjByProfile := map[string]string{}
	for _, s := range nl6576RehomedSysObjectIDs {
		sysObjByProfile[s.profile] = s.newValue
	}

	// The dynamic block, spelled out from the literal arc: 8 metrics x 8 GPUs.
	// The metric sub-identifiers are 5..12 and the GPU index 0..7, which is the
	// schema nvidiaGPUOIDs implements and this change did not touch.
	var dynamic []string
	for metric := 5; metric <= 12; metric++ {
		for gpu := 0; gpu <= 7; gpu++ {
			dynamic = append(dynamic, fmt.Sprintf("%s.1.1.1.1.%d.%d", nvidiaArcPrefix, metric, gpu))
		}
	}
	if len(dynamic) != nl6576DynamicGPUOIDsPerDevice {
		t.Fatalf("the dynamic block is %d OIDs, want %d", len(dynamic), nl6576DynamicGPUOIDsPerDevice)
	}

	staticAnswered, dynamicAnswered, oldArcAbsent := 0, 0, 0
	for _, profile := range nvidiaProfiles {
		srv := gpuDeviceForProfile(t, profile)

		// mailteckTwinIsGone asserts the old spelling of an OID is not served at
		// all. Applied to EVERY static and EVERY dynamic OID, since the two are
		// served by different mechanisms.
		mailteckTwinIsGone := func(oid string) {
			t.Helper()
			old := mailteckArcPrefix + strings.TrimPrefix(oid, nvidiaArcPrefix)
			if got := srv.findResponse(old); !isSNMPExceptionValue(got) {
				t.Errorf("%s: %s still answers %q; the Mailteck arc must not be served at all",
					profile, old, got)
				return
			}
			oldArcAbsent++
		}

		for _, e := range staticByProfile[profile] {
			switch got := srv.findResponse(e.oid); {
			case isSNMPExceptionValue(got):
				t.Errorf("%s: %s is unanswered (%q). The arc was re-homed here; do NOT re-pin a "+
					"corpus digest to absorb this", profile, e.oid, got)
			case got != e.value:
				t.Errorf("%s: %s answers %q, but the 53246 twin answered %q. A re-homing preserves "+
					"the value", profile, e.oid, got, e.value)
			default:
				staticAnswered++
			}
			mailteckTwinIsGone(e.oid)
		}

		if got, want := srv.findResponse(".1.3.6.1.2.1.1.2.0"), sysObjByProfile[profile]; got != want {
			t.Errorf("%s: sysObjectID.0 answers %q, want %q — vendor detection is the reason this "+
				"arc was re-homed rather than deleted", profile, got, want)
		}

		for _, oid := range dynamic {
			switch got := srv.findResponse(oid); {
			case isSNMPExceptionValue(got):
				t.Errorf("%s: dynamic GPU OID %s is unanswered (%q). The static data was re-homed "+
					"to %s but nvidiaGPUMetricPrefix was not, so 64 OIDs per device went quiet",
					profile, oid, got, nvidiaArcPrefix)
			default:
				if _, err := strconv.ParseInt(got, 10, 64); err != nil {
					t.Errorf("%s: dynamic GPU OID %s answers %q, which is not a number",
						profile, oid, got)
				}
				dynamicAnswered++
			}
			mailteckTwinIsGone(oid)
		}
	}

	if want := len(nl6576RenamedGPUOIDs); staticAnswered != want {
		t.Errorf("%d of %d static arc OIDs answered", staticAnswered, want)
	}
	if want := nl6576DynamicGPUOIDsPerDevice * len(nvidiaProfiles); dynamicAnswered != want {
		t.Errorf("%d of %d dynamic GPU OIDs answered", dynamicAnswered, want)
	}
	if want := len(nl6576RenamedGPUOIDs) + nl6576DynamicGPUOIDsPerDevice*len(nvidiaProfiles); oldArcAbsent != want {
		t.Errorf("%d of %d Mailteck twins are absent from the serve path", oldArcAbsent, want)
	}
	t.Logf("%d static and %d dynamic arc OIDs answered across %d profiles; all %d Mailteck twins absent",
		staticAnswered, dynamicAnswered, len(nvidiaProfiles), oldArcAbsent)
}

// TestNvidiaArcWalkIsStrictlyIncreasing covers the last matrix row. A prefix swap
// MOVES the arc in walk order — 5703 sorts before 53246, and both sort against
// whatever else lives under 1.3.6.1.4.1 — so "the values are right" is not enough:
// a non-increasing walk is nl6#526's class of defect and no value assertion can
// see it.
//
// The count is asserted too, at 74 static + 64 dynamic per profile, which is what
// the arc emitted before the re-homing. It is derived from the ledger and the
// dynamic block rather than pinned as a bare number, so it moves only if the arc
// itself does.
//
// "Before the re-homing" is a MEASUREMENT, not an inference from the rename being
// a bijection: the same walk run in a worktree at 1bca8e8 emits 317 / 321 / 321
// OIDs for a100 / h100 / h200, of which 138 are under 53246 — the same totals and
// the same 138 this test observes under 5703. The totals are recorded here rather
// than asserted, because an unrelated profile edit may legitimately move them;
// the 138 is the number this change is about.
func TestNvidiaArcWalkIsStrictlyIncreasing(t *testing.T) {
	const maxSteps = 200000

	for _, profile := range nvidiaProfiles {
		t.Run(profile, func(t *testing.T) {
			srv := gpuDeviceForProfile(t, profile)
			served := srv.lldpServedOIDs()

			newArc, oldArc, steps := 0, 0, 0
			cur := ""
			for steps < maxSteps {
				next, _ := srv.findNextOIDWithServed(cur, served)
				if next == "" {
					break
				}
				if cur != "" && compareOIDs(next, cur) <= 0 {
					t.Fatalf("the walk went from %s to %s, which is not strictly increasing: a "+
						"manager walking this device never terminates", cur, next)
				}
				n := normaliseResourceOID(next)
				if strings.HasPrefix(n, nvidiaArcPrefix+".") {
					newArc++
				}
				if strings.HasPrefix(n, mailteckArcPrefix+".") {
					oldArc++
				}
				steps++
				cur = next
			}
			if steps >= maxSteps {
				t.Fatalf("the walk did not terminate within %d steps", maxSteps)
			}

			want := nl6576StaticArcOIDsPerProfile + nl6576DynamicGPUOIDsPerDevice
			if newArc != want {
				t.Errorf("the walk emitted %d OIDs under %s, want %d (%d static + %d dynamic) — the "+
					"same count the arc emitted under 53246", newArc, nvidiaArcPrefix, want,
					nl6576StaticArcOIDsPerProfile, nl6576DynamicGPUOIDsPerDevice)
			}
			if oldArc != 0 {
				t.Errorf("the walk emitted %d OIDs under the Mailteck arc %s", oldArc, mailteckArcPrefix)
			}
			t.Logf("%d OIDs walked, %d of them under %s", steps, newArc, nvidiaArcPrefix)
		})
	}
}
