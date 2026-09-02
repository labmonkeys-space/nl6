/*
 * Copyright 2026 Ronny Trommer <ronny@no42.org>
 * SPDX-License-Identifier: Apache-2.0
 */

package main

import (
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// nl6#624. WHAT nl6'S SNMPv3 USM ACTUALLY DOES, PINNED.
//
// nl6 documented MD5/SHA1 authentication in six places and implements none of
// it. The docs are corrected; these tests are what keep the correction true.
//
// EVERY FAILURE MESSAGE HERE NAMES THE DOCUMENTS TO UPDATE. That is the point:
// the day someone implements USM auth, the suite must fail with a list of files
// whose claims have become false, rather than leaving five documents quietly
// asserting the opposite of what nl6 emits. It is the convention
// TestGetNextWalkWorkPerDatagramIsBounded already uses one file over.
//
// These assert ABSENCE OF A FEATURE, which is an unusual thing to pin, so each
// one is written to fail on the implementation rather than on a refactor: they
// test emitted bytes and package-level facts, not the shape of any function.
//
// NOT VERIFIED AGAINST AN EXTERNAL STACK. Everything below reads nl6's own
// output with nl6's own parser. The repo's golden captures are v2c only, so no
// v3 byte sequence here came from net-snmp or snmp4j, and these tests cannot
// tell you whether a real manager accepts any of it. They pin what nl6 does,
// not that it is right.

// docsAssertingNoUSMAuth lists every file whose text depends on USM auth being
// absent. Named in failure messages so the edit is mechanical rather than a
// hunt.
var docsAssertingNoUSMAuth = []string{
	"docs/reference/snmp.md",
	"docs/reference/cli-flags.md",
	"docs/reference/architecture.md",
	"docs/reference/device-types.md",
	"docs/reference/web-api.md",
	"README.md",
	"CLAUDE.md",
}

func docsToUpdate() string { return strings.Join(docsAssertingNoUSMAuth, ", ") }

// TestV3ResponseCarriesTwelveZeroAuthParams pins the emitted field, which is
// the fact a peer actually sees. RFC 3414 §6.3.1 wants a zero-LENGTH
// msgAuthenticationParameters at noAuthNoPriv; nl6 sends twelve zero bytes, so
// even the security level nl6 can serve carries a non-conformant field.
func TestV3ResponseCarriesTwelveZeroAuthParams(t *testing.T) {
	s := v3TestServer(map[string]string{".1.3.6.1.4.1.99999.1.0": "probe"})

	scoped, err := s.createScopedPDU(".1.3.6.1.4.1.99999.1.0", "probe", &SNMPv3Message{
		GlobalData:     SNMPv3GlobalData{MsgID: 7, MsgFlags: 0},
		SecurityParams: SNMPv3SecurityParams{UserName: "testuser"},
	})
	if err != nil {
		t.Fatalf("createScopedPDU: %v", err)
	}
	raw, err := s.wrapScopedPDUInV3Message(scoped, &SNMPv3Message{
		GlobalData:     SNMPv3GlobalData{MsgID: 7, MsgFlags: 0},
		SecurityParams: SNMPv3SecurityParams{UserName: "testuser"},
	})
	if err != nil {
		t.Fatalf("wrapScopedPDUInV3Message: %v", err)
	}

	msg, err := s.parseSNMPv3Message(raw)
	if err != nil {
		t.Fatalf("parse our own response: %v", err)
	}
	got := msg.SecurityParams.AuthParams
	if len(got) != 12 {
		t.Errorf("msgAuthenticationParameters is %d bytes, expected 12.\nIf USM auth was implemented, "+
			"update: %s", len(got), docsToUpdate())
		return
	}
	for _, b := range got {
		if b != 0 {
			t.Errorf("msgAuthenticationParameters is non-zero (% x), so something now computes a "+
				"digest.\nUpdate the claims in: %s", got, docsToUpdate())
			return
		}
	}
}

// TestPackageComputesNoHMAC is the blunt half: no HMAC anywhere means no USM
// authentication anywhere, whatever any config field says.
func TestPackageComputesNoHMAC(t *testing.T) {
	files, scanned := productionGoFiles(t)
	for _, f := range files {
		src, err := os.ReadFile(f)
		if err != nil {
			t.Fatalf("read %s: %v", f, err)
		}
		body := stripLineComments(string(src))
		if strings.Contains(body, "crypto/hmac") || strings.Contains(body, "hmac.New") {
			t.Errorf("%s references crypto/hmac, so USM authentication may now exist.\nUpdate the "+
				"claims in: %s", filepath.Base(f), docsToUpdate())
		}
	}
	if scanned == 0 {
		t.Fatal("scanned no production files, so this guard proves nothing")
	}
}

// TestAuthProtocolIsNeverReadInProduction pins the sharpest of the claims: the
// -snmpv3-auth flag is parsed, stored, and consulted by nothing.
//
// AST-based and comment-blind, so a comment mentioning the field does not
// register, and the two legitimate sites are excluded by ROLE rather than by
// name: the struct field declaration, and the single assignment in simulator.go
// that stores the parsed flag.
func TestAuthProtocolIsNeverReadInProduction(t *testing.T) {
	files, scanned := productionGoFiles(t)
	if scanned == 0 {
		t.Fatal("scanned no production files, so this guard proves nothing")
	}

	var reads []string
	fset := token.NewFileSet()
	for _, path := range files {
		file, err := parser.ParseFile(fset, path, nil, 0)
		if err != nil {
			t.Fatalf("parse %s: %v", path, err)
		}
		ast.Inspect(file, func(n ast.Node) bool {
			// The declaration is not a read.
			if _, ok := n.(*ast.StructType); ok {
				return true
			}
			// An assignment TO the field is how the flag is stored; only a read
			// would mean the value influences behaviour.
			if as, ok := n.(*ast.AssignStmt); ok {
				for _, lhs := range as.Lhs {
					if sel, ok := lhs.(*ast.SelectorExpr); ok && sel.Sel.Name == "AuthProtocol" {
						return true
					}
				}
			}
			if kv, ok := n.(*ast.KeyValueExpr); ok {
				if id, ok := kv.Key.(*ast.Ident); ok && id.Name == "AuthProtocol" {
					return true // composite-literal initialisation, also a store
				}
			}
			if sel, ok := n.(*ast.SelectorExpr); ok && sel.Sel.Name == "AuthProtocol" {
				reads = append(reads, filepath.Base(path)+":"+
					strings.TrimPrefix(fset.Position(sel.Pos()).String(), fset.Position(sel.Pos()).Filename))
			}
			return true
		})
	}
	if len(reads) != 0 {
		t.Errorf("AuthProtocol is read by production code at %s, so -snmpv3-auth may now have an "+
			"effect.\nUpdate the claims in: %s", strings.Join(reads, ", "), docsToUpdate())
	}
}

// TestPrivacyKeysIgnoreTheAuthProtocolAndThePrivPassword pins the two privacy
// defects, and pins them in BOTH directions because the shipped hardcodings run
// opposite ways: generateDESKey hardcodes MD5, generateAESKey hardcodes SHA1.
//
// So md5+des happens to match RFC 3414 while sha1+des does not, and sha1+aes128
// matches on the hash while deriving from the wrong password. An earlier draft
// of the docs had those rows inverted; this is what keeps the table honest.
func TestPrivacyKeysIgnoreTheAuthProtocolAndThePrivPassword(t *testing.T) {
	mk := func(auth int) *SNMPServer {
		s := v3TestServer(nil)
		s.v3Config.AuthProtocol = auth
		s.v3Config.Password = "authpass"
		s.v3Config.PrivPassword = "privpass"
		s.cachedAESKey = nil
		return s
	}

	// The auth protocol does not reach either derivation.
	md5Srv, shaSrv := mk(SNMPV3_AUTH_MD5), mk(SNMPV3_AUTH_SHA1)
	if a, b := md5Srv.getAESKey(), shaSrv.getAESKey(); string(a) != string(b) {
		t.Errorf("the AES key changed with AuthProtocol, so the derivation now honours it.\nRFC 3414 "+
			"requires exactly that, so this is progress: update the matrix and the claims in %s",
			docsToUpdate())
	}
	if a, b := md5Srv.generateDESKey(), shaSrv.generateDESKey(); string(a) != string(b) {
		t.Errorf("the DES key changed with AuthProtocol, so the derivation now honours it.\nUpdate "+
			"the matrix and the claims in %s", docsToUpdate())
	}

	// AES ignores priv_password; DES honours it. Validate's comment promises the
	// DES behaviour for both, which is why the divergence is an interop defect
	// and not only a documentation one.
	s := mk(SNMPV3_AUTH_MD5)
	fromAuthPassword := s.generateAESKey("authpass")
	if string(s.getAESKey()) != string(fromAuthPassword) {
		t.Errorf("the AES key is no longer derived from the AUTH password, so getAESKey now honours "+
			"priv_password.\nUpdate the claims in: %s", docsToUpdate())
	}
	des := s.generateDESKey()
	s2 := mk(SNMPV3_AUTH_MD5)
	s2.v3Config.PrivPassword = ""
	if string(des) == string(s2.generateDESKey()) {
		t.Errorf("the DES key no longer varies with priv_password, so that path stopped honouring "+
			"it.\nUpdate the claims in: %s", docsToUpdate())
	}
}

// TestInboundV3RequestsAreNotAuthenticated pins the half the first draft of the
// docs missed entirely, and the one an operator can actually be bitten by: nl6
// answers a request carrying any auth parameters at all, because
// validateSNMPv3Credentials checks the username and nothing else.
//
// The consequence is that a collector's wrong-credential handling cannot be
// tested against nl6, and a "successful" authNoPriv exchange proves nothing.
func TestInboundV3RequestsAreNotAuthenticated(t *testing.T) {
	s := v3TestServer(map[string]string{".1.3.6.1.4.1.99999.1.0": "probe"})
	s.v3Config.AuthProtocol = SNMPV3_AUTH_MD5

	msg := &SNMPv3Message{
		GlobalData: SNMPv3GlobalData{MsgID: 1, MsgFlags: SNMPV3_MSG_FLAG_AUTH},
		SecurityParams: SNMPv3SecurityParams{
			UserName:   "testuser",
			AuthParams: []byte("totally-wrong-digest"),
		},
	}
	if !s.validateSNMPv3Credentials(msg) {
		t.Errorf("a request carrying a bogus authentication digest was REJECTED, so nl6 now verifies "+
			"inbound authentication.\nThat is a real improvement and it changes what an operator can "+
			"test: update the claims in %s", docsToUpdate())
	}
}

// ── helpers ─────────────────────────────────────────────────────────────────

// productionGoFiles lists the package's non-test Go sources.
func productionGoFiles(t *testing.T) ([]string, int) {
	t.Helper()
	entries, err := os.ReadDir(".")
	if err != nil {
		t.Fatalf("read package dir: %v", err)
	}
	var out []string
	for _, e := range entries {
		n := e.Name()
		if e.IsDir() || !strings.HasSuffix(n, ".go") || strings.HasSuffix(n, "_test.go") {
			continue
		}
		out = append(out, n)
	}
	return out, len(out)
}

// stripLineComments removes // comments so a comment naming a symbol does not
// register as a use of it.
func stripLineComments(src string) string {
	var b strings.Builder
	for _, line := range strings.Split(src, "\n") {
		if i := strings.Index(line, "//"); i >= 0 {
			line = line[:i]
		}
		b.WriteString(line)
		b.WriteByte('\n')
	}
	return b.String()
}
