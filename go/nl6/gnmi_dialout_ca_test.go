/*
 * Copyright 2026 Ronny Trommer <ronny@no42.org>
 * SPDX-License-Identifier: Apache-2.0
 */

package main

import (
	"bytes"
	"crypto/tls"
	"encoding/json"
	"encoding/pem"
	"strings"
	"testing"
)

// TestDialoutTLS_CAIsInlineNotAPath is the regression for a REST-reachable
// arbitrary-file-read.
//
// `tls.ca_file` used to name a path that buildDialoutCreds opened at dial time.
// DeviceGnmiDialoutConfig is settable over REST, so that let any API caller
// point the simulator at any file: the content never came back, but the error
// distinguishing "read failed" from "no PEM certificates found" is an oracle
// for file existence and shape.
//
// CodeQL flagged the identical construct in the syslog TLS transport as
// `go/path-injection` and it was fixed there first; this one was never flagged,
// because CodeQL only analyses code a PR changes and this line is older. Older
// is not safer.
func TestDialoutTLS_CAIsInlineNotAPath(t *testing.T) {
	_, leaf := newTestTLSCert(t)
	pemBytes := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: leaf.Raw})

	creds, err := buildDialoutCreds(&DialoutTLSConfig{Enabled: true, CAPEM: string(pemBytes)}, nil)
	if err != nil {
		t.Fatalf("inline PEM rejected: %v", err)
	}
	if creds == nil {
		t.Fatal("no credentials returned for a valid inline CA")
	}

	// Garbage must fail rather than silently degrade to system-roots
	// verification, which would look like it worked and verify the wrong thing.
	if _, err := buildDialoutCreds(&DialoutTLSConfig{Enabled: true, CAPEM: "not a certificate"}, nil); err == nil {
		t.Error("non-PEM ca_pem accepted; it must fail rather than fall back to system roots")
	}

	// The floor is asserted through the extracted builder. Asserting it via
	// buildDialoutCreds is impossible — credentials.NewTLS returns an opaque
	// type — and an earlier revision of this test "covered" it with a bare
	// `var _ = tls.VersionTLS12`, which is an import-keeper, not an assertion.
	cfg, err := buildDialoutTLSConfig(&DialoutTLSConfig{Enabled: true}, nil)
	if err != nil {
		t.Fatalf("system-roots config rejected: %v", err)
	}
	if cfg.MinVersion != tls.VersionTLS12 {
		t.Errorf("MinVersion = %#x, want TLS 1.2 — a simulator that can be negotiated down is a worse stand-in than one that cannot", cfg.MinVersion)
	}
	if cfg.RootCAs != nil {
		t.Error("no CA configured but RootCAs is set; verification should fall back to the host store")
	}
}

// TestDialoutTLS_APathInCAPEMIsNotOpened is the regression that defines this
// change. A path must be treated as literal bytes that fail to parse, never as
// something to read.
//
// Without this, a later "helpful" refactor adding
// `if looksLikeAPath(cfg.CAPEM) { os.ReadFile(...) }` reintroduces the exact
// vulnerability and the rest of this file stays green.
func TestDialoutTLS_APathInCAPEMIsNotOpened(t *testing.T) {
	// A real, readable, certificate-bearing file on nearly every system. If
	// the value were opened rather than parsed, this would SUCCEED.
	for _, p := range []string{"/etc/ssl/cert.pem", "/etc/ssl/certs/ca-certificates.crt", "/etc/passwd"} {
		if _, err := buildDialoutTLSConfig(&DialoutTLSConfig{Enabled: true, CAPEM: p}, nil); err == nil {
			t.Errorf("ca_pem=%q was accepted; a path must be parsed as literal bytes, not opened", p)
		}
	}
}

// TestDialoutTLS_CAFileNeverReachesAFileRead: the no-file-read property must
// not rest solely on Validate. buildDialoutCreds is also reached from the CLI
// seed path, which builds a DialoutTLSConfig directly.
func TestDialoutTLS_CAFileNeverReachesAFileRead(t *testing.T) {
	cfg, err := buildDialoutTLSConfig(&DialoutTLSConfig{Enabled: true, CAFile: "/etc/ssl/cert.pem"}, nil)
	if err != nil {
		t.Fatalf("CAFile should be inert here, not an error: %v", err)
	}
	if cfg.RootCAs != nil {
		t.Error("CAFile populated the trust pool — it reached a file read")
	}
}

// TestDialoutTLS_PrivateKeyIsStrippedNotStored is the regression for the
// disclosure this review found.
//
// A trust bundle is stored on the device config and echoed by
// GET /api/v1/devices. x509.AppendCertsFromPEM returns true as soon as ONE
// certificate parses and ignores other block types, so a combined chain+key
// file — a common /etc/ssl layout — would validate and then serve the
// operator's PRIVATE KEY over an unauthenticated endpoint.
func TestDialoutTLS_PrivateKeyIsStrippedNotStored(t *testing.T) {
	_, leaf := newTestTLSCert(t)
	certPEM := string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: leaf.Raw}))
	keyPEM := "-----BEGIN PRIVATE KEY-----\nMC4CAQAwBQYDK2VwBCIEIHNOTAREALKEY\n-----END PRIVATE KEY-----\n"

	c := &DeviceGnmiDialoutConfig{
		Collector: "127.0.0.1:5555",
		TLS:       &DialoutTLSConfig{Enabled: true, CAPEM: keyPEM + certPEM},
	}
	c.ApplyDefaults()
	if err := c.Validate(); err != nil {
		t.Fatalf("a bundle with a key alongside a cert should be accepted after stripping: %v", err)
	}
	if strings.Contains(c.TLS.CAPEM, "PRIVATE KEY") {
		t.Error("PRIVATE KEY survived into the stored config; it would be served by GET /api/v1/devices")
	}
	if !strings.Contains(c.TLS.CAPEM, "CERTIFICATE") {
		t.Error("stripping removed the certificate too")
	}

	// A bundle that is ONLY a key has nothing usable and must be refused.
	only := &DeviceGnmiDialoutConfig{
		Collector: "127.0.0.1:5555",
		TLS:       &DialoutTLSConfig{Enabled: true, CAPEM: keyPEM},
	}
	only.ApplyDefaults()
	if err := only.Validate(); err == nil {
		t.Error("a key-only ca_pem was accepted; it contains no trust anchor")
	}
}

// TestDialoutTLS_BadCAPEMFailsAtValidateNotAtAttach: unvalidated, a whitespace
// bundle returns 201 Created and then disables dial-out per device at attach,
// logging once per device while the caller believes it worked.
func TestDialoutTLS_BadCAPEMFailsAtValidateNotAtAttach(t *testing.T) {
	for _, bad := range []string{"   ", "not a certificate", "-----BEGIN CERTIFICATE-----\nZ\n-----END CERTIFICATE-----\n"} {
		c := &DeviceGnmiDialoutConfig{
			Collector: "127.0.0.1:5555",
			TLS:       &DialoutTLSConfig{Enabled: true, CAPEM: bad},
		}
		c.ApplyDefaults()
		if err := c.Validate(); err == nil {
			t.Errorf("ca_pem %q passed Validate; it would 201 and then fail per-device at attach", bad)
		}
	}
}

// TestDialoutTLS_DisabledTLSRejectsOptions covers the predicate this change
// renamed. Had one disjunct been missed, a config could carry a CA that is
// silently discarded at dial time while the operator believes TLS is on.
func TestDialoutTLS_DisabledTLSRejectsOptions(t *testing.T) {
	for name, tlsCfg := range map[string]*DialoutTLSConfig{
		"ca_pem":               {Enabled: false, CAPEM: "x"},
		"ca_file":              {Enabled: false, CAFile: "/x"},
		"mtls":                 {Enabled: false, MTLS: true},
		"insecure_skip_verify": {Enabled: false, InsecureSkipVerify: true},
	} {
		c := &DeviceGnmiDialoutConfig{Collector: "127.0.0.1:5555", TLS: tlsCfg}
		c.ApplyDefaults()
		if err := c.Validate(); err == nil {
			t.Errorf("tls.enabled=false with %s set was accepted", name)
		}
	}
}

// TestDialoutTLS_CAFileIsRejectedWithGuidance: `ca_file` shipped, so removing
// it silently would change what an existing config does. It is refused with a
// message naming both replacements instead.
func TestDialoutTLS_CAFileIsRejectedWithGuidance(t *testing.T) {
	c := &DeviceGnmiDialoutConfig{
		Collector: "127.0.0.1:5555",
		TLS:       &DialoutTLSConfig{Enabled: true, CAFile: "/etc/ssl/ca.pem"},
	}
	c.ApplyDefaults()
	err := c.Validate()
	if err == nil {
		t.Fatal("tls.ca_file was accepted; a path here is settable over REST and must be refused")
	}
	for _, want := range []string{"ca_pem", "-gnmi-dialout-tls-ca"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("rejection does not mention %q, leaving the operator to guess: %v", want, err)
		}
	}
}

// TestDialoutTLS_CAPEMRoundTripsOverREST pins that the wire field is the inline
// one. The create handler sets DisallowUnknownFields, so a body carrying the
// old key 400s — but only if the field is genuinely gone from the JSON shape
// that callers are told to send.
func TestDialoutTLS_CAPEMRoundTripsOverREST(t *testing.T) {
	blob, err := json.Marshal(&DialoutTLSConfig{Enabled: true, CAPEM: "PEMDATA"})
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Contains(blob, []byte("ca_pem")) {
		t.Error("ca_pem missing from the serialised config")
	}
	if bytes.Contains(blob, []byte("ca_file")) {
		t.Error("ca_file is serialised; the deprecation shim must stay omitempty and unset")
	}
	// The check above is near-tautological on a struct that never sets CAFile.
	// The load-bearing assertion is that a config CARRYING it is refused.
	rejected := &DeviceGnmiDialoutConfig{
		Collector: "127.0.0.1:5555",
		TLS:       &DialoutTLSConfig{Enabled: true, CAFile: "/etc/ssl/ca.pem"},
	}
	rejected.ApplyDefaults()
	if err := rejected.Validate(); err == nil {
		t.Error("a config carrying ca_file was accepted")
	}

	var back DialoutTLSConfig
	if err := json.Unmarshal(blob, &back); err != nil {
		t.Fatal(err)
	}
	if back.CAPEM != "PEMDATA" {
		t.Errorf("ca_pem round-trip lost data: %q", back.CAPEM)
	}
}
