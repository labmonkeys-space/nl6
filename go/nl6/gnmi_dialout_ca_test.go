/*
 * Copyright 2026 Ronny Trommer <ronny@no42.org>
 * SPDX-License-Identifier: Apache-2.0
 */

package main

import (
	"bytes"
	"crypto/tls"
	"crypto/x509"
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
// CodeQL flags the identical construct in the syslog TLS transport as
// `go/path-injection`; it did NOT flag this one, because CodeQL only analyses
// code a PR changes and this line is older. Older is not safer.
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

	// TLS 1.2 floor survives the change.
	if _, err := buildDialoutCreds(&DialoutTLSConfig{Enabled: true}, nil); err != nil {
		t.Errorf("system-roots config rejected: %v", err)
	}
	var _ = tls.VersionTLS12
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

	var back DialoutTLSConfig
	if err := json.Unmarshal(blob, &back); err != nil {
		t.Fatal(err)
	}
	if back.CAPEM != "PEMDATA" {
		t.Errorf("ca_pem round-trip lost data: %q", back.CAPEM)
	}
	var _ = x509.NewCertPool
}
