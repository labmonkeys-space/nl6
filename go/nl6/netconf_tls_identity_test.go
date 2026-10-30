/*
 * Copyright 2026 Ronny Trommer <ronny@no42.org>
 * SPDX-License-Identifier: Apache-2.0
 */

package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"os"
	"strings"
	"testing"
	"time"
)

const probeClientFingerprint = "04:F0:14:CF:62:29:FD:74:5E:67:84:D5:D3:6C:23:DD:6B:2F:CA:D5:D4:DE:A3:BF:F9:A3:5E:0C:DA:21:CE:E8:66"

func TestNormaliseTLSFingerprint(t *testing.T) {
	bare := strings.ReplaceAll(probeClientFingerprint[3:], ":", "")
	for _, in := range []string{
		probeClientFingerprint,
		strings.ToLower(probeClientFingerprint),
		probeClientFingerprint[3:],
		bare,
		strings.ToLower(bare),
	} {
		got, err := normaliseTLSFingerprint(in)
		if err != nil || got != probeClientFingerprint {
			t.Errorf("normaliseTLSFingerprint(%q) = %q, %v", in, got, err)
		}
	}
	short := strings.Join(strings.Split(probeClientFingerprint, ":")[:31], ":")
	for _, in := range []string{short, probeClientFingerprint[:len(probeClientFingerprint)-2] + "ZZ", ""} {
		if _, err := normaliseTLSFingerprint(in); err == nil {
			t.Errorf("normaliseTLSFingerprint(%q) accepted bad input", in)
		}
	}
}

func TestCertSHA256FingerprintMatchesOpenSSL(t *testing.T) {
	b, err := os.ReadFile("testdata/netconf/junos/client.crt")
	if err != nil {
		t.Fatal(err)
	}
	blk, _ := pem.Decode(b)
	c, err := x509.ParseCertificate(blk.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	if got := certSHA256Fingerprint(c); got != probeClientFingerprint {
		t.Errorf("fingerprint = %s, want %s", got, probeClientFingerprint)
	}
}

// newTestCAPEM returns a self-signed CA certificate PEM and its parsed form.
func newTestCAPEM(t *testing.T) (string, *x509.Certificate) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tpl := &x509.Certificate{
		SerialNumber:          big.NewInt(7),
		Subject:               pkix.Name{CommonName: "test-ca"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign,
	}
	der, err := x509.CreateCertificate(rand.Reader, tpl, tpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	c, _ := x509.ParseCertificate(der)
	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})), c
}

func TestNetconfTLSIdentityValidate(t *testing.T) {
	caPEM, _ := newTestCAPEM(t)
	keyOnly := string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: []byte("secret")}))
	if err := (&NetconfTLSIdentity{CAPEM: keyOnly}).Validate(); err == nil {
		t.Error("a PEM with only a private key block was accepted")
	}
	if err := (&NetconfTLSIdentity{CAPEM: caPEM, Identities: map[string]string{probeClientFingerprint: ""}}).Validate(); err == nil {
		t.Error("an empty username was accepted")
	}
	if err := (&NetconfTLSIdentity{Identities: map[string]string{"nonsense": "u"}}).Validate(); err == nil {
		t.Error("a bad fingerprint was accepted")
	}
	for _, bad := range []string{" ", "a--b", "a-->b", "a b", "a<b", "a\"b"} {
		if err := (&NetconfTLSIdentity{Identities: map[string]string{probeClientFingerprint: bad}}).Validate(); err == nil {
			t.Errorf("table username %q was accepted", bad)
		}
		if err := (&NetconfTLSIdentity{DefaultUsername: bad}).Validate(); err == nil && bad != "" {
			t.Errorf("default username %q was accepted", bad)
		}
	}
	if err := (&NetconfTLSIdentity{CAPEM: caPEM, Identities: map[string]string{probeClientFingerprint: "alice"}, DefaultUsername: "bob"}).Validate(); err != nil {
		t.Errorf("valid table refused: %v", err)
	}
	if err := (&NetconfTLSIdentity{}).Validate(); err != nil {
		t.Errorf("empty table refused: %v", err)
	}
}

func TestNetconfTLSIdentityUserFor(t *testing.T) {
	b, err := os.ReadFile("testdata/netconf/junos/client.crt")
	if err != nil {
		t.Fatal(err)
	}
	blk, _ := pem.Decode(b)
	c, _ := x509.ParseCertificate(blk.Bytes)

	hit := &NetconfTLSIdentity{Identities: map[string]string{probeClientFingerprint: "alice"}, DefaultUsername: "bob"}
	if u, ok := hit.userFor(c); !ok || u != "alice" {
		t.Errorf("table hit = %q, %v", u, ok)
	}
	def := &NetconfTLSIdentity{Identities: map[string]string{"04:" + strings.Repeat("00:", 31) + "00": "x"}, DefaultUsername: "bob"}
	if u, ok := def.userFor(c); !ok || u != "bob" {
		t.Errorf("default = %q, %v", u, ok)
	}
	if u, ok := (&NetconfTLSIdentity{}).userFor(c); ok {
		t.Errorf("neither gave %q", u)
	}
}

func TestNetconfTLSFlagsRequireEnable(t *testing.T) {
	if _, err := buildNetconfTLSIdentity(false, "", []string{probeClientFingerprint + "=alice"}, ""); err == nil {
		t.Error("identity flag without -netconf-enable accepted")
	}
	if _, err := buildNetconfTLSIdentity(false, "", nil, "bob"); err == nil {
		t.Error("default username without -netconf-enable accepted")
	}
	if _, err := buildNetconfTLSIdentity(false, "/some/ca.pem", nil, ""); err == nil {
		t.Error("client CA without -netconf-enable accepted")
	}
	if id, err := buildNetconfTLSIdentity(false, "", nil, ""); err != nil || id != nil {
		t.Errorf("no flags: %v, %v", id, err)
	}
	for _, bad := range []string{"noequals", "=alice", probeClientFingerprint + "=", "zz=alice"} {
		if _, err := buildNetconfTLSIdentity(true, "", []string{bad}, ""); err == nil {
			t.Errorf("malformed %q accepted", bad)
		}
	}
	id, err := buildNetconfTLSIdentity(true, "", []string{strings.ToLower(probeClientFingerprint[3:]) + "=alice"}, "bob")
	if err != nil || id.Identities[probeClientFingerprint] != "alice" || id.DefaultUsername != "bob" {
		t.Errorf("good flags: %+v, %v", id, err)
	}
}
