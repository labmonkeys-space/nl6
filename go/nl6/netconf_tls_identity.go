/*
 * Copyright 2026 Ronny Trommer <ronny@no42.org>
 * SPDX-License-Identifier: Apache-2.0
 */

package main

import (
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"strings"
)

// netconfTLSDefaultPort is the IANA port for NETCONF over TLS.
const netconfTLSDefaultPort = 6513

// NetconfTLSIdentity is the fleet-wide client identity table of the NETCONF
// TLS transport. It mirrors what Junos keeps under
// system services netconf tls: the client CA that must have signed the
// client certificate, a map from certificate fingerprint to NETCONF user,
// and an optional user for certificates missing from the map.
//
// Identities keys are in the Junos spelling, "04:" followed by the
// upper-case colon-separated SHA-256 of the certificate.
type NetconfTLSIdentity struct {
	CAPEM           string            `json:"ca_pem"`
	Identities      map[string]string `json:"identities"`
	DefaultUsername string            `json:"default_username"`

	// caPool is CAPEM parsed once by normalised, so a handshake does no PEM
	// parsing. A PUT replaces the whole table, so it never goes stale.
	caPool *x509.CertPool
}

// normaliseTLSFingerprint returns the Junos spelling of a SHA-256
// fingerprint. It accepts 64 bare hex digits, 32 colon-separated pairs, or
// the same pairs behind the "04:" algorithm prefix, in any case.
func normaliseTLSFingerprint(s string) (string, error) {
	h := s
	if strings.Contains(s, ":") {
		parts := strings.Split(s, ":")
		if len(parts) == 33 && parts[0] == "04" {
			parts = parts[1:]
		}
		if len(parts) != 32 {
			return "", fmt.Errorf("invalid TLS fingerprint %q: want 32 colon-separated bytes", s)
		}
		for _, p := range parts {
			if len(p) != 2 {
				return "", fmt.Errorf("invalid TLS fingerprint %q: want 32 colon-separated bytes", s)
			}
		}
		h = strings.Join(parts, "")
	}
	raw, err := hex.DecodeString(h)
	if err != nil || len(raw) != sha256.Size {
		return "", fmt.Errorf("invalid TLS fingerprint %q: want 32 hex bytes", s)
	}
	return fingerprintSpelling(raw), nil
}

func fingerprintSpelling(sum []byte) string {
	var b strings.Builder
	b.WriteString("04")
	for _, c := range sum {
		fmt.Fprintf(&b, ":%02X", c)
	}
	return b.String()
}

// certSHA256Fingerprint returns the certificate's fingerprint in the Junos
// spelling.
func certSHA256Fingerprint(c *x509.Certificate) string {
	sum := sha256.Sum256(c.Raw)
	return fingerprintSpelling(sum[:])
}

// Validate checks the table and does not change it. CAPEM must hold
// certificate blocks only, so a request body cannot park a private key in
// the stored table.
func (id *NetconfTLSIdentity) Validate() error {
	if strings.TrimSpace(id.CAPEM) != "" {
		n := 0
		rest := []byte(id.CAPEM)
		for {
			var blk *pem.Block
			blk, rest = pem.Decode(rest)
			if blk == nil {
				break
			}
			if blk.Type != "CERTIFICATE" {
				return fmt.Errorf("ca_pem: contains a %s block, only certificates are accepted", blk.Type)
			}
			if _, err := x509.ParseCertificate(blk.Bytes); err != nil {
				return fmt.Errorf("ca_pem: invalid certificate: %v", err)
			}
			n++
		}
		if n == 0 {
			return fmt.Errorf("ca_pem: no PEM certificates found")
		}
	}
	if id.DefaultUsername != "" {
		if err := validateNetconfUsername(id.DefaultUsername); err != nil {
			return fmt.Errorf("default_username: %w", err)
		}
	}
	seen := make(map[string]string, len(id.Identities))
	for fp, user := range id.Identities {
		norm, err := normaliseTLSFingerprint(fp)
		if err != nil {
			return err
		}
		if err := validateNetconfUsername(user); err != nil {
			return fmt.Errorf("identities: %s: %w", fp, err)
		}
		if prev, dup := seen[norm]; dup && prev != user {
			return fmt.Errorf("identities: %s is listed twice with different usernames", norm)
		}
		seen[norm] = user
	}
	return nil
}

// normalised returns a copy with every fingerprint in the Junos spelling and
// the CA reduced to its certificate blocks. Call it after Validate.
func (id *NetconfTLSIdentity) normalised() *NetconfTLSIdentity {
	out := &NetconfTLSIdentity{
		CAPEM:           string(certificateBlocksOnly([]byte(id.CAPEM))),
		Identities:      make(map[string]string, len(id.Identities)),
		DefaultUsername: id.DefaultUsername,
	}
	for fp, user := range id.Identities {
		norm, _ := normaliseTLSFingerprint(fp)
		out.Identities[norm] = user
	}
	out.caPool = out.parsePool()
	return out
}

// pool returns the client CA pool, nil when no CA is set. A table built by
// normalised returns the pool it parsed then.
func (id *NetconfTLSIdentity) pool() *x509.CertPool {
	if id.caPool != nil {
		return id.caPool
	}
	return id.parsePool()
}

func (id *NetconfTLSIdentity) parsePool() *x509.CertPool {
	certs := certificateBlocksOnly([]byte(id.CAPEM))
	if len(certs) == 0 {
		return nil
	}
	p := x509.NewCertPool()
	p.AppendCertsFromPEM(certs)
	return p
}

// userFor maps a verified client certificate to a NETCONF username: the
// table first, then the default.
func (id *NetconfTLSIdentity) userFor(c *x509.Certificate) (string, bool) {
	if u, ok := id.Identities[certSHA256Fingerprint(c)]; ok {
		return u, true
	}
	if id.DefaultUsername != "" {
		return id.DefaultUsername, true
	}
	return "", false
}

// validateNetconfUsername refuses a name that is blank or holds a character
// outside [A-Za-z0-9._-], so it can never break the XML comment of the hello.
func validateNetconfUsername(u string) error {
	if strings.TrimSpace(u) == "" {
		return fmt.Errorf("empty username")
	}
	if strings.Contains(u, "--") {
		return fmt.Errorf("username %q: '--' is not allowed", u)
	}
	for _, c := range u {
		switch {
		case c >= 'a' && c <= 'z', c >= 'A' && c <= 'Z', c >= '0' && c <= '9', c == '.', c == '_', c == '-':
		default:
			return fmt.Errorf("username %q: only letters, digits, '.', '_' and '-' are allowed", u)
		}
	}
	return nil
}
