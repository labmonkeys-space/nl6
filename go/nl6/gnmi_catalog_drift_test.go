/*
 * Copyright 2026 Ronny Trommer <ronny@no42.org>
 * SPDX-License-Identifier: Apache-2.0
 */

package main

import (
	"bytes"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// gnmiCatalogDriftCases are the generated catalogues: each regenerates from
// its pinned YANG checkout under the cache directory and its bindings.
// "{cache}" in args is that checkout.
var gnmiCatalogDriftCases = []struct {
	slug     string
	cacheRel string
	args     []string
}{
	{"juniper_mx10004", "juniper/24.2/24.2R1.17", []string{
		"-yang", "{cache}/openconfig/models,{cache}/ietf",
		"-path", "{cache}/native/jti/models",
	}},
	{"cisco_asr9902", "yangmodels/vendor/cisco/xr/2422", []string{
		"-yang", "{cache}",
		"-modules", "../cmd/xr-chassis/yang-modules.txt",
	}},
}

// TestGnmiCatalogNotDrifted regenerates every committed catalogue from its
// bindings and diffs. A case skips when its YANG cache is absent, so a local
// run without network still passes. `make test-gnmi-drift` populates the cache
// and sets NL6_REQUIRE_YANG_CACHE, under which an absent cache FAILS: a skip in
// CI asserts nothing, and this guard skipped on every runner until CI ran it.
func TestGnmiCatalogNotDrifted(t *testing.T) {
	require := os.Getenv("NL6_REQUIRE_YANG_CACHE") != ""
	cache := os.Getenv("YANG_CACHE")
	if cache == "" {
		home, _ := os.UserHomeDir()
		cache = filepath.Join(home, ".cache", "nl6-yang")
	}
	for _, c := range gnmiCatalogDriftCases {
		t.Run(c.slug, func(t *testing.T) {
			rel := filepath.Join(cache, filepath.FromSlash(c.cacheRel))
			if _, err := os.Stat(rel); err != nil {
				if require {
					t.Fatalf("YANG cache %s missing and NL6_REQUIRE_YANG_CACHE is set; run make yang-cache", rel)
				}
				t.Skipf("YANG cache %s missing; run make test-gnmi-drift", rel)
			}
			bindings := filepath.Join("resources", c.slug, "gnmi-bindings.json")
			if _, err := os.Stat(bindings); err != nil {
				if require {
					t.Fatalf("%s has no bindings and NL6_REQUIRE_YANG_CACHE is set", c.slug)
				}
				t.Skipf("%s has no bindings yet", c.slug)
			}
			out := filepath.Join(t.TempDir(), "gnmi.json")
			args := []string{"run", "../cmd/gnmi-catalog"}
			for _, a := range c.args {
				args = append(args, strings.ReplaceAll(a, "{cache}", rel))
			}
			args = append(args, "-bindings", bindings, "-out", out)
			if b, err := exec.Command("go", args...).CombinedOutput(); err != nil {
				t.Fatalf("generator: %v\n%s", err, b)
			}
			got, err := os.ReadFile(out)
			if err != nil {
				t.Fatalf("generator output: %v", err)
			}
			want, err := os.ReadFile(filepath.Join("resources", c.slug, "gnmi.json"))
			if err != nil {
				t.Fatalf("committed catalogue: %v", err)
			}
			if !bytes.Equal(got, want) {
				t.Fatalf("resources/%s/gnmi.json differs from generator output; run make gen-gnmi-catalog and commit", c.slug)
			}
		})
	}
}
