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
// bindings and diffs. A case skips when its YANG cache is absent so CI
// without network still passes; `make gen-gnmi-catalog` populates it.
func TestGnmiCatalogNotDrifted(t *testing.T) {
	cache := os.Getenv("YANG_CACHE")
	if cache == "" {
		home, _ := os.UserHomeDir()
		cache = filepath.Join(home, ".cache", "nl6-yang")
	}
	for _, c := range gnmiCatalogDriftCases {
		t.Run(c.slug, func(t *testing.T) {
			rel := filepath.Join(cache, filepath.FromSlash(c.cacheRel))
			if _, err := os.Stat(rel); err != nil {
				t.Skipf("YANG cache %s missing; run make gen-gnmi-catalog", rel)
			}
			bindings := filepath.Join("resources", c.slug, "gnmi-bindings.json")
			if _, err := os.Stat(bindings); err != nil {
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
			got, _ := os.ReadFile(out)
			want, _ := os.ReadFile(filepath.Join("resources", c.slug, "gnmi.json"))
			if !bytes.Equal(got, want) {
				t.Fatalf("resources/%s/gnmi.json differs from generator output; run make gen-gnmi-catalog and commit", c.slug)
			}
		})
	}
}
