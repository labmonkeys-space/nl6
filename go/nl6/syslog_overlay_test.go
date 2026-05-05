/*
 * © 2025 Labmonkeys Space
 *
 * Layer 8 Ecosystem is licensed under the Apache License, Version 2.0.
 */

package main

import (
	"os"
	"path/filepath"
	"testing"
)

// TestLoadSyslogCatalog_ExtendsTrueMergesEntries is the syslog equivalent
// of TestLoadCatalog_ExtendsTrueMergesEntries. Covers merge arithmetic on
// the syslog side so both catalog implementations stay in lockstep.
func TestLoadSyslogCatalog_ExtendsTrueMergesEntries(t *testing.T) {
	universal := mustLoadEmbeddedSyslogCatalog(t)
	overlayJSON := `{"entries":[{"name":"vendor-unique","facility":"local7","severity":"notice","appName":"VND","template":"test"}]}`
	overlay := mustParseSyslogCatalog(t, overlayJSON)
	if !overlay.Extends {
		t.Fatal("overlay.Extends: got false, want true (JSON omitted the field)")
	}
	merged := universal.MergeOverlay(overlay)
	if got := len(merged.Entries); got != len(universal.Entries)+1 {
		t.Errorf("merged entries: got %d, want %d (universal + 1)", got, len(universal.Entries)+1)
	}
	if _, ok := merged.ByName["vendor-unique"]; !ok {
		t.Error("merged catalog missing vendor-unique overlay entry")
	}
	if _, ok := merged.ByName["interface-down"]; !ok {
		t.Error("merged catalog missing universal interface-down entry")
	}
}

// TestLoadSyslogCatalog_ExtendsFalseReplaces pins the escape-hatch
// semantic — when a per-type file sets extends=false, no universal
// content carries through for that type.
func TestLoadSyslogCatalog_ExtendsFalseReplaces(t *testing.T) {
	overlayJSON := `{"extends":false,"entries":[{"name":"onlyOne","facility":"local7","severity":"notice","appName":"VND","template":"x"}]}`
	overlay := mustParseSyslogCatalog(t, overlayJSON)
	if overlay.Extends {
		t.Fatal("overlay.Extends: got true, want false")
	}
	if len(overlay.Entries) != 1 {
		t.Errorf("overlay entries: got %d, want 1", len(overlay.Entries))
	}
}

// TestScanPerTypeSyslogCatalogs_SkipsUnderscoreDirs mirrors the trap-side
// guard against loading resources/_common/ as a per-type overlay.
func TestScanPerTypeSyslogCatalogs_SkipsUnderscoreDirs(t *testing.T) {
	universal := mustLoadEmbeddedSyslogCatalog(t)
	tmp := t.TempDir()
	commonDir := filepath.Join(tmp, "_common")
	if err := os.MkdirAll(commonDir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(commonDir, "syslog.json"), []byte("BROKEN"), 0o644); err != nil {
		t.Fatal(err)
	}
	result, err := ScanPerTypeSyslogCatalogs(universal, tmp)
	if err != nil {
		t.Errorf("_common should be skipped, got error: %v", err)
	}
	if _, ok := result["_common"]; ok {
		t.Error("result map should not contain _common key")
	}
}

func mustParseSyslogCatalog(t *testing.T, body string) *SyslogCatalog {
	t.Helper()
	tmp := t.TempDir()
	path := filepath.Join(tmp, "s.json")
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	cat, err := LoadSyslogCatalogFromFile(path)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	return cat
}

func mustLoadEmbeddedSyslogCatalog(t *testing.T) *SyslogCatalog {
	t.Helper()
	cat, err := LoadEmbeddedSyslogCatalog()
	if err != nil {
		t.Fatalf("LoadEmbeddedSyslogCatalog: %v", err)
	}
	return cat
}
