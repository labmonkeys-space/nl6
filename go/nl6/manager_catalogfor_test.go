/*
 * © 2025 Labmonkeys Space
 *
 * Layer 8 Ecosystem is licensed under the Apache License, Version 2.0.
 */

package main

import (
	"testing"
)

// TestManager_CatalogFor_PerTypeMatch confirms that a device IP mapped to
// a known type slug resolves to the per-type catalog.
func TestManager_CatalogFor_PerTypeMatch(t *testing.T) {
	sm := &SimulatorManager{
		deviceTypesByIP: map[string]string{"10.42.0.1": "cisco_ios"},
	}
	universal := mustLoadEmbeddedCatalog(t)
	ciscoOverlay := mustParseTrapCatalog(t, `{"traps":[{"name":"ciscoOnly","snmpTrapOID":"1.3.6.1.4.1.9.1","varbinds":[]}]}`)
	ciscoMerged := universal.MergeOverlay(ciscoOverlay)
	sm.trapCatalogsByType = map[string]*Catalog{
		universalCatalogKey: universal,
		"cisco_ios":        ciscoMerged,
	}

	cat := sm.CatalogFor("10.42.0.1")
	if cat == nil {
		t.Fatal("CatalogFor returned nil for known IP")
	}
	if _, ok := cat.ByName["ciscoOnly"]; !ok {
		t.Error("resolved catalog should contain cisco-only entry; got universal only")
	}
}

// TestManager_CatalogFor_FallbackForUnknownType confirms IPs whose type
// has no per-type catalog fall through to _universal.
func TestManager_CatalogFor_FallbackForUnknownType(t *testing.T) {
	sm := &SimulatorManager{
		deviceTypesByIP: map[string]string{"10.42.0.2": "netapp_ontap"},
	}
	universal := mustLoadEmbeddedCatalog(t)
	ciscoOverlay := mustParseTrapCatalog(t, `{"traps":[{"name":"ciscoOnly","snmpTrapOID":"1.3.6.1.4.1.9.1","varbinds":[]}]}`)
	ciscoMerged := universal.MergeOverlay(ciscoOverlay)
	sm.trapCatalogsByType = map[string]*Catalog{
		universalCatalogKey: universal,
		"cisco_ios":        ciscoMerged,
	}

	cat := sm.CatalogFor("10.42.0.2")
	if cat == nil {
		t.Fatal("CatalogFor returned nil for known IP with no per-type catalog")
	}
	if _, ok := cat.ByName["ciscoOnly"]; ok {
		t.Error("netapp device should not get cisco-only entry")
	}
	if _, ok := cat.ByName["linkDown"]; !ok {
		t.Error("fallback catalog should contain universal linkDown")
	}
}

// TestManager_CatalogFor_UnknownIPFallsThrough confirms IPs not present in
// deviceTypesByIP resolve to the fallback — this happens at scheduler
// startup before AddDevice has populated the map for newly-registered
// devices. Must not panic or return nil.
func TestManager_CatalogFor_UnknownIPFallsThrough(t *testing.T) {
	sm := &SimulatorManager{
		deviceTypesByIP: map[string]string{},
	}
	universal := mustLoadEmbeddedCatalog(t)
	sm.trapCatalogsByType = map[string]*Catalog{
		universalCatalogKey: universal,
	}
	cat := sm.CatalogFor("10.99.99.99")
	if cat == nil {
		t.Fatal("CatalogFor returned nil for unknown IP; expected _universal")
	}
	if len(cat.Entries) == 0 {
		t.Error("fallback catalog should be non-empty")
	}
}

// TestManager_CatalogFor_OverrideFlagDisablesPerType pins the behaviour
// that `-trap-catalog path` means: catalogsByType contains only
// `_universal`, so every device resolves to the single override file
// regardless of device type.
func TestManager_CatalogFor_OverrideFlagDisablesPerType(t *testing.T) {
	override := mustParseTrapCatalog(t, `{"traps":[{"name":"overrideOnly","snmpTrapOID":"1.2.3","varbinds":[]}]}`)
	sm := &SimulatorManager{
		deviceTypesByIP: map[string]string{"10.42.0.1": "cisco_ios"},
		// Override path: only _universal is populated, no per-type keys.
		trapCatalogsByType: map[string]*Catalog{
			universalCatalogKey: override,
		},
	}
	cat := sm.CatalogFor("10.42.0.1")
	if cat == nil {
		t.Fatal("CatalogFor returned nil under override")
	}
	if _, ok := cat.ByName["overrideOnly"]; !ok {
		t.Error("cisco_ios device should resolve to the override catalog, not a per-type overlay")
	}
	if len(cat.Entries) != 1 {
		t.Errorf("override catalog entries: got %d, want 1", len(cat.Entries))
	}
}

// TestManager_SyslogCatalogFor_PerTypeMatch is the symmetric syslog test.
func TestManager_SyslogCatalogFor_PerTypeMatch(t *testing.T) {
	sm := &SimulatorManager{
		deviceTypesByIP: map[string]string{"10.42.0.1": "juniper_mx240"},
	}
	universal := mustLoadEmbeddedSyslogCatalog(t)
	jnxOverlay := mustParseSyslogCatalog(t, `{"entries":[{"name":"jnx-only","facility":"local7","severity":"warning","appName":"JNX","template":"x"}]}`)
	jnxMerged := universal.MergeOverlay(jnxOverlay)
	sm.syslogCatalogsByType = map[string]*SyslogCatalog{
		universalCatalogKey: universal,
		"juniper_mx240":    jnxMerged,
	}

	cat := sm.SyslogCatalogFor("10.42.0.1")
	if cat == nil {
		t.Fatal("SyslogCatalogFor returned nil for known IP")
	}
	if _, ok := cat.ByName["jnx-only"]; !ok {
		t.Error("resolved catalog should contain juniper-only entry")
	}
}
