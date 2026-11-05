/*
 * Copyright 2026 Ronny Trommer <ronny@no42.org>
 * SPDX-License-Identifier: Apache-2.0
 */

package main

import (
	"encoding/xml"
	"regexp"
	"slices"
	"strconv"
	"testing"
)

var (
	yangTestStringRe  = regexp.MustCompile(`(?s)"(?:[^"\\]|\\.)*"`)
	yangTestCommentRe = regexp.MustCompile(`(?s)/\*.*?\*/`)
	yangTestImportRe  = regexp.MustCompile(`(?m)^\s*import\s+(\S+)`)
)

func TestVrpYangModuleClosure(t *testing.T) {
	served := map[string]bool{}
	for _, m := range vrpYangModules() {
		served[m.Name] = true
	}
	if len(served) == 0 {
		t.Fatal("no modules served")
	}
	for _, m := range vrpYangModules() {
		src := yangTestCommentRe.ReplaceAllString(string(m.Source), "")
		src = yangTestStringRe.ReplaceAllString(src, `""`)
		for _, im := range yangTestImportRe.FindAllStringSubmatch(src, -1) {
			if !served[im[1]] {
				t.Errorf("%s imports %s which is not served", m.Name, im[1])
			}
		}
	}
}

func TestVrpYangModuleRevisions(t *testing.T) {
	want := map[string]string{
		"ietf-interfaces":               "2018-02-20",
		"ietf-yang-push":                "2019-09-09",
		"ietf-subscribed-notifications": "2019-09-09",
		"ietf-udp-notif-transport":      "2025-04-27",
		"ietf-yp-notification":          "2025-02-24",
		"ietf-yp-observation":           "2025-02-24",
		"ietf-yang-library-augmentedby": "2025-05-28",
		"ietf-distributed-notif":        "2025-04-12",
		"ietf-yang-patch":               "2017-02-22",
		"ietf-yang-push-revision":       "2025-08-29",
		"ietf-netconf-monitoring":       "2010-10-04",
	}
	for name, rev := range want {
		m, ok := vrpYangModule(name, "")
		if !ok {
			t.Errorf("%s not served", name)
			continue
		}
		if m.Revision != rev {
			t.Errorf("%s revision = %s, want %s", name, m.Revision, rev)
		}
		if m.Namespace == "" || len(m.Source) == 0 {
			t.Errorf("%s has empty namespace or source", name)
		}
		if _, ok := vrpYangModule(name, rev); !ok {
			t.Errorf("%s@%s not found by explicit revision", name, rev)
		}
		if _, ok := vrpYangModule(name, "1999-01-01"); ok {
			t.Errorf("%s found at bogus revision", name)
		}
	}
	mods := vrpYangModules()
	if !slices.IsSortedFunc(mods, func(a, b yangModule) int {
		switch {
		case a.Name < b.Name:
			return -1
		case a.Name > b.Name:
			return 1
		}
		return 0
	}) {
		t.Error("modules not sorted by name")
	}
}

func TestVrpContentIDStable(t *testing.T) {
	a, b := vrpContentID(), vrpContentID()
	if a != b {
		t.Fatalf("content-id not stable: %s vs %s", a, b)
	}
	if _, err := strconv.ParseUint(a, 10, 32); err != nil {
		t.Fatalf("content-id %q is not a decimal uint32: %v", a, err)
	}
	mods := vrpYangModules()
	if got := yangContentID(mods); got != a {
		t.Errorf("yangContentID(served) = %s, want %s", got, a)
	}
	if yangContentID(mods[1:]) == a {
		t.Error("content-id did not change when a module was removed")
	}
	changed := slices.Clone(mods)
	changed[0].Revision = "1999-01-01"
	if yangContentID(changed) == a {
		t.Error("content-id did not change when a revision changed")
	}
}

type testYangLib struct {
	ContentID string `xml:"content-id"`
	ModuleSet []struct {
		Name    string `xml:"name"`
		Modules []struct {
			Name      string   `xml:"name"`
			Revision  string   `xml:"revision"`
			Namespace string   `xml:"namespace"`
			Features  []string `xml:"feature"`
			Augmented []string `xml:"augmented-by"`
		} `xml:"module"`
		ImportOnly []struct {
			Name      string   `xml:"name"`
			Revision  string   `xml:"revision"`
			Namespace string   `xml:"namespace"`
			Features  []string `xml:"feature"`
			Augmented []string `xml:"augmented-by"`
		} `xml:"import-only-module"`
	} `xml:"module-set"`
}

type testModulesState struct {
	SetID   string `xml:"module-set-id"`
	Modules []struct {
		Name      string   `xml:"name"`
		Revision  string   `xml:"revision"`
		Namespace string   `xml:"namespace"`
		Features  []string `xml:"feature"`
	} `xml:"module"`
}

func TestVrpYangLibraryXML(t *testing.T) {
	var doc struct {
		Lib   testYangLib      `xml:"yang-library"`
		State testModulesState `xml:"modules-state"`
	}
	raw := vrpYangLibraryXML()
	if err := xml.Unmarshal([]byte("<data>"+string(raw)+"</data>"), &doc); err != nil {
		t.Fatalf("library XML does not parse: %v\n%s", err, raw)
	}
	if doc.Lib.ContentID != vrpContentID() {
		t.Errorf("content-id = %q, want %q", doc.Lib.ContentID, vrpContentID())
	}
	if doc.State.SetID != vrpContentID() {
		t.Errorf("module-set-id = %q, want %q", doc.State.SetID, vrpContentID())
	}
	type nsrev struct{ ns, rev string }
	inLib := map[string]nsrev{}
	augmented := map[string][]string{}
	for _, ms := range doc.Lib.ModuleSet {
		for _, m := range ms.Modules {
			inLib[m.Name] = nsrev{m.Namespace, m.Revision}
			augmented[m.Name] = m.Augmented
		}
		for _, m := range ms.ImportOnly {
			inLib[m.Name] = nsrev{m.Namespace, m.Revision}
			augmented[m.Name] = m.Augmented
		}
	}
	inState := map[string]nsrev{}
	for _, m := range doc.State.Modules {
		inState[m.Name] = nsrev{m.Namespace, m.Revision}
	}
	for _, m := range vrpYangModules() {
		want := nsrev{m.Namespace, m.Revision}
		if inLib[m.Name] != want {
			t.Errorf("yang-library %s = %v, want %v", m.Name, inLib[m.Name], want)
		}
		if inState[m.Name] != want {
			t.Errorf("modules-state %s = %v, want %v", m.Name, inState[m.Name], want)
		}
	}
	// Pairs copied from the NE capture (get-ietf-yang-library.xml).
	neAugmentedBy := map[string][]string{
		"ietf-interfaces":                 {"ietf-network-instance", "ietf-ip"},
		"ietf-ip":                         {"ietf-network-instance"},
		"ietf-notification-capabilities":  {"ietf-yp-observation", "ietf-yp-notification"},
		"ietf-subscribed-notif-receivers": {"ietf-udp-notif-transport"},
		"ietf-yang-library":               {"ietf-yang-library-augmentedby"},
		"ietf-yang-push":                  {"ietf-yp-observation", "ietf-distributed-notif"},
	}
	for mod, want := range neAugmentedBy {
		if !slices.Equal(augmented[mod], want) {
			t.Errorf("XML augmented-by for %s = %v, want NE %v", mod, augmented[mod], want)
		}
	}
	// The NE lists these four for ietf-subscribed-notifications. nl6 adds
	// ietf-yang-push-revision and ietf-udp-notif-transport.
	for _, aug := range []string{"ietf-yp-notification", "ietf-yang-push", "ietf-subscribed-notif-receivers", "ietf-distributed-notif"} {
		if !slices.Contains(augmented["ietf-subscribed-notifications"], aug) {
			t.Errorf("ietf-subscribed-notifications not augmented-by %s", aug)
		}
	}
	// ietf-system-capabilities: the NE lists ietf-notification-capabilities.
	// The other three are nl6 additions taken from the YANG augment targets.
	if got := augmented["ietf-system-capabilities"]; !slices.Contains(got, "ietf-notification-capabilities") || len(got) != 4 {
		t.Errorf("ietf-system-capabilities augmented-by = %v", got)
	}
}

// TestVrpYangFeatures pins the feature list of every module with features. The
// NE capture is the source, plus the two nl6 additions named in the comment.
func TestVrpYangFeatures(t *testing.T) {
	want := map[string][]string{
		"ietf-interfaces": {"pre-provisioning", "if-mib"},
		"ietf-subscribed-notifications": {"encode-xml", "replay", "xpath", "subtree", "configured", "dscp",
			"interface-designation", "supports-vrf",
			"encode-json"}, // nl6 addition
		"ietf-yang-push":          {"on-change"},
		"ietf-yang-push-revision": {"yang-push-revision-supported"}, // nl6 addition
	}
	var doc struct {
		Lib   testYangLib      `xml:"yang-library"`
		State testModulesState `xml:"modules-state"`
	}
	if err := xml.Unmarshal([]byte("<data>"+string(vrpYangLibraryXML())+"</data>"), &doc); err != nil {
		t.Fatal(err)
	}
	lib := map[string][]string{}
	for _, ms := range doc.Lib.ModuleSet {
		for _, m := range ms.Modules {
			lib[m.Name] = m.Features
		}
		for _, m := range ms.ImportOnly {
			if len(m.Features) > 0 {
				t.Errorf("import-only %s has features", m.Name)
			}
		}
	}
	state := map[string][]string{}
	for _, m := range doc.State.Modules {
		state[m.Name] = m.Features
	}
	for _, m := range vrpYangModules() {
		w := want[m.Name]
		if !slices.Equal(lib[m.Name], w) && !(len(lib[m.Name]) == 0 && len(w) == 0) {
			t.Errorf("yang-library %s features = %v, want %v", m.Name, lib[m.Name], w)
		}
		if !slices.Equal(state[m.Name], w) && !(len(state[m.Name]) == 0 && len(w) == 0) {
			t.Errorf("modules-state %s features = %v, want %v", m.Name, state[m.Name], w)
		}
	}
}

func TestVrpContentIDCoversFeatures(t *testing.T) {
	base := vrpContentID()
	saved := vrpYangFeatures["ietf-yang-push"]
	vrpYangFeatures["ietf-yang-push"] = nil
	defer func() { vrpYangFeatures["ietf-yang-push"] = saved }()
	if vrpContentID() == base {
		t.Error("content-id did not change when a feature was removed")
	}
}
