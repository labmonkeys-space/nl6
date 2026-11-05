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
		"ietf-yang-push-revision":       "2024-12-17",
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
			Augmented []string `xml:"augmented-by"`
		} `xml:"module"`
		ImportOnly []struct {
			Name      string   `xml:"name"`
			Revision  string   `xml:"revision"`
			Namespace string   `xml:"namespace"`
			Augmented []string `xml:"augmented-by"`
		} `xml:"import-only-module"`
	} `xml:"module-set"`
}

type testModulesState struct {
	SetID   string `xml:"module-set-id"`
	Modules []struct {
		Name      string `xml:"name"`
		Revision  string `xml:"revision"`
		Namespace string `xml:"namespace"`
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
	for _, aug := range []string{"ietf-yang-push", "ietf-yang-push-revision", "ietf-distributed-notif", "ietf-udp-notif-transport", "ietf-subscribed-notif-receivers"} {
		if !slices.Contains(augmented["ietf-subscribed-notifications"], aug) {
			t.Errorf("ietf-subscribed-notifications not augmented-by %s in XML", aug)
		}
	}
	for mod, augs := range vrpAugmentedBy {
		if _, ok := vrpYangModule(mod, ""); !ok {
			t.Errorf("vrpAugmentedBy key %s not served", mod)
		}
		for _, a := range augs {
			if _, ok := vrpYangModule(a, ""); !ok {
				t.Errorf("vrpAugmentedBy[%s] lists %s which is not served", mod, a)
			}
		}
		if !slices.Equal(augmented[mod], augs) {
			t.Errorf("XML augmented-by for %s = %v, want %v", mod, augmented[mod], augs)
		}
	}
}
