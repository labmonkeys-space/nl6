/*
 * Copyright 2026 Ronny Trommer <ronny@no42.org>
 * SPDX-License-Identifier: Apache-2.0
 */

package main

import (
	"bytes"
	"embed"
	"fmt"
	"hash/fnv"
	"path"
	"regexp"
	"slices"
	"sort"
	"strconv"
	"strings"
	"sync"
)

// The served YANG set for simulated huawei_ne8000 devices. Only IETF modules
// are embedded, never huawei-* ones. Files are named <name>@<revision>.yang.
// Revisions follow the IETF 123 hackathon NE capture; the files come from that
// capture, the IETF archive, or (ietf-yang-push-revision@2025-08-29) the copy
// NetGauze bundles. That revision keys module-version by "name", as the IETF 125
// NE capture sends it; 2024-12-17 used "module-name".
//
//go:embed resources/huawei_ne8000/yang/*.yang
var vrpYangFS embed.FS

type yangModule struct {
	Name, Revision, Namespace string
	Source                    []byte
}

// vrpYangImplemented names the modules the device implements. The rest of the
// served set is import-only.
var vrpYangImplemented = map[string]bool{
	"ietf-interfaces":                 true,
	"ietf-ip":                         true,
	"ietf-network-instance":           true,
	"ietf-yang-push":                  true,
	"ietf-subscribed-notifications":   true,
	"ietf-udp-notif-transport":        true,
	"ietf-yp-notification":            true,
	"ietf-yp-observation":             true,
	"ietf-yang-library-augmentedby":   true,
	"ietf-distributed-notif":          true,
	"ietf-subscribed-notif-receivers": true,
	"ietf-yang-push-revision":         true,
	"ietf-yang-library":               true,
	"ietf-system-capabilities":        true,
	"ietf-notification-capabilities":  true,
	"ietf-datastores":                 true,
	"ietf-netconf-monitoring":         true,
}

// vrpYangFeatures lists the features each implemented module advertises.
// Copied from the NE capture (get-ietf-yang-library.xml), in capture order.
// nl6 adds two the NE does not list, because the payloads it sends sit behind
// them: encode-json (the "encode-json" encoding identity) and
// yang-push-revision-supported (module-version and yang-library-content-id in
// subscription-started). ietf-yang-push-revision is not in the NE capture at
// all, so its feature is part of that addition.
var vrpYangFeatures = map[string][]string{
	"ietf-interfaces": {"pre-provisioning", "if-mib"},
	"ietf-subscribed-notifications": {
		"encode-xml", "replay", "xpath", "subtree", "configured", "dscp",
		"interface-designation", "supports-vrf", "encode-json",
	},
	"ietf-yang-push":          {"on-change"},
	"ietf-yang-push-revision": {"yang-push-revision-supported"},
}

// vrpAugmentedBy maps a served module to the served modules that augment it.
// Copied from the augmented-by data in the NE capture (get-ietf-yang-library.xml)
// and, for ietf-yang-push-revision, the MA5800T capture. Entries naming modules
// outside the served set are dropped. The NE lists only ietf-notification-capabilities
// as augmenting ietf-system-capabilities. nl6 also lists ietf-yang-push-revision,
// ietf-yp-notification and ietf-yp-observation there, because their YANG text
// augments /sysc:system-capabilities.
var vrpAugmentedBy = map[string][]string{
	"ietf-interfaces":                 {"ietf-network-instance", "ietf-ip"},
	"ietf-ip":                         {"ietf-network-instance"},
	"ietf-notification-capabilities":  {"ietf-yp-observation", "ietf-yp-notification"},
	"ietf-subscribed-notif-receivers": {"ietf-udp-notif-transport"},
	"ietf-subscribed-notifications": {
		"ietf-yp-notification", "ietf-yang-push", "ietf-subscribed-notif-receivers",
		"ietf-distributed-notif", "ietf-yang-push-revision", "ietf-udp-notif-transport",
	},
	"ietf-system-capabilities": {
		"ietf-notification-capabilities", "ietf-yang-push-revision",
		"ietf-yp-notification", "ietf-yp-observation",
	},
	"ietf-yang-library": {"ietf-yang-library-augmentedby"},
	"ietf-yang-push":    {"ietf-yp-observation", "ietf-distributed-notif"},
}

var (
	yangModuleRe    = regexp.MustCompile(`(?m)^\s*module\s+([\w.-]+)\s*\{`)
	yangRevisionRe  = regexp.MustCompile(`(?m)^\s*revision\s+"?(\d{4}-\d{2}-\d{2})"?`)
	yangNamespaceRe = regexp.MustCompile(`(?m)^\s*namespace\s+"?([^";\s]+)"?\s*;`)
)

var (
	vrpYangOnce sync.Once
	vrpYangList []yangModule
)

func vrpYangModules() []yangModule {
	vrpYangOnce.Do(func() {
		entries, err := vrpYangFS.ReadDir("resources/huawei_ne8000/yang")
		if err != nil {
			panic(err)
		}
		for _, e := range entries {
			src, err := vrpYangFS.ReadFile(path.Join("resources/huawei_ne8000/yang", e.Name()))
			if err != nil {
				panic(err)
			}
			m := yangModule{Source: src}
			if g := yangModuleRe.FindSubmatch(src); g != nil {
				m.Name = string(g[1])
			}
			if g := yangRevisionRe.FindSubmatch(src); g != nil {
				m.Revision = string(g[1])
			}
			if g := yangNamespaceRe.FindSubmatch(src); g != nil {
				m.Namespace = string(g[1])
			}
			if m.Name == "" || m.Revision == "" || m.Namespace == "" {
				panic(fmt.Sprintf("yang file %s: cannot parse name, revision and namespace", e.Name()))
			}
			if want := m.Name + "@" + m.Revision + ".yang"; want != e.Name() {
				panic(fmt.Sprintf("yang file %s should be named %s", e.Name(), want))
			}
			vrpYangList = append(vrpYangList, m)
		}
		sort.Slice(vrpYangList, func(i, j int) bool { return vrpYangList[i].Name < vrpYangList[j].Name })
	})
	return slices.Clone(vrpYangList)
}

// vrpYangModule returns the served module. An empty revision matches the
// served revision.
func vrpYangModule(name, revision string) (yangModule, bool) {
	for _, m := range vrpYangModules() {
		if m.Name == name && (revision == "" || revision == m.Revision) {
			return m, true
		}
	}
	return yangModule{}, false
}

// yangContentID hashes the sorted name@revision list, each followed by its
// features, with FNV-32a. A feature change therefore changes the id.
func yangContentID(mods []yangModule) string {
	ids := make([]string, len(mods))
	for i, m := range mods {
		ids[i] = m.Name + "@" + m.Revision
		if f := vrpYangFeatures[m.Name]; len(f) > 0 {
			ids[i] += "+" + strings.Join(f, ",")
		}
	}
	sort.Strings(ids)
	h := fnv.New32a()
	h.Write([]byte(strings.Join(ids, "\n")))
	return strconv.FormatUint(uint64(h.Sum32()), 10)
}

// yangFeatureXML renders the <feature> elements of module m.
func yangFeatureXML(b *bytes.Buffer, m yangModule) {
	for _, f := range vrpYangFeatures[m.Name] {
		fmt.Fprintf(b, "<feature>%s</feature>", f)
	}
}

func vrpContentID() string { return yangContentID(vrpYangModules()) }

const (
	yangLibNS    = "urn:ietf:params:xml:ns:yang:ietf-yang-library"
	yangLibAugNS = "urn:ietf:params:xml:ns:yang:ietf-yang-library-augmentedby"
)

// vrpYangLibraryXML returns the <yang-library> (RFC 8525) and <modules-state>
// (RFC 7895) data for a <get> reply.
func vrpYangLibraryXML() []byte {
	id := vrpContentID()
	mods := vrpYangModules()
	var b bytes.Buffer
	fmt.Fprintf(&b, "<yang-library xmlns=%q>", yangLibNS)
	fmt.Fprintf(&b, "<content-id>%s</content-id>", id)
	b.WriteString("<module-set><name>yang-push</name>")
	for _, m := range mods {
		if !vrpYangImplemented[m.Name] {
			continue
		}
		fmt.Fprintf(&b, "<module><name>%s</name><revision>%s</revision><namespace>%s</namespace>", m.Name, m.Revision, m.Namespace)
		yangFeatureXML(&b, m)
		for _, a := range vrpAugmentedBy[m.Name] {
			fmt.Fprintf(&b, "<augmented-by xmlns=%q>%s</augmented-by>", yangLibAugNS, a)
		}
		b.WriteString("</module>")
	}
	for _, m := range mods {
		if vrpYangImplemented[m.Name] {
			continue
		}
		fmt.Fprintf(&b, "<import-only-module><name>%s</name><revision>%s</revision><namespace>%s</namespace>", m.Name, m.Revision, m.Namespace)
		yangFeatureXML(&b, m)
		for _, a := range vrpAugmentedBy[m.Name] {
			fmt.Fprintf(&b, "<augmented-by xmlns=%q>%s</augmented-by>", yangLibAugNS, a)
		}
		b.WriteString("</import-only-module>")
	}
	b.WriteString("</module-set></yang-library>")
	fmt.Fprintf(&b, "<modules-state xmlns=%q><module-set-id>%s</module-set-id>", yangLibNS, id)
	for _, m := range mods {
		ct := "import"
		if vrpYangImplemented[m.Name] {
			ct = "implement"
		}
		fmt.Fprintf(&b, "<module><name>%s</name><revision>%s</revision><namespace>%s</namespace>", m.Name, m.Revision, m.Namespace)
		yangFeatureXML(&b, m)
		fmt.Fprintf(&b, "<conformance-type>%s</conformance-type></module>", ct)
	}
	b.WriteString("</modules-state>")
	return b.Bytes()
}
