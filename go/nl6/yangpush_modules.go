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
// capture, the MA5800T capture (ietf-yang-push-revision) or the IETF archive.
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
}

// vrpAugmentedBy maps a served module to the served modules that augment it.
// Copied from the augmented-by data in the NE capture (get-ietf-yang-library.xml)
// and, for ietf-yang-push-revision, the MA5800T capture. Entries naming modules
// outside the served set are dropped.
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

// yangContentID hashes the sorted name@revision list with FNV-32a.
func yangContentID(mods []yangModule) string {
	ids := make([]string, len(mods))
	for i, m := range mods {
		ids[i] = m.Name + "@" + m.Revision
	}
	sort.Strings(ids)
	h := fnv.New32a()
	h.Write([]byte(strings.Join(ids, "\n")))
	return strconv.FormatUint(uint64(h.Sum32()), 10)
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
		fmt.Fprintf(&b, "<module><name>%s</name><revision>%s</revision><namespace>%s</namespace><conformance-type>%s</conformance-type></module>", m.Name, m.Revision, m.Namespace, ct)
	}
	b.WriteString("</modules-state>")
	return b.Bytes()
}
