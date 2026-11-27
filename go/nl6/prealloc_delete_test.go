/*
 * Copyright 2026 Ronny Trommer <ronny@no42.org>
 * SPDX-License-Identifier: Apache-2.0
 */

// The tests replace the ip command and the link listing, so they need neither
// root nor real TUN links.

package main

import (
	"errors"
	"strings"
	"sync"
	"testing"
)

// fakeLinks stands in for the host's links during a root-namespace delete.
type fakeLinks struct {
	mu           sync.Mutex
	links        map[string]struct{}
	stuck        map[string]struct{} // `ip link delete` fails although the link exists
	vanish       map[string]struct{} // `ip link delete` fails, but the link is gone afterwards
	batchSucceed bool
	listErr      error
	listCalls    int
	commands     []string
}

// fakeTunDelete replaces runIPCommand and listLinkNames for the test. The batch
// fails as `ip -batch` does on a missing link, unless batchSucceed is set.
// `link delete X` removes X when it exists and is not stuck.
func fakeTunDelete(t *testing.T, links ...string) *fakeLinks {
	t.Helper()
	f := &fakeLinks{links: map[string]struct{}{}, stuck: map[string]struct{}{}, vanish: map[string]struct{}{}}
	for _, l := range links {
		f.links[l] = struct{}{}
	}
	originalRun, originalList := runIPCommand, listLinkNames
	t.Cleanup(func() { runIPCommand, listLinkNames = originalRun, originalList })

	runIPCommand = func(args ...string) ([]byte, error) {
		f.mu.Lock()
		defer f.mu.Unlock()
		f.commands = append(f.commands, strings.Join(args, " "))
		if len(args) > 0 && args[0] == "-batch" {
			if f.batchSucceed {
				f.links = map[string]struct{}{}
				return nil, nil
			}
			return []byte(`Cannot find device "sim0"`), errors.New("exit status 1")
		}
		if len(args) == 3 && args[0] == "link" && args[1] == "delete" {
			name := args[2]
			_, exists := f.links[name]
			_, stuck := f.stuck[name]
			if _, vanish := f.vanish[name]; vanish {
				// The file descriptor closed while ip ran: the delete fails, the link is gone.
				delete(f.links, name)
				return []byte("Cannot find device"), errors.New("exit status 1")
			}
			if exists && !stuck {
				delete(f.links, name)
				return nil, nil
			}
		}
		return []byte("Cannot find device"), errors.New("exit status 1")
	}
	listLinkNames = func() (map[string]struct{}, error) {
		f.mu.Lock()
		defer f.mu.Unlock()
		f.listCalls++
		if f.listErr != nil {
			return nil, f.listErr
		}
		out := make(map[string]struct{}, len(f.links))
		for l := range f.links {
			out[l] = struct{}{}
		}
		return out, nil
	}
	return f
}

func TestBulkDeleteTunInterfacesTreatsGoneLinksAsDeleted(t *testing.T) {
	f := fakeTunDelete(t)
	sm := &SimulatorManager{}

	if err := sm.bulkDeleteTunInterfaces([]string{"sim0", "sim1", "sim2"}); err != nil {
		t.Fatalf("links that are already gone must count as deleted, got %v", err)
	}
	if len(f.commands) != 1 || !strings.HasPrefix(f.commands[0], "-batch") {
		t.Fatalf("want only the batch command, got %q", f.commands)
	}
}

func TestBulkDeleteTunInterfacesRetriesOnlyLinksThatRemain(t *testing.T) {
	f := fakeTunDelete(t, "sim1")
	sm := &SimulatorManager{}

	if err := sm.bulkDeleteTunInterfaces([]string{"sim0", "sim1", "sim2"}); err != nil {
		t.Fatalf("got %v", err)
	}
	if len(f.commands) != 2 || !strings.HasPrefix(f.commands[0], "-batch") || f.commands[1] != "link delete sim1" {
		t.Fatalf("want the batch and then `link delete sim1` only, got %q", f.commands)
	}
	if len(f.links) != 0 {
		t.Fatalf("links left: %v", f.links)
	}
	if f.listCalls != 1 {
		t.Fatalf("want one link listing, after the batch only, got %d", f.listCalls)
	}
}

func TestBulkDeleteTunInterfacesTreatsLinkThatVanishesDuringItsDeleteAsDeleted(t *testing.T) {
	f := fakeTunDelete(t, "sim1")
	f.vanish["sim1"] = struct{}{}
	sm := &SimulatorManager{}

	if err := sm.bulkDeleteTunInterfaces([]string{"sim0", "sim1"}); err != nil {
		t.Fatalf("a link gone after its failed delete must count as deleted, got %v", err)
	}
}

func TestBulkDeleteTunInterfacesReportsLinkThatSurvives(t *testing.T) {
	f := fakeTunDelete(t, "sim1")
	f.stuck["sim1"] = struct{}{}
	sm := &SimulatorManager{}

	err := sm.bulkDeleteTunInterfaces([]string{"sim0", "sim1"})
	if err == nil {
		t.Fatal("a link that still exists must be reported")
	}
	if !strings.Contains(err.Error(), "sim1") || strings.Contains(err.Error(), "sim0") {
		t.Fatalf("want the error to name sim1 and not sim0, got %v", err)
	}
}

func TestBulkDeleteTunInterfacesReportsEveryLinkWhenLinksCannotBeListed(t *testing.T) {
	f := fakeTunDelete(t)
	f.listErr = errors.New("netlink: permission denied")
	sm := &SimulatorManager{}

	err := sm.bulkDeleteTunInterfaces([]string{"sim0", "sim1"})
	if err == nil {
		t.Fatal("without a link listing no failed delete may count as done")
	}
	if !strings.Contains(err.Error(), "sim0") || !strings.Contains(err.Error(), "sim1") {
		t.Fatalf("want both links in the error, got %v", err)
	}
}

func TestBulkDeleteTunInterfacesSucceedsWhenBatchSucceeds(t *testing.T) {
	f := fakeTunDelete(t, "sim0")
	f.batchSucceed = true
	sm := &SimulatorManager{}

	if err := sm.bulkDeleteTunInterfaces([]string{"sim0"}); err != nil {
		t.Fatalf("got %v", err)
	}
	if len(f.commands) != 1 || f.listCalls != 0 {
		t.Fatalf("want one command and no link listing, got %q and %d listings", f.commands, f.listCalls)
	}
}
