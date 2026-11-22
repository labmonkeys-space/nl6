/*
 * Copyright 2026 Ronny Trommer <ronny@no42.org>
 * SPDX-License-Identifier: Apache-2.0
 */

package main

import (
	"errors"
	"strings"
	"testing"
	"time"
)

// A namespace that cannot be created must stop the manager. Running on in the
// root namespace sends exports for the veth address out of the default route,
// where they vanish while every send still counts as a success.
func TestNewSimulatorManagerFailsWhenNamespaceCannotBeCreated(t *testing.T) {
	original := createNetNamespace
	t.Cleanup(func() { createNetNamespace = original })

	cause := errors.New("mount --make-shared /var/run/netns failed: Permission denied")
	createNetNamespace = func() (*NetNamespace, error) { return nil, cause }

	sm, err := NewSimulatorManagerWithOptions(true)
	if err == nil {
		t.Fatal("expected an error when the namespace cannot be created")
	}
	if sm != nil {
		t.Fatalf("expected no manager, got %+v", sm)
	}
	if !errors.Is(err, cause) {
		t.Fatalf("error %q does not wrap the cause", err)
	}
	if !strings.Contains(err.Error(), NETNS_NAME) {
		t.Fatalf("error %q does not name the namespace %q", err, NETNS_NAME)
	}
}

func TestNewSimulatorManagerWithoutNamespaceNeverCreatesOne(t *testing.T) {
	original := createNetNamespace
	t.Cleanup(func() { createNetNamespace = original })

	createNetNamespace = func() (*NetNamespace, error) {
		t.Fatal("namespace creator called with useNamespace=false")
		return nil, nil
	}

	sm, err := NewSimulatorManagerWithOptions(false, WithFlowTickInterval(30*time.Second))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if sm == nil {
		t.Fatal("expected a manager")
	}
	defer func() { _ = sm.Shutdown() }()
	if sm.useNamespace || sm.netNamespace != nil {
		t.Fatalf("expected root-namespace mode, got useNamespace=%v netNamespace=%v", sm.useNamespace, sm.netNamespace)
	}
}

// The startup hint is printed for every namespace failure, not only for
// AppArmor. A container started without CAP_SYS_ADMIN fails the same way and
// must be told so, or the operator adds security_opt and fails again.
func TestNamespaceFailureHintNamesEveryRequirement(t *testing.T) {
	for _, want := range []string{"sudo", "NET_ADMIN", "SYS_ADMIN", "/dev/net/tun", "apparmor=unconfined", "appArmorProfile", "-no-namespace"} {
		if !strings.Contains(namespaceFailureHint, want) {
			t.Errorf("namespaceFailureHint does not mention %q:\n%s", want, namespaceFailureHint)
		}
	}
}
