/*
 * Copyright 2026 Ronny Trommer <ronny@no42.org>
 * SPDX-License-Identifier: Apache-2.0
 */

package main

import (
	"errors"
	"reflect"
	"testing"
)

const fullCaps = 0x1ffffffffff

func ids(fs []finding) []string {
	out := []string{}
	for _, f := range fs {
		out = append(out, f.ID)
	}
	return out
}

func TestParseCapEff(t *testing.T) {
	got, err := parseCapEff("Name:\tx\nCapEff:\t000001ffffffffff\nCapBnd:\t0\n")
	if err != nil || got != fullCaps {
		t.Fatalf("got %x, %v", got, err)
	}
}

func TestParseCapEffMissing(t *testing.T) {
	if _, err := parseCapEff("Name:\tx\n"); err == nil {
		t.Fatal("expected an error when CapEff is absent")
	}
}

func TestPreflightFitRunner(t *testing.T) {
	if f := preflight(probe{goos: "linux", euid: 0, capEff: fullCaps}); len(f) != 0 {
		t.Fatalf("%v", f)
	}
}

func TestPreflightDefaultDockerContainer(t *testing.T) {
	// 0xa80425fb is the default Docker capability set: no NET_ADMIN (bit 12), no SYS_ADMIN (bit 21).
	f := preflight(probe{goos: "linux", euid: 0, capEff: 0xa80425fb, tunErr: errors.New("no such file or directory")})
	want := []string{"cap_net_admin", "cap_sys_admin", "tun"}
	if got := ids(f); !reflect.DeepEqual(got, want) {
		t.Fatalf("got %v, want %v", got, want)
	}
	if f[2].Problem != "/dev/net/tun cannot be opened: no such file or directory" {
		t.Fatalf("problem: %q", f[2].Problem)
	}
}

// A process that is not root has an empty effective set. That says nothing
// about the runner, so only the root finding is reported.
func TestPreflightNotRoot(t *testing.T) {
	f := preflight(probe{goos: "linux", euid: 1001, capEff: 0})
	if got := ids(f); !reflect.DeepEqual(got, []string{"root"}) {
		t.Fatalf("got %v", got)
	}
}

func TestPreflightNotLinux(t *testing.T) {
	f := preflight(probe{goos: "darwin", euid: 501, tunErr: errors.New("x"), ipErr: errors.New("y")})
	if got := ids(f); !reflect.DeepEqual(got, []string{"linux"}) {
		t.Fatalf("got %v", got)
	}
	if f[0].Problem != "nl6 needs Linux, this is darwin" {
		t.Fatalf("problem: %q", f[0].Problem)
	}
}

func TestPreflightNoIP(t *testing.T) {
	f := preflight(probe{goos: "linux", euid: 0, capEff: fullCaps, ipErr: errors.New("not found")})
	if got := ids(f); !reflect.DeepEqual(got, []string{"ip"}) {
		t.Fatalf("got %v", got)
	}
}

func TestPreflightUnreadableCaps(t *testing.T) {
	got := ids(preflight(probe{goos: "linux", euid: 0, capErr: errors.New("boom")}))
	if !reflect.DeepEqual(got, []string{"caps"}) {
		t.Fatalf("%v", got)
	}
}
