/*
 * Copyright 2026 Ronny Trommer <ronny@no42.org>
 * SPDX-License-Identifier: Apache-2.0
 */

package main

import (
	"go/ast"
	"go/parser"
	"go/token"
	"net"
	"path/filepath"
	"strings"
	"sync"
	"testing"
)

// stubDeviceNames replaces the sysName generator with one that cycles
// through names, so the redraw and fallback branches are reachable without
// fleet-scale draws.
func stubDeviceNames(t *testing.T, names ...string) {
	t.Helper()
	orig := randomDeviceName
	t.Cleanup(func() { randomDeviceName = orig })
	var mu sync.Mutex
	i := 0
	randomDeviceName = func(string) string {
		mu.Lock()
		defer mu.Unlock()
		n := names[i%len(names)]
		i++
		return n
	}
}

// nl6#743: the shipped generator put 7,099 duplicates into 30,000 draws for
// one type before the registry existed.
func TestReserveSysNameUniqueAtFleetScale(t *testing.T) {
	sm := &SimulatorManager{}
	const n = 30000
	seen := make(map[string]struct{}, n)
	for i := 0; i < n; i++ {
		ip := net.IPv4(10, 42, byte(i>>8), byte(i))
		name := sm.reserveSysName("cisco-crs-x", ip)
		if _, dup := seen[name]; dup {
			t.Fatalf("draw %d returned %q, already held by a live device", i, name)
		}
		seen[name] = struct{}{}
	}
}

func TestReserveSysNameRedrawsHeldName(t *testing.T) {
	stubDeviceNames(t, "atlas-nyc-x", "atlas-nyc-x", "wolf-07-x")
	sm := &SimulatorManager{}
	if got := sm.reserveSysName("x", net.IPv4(10, 0, 0, 1)); got != "atlas-nyc-x" {
		t.Fatalf("first reservation = %q, want atlas-nyc-x", got)
	}
	if got := sm.reserveSysName("x", net.IPv4(10, 0, 0, 2)); got != "wolf-07-x" {
		t.Fatalf("second reservation = %q, want the redraw wolf-07-x", got)
	}
}

func TestReserveSysNameFallsBackToIP(t *testing.T) {
	stubDeviceNames(t, "loki-van-cisco-crs-x")
	sm := &SimulatorManager{}
	sm.reserveSysName("cisco-crs-x", net.IPv4(172, 27, 0, 9))
	got := sm.reserveSysName("cisco-crs-x", net.IPv4(172, 27, 0, 1))
	if want := "loki-van-cisco-crs-x-172-27-0-1"; got != want {
		t.Fatalf("exhausted redraws gave %q, want %q", got, want)
	}
	if got != strings.ToLower(got) || !strings.Contains(got, "-") {
		t.Fatalf("fallback %q must be lower case and contain '-' (sentinel safety)", got)
	}
	if _, held := sm.sysNamesInUse[got]; !held {
		t.Fatalf("fallback %q was returned but not reserved", got)
	}
}

func TestReleaseSysNameMakesNameReusable(t *testing.T) {
	stubDeviceNames(t, "atlas-nyc-x")
	sm := &SimulatorManager{}
	name := sm.reserveSysName("x", net.IPv4(10, 0, 0, 1))
	sm.releaseSysName(name)
	if got := sm.reserveSysName("x", net.IPv4(10, 0, 0, 2)); got != name {
		t.Fatalf("after release, reservation = %q, want %q", got, name)
	}
}

// Parallel creation workers reserve concurrently; every result must be
// distinct. Run under -race to also pin the locking.
func TestReserveSysNameConcurrentReservationsAreDistinct(t *testing.T) {
	stubDeviceNames(t, "a-x", "b-x", "c-x", "d-x")
	sm := &SimulatorManager{}
	const workers = 64
	names := make([]string, workers)
	var wg sync.WaitGroup
	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			names[i] = sm.reserveSysName("x", net.IPv4(10, 0, 1, byte(i)))
		}(i)
	}
	wg.Wait()
	seen := map[string]struct{}{}
	for _, n := range names {
		if _, dup := seen[n]; dup {
			t.Fatalf("two concurrent reservations returned %q", n)
		}
		seen[n] = struct{}{}
	}
}

func TestDeleteDeviceReleasesSysName(t *testing.T) {
	origDelete := deleteDeviceTunInterfaces
	t.Cleanup(func() { deleteDeviceTunInterfaces = origDelete })
	deleteDeviceTunInterfaces = func(*SimulatorManager, []string) error { return nil }

	ip := net.IPv4(127, 0, 0, 3)
	device := &DeviceSimulator{ID: "d1", IP: ip, sysName: "atlas-nyc-x", tunIface: &TunInterface{Name: "sim1"}, running: true}
	sm := &SimulatorManager{
		devices:       map[string]*DeviceSimulator{device.ID: device},
		deviceIPs:     map[string]struct{}{ip.String(): {}},
		sysNamesInUse: map[string]struct{}{"atlas-nyc-x": {}},
	}
	manager = nil
	if err := sm.DeleteDevice(device.ID); err != nil {
		t.Fatalf("DeleteDevice() error = %v", err)
	}
	if _, held := sm.sysNamesInUse["atlas-nyc-x"]; held {
		t.Fatal("DeleteDevice left the deleted device's sysName reserved")
	}
}

// DeleteAllDevices is not gated against a running batch, so it must release
// only the names of the devices it deletes, never a name an in-flight worker
// has reserved but not yet published.
func TestDeleteAllDevicesReleasesOnlyDeletedNames(t *testing.T) {
	sm := &SimulatorManager{
		devices: map[string]*DeviceSimulator{
			"d1": {ID: "d1", IP: net.IPv4(127, 0, 0, 4), sysName: "atlas-nyc-x"},
			"d2": {ID: "d2", IP: net.IPv4(127, 0, 0, 5), sysName: "wolf-07-x"},
		},
		sysNamesInUse: map[string]struct{}{"atlas-nyc-x": {}, "wolf-07-x": {}, "in-flight-x": {}},
	}
	manager = nil
	if err := sm.DeleteAllDevices(); err != nil {
		t.Fatalf("DeleteAllDevices() error = %v", err)
	}
	for _, n := range []string{"atlas-nyc-x", "wolf-07-x"} {
		if _, held := sm.sysNamesInUse[n]; held {
			t.Errorf("DeleteAllDevices left deleted device name %q reserved", n)
		}
	}
	if _, held := sm.sysNamesInUse["in-flight-x"]; !held {
		t.Error("DeleteAllDevices released a name held by an in-flight creation")
	}
}

// The two creation paths and their Start() failure branches need root and a
// TUN device, so their wiring is pinned by source: the generator is called
// only from reserveSysName, device.go reserves exactly twice (one per path),
// and every device.Stop() cleanup in device.go is followed by a release.
func TestSysNameReservationWiring(t *testing.T) {
	fset := token.NewFileSet()
	files, err := filepath.Glob("*.go")
	if err != nil {
		t.Fatal(err)
	}
	reserves := 0
	for _, fname := range files {
		if strings.HasSuffix(fname, "_test.go") {
			continue
		}
		f, err := parser.ParseFile(fset, fname, nil, 0)
		if err != nil {
			t.Fatal(err)
		}
		{
			ast.Inspect(f, func(n ast.Node) bool {
				fd, ok := n.(*ast.FuncDecl)
				if !ok {
					return true
				}
				ast.Inspect(fd.Body, func(n ast.Node) bool {
					call, ok := n.(*ast.CallExpr)
					if !ok {
						return true
					}
					switch callName(call) {
					case "getRandomDeviceName", "randomDeviceName":
						if fd.Name.Name != "reserveSysName" {
							t.Errorf("%s: %s calls the sysName generator directly; reserve through reserveSysName (nl6#743)",
								fname, fd.Name.Name)
						}
					case "reserveSysName":
						if fname == "device.go" {
							reserves++
						}
					}
					return true
				})
				if fname == "device.go" {
					checkStopFollowedByRelease(t, fset, fd)
				}
				return false
			})
		}
	}
	if reserves != 2 {
		t.Errorf("device.go calls reserveSysName %d times, want 2 (sequential and parallel creation paths)", reserves)
	}
}

func callName(call *ast.CallExpr) string {
	switch fn := call.Fun.(type) {
	case *ast.Ident:
		return fn.Name
	case *ast.SelectorExpr:
		return fn.Sel.Name
	}
	return ""
}

// checkStopFollowedByRelease requires every `device.Stop()` statement that
// cleans up a failed Start() to be followed, in the same block, by a
// releaseSysName call.
func checkStopFollowedByRelease(t *testing.T, fset *token.FileSet, fd *ast.FuncDecl) {
	t.Helper()
	ast.Inspect(fd.Body, func(n ast.Node) bool {
		ifs, ok := n.(*ast.IfStmt)
		if !ok || !isStartFailure(ifs) {
			return true
		}
		stops, released := false, false
		for _, st := range ifs.Body.List {
			es, ok := st.(*ast.ExprStmt)
			if !ok {
				continue
			}
			call, ok := es.X.(*ast.CallExpr)
			if !ok {
				continue
			}
			switch callName(call) {
			case "Stop":
				stops = true
			case "releaseSysName":
				released = stops
			}
		}
		if !released {
			t.Errorf("%s: %s: device.Start() failure branch does not call releaseSysName after device.Stop()",
				fset.Position(ifs.Pos()), fd.Name.Name)
		}
		return true
	})
}

// isStartFailure matches `if err := device.Start(); err != nil { ... }`.
func isStartFailure(ifs *ast.IfStmt) bool {
	as, ok := ifs.Init.(*ast.AssignStmt)
	if !ok || len(as.Rhs) != 1 {
		return false
	}
	call, ok := as.Rhs[0].(*ast.CallExpr)
	if !ok {
		return false
	}
	sel, ok := call.Fun.(*ast.SelectorExpr)
	if !ok || sel.Sel.Name != "Start" {
		return false
	}
	id, ok := sel.X.(*ast.Ident)
	return ok && id.Name == "device"
}

// Guard against the scan matching nothing: device.go must contain exactly
// the two Start() failure branches the wiring test inspects.
func TestSysNameWiringScanFindsBothStartFailures(t *testing.T) {
	fset := token.NewFileSet()
	f, err := parser.ParseFile(fset, "device.go", nil, 0)
	if err != nil {
		t.Fatal(err)
	}
	found := 0
	ast.Inspect(f, func(n ast.Node) bool {
		if ifs, ok := n.(*ast.IfStmt); ok && isStartFailure(ifs) {
			found++
		}
		return true
	})
	if found != 2 {
		t.Fatalf("found %d device.Start() failure branches in device.go, want 2", found)
	}
}
