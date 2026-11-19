/*
 * Copyright 2026 Ronny Trommer <ronny@no42.org>
 * SPDX-License-Identifier: Apache-2.0
 */

package main

import (
	"fmt"
	"os"
	"os/exec"
	"runtime"
	"strconv"
	"strings"
)

const (
	capNetAdmin = 12
	capSysAdmin = 21

	privilegedFix = "Forgejo runner in Docker mode: set container.privileged: true in the runner config. docker run: add --cap-add "
)

// probe is a snapshot of the facts preflight judges. liveProbe fills it from
// the real environment, tests fill it by hand.
type probe struct {
	goos   string
	euid   int
	capEff uint64
	tunErr error // result of opening /dev/net/tun O_RDWR
	ipErr  error // result of exec.LookPath("ip")
	capErr error // set when the capability set could not be read
}

type finding struct{ ID, Problem, Fix string }

// preflight returns one finding per unmet requirement. An empty slice means
// the runner is fit to run nl6.
func preflight(p probe) []finding {
	if p.goos != "linux" {
		return []finding{{"linux", "nl6 needs Linux, this is " + p.goos, "run the job on a Linux runner"}}
	}
	var out []finding
	if p.euid != 0 {
		out = append(out, finding{"root", "nl6-ci up must run as root", "call it with sudo"})
	}
	// A process that is not root has no effective capabilities, whatever the
	// runner grants root. Judging them then would blame the runner config.
	switch {
	case p.euid != 0:
	case p.capErr != nil:
		out = append(out, finding{"caps", "the capability set could not be read: " + p.capErr.Error(),
			"check that /proc is mounted and readable"})
	default:
		if p.capEff&(1<<capNetAdmin) == 0 {
			out = append(out, finding{"cap_net_admin", "CAP_NET_ADMIN is missing", privilegedFix + "NET_ADMIN"})
		}
		if p.capEff&(1<<capSysAdmin) == 0 {
			out = append(out, finding{"cap_sys_admin", "CAP_SYS_ADMIN is missing", privilegedFix + "SYS_ADMIN"})
		}
	}
	if p.tunErr != nil {
		out = append(out, finding{"tun", "/dev/net/tun cannot be opened: " + p.tunErr.Error(),
			"Forgejo runner in Docker mode: set container.privileged: true. docker run: add --device /dev/net/tun"})
	}
	if p.ipErr != nil {
		out = append(out, finding{"ip", "the ip command is missing", "install the iproute2 package"})
	}
	return out
}

// parseCapEff extracts the effective capability mask from /proc/self/status.
func parseCapEff(procStatus string) (uint64, error) {
	for _, line := range strings.Split(procStatus, "\n") {
		if v, ok := strings.CutPrefix(line, "CapEff:"); ok {
			return strconv.ParseUint(strings.TrimSpace(v), 16, 64)
		}
	}
	return 0, fmt.Errorf("CapEff not found in process status")
}

// liveProbe reads the real environment. It never creates the TUN node.
func liveProbe() probe {
	p := probe{goos: runtime.GOOS, euid: os.Geteuid()}
	if p.goos != "linux" {
		return p
	}
	if b, err := os.ReadFile("/proc/self/status"); err != nil {
		p.capErr = err
	} else {
		p.capEff, p.capErr = parseCapEff(string(b))
	}
	if f, err := os.OpenFile("/dev/net/tun", os.O_RDWR, 0); err != nil {
		p.tunErr = err
	} else if err := f.Close(); err != nil {
		p.tunErr = err
	}
	_, p.ipErr = exec.LookPath("ip")
	return p
}
