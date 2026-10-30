/*
 * Copyright 2026 Ronny Trommer <ronny@no42.org>
 * SPDX-License-Identifier: Apache-2.0
 */

package main

import "io"

// netconfDialect describes how one device profile serves NETCONF: which
// wire dialect and which transports it gets, and how its sessions are built.
type netconfDialect struct {
	Name string
	// SSH and TLS say which transports the profile is served on.
	SSH, TLS bool
	// NewSession builds a session on an established transport. user is the
	// authenticated login name; dialects that do not print it ignore it.
	NewSession func(id uint32, dev *DeviceSimulator, rw io.ReadWriter, reg *netconfSessionRegistry, user string) *netconfSession
}

// netconfDialects is keyed by resource directory name. A profile that is
// not in the table serves no NETCONF.
var netconfDialects = map[string]netconfDialect{
	"cisco_catalyst_9500": {
		Name: "iosxe",
		SSH:  true,
		NewSession: func(id uint32, dev *DeviceSimulator, rw io.ReadWriter, reg *netconfSessionRegistry, _ string) *netconfSession {
			return newIOSXENetconfSession(id, dev, rw, reg)
		},
	},
	"juniper_mx10004": {
		Name:       "junos",
		SSH:        true,
		TLS:        true,
		NewSession: newJunosNetconfSession,
	},
}

// netconfDialectFor returns the dialect of d's profile and whether it has one.
func netconfDialectFor(d *DeviceSimulator) (netconfDialect, bool) {
	if d == nil {
		return netconfDialect{}, false
	}
	dia, ok := netconfDialects[resourceDirName(d.resourceFile)]
	return dia, ok
}
