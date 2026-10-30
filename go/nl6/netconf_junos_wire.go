/*
 * Copyright 2026 Ronny Trommer <ronny@no42.org>
 * SPDX-License-Identifier: Apache-2.0
 */

package main

import (
	"fmt"
	"strings"
	"time"
)

// Junos wire vocabulary, pinned byte for byte to a vJunos 25.4R1.12 capture.
// Replies begin and end with a newline. The hello does not begin with one.

// junosSessionEndFormat is what the device writes after the close-session
// reply's end-of-message marker: a newline, the comment, a newline.
const junosSessionEndFormat = "\n<!-- session end at %s -->\n"

// junosTimeFormat is the layout of every Junos timestamp attribute.
const junosTimeFormat = "2006-01-02 15:04:05 UTC"

// junosCapabilities is the capability list of the hello and of the
// netconf-state reply, in device order.
var junosCapabilities = []string{
	"urn:ietf:params:netconf:base:1.0",
	"urn:ietf:params:netconf:capability:candidate:1.0",
	"urn:ietf:params:netconf:capability:confirmed-commit:1.0",
	"urn:ietf:params:netconf:capability:validate:1.0",
	"urn:ietf:params:netconf:capability:url:1.0?scheme=http,ftp,file",
	"urn:ietf:params:xml:ns:netconf:base:1.0",
	"urn:ietf:params:xml:ns:netconf:capability:candidate:1.0",
	"urn:ietf:params:xml:ns:netconf:capability:confirmed-commit:1.0",
	"urn:ietf:params:xml:ns:netconf:capability:validate:1.0",
	"urn:ietf:params:xml:ns:netconf:capability:url:1.0?scheme=http,ftp,file",
	"urn:ietf:params:xml:ns:yang:ietf-yang-metadata?module=ietf-yang-metadata&amp;revision=2016-08-05",
	"urn:ietf:params:xml:ns:yang:ietf-netconf-monitoring",
	"http://xml.juniper.net/netconf/junos/1.0",
	"http://xml.juniper.net/dmi/system/1.0",
	"urn:ietf:params:netconf:capability:notification:1.0",
	"urn:ietf:params:xml:ns:netconf:notification:1.0",
	"urn:ietf:params:netconf:capability:interleave:1.0",
	"urn:ietf:params:xml:ns:netmod:notification",
	"http://yang.juniper.net/junos/jcmd?module=junos-configuration-metadata&amp;revision=2021-09-01",
}

func junosCapabilityLines() string {
	var b strings.Builder
	b.WriteString("  <capabilities>\n")
	for _, c := range junosCapabilities {
		b.WriteString("    <capability>" + c + "</capability>\n")
	}
	b.WriteString("  </capabilities>\n")
	return b.String()
}

// junosVersion returns the version token after "kernel JUNOS " in sysDescr,
// or "" when the device has none.
func junosVersion(dev *DeviceSimulator) string {
	if dev == nil || dev.resources == nil || dev.resources.oidIndex == nil {
		return ""
	}
	v, ok := dev.resources.oidIndex.Load(oidSysDescr)
	if !ok {
		return ""
	}
	s, _ := v.(string)
	const marker = "kernel JUNOS "
	i := strings.Index(s, marker)
	if i < 0 {
		return ""
	}
	rest := s[i+len(marker):]
	if j := strings.IndexAny(rest, ", \t\r\n"); j >= 0 {
		rest = rest[:j]
	}
	return rest
}

// junosServerHello renders the device hello for one session.
func junosServerHello(sessionID uint32, user string) []byte {
	var b strings.Builder
	b.WriteString("<!-- No zombies were killed during the creation of this user interface -->\n")
	fmt.Fprintf(&b, "<!-- user %s, class j-super-user -->\n", user)
	b.WriteString("<hello xmlns=\"urn:ietf:params:xml:ns:netconf:base:1.0\">\n")
	b.WriteString(junosCapabilityLines())
	fmt.Fprintf(&b, "  <session-id>%d</session-id>\n", sessionID)
	b.WriteString("</hello>\n")
	return []byte(b.String())
}

func junosReplyOpen(version, messageID string) string {
	return fmt.Sprintf("\n<rpc-reply xmlns:junos=\"http://xml.juniper.net/junos/%s/junos\" xmlns=\"urn:ietf:params:xml:ns:netconf:base:1.0\" message-id=\"%s\">\n", version, messageID)
}

func junosOKReply(version, messageID string) []byte {
	return []byte(junosReplyOpen(version, messageID) + "<ok/>\n</rpc-reply>\n")
}

// junosSyntaxError renders repeat copies of the syntax error block. The
// device repeats the block for an rpc it parses twice.
func junosSyntaxError(version, messageID, badElement string, repeat int) []byte {
	var b strings.Builder
	b.WriteString(junosReplyOpen(version, messageID))
	for i := 0; i < repeat; i++ {
		b.WriteString("<rpc-error>\n<error-type>protocol</error-type>\n<error-tag>operation-failed</error-tag>\n<error-severity>error</error-severity>\n<error-message>syntax error</error-message>\n<error-info>\n")
		fmt.Fprintf(&b, "<bad-element>%s</bad-element>\n</error-info>\n</rpc-error>\n", badElement)
	}
	b.WriteString("</rpc-reply>\n")
	return []byte(b.String())
}

// junosConfigurationBody is the reduced configuration: the version and the
// host name.
func junosConfigurationBody(dev *DeviceSimulator, version string) string {
	name := ""
	if dev != nil {
		if v := dev.cachedSysName.Load(); v != nil {
			name, _ = v.(string)
		} else {
			name = dev.sysName
		}
	}
	return "    <version>" + version + "</version>\n    <system>\n        <host-name>" + netconfEscape(name) + "</host-name>\n    </system>\n"
}

const junosConfigurationNS = `xmlns="http://xml.juniper.net/xnm/1.1/xnm"`

// junosConfiguration renders the configuration element of a get reply.
func junosConfiguration(dev *DeviceSimulator, version string, commitAt time.Time) string {
	t := commitAt.UTC()
	return fmt.Sprintf("<configuration %s junos:commit-seconds=\"%d\" junos:commit-localtime=\"%s\" junos:commit-user=\"admin\">\n%s</configuration>\n",
		junosConfigurationNS, t.Unix(), t.Format(junosTimeFormat), junosConfigurationBody(dev, version))
}

// junosGetConfigurationReply renders the reply of get-configuration.
func junosGetConfigurationReply(dev *DeviceSimulator, version, messageID string, changedAt time.Time) []byte {
	t := changedAt.UTC()
	return []byte(junosReplyOpen(version, messageID) +
		fmt.Sprintf("<configuration %s junos:changed-seconds=\"%d\" junos:changed-localtime=\"%s\">\n%s</configuration>\n",
			junosConfigurationNS, t.Unix(), t.Format(junosTimeFormat), junosConfigurationBody(dev, version)) +
		"</rpc-reply>\n")
}

// junosGetReply renders the reply of a NETCONF get. The device follows the
// configuration with an empty database-status-information element.
func junosGetReply(dev *DeviceSimulator, version, messageID string, commitAt time.Time) []byte {
	return []byte(junosReplyOpen(version, messageID) + "<data>\n" + junosConfiguration(dev, version, commitAt) +
		"<database-status-information>\n</database-status-information>\n</data>\n</rpc-reply>\n")
}

// junosStreamsReply is the reply to a get of the streams subtree.
func junosStreamsReply(version, messageID string) []byte {
	return []byte(junosReplyOpen(version, messageID) + "<data>\n</data>\n</rpc-reply>\n")
}

// junosNetconfStateReply is the reply to a get of netconf-state/capabilities.
func junosNetconfStateReply(version, messageID string) []byte {
	return []byte(junosReplyOpen(version, messageID) + "<data>\n<netconf-state xmlns=\"urn:ietf:params:xml:ns:yang:ietf-netconf-monitoring\">\n" +
		junosCapabilityLines() + "</netconf-state>\n</data>\n</rpc-reply>\n")
}
