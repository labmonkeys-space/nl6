/*
 * Copyright 2026 Ronny Trommer <ronny@no42.org>
 * SPDX-License-Identifier: Apache-2.0
 */

package main

import (
	"bytes"
	"encoding/xml"
	"io"
	"strings"
)

// iosxeSelection is what a subscription watches. An empty IfName means
// every interface.
type iosxeSelection struct {
	IfName string
	Leaves iosxeLeafSet
}

// iosxeSubResult is the subscription-result value of the reply.
type iosxeSubResult string

const (
	iosxeSubOK           iosxeSubResult = "notif-bis:ok"
	iosxeSubErrorOther   iosxeSubResult = "notif-bis:error-other"
	iosxeSubNoSuchOption iosxeSubResult = "notif-bis:error-no-such-option"
)

// iosxeRPCError is rendered as an rpc-error element. Path, Message and
// BadNamespace are optional; the device fills them for some errors only.
type iosxeRPCError struct {
	Type, Tag, BadElement string
	// Path is the error-path text. PathNS declares the prefixes it uses.
	Path, PathNS string
	Message      string
	BadNamespace string
}

// iosxeDampPathNS declares the prefixes of the dampening-period error-path.
const iosxeDampPathNS = ` xmlns:yp="urn:ietf:params:xml:ns:yang:ietf-yang-push" xmlns:notif-bis="urn:ietf:params:xml:ns:yang:ietf-event-notifications"`

const (
	iosxeOperModule  = "interfaces-ios-xe-oper:interfaces"
	iosxeStatePrefix = "if:interfaces-state"
)

// parseEstablishSubscription decides, as an IOS XE switch does, whether an
// establish-subscription element is accepted. It is pure.
// A non-nil rpcErr takes precedence over result.
func parseEstablishSubscription(body []byte) (sel iosxeSelection, result iosxeSubResult, rpcErr *iosxeRPCError) {
	var stream, xpath, damp string
	var hasStream, hasXPath, hasDamp, hasPeriod bool

	dec := xml.NewDecoder(bytes.NewReader(body))
	var cur string
	var text strings.Builder
	depth := 0
	for {
		tok, err := dec.Token()
		if err == io.EOF {
			break
		}
		if err != nil {
			return sel, iosxeSubErrorOther, nil
		}
		switch t := tok.(type) {
		case xml.StartElement:
			depth++
			if depth == 2 {
				cur = t.Name.Local
				text.Reset()
				switch cur {
				case "stream":
					hasStream = true
				case "xpath-filter":
					hasXPath = true
				case "dampening-period":
					hasDamp = true
				case "period":
					hasPeriod = true
				}
			}
		case xml.CharData:
			if depth == 2 {
				text.Write(t)
			}
		case xml.EndElement:
			if depth == 2 {
				v := strings.TrimSpace(text.String())
				switch cur {
				case "stream":
					stream = v
				case "xpath-filter":
					xpath = v
				case "dampening-period":
					damp = v
				}
				cur = ""
			}
			depth--
		}
	}

	if !hasStream || stream == "" {
		return sel, iosxeSubNoSuchOption, nil
	}
	if !hasXPath {
		return sel, iosxeSubErrorOther, nil
	}
	sel, result = parseIosxeXPath(xpath)
	if result != iosxeSubOK {
		return iosxeSelection{}, result, nil
	}
	if hasPeriod {
		// The device accepts periodic subscriptions. nl6 refuses them.
		return iosxeSelection{}, iosxeSubNoSuchOption, nil
	}
	if !hasDamp {
		return iosxeSelection{}, iosxeSubErrorOther, nil
	}
	if damp != "0" {
		return iosxeSelection{}, "", &iosxeRPCError{Type: "protocol", Tag: "invalid-value", BadElement: "dampening-period",
			Path: "/rpc/notif-bis:establish-subscription/yp:dampening-period", PathNS: iosxeDampPathNS,
			Message: `"` + damp + `" is out of range.`}
	}
	return sel, iosxeSubOK, nil
}

// parseIosxeXPath accepts exactly:
// /interfaces-ios-xe-oper:interfaces/interface[name=K]?(/oper-status|/admin-status)?
func parseIosxeXPath(x string) (iosxeSelection, iosxeSubResult) {
	if !strings.HasPrefix(x, "/") {
		return iosxeSelection{}, iosxeSubErrorOther
	}
	rest := x[1:]
	if rest == iosxeStatePrefix || strings.HasPrefix(rest, iosxeStatePrefix+"/") {
		return iosxeSelection{}, iosxeSubErrorOther
	}
	if !strings.HasPrefix(rest, iosxeOperModule) {
		return iosxeSelection{}, iosxeSubNoSuchOption
	}
	rest = strings.TrimPrefix(rest, iosxeOperModule)
	if !strings.HasPrefix(rest, "/interface") {
		return iosxeSelection{}, iosxeSubNoSuchOption
	}
	rest = strings.TrimPrefix(rest, "/interface")
	var sel iosxeSelection
	if strings.HasPrefix(rest, "[") {
		name, after, ok := iosxeParsePredicate(rest)
		if !ok {
			return iosxeSelection{}, iosxeSubErrorOther
		}
		sel.IfName, rest = name, after
	}
	switch rest {
	case "":
		sel.Leaves = iosxeLeafRow
	case "/oper-status":
		sel.Leaves = iosxeLeafOper
	case "/admin-status":
		sel.Leaves = iosxeLeafAdmin
	default:
		return iosxeSelection{}, iosxeSubNoSuchOption
	}
	return sel, iosxeSubOK
}

// iosxeParsePredicate reads [name='K'] or [name="K"] and returns K and the
// text after the closing bracket. K may contain slashes.
func iosxeParsePredicate(s string) (name, after string, ok bool) {
	const open = "[name="
	if !strings.HasPrefix(s, open) {
		return "", "", false
	}
	s = s[len(open):]
	if s == "" || (s[0] != '\'' && s[0] != '"') {
		return "", "", false
	}
	q := s[0]
	end := strings.IndexByte(s[1:], q)
	if end < 0 {
		return "", "", false
	}
	name = s[1 : 1+end]
	s = s[1+end+1:]
	if !strings.HasPrefix(s, "]") {
		return "", "", false
	}
	return name, s[1:], true
}
