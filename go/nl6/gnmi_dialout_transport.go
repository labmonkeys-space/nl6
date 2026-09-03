/*
 * Copyright 2026 Ronny Trommer <ronny@no42.org>
 * SPDX-License-Identifier: Apache-2.0
 */

package main

import (
	"context"
	"fmt"
	"strings"

	"github.com/aristanetworks/goarista/gnmireverse"
	gnmipb "github.com/openconfig/gnmi/proto/gnmi"
	"google.golang.org/grpc"
)

// DialoutStream is the minimal streaming surface the dial-out exporter
// needs from a transport flavor: send a SubscribeResponse and close the
// send side. Both the Arista gNMIReverse client-streaming stub and a
// future SONiC gNMIDialOut stub satisfy this (Send + CloseSend from the
// embedded gRPC ClientStream).
type DialoutStream interface {
	Send(*gnmipb.SubscribeResponse) error
	CloseSend() error
}

// DialoutTransport abstracts a dial-out wire flavor. Only the transport
// (which gRPC service/RPC to open, what the ack contract is) differs
// between flavors; the payload (gnmi.SubscribeResponse) and the pacing
// (SAMPLE / ON_CHANGE) are shared. This is the seam that lets the SONiC
// gNMIDialOut flavor be added later without touching the exporter —
// mirrors the FlowEncoder multi-protocol pattern.
type DialoutTransport interface {
	// Name returns the canonical flavor name (matches the config Flavor).
	Name() string
	// OpenStream opens the flavor's publish stream on cc.
	OpenStream(ctx context.Context, cc grpc.ClientConnInterface) (DialoutStream, error)
}

// gnmiReverseTransport implements the Arista gNMIReverse flavor:
// Publish(stream gnmi.SubscribeResponse) → google.protobuf.Empty
// (fire-and-forget; no per-message ack). This is the default and only
// shipped flavor.
type gnmiReverseTransport struct{}

func (gnmiReverseTransport) Name() string { return "gnmireverse" }

func (gnmiReverseTransport) OpenStream(ctx context.Context, cc grpc.ClientConnInterface) (DialoutStream, error) {
	client := gnmireverse.NewGNMIReverseClient(cc)
	// The returned grpc.ClientStreamingClient[gnmi.SubscribeResponse,
	// emptypb.Empty] satisfies DialoutStream via Send + CloseSend.
	return client.Publish(ctx)
}

// buildDialoutTransport returns the transport + canonical flavor name for
// a configured flavor string. Caller must have canonicalised via
// DeviceGnmiDialoutConfig.Validate; this is strict.
func buildDialoutTransport(flavor string) (DialoutTransport, string, error) {
	switch strings.ToLower(strings.TrimSpace(flavor)) {
	case "", "gnmireverse":
		return gnmiReverseTransport{}, "gnmireverse", nil
	case "altiplano":
		return gnmiReverseTransport{}, "altiplano", nil
	default:
		return nil, "", fmt.Errorf("unknown gnmi dial-out flavor %q (supported: gnmireverse)", flavor)
	}
}

// parseDialoutEncoding maps a canonical encoding string to the gNMI
// Encoding enum used by encodeUpdates. Caller must have canonicalised via
// Validate; unknown values error rather than silently defaulting.
func parseDialoutEncoding(enc string) (gnmipb.Encoding, error) {
	switch strings.ToLower(strings.TrimSpace(enc)) {
	case "", "json_ietf", "json-ietf":
		return gnmipb.Encoding_JSON_IETF, nil
	case "proto":
		return gnmipb.Encoding_PROTO, nil
	default:
		return 0, fmt.Errorf("unknown gnmi dial-out encoding %q (supported: json_ietf, proto)", enc)
	}
}

// parseGnmiPath parses a canonical gNMI path string
// (`/interfaces/interface[name=GigabitEthernet0/1]/state/oper-status`) into
// a gnmipb.Path. Each element is `name` optionally followed by one or more
// `[key=value]` predicates. The '/' separator is only recognised at
// bracket-depth 0, so interface names containing '/' inside `[name=...]`
// (common on Cisco/Juniper) are handled. `]` inside a key value is not
// escaped — the interface names the simulator emits never contain it.
func parseGnmiPath(s string) (*gnmipb.Path, error) {
	s = strings.TrimSpace(s)
	if s == "" || s[0] != '/' {
		return nil, fmt.Errorf("path must be absolute (start with '/')")
	}
	body := strings.TrimPrefix(s, "/")
	if body == "" {
		// Root path "/" — no elements.
		return &gnmipb.Path{}, nil
	}
	segments := splitPathSegments(body)
	elems := make([]*gnmipb.PathElem, 0, len(segments))
	for _, seg := range segments {
		if seg == "" {
			return nil, fmt.Errorf("empty path element (double slash?)")
		}
		name := seg
		var keys map[string]string
		if i := strings.IndexByte(seg, '['); i >= 0 {
			name = seg[:i]
			rest := seg[i:]
			keys = map[string]string{}
			for len(rest) > 0 {
				if rest[0] != '[' {
					return nil, fmt.Errorf("malformed key predicate in %q", seg)
				}
				end := strings.IndexByte(rest, ']')
				if end < 0 {
					return nil, fmt.Errorf("unterminated '[' in %q", seg)
				}
				kv := rest[1:end]
				eq := strings.IndexByte(kv, '=')
				if eq < 0 {
					return nil, fmt.Errorf("key predicate %q missing '='", kv)
				}
				k := strings.TrimSpace(kv[:eq])
				if k == "" {
					return nil, fmt.Errorf("empty key name in %q", seg)
				}
				keys[k] = kv[eq+1:]
				rest = rest[end+1:]
			}
		}
		if name == "" {
			return nil, fmt.Errorf("empty element name in %q", seg)
		}
		elems = append(elems, &gnmipb.PathElem{Name: name, Key: keys})
	}
	return &gnmipb.Path{Elem: elems}, nil
}

// splitPathSegments splits a gNMI path body on '/' but only at
// bracket-depth 0, so a '/' inside a `[key=value]` predicate (e.g.
// `name=GigabitEthernet0/1`) does not start a new element.
func splitPathSegments(body string) []string {
	var segs []string
	depth := 0
	start := 0
	for i := 0; i < len(body); i++ {
		switch body[i] {
		case '[':
			depth++
		case ']':
			if depth > 0 {
				depth--
			}
		case '/':
			if depth == 0 {
				segs = append(segs, body[start:i])
				start = i + 1
			}
		}
	}
	segs = append(segs, body[start:])
	return segs
}
