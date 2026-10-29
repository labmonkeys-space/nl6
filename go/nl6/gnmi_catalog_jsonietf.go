/*
 * Copyright 2026 Ronny Trommer <ronny@no42.org>
 * SPDX-License-Identifier: Apache-2.0
 */

package main

import (
	"bytes"
	"encoding/json"
	"sort"
	"strings"

	gnmipb "github.com/openconfig/gnmi/proto/gnmi"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// The JSON_IETF container layout (json_ietf_layout "container") answers
// with one update per requested node, its value the node's leaves
// nested as RFC 7951 JSON, as IOS-XR does. The folds below only regroup
// what the catalogue resolver returned, so the two layouts cannot
// disagree on which leaves exist or on their scalar encoding.

// jsonIETFNode is one node of a folded value: a leaf's encoded scalar,
// a container's members, or a list's entries.
type jsonIETFNode struct {
	scalar  json.RawMessage
	key     bool // a list key repeated as an entry member
	members map[string]*jsonIETFNode
	list    bool
	entries []*jsonIETFNode // resolver order
	entryAt map[string]int  // entry index by its keys
}

func newJSONIETFContainer() *jsonIETFNode {
	return &jsonIETFNode{members: map[string]*jsonIETFNode{}}
}

// insert places val at elems below n.
func (n *jsonIETFNode) insert(elems []*gnmipb.PathElem, val json.RawMessage) error {
	if len(elems) == 0 {
		return n.setScalar(val)
	}
	parent, err := n.descend(elems[:len(elems)-1])
	if err != nil {
		return err
	}
	leaf, err := parent.child(elems[len(elems)-1])
	if err != nil {
		return err
	}
	return leaf.setScalar(val)
}

func (n *jsonIETFNode) setScalar(val json.RawMessage) error {
	if len(n.members) > 0 || n.list {
		return status.Error(codes.Internal, "JSON_IETF fold: a leaf and a container share a path")
	}
	// A leaf may restate its entry's key; two leaves on one node are a
	// catalogue defect, never resolved by keeping whichever came last.
	if n.scalar != nil && !n.key {
		return status.Error(codes.Internal, "JSON_IETF fold: two leaves share a path")
	}
	n.scalar, n.key = val, false
	return nil
}

// descend returns the container at elems below n, creating it.
func (n *jsonIETFNode) descend(elems []*gnmipb.PathElem) (*jsonIETFNode, error) {
	for _, e := range elems {
		var err error
		if n, err = n.child(e); err != nil {
			return nil, err
		}
	}
	return n, nil
}

// child returns the node for e below n, creating it. A keyed element
// is a list entry, which repeats its keys as members, as RFC 7951 §5.4
// encodes a list.
func (n *jsonIETFNode) child(e *gnmipb.PathElem) (*jsonIETFNode, error) {
	if n.scalar != nil {
		return nil, status.Error(codes.Internal, "JSON_IETF fold: a leaf and a container share a path")
	}
	keyed := len(e.GetKey()) > 0
	c := n.members[e.GetName()]
	if c == nil {
		c = newJSONIETFContainer()
		c.list = keyed
		n.members[e.GetName()] = c
	}
	if c.list != keyed {
		return nil, status.Errorf(codes.Internal, "JSON_IETF fold: %s is both a list and a container", e.GetName())
	}
	if !keyed {
		return c, nil
	}
	id := entryID(e.GetKey())
	if c.entryAt == nil {
		c.entryAt = map[string]int{}
	}
	i, ok := c.entryAt[id]
	if !ok {
		entry := newJSONIETFContainer()
		for k, v := range e.GetKey() {
			b, err := json.Marshal(v)
			if err != nil {
				return nil, status.Errorf(codes.Internal, "json marshal: %v", err)
			}
			entry.members[k] = &jsonIETFNode{scalar: b, key: true}
		}
		i = len(c.entries)
		c.entries = append(c.entries, entry)
		c.entryAt[id] = i
	}
	return c.entries[i], nil
}

// entryID identifies a list entry by its keys, in key-name order.
func entryID(keys map[string]string) string {
	if len(keys) == 1 {
		for _, v := range keys {
			return v
		}
	}
	names := make([]string, 0, len(keys))
	for k := range keys {
		names = append(names, k)
	}
	sort.Strings(names)
	var b strings.Builder
	for _, k := range names {
		b.WriteString(k)
		b.WriteByte(0)
		b.WriteString(keys[k])
		b.WriteByte(0)
	}
	return b.String()
}

// instanceID identifies a concrete path with NUL separators, so a key
// value holding `]` or `=` cannot make two instances collide.
func instanceID(p *gnmipb.Path) string {
	var b strings.Builder
	b.WriteString(p.GetOrigin())
	for _, e := range p.GetElem() {
		b.WriteByte(0)
		b.WriteString(e.GetName())
		b.WriteByte(0)
		b.WriteString(entryID(e.GetKey()))
	}
	return b.String()
}

// write appends n as compact JSON, members sorted so one request always
// folds to the same bytes.
func (n *jsonIETFNode) write(b *bytes.Buffer) {
	switch {
	case n.scalar != nil:
		b.Write(n.scalar)
	case n.list:
		b.WriteByte('[')
		for i, e := range n.entries {
			if i > 0 {
				b.WriteByte(',')
			}
			e.write(b)
		}
		b.WriteByte(']')
	default:
		names := make([]string, 0, len(n.members))
		for k := range n.members {
			names = append(names, k)
		}
		sort.Strings(names)
		b.WriteByte('{')
		for i, k := range names {
			if i > 0 {
				b.WriteByte(',')
			}
			kb, _ := json.Marshal(k) // a string always marshals
			b.Write(kb)
			b.WriteByte(':')
			n.members[k].write(b)
		}
		b.WriteByte('}')
	}
}

// typeKeys re-encodes the key members child spelled as strings on the
// entry node for the last prefix element. An OpenConfig list key is a
// leafref to state/<key>, so RFC 7951 encodes it as that leaf: the path
// key value is cast through the subtree's state/<key> leaf, whichever
// leaves the request covered (nl6#807). A key with no such leaf stays a
// string.
func (n *jsonIETFNode) typeKeys(last *gnmipb.PathElem, st *gnmiCatalogSubtree) error {
	if st == nil {
		return nil
	}
	for k, v := range last.GetKey() {
		m := n.members[k]
		if m == nil || !m.key {
			continue
		}
		for _, leaf := range st.Leaves {
			if leaf.Name != "state/"+k {
				continue
			}
			cast, err := leaf.cast(v)
			if err != nil {
				return status.Errorf(codes.Internal, "JSON_IETF fold: key %s=%q: %v", k, v, err)
			}
			if m.scalar, err = jsonIETFScalar(cast); err != nil {
				return err
			}
		}
	}
	return nil
}

func (n *jsonIETFNode) typedValue() *gnmipb.TypedValue {
	var b bytes.Buffer
	n.write(&b)
	return &gnmipb.TypedValue{Value: &gnmipb.TypedValue_JsonIetfVal{JsonIetfVal: b.Bytes()}}
}

// jsonIETFScalar is a leaf's per-leaf JSON_IETF encoding.
func jsonIETFScalar(v any) (json.RawMessage, error) {
	tv, err := gnmiEncodeTypedValue(v, gnmipb.Encoding_JSON_IETF)
	if err != nil {
		return nil, err
	}
	return tv.GetJsonIetfVal(), nil
}

// foldJSONIETFGet answers a Get: one update per concrete instance of
// the request path, the instance carrying the entry's origin and keys.
// A request that names every list key it crosses has one instance; one
// crossing a list without a key has one per entry. A leaf outside the
// requested node (an `always` leaf riding along on a deeper request)
// cannot nest under it and is left out. notifs are list-entry
// notifications, so every Prefix is set.
func foldJSONIETFGet(request *gnmipb.Path, notifs []catalogNotification) ([]*gnmipb.Update, error) {
	q := request.GetElem()
	type instance struct {
		path *gnmipb.Path
		root *jsonIETFNode
	}
	var order []*instance
	byID := map[string]*instance{}
	lookup := func(p *gnmipb.Path) *instance {
		id := instanceID(p)
		in := byID[id]
		if in == nil {
			in = &instance{path: p, root: newJSONIETFContainer()}
			byID[id] = in
			order = append(order, in)
		}
		return in
	}
	for _, n := range notifs {
		// An entry the type filter emptied answers nothing, not its keys.
		if len(n.Updates) == 0 {
			continue
		}
		pe := n.Prefix.GetElem()
		// A request no deeper than the entry prefix has one instance
		// for the whole entry; find the entry's node once, not per leaf.
		// The resolver returns only entries the request covers.
		var entry *jsonIETFNode
		if len(q) <= len(pe) {
			var err error
			if entry, err = lookup(&gnmipb.Path{Origin: n.Prefix.GetOrigin(), Elem: pe[:len(q)]}).root.descend(pe[len(q):]); err != nil {
				return nil, err
			}
			if len(q) < len(pe) {
				if err := entry.typeKeys(pe[len(pe)-1], n.subtree); err != nil {
					return nil, err
				}
			}
		}
		for _, u := range n.Updates {
			val, err := jsonIETFScalar(u.Value)
			if err != nil {
				return nil, err
			}
			if entry != nil {
				if err := entry.insert(u.Path.GetElem(), val); err != nil {
					return nil, err
				}
				continue
			}
			leaf := u.Path.GetElem()
			if !pathCoversSplit(q, pe, leaf) {
				continue
			}
			// Here len(q) > len(pe): the instance path is the prefix plus
			// the covered head of the leaf, and the rest is inserted under it.
			k := len(q) - len(pe)
			head := append(append(make([]*gnmipb.PathElem, 0, len(q)), pe...), leaf[:k]...)
			in := lookup(&gnmipb.Path{Origin: n.Prefix.GetOrigin(), Elem: head})
			if err := in.root.insert(leaf[k:], val); err != nil {
				return nil, err
			}
		}
	}
	out := make([]*gnmipb.Update, 0, len(order))
	for _, in := range order {
		out = append(out, &gnmipb.Update{Path: in.path, Val: in.root.typedValue()})
	}
	return out, nil
}

// foldJSONIETFEntry answers one list entry of a Subscribe: the update
// path is the entry prefix with its origin and keys, the value the
// entry's leaves.
func foldJSONIETFEntry(n catalogNotification) (*gnmipb.Update, error) {
	root := newJSONIETFContainer()
	for _, u := range n.Updates {
		val, err := jsonIETFScalar(u.Value)
		if err != nil {
			return nil, err
		}
		if err := root.insert(u.Path.GetElem(), val); err != nil {
			return nil, err
		}
	}
	return &gnmipb.Update{Path: n.Prefix, Val: root.typedValue()}, nil
}
