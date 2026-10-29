/*
 * Copyright 2026 Ronny Trommer <ronny@no42.org>
 * SPDX-License-Identifier: Apache-2.0
 */

package main

import (
	"bufio"
	"bytes"
	"errors"
	"fmt"
	"io"
	"strconv"
)

// netconfMaxMessageBytes bounds one inbound NETCONF message, summed over all
// chunks. A larger message is an error.
const netconfMaxMessageBytes = 1 << 20

const netconfEOM = "]]>]]>"

// netconfFramer reads and writes NETCONF messages over a byte stream. It uses
// the end-of-message marker until chunked is set, then RFC 6242 section 4.2
// chunked framing. The session sets chunked after the hello exchange when both
// peers advertise base:1.1.
type netconfFramer struct {
	br      *bufio.Reader
	w       io.Writer
	chunked bool
}

func newNetconfFramer(r io.Reader, w io.Writer) *netconfFramer {
	if r == nil {
		r = bytes.NewReader(nil)
	}
	return &netconfFramer{br: bufio.NewReader(r), w: w}
}

// ReadMessage returns the next message without its framing.
func (f *netconfFramer) ReadMessage() ([]byte, error) {
	if f.chunked {
		return f.readChunked()
	}
	return f.readEOM()
}

func (f *netconfFramer) readEOM() ([]byte, error) {
	var msg []byte
	for {
		b, err := f.br.ReadByte()
		if err != nil {
			return nil, err
		}
		msg = append(msg, b)
		if b == '>' && bytes.HasSuffix(msg, []byte(netconfEOM)) {
			msg = msg[:len(msg)-len(netconfEOM)]
			if len(msg) > netconfMaxMessageBytes {
				return nil, errors.New("netconf: message exceeds size limit")
			}
			return msg, nil
		}
		if len(msg) > netconfMaxMessageBytes+len(netconfEOM) {
			return nil, errors.New("netconf: message exceeds size limit")
		}
	}
}

func (f *netconfFramer) readChunked() ([]byte, error) {
	var msg []byte
	for {
		var hdr [2]byte
		if _, err := io.ReadFull(f.br, hdr[:]); err != nil {
			return nil, err
		}
		if hdr[0] != '\n' || hdr[1] != '#' {
			return nil, errors.New("netconf: bad chunk header")
		}
		first, err := f.br.ReadByte()
		if err != nil {
			return nil, err
		}
		if first == '#' {
			nl, err := f.br.ReadByte()
			if err != nil {
				return nil, err
			}
			if nl != '\n' {
				return nil, errors.New("netconf: bad end-of-chunks marker")
			}
			return msg, nil
		}
		digits := []byte{first}
		for {
			b, err := f.br.ReadByte()
			if err != nil {
				return nil, err
			}
			if b == '\n' {
				break
			}
			digits = append(digits, b)
			if len(digits) > 10 {
				return nil, errors.New("netconf: chunk size too long")
			}
		}
		if digits[0] < '1' || digits[0] > '9' {
			return nil, errors.New("netconf: bad chunk size")
		}
		for _, d := range digits {
			if d < '0' || d > '9' {
				return nil, errors.New("netconf: bad chunk size")
			}
		}
		n, err := strconv.ParseUint(string(digits), 10, 32)
		if err != nil {
			return nil, fmt.Errorf("netconf: bad chunk size: %w", err)
		}
		if uint64(len(msg))+n > netconfMaxMessageBytes {
			return nil, errors.New("netconf: message exceeds size limit")
		}
		start := len(msg)
		msg = append(msg, make([]byte, n)...)
		if _, err := io.ReadFull(f.br, msg[start:]); err != nil {
			return nil, err
		}
	}
}

// WriteMessage frames msg and writes it in a single Write call.
func (f *netconfFramer) WriteMessage(msg []byte) error {
	var out []byte
	if f.chunked {
		if len(msg) > 0 {
			out = append(out, fmt.Sprintf("\n#%d\n", len(msg))...)
			out = append(out, msg...)
		}
		out = append(out, "\n##\n"...)
	} else {
		out = append(append(out, msg...), netconfEOM...)
	}
	_, err := f.w.Write(out)
	return err
}
