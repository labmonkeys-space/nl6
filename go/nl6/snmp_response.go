/*
 * © 2025 Sharon Aicler (saichler@gmail.com)
 *
 * Layer 8 Ecosystem is licensed under the Apache License, Version 2.0.
 * You may obtain a copy of the License at:
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package main

import (
	"crypto/cipher"
	"crypto/des"
	"crypto/md5"
	"fmt"
)

// SNMP request parser
type SNMPRequest struct {
	Community string
	RequestID int
	OID       string
	Version   int
}

// Parse incoming SNMP request to extract all needed info
func (s *SNMPServer) parseIncomingRequest(data []byte) SNMPRequest {
	req := SNMPRequest{
		Community: "public",
		RequestID: 123,
		OID:       ".1.3.6.1.2.1.1.1.0",
		Version:   snmpVersion2c,
	}

	if len(data) < 10 {
		return req
	}

	// Parse the SNMP packet structure
	// SEQUENCE { version, community, PDU }
	pos := 0

	// Skip SEQUENCE tag and length
	if data[pos] != ASN1_SEQUENCE {
		return req
	}
	pos++
	// parseLength, not skipLength: skipLength answers a malformed long-form
	// length with `1 + lengthBytes`, a plausible skip computed from a length
	// it could not read, and it has no failure signal to distinguish that from
	// a good one. All three envelope readers stop here instead (nl6#559
	// review R11).
	outerLen, newPos := parseLength(data, pos)
	if outerLen < 0 {
		return req
	}
	pos = newPos

	// Parse version at its DECLARED width.
	//
	// `versionLen == 1` was the same one-octet assumption nl6#559 fixed in the
	// OFFSET, left standing in the VALUE: `02 02 00 00` is a legal BER v1 and
	// used to leave req.Version at the snmpVersion2c default, silently
	// disabling every v1-specific behaviour this repo documents — the
	// Counter64 GET-divert and GETNEXT-skip (nl6#524) and the noSuchName
	// sentinel diversion (nl6#517). parseBERInt reads any width, strips the
	// leading padding an encoder may have added and refuses more than 8
	// significant octets, which is the convention nl6#489/#535 already
	// established at every other parse site in this family.
	//
	// A zero-length version (`02 00`, illegal per X.690 §8.3.1) makes
	// parseBERInt report !ok, so the default stands and the request is
	// answered as v2c. That is the lenient choice, stated in getPDUType.
	if pos < len(data) && data[pos] == ASN1_INTEGER {
		pos++
		versionLen, newPos := parseLength(data, pos)
		pos = newPos
		if v, ok := parseBERInt(data, pos, versionLen); ok {
			req.Version = v
		}
		if versionLen > 0 {
			pos += versionLen
		}
	}

	// Parse community
	if pos < len(data) && data[pos] == ASN1_OCTET_STRING {
		pos++
		communityLen, newPos := parseLength(data, pos)
		pos = newPos
		// `>= 0`, not `> 0`: a zero-length community is a legal OCTET STRING and
		// both shipped clients emit it on request (net-snmp 5.6.2.1 and snmp4j
		// 3.13.1 each send `04 00` for `-c ""`). Treating it as absent left
		// req.Community at its "public" default, which nl6 then echoed back to a
		// caller that had sent no community at all (nl6#514).
		//
		// The lower bound cannot be dropped entirely: parseLength signals failure
		// with -1, and pos+(-1) <= len(data) is true, so an unbounded guard would
		// evaluate data[pos : pos-1] and panic on the inverted range.
		if communityLen >= 0 && pos+communityLen <= len(data) {
			req.Community = string(data[pos : pos+communityLen])
			pos += communityLen
		}
	}

	// Parse PDU (GetRequest = 0xa0, GetNext = 0xa1, GetBulk = 0xa5)
	if pos < len(data) && (data[pos] == 0xa0 || data[pos] == 0xa1 || data[pos] == 0xa5) {
		pos++
		pduLen, newPos := parseLength(data, pos)
		if pduLen < 0 {
			return req
		}
		pos = newPos

		// Parse request ID at its DECLARED width (nl6#562).
		//
		// The old bound was `reqIDLen > 0 && reqIDLen <= 4`, and outside it the
		// parser did not advance — which is the third instance of nl6#559's
		// root assumption, that the encoder was minimal. A padded five-octet
		// request-id (`02 05 00 7f ff ff fd`) is legal BER and is what an
		// encoder emits for any value at or above 2^31, and leaving the cursor
		// on it does NOT merely cost the request-id: every field after it is
		// read from the wrong offset. Live fuzzing found the datagram where
		// that decodes the `06 01 30` sitting INSIDE the PDU as the first
		// varbind name, so the parser reported a name nobody sent and CLAIM 2
		// fired on a shape none of its three documented skips covers.
		//
		// parseBERInt is the same reader the GETBULK parameters use: any
		// width, leading padding stripped, more than 8 significant octets
		// refused. It is SIGNED, where the old assembly was unsigned, so a
		// four-octet request-id with the high bit set now reads as the
		// negative Integer32 RFC 3416 says it is instead of as a value above
		// 2^31 that nl6 would then echo back as a request-id the manager never
		// sent. No shipped manager emits one: net-snmp and snmp4j both draw
		// request-ids from 0..2^31-1.
		if pos < len(data) && data[pos] == ASN1_INTEGER {
			pos++
			reqIDLen, newPos := parseLength(data, pos)
			pos = newPos
			if v, ok := parseBERInt(data, pos, reqIDLen); ok {
				req.RequestID = v
			}
			if reqIDLen > 0 {
				pos += reqIDLen
			}
		}

		// Skip error-status and error-index
		for i := 0; i < 2; i++ {
			if pos < len(data) && data[pos] == ASN1_INTEGER {
				pos++
				fieldLen, newPos := parseLength(data, pos)
				if fieldLen >= 0 {
					pos = newPos + fieldLen
				}
			}
		}

		// Parse variable bindings
		if pos < len(data) && data[pos] == ASN1_SEQUENCE {
			pos++
			pos += s.skipLength(data[pos:])

			// First variable binding
			if pos < len(data) && data[pos] == ASN1_SEQUENCE {
				pos++
				pos += s.skipLength(data[pos:])

				// Parse OID
				if pos < len(data) && data[pos] == ASN1_OID {
					pos++
					oidLen, newPos := parseLength(data, pos)
					pos = newPos
					if oidLen > 0 && pos+oidLen <= len(data) {
						oidBytes := data[pos : pos+oidLen]
						if oid := decodeOID(oidBytes); oid != "" {
							req.OID = oid
						}
					}
				}
			}
		}
	}

	return req
}

// createSNMPResponse builds a SINGLE-variable-binding GetResponse.
//
// PRODUCTION-UNREACHABLE as of nl6#542, and that is worth stating plainly
// because the code reads as a live path. It was the GETNEXT response builder;
// GETNEXT now answers every binding through createGetNextResponse, so the only
// caller left is createVarbindResponse's `len(oids) != len(responses)`
// fallback, whose value is the literal "No data" — never a sentinel. So the
// SNMPv1 diversion below cannot fire in production either.
//
// It is kept rather than deleted for two reasons. It is the defensive answer to
// an internal invariant violation (mismatched slice lengths), which is a branch
// this repo prefers to keep answerable; and its diversion is the SECOND copy of
// the v1 noSuchName rule, so deleting it silently would leave the reachable
// copy with no independent check. Instead
// TestBothV1SentinelDiversionsAgreeByteForByte drives both copies over the same
// input and requires identical bytes — the nl6#539 lesson, where a second
// predicate agreed with its twin on the day it was written and drifted later
// (nl6#542 review R5).
//
// The one behavioural difference, deliberate and now unreachable: this builder
// applies NO maxSNMPResponseSize bound, where createVarbindResponse does. Do
// not add a caller without considering that.
func (s *SNMPServer) createSNMPResponse(oid, value string, requestData []byte) []byte {
	// Parse incoming request to get actual community and request ID
	req := s.parseIncomingRequest(requestData)

	// SNMPv1 has no exception values. Divert to a noSuchName error-status
	// before encoding, or the manager receives a context tag its decoder does
	// not define (RFC 3584 §4.2.2.2: §4.2.2.2.1 for noSuchObject, §4.2.2.2.2
	// for endOfMibView). Single varbind, so error-index is 1.
	//
	// The endOfMibView case used to arrive here from a v1 GETNEXT past the last
	// OID; since nl6#542 that goes through createVarbindResponse under
	// v1DivertSentinel and this copy is unreachable — see the function comment.
	if req.Version == snmpVersion1 && isSNMPExceptionValue(value) {
		return s.encodeGetResponseAt(req, encodeVarBind(oid, encodeNull()), snmpErrNoSuchName, 1)
	}

	// Encode value with the correct ASN.1 type for this OID (RFC 1902).
	valueBytes := encodeTypedValue(oid, value)

	// Create variable binding (OID + value)
	oidBytes := encodeOID(oid)
	varBind := encodeSequence(append(oidBytes, valueBytes...))

	// Variable bindings list
	varBindList := encodeSequence(varBind)

	// PDU contents: request-id, error-status, error-index, variable-bindings
	pduContents := []byte{}
	pduContents = append(pduContents, encodeInteger(req.RequestID)...) // Use actual request ID
	pduContents = append(pduContents, encodeInteger(0)...)             // error-status (noError)
	pduContents = append(pduContents, encodeInteger(0)...)             // error-index
	pduContents = append(pduContents, varBindList...)                  // variable-bindings

	// GetResponse PDU
	pdu := []byte{SNMP_GET_RESPONSE}
	pdu = append(pdu, encodeLength(len(pduContents))...)
	pdu = append(pdu, pduContents...)

	// Message contents: version, community, PDU
	msgContents := []byte{}
	msgContents = append(msgContents, encodeInteger(req.Version)...)       // Use client's version
	msgContents = append(msgContents, encodeOctetString(req.Community)...) // Use actual community
	msgContents = append(msgContents, pdu...)                              // PDU

	// Complete SNMP message
	msg := encodeSequence(msgContents)
	// Debug: Hex dump of regular response
	// log.Printf("SNMP %s: Regular response hex: %x", s.device.ID, msg[:min(len(msg), 100)])
	return msg
}

// createGetBulkResponse creates a GetBulk response with multiple variable bindings
// maxSNMPResponseSize bounds an assembled SNMP response so the resulting UDP
// datagram FRAME fits the link, not so the payload fills it.
//
// Derived from the shared egress-path constants (datagram_budget.go) and
// refreshed by recomputeDatagramBudgets, so it tracks `-datagram-mtu`. udp4
// only, so no address-family branch: an agent answers whoever polls it, and
// nl6's devices bind per-device IPv4 sockets.
//
// Before nl6#489 there was no bound at all — `handleGetBulk` built
// maxRepetitions × repeaterCols bindings and handed the result to the kernel.
// At 10 columns × 127 repetitions that is a ~29 KB datagram in 20 fragments.
var maxSNMPResponseSize = defaultLinkMTU - ipv4HeaderBytes - udpHeaderBytes

// SNMP error-status values (RFC 3416 §3).
const (
	snmpErrNoError = 0
	snmpErrTooBig  = 1
	// snmpErrNoSuchName is SNMPv1's only way to say "no such object". v1 has
	// no exception values, so RFC 3584 §4.2.2.2 maps a v2c noSuchObject /
	// noSuchInstance (§4.2.2.2.1) and endOfMibView (§4.2.2.2.2) onto this
	// error-status when answering a v1 manager.
	snmpErrNoSuchName = 2
)

// SNMP message versions on the wire (SNMPv3 is 3). Named because the
// exception encoding below turns on the v1 value.
const (
	snmpVersion1  = 0
	snmpVersion2c = 1
)

// Sentinel response values. findResponse and findNextOID return these strings
// in place of a value, and encodeTypedValue turns them into the corresponding
// RFC 3416 exception. They live in the value space rather than in the type
// system, which is how endOfMibView has always worked here — see the caveat on
// isSNMPExceptionValue.
const (
	valueNoSuchObject = "noSuchObject"
	valueEndOfMibView = "endOfMibView"
)

// isSNMPExceptionValue reports whether a response string is a sentinel that
// encodes to an RFC 3416 exception rather than to data.
//
// Caveat, inherited from the endOfMibView design and widened by adding a
// second sentinel: the test is on the value string, so a resource file whose
// legitimate value were literally "noSuchObject" would encode as an exception.
// No shipped profile does, and validateSNMPResourceValues (resources.go) now
// rejects such a file at load. Removing the hazard at the root means a typed
// value in place of the string, which is a larger change than this one.
//
// If you add a third sentinel here, add it to encodeTypedValue's switch too:
// the two sets are enumerated separately, and the load guard is blind to any
// sentinel the encoder knows but this predicate does not.
func isSNMPExceptionValue(v string) bool {
	return v == valueNoSuchObject || v == valueEndOfMibView
}

// snmpOverflowRule selects what happens when a response will not fit the
// datagram budget. GET, GETNEXT and GETBULK share this response encoder
// (deliberately — see nl6#176) but RFC 3416 gives GETBULK the opposite rule to
// the other two, so the rule is an explicit argument rather than something the
// encoder infers from its caller.
//
// Getting this backwards is the most damaging mistake available here: a
// truncated GET is a silent partial answer that the requester cannot detect and
// has no way to complete.
type snmpOverflowRule int

const (
	// overflowRuleUnset is the ZERO VALUE and is not a rule. It exists so that
	// a varbindResponseRules literal which omits this field cannot compile into
	// working code with a silently-chosen policy — the positional argument this
	// struct replaced could not be omitted, and a struct field can be
	// (nl6#542 review R7).
	overflowRuleUnset snmpOverflowRule = iota
	// overflowTruncate: RFC 3416 §4.2.3. Emit as many variable bindings as fit
	// and stop. Safe because a walk resumes from the last OID returned.
	overflowTruncate
	// overflowTooBig: RFC 3416 §4.2.1. Replace the whole response with
	// error-status tooBig and an EMPTY binding list. A GET or GETNEXT requester
	// asked for specific bindings and has no resume point.
	overflowTooBig
)

// v1DiversionRule selects which offences make an SNMPv1 response divert to
// error-status noSuchName. SNMPv1 has neither exception values nor Counter64,
// but RFC 3584 does NOT treat the two the same way across PDU types, and the
// PDU type is not visible from this function's arguments — so the rule is an
// explicit argument, exactly as snmpOverflowRule is (nl6#489's lesson, applied
// again by nl6#542).
//
// The asymmetry that matters: a GETNEXT names a POSITION, not an object, so a
// Counter64 successor is SKIPPED by the walk and never reaches here. Diverting
// on it instead would stop a v1 walk dead at the first ifHC* column and
// truncate the table with no signal — the most damaging mistake available in
// this area, which is why it is named rather than inferred.
type v1DiversionRule int

const (
	// v1DivertUnset is the ZERO VALUE and is not a rule; see overflowRuleUnset.
	// Without it the zero value of varbindResponseRules would be silently
	// GETBULK-shaped ("never divert, truncate"), which is the one combination
	// no other PDU type wants.
	v1DivertUnset v1DiversionRule = iota
	// v1DivertNothing: GETBULK. SNMPv1 has no GETBULK PDU, so a version-0
	// GETBULK is already a malformed request; its bindings are WALKED OIDs
	// rather than the request's names, and there can be
	// max-repetitions × columns of them, so neither the RFC 1157 echo nor a
	// per-binding error-index means anything. Answered unchanged (nl6#524).
	v1DivertNothing
	// v1DivertSentinel: GETNEXT. An exception sentinel diverts (RFC 3584
	// §4.2.2.2.2 for the endOfMibView a walk reaches past the last OID), a
	// Counter64-typed binding does NOT — handleSNMPv2cRequest's skip run has
	// already stepped over it (RFC 3584 §4.2.2.1).
	v1DivertSentinel
	// v1DivertSentinelAndCounter64: GET. Both offences divert, and the FIRST
	// one in the list wins whichever kind it is (RFC 1157 error-index).
	v1DivertSentinelAndCounter64
)

// varbindResponseRules carries the per-PDU-type decisions createVarbindResponse
// cannot infer from its arguments. Every field must be set explicitly at the
// call site, and BOTH rule fields have a zero value that is not a rule, so a
// literal that omits one is a detectable bug rather than a silent policy —
// see resolveDefaults, and TestRuleConstructorsSetEveryField, which pins that
// each of the three constructors sets both.
type varbindResponseRules struct {
	// overflow: what happens when the response will not fit the datagram.
	overflow snmpOverflowRule
	// v1Diversion: which offences divert a v1 response to noSuchName.
	v1Diversion v1DiversionRule
	// echoNames is the REQUEST's own variable-binding names, echoed with NULL
	// values in a v1 noSuchName response (RFC 1157 §4.1.3). One per binding,
	// in request order.
	//
	// GET and GETBULK leave it NIL, because there `oids` already ARE the
	// request's names. GETNEXT must supply it: its `oids` are the SUCCESSORS
	// it found, so echoing those would answer with names the manager never
	// sent.
	//
	// nil is therefore the normal GET/GETBULK path, NOT an error path, which is
	// why the fallback below keys on nil and not on a length mismatch. Keying
	// on the mismatch made a mis-sized GETNEXT slice fall back to `oids` —
	// echoing the successors, the exact answer the field exists to prevent
	// (nl6#542 review R6).
	echoNames []string
}

// resolveDefaults substitutes for a rule field left at its zero value and
// reports whether it had to.
//
// Unreachable from the three constructors, which is the point: a FUTURE call
// site that omits a field must not get a working default silently. The
// substitutes are the STRICTEST rules available — never truncate, always
// divert — so an omission degrades toward answering a v1 manager correctly and
// never toward a silent partial response.
func (r varbindResponseRules) resolveDefaults() (varbindResponseRules, bool) {
	unset := false
	if r.overflow == overflowRuleUnset {
		r.overflow, unset = overflowTooBig, true
	}
	if r.v1Diversion == v1DivertUnset {
		r.v1Diversion, unset = v1DivertSentinelAndCounter64, true
	}
	return r, unset
}

// lenBytesFor returns how many bytes encodeLength spends on a content length of
// n. Needed to size a message without assembling it: the three nested SEQUENCEs
// (variable-bindings, PDU, message) each carry one, and the width steps at 128
// and 256 — which is precisely the boundary region this bound operates in.
func lenBytesFor(n int) int {
	switch {
	case n < 128:
		return 1
	case n < 256:
		return 2
	default:
		return 3
	}
}

// snmpMessageSizeFor computes the exact encoded size of a GetResponse whose
// variable-binding list is varBindLen bytes, given the pre-computed sizes of
// the message prefix (version + community) and the PDU prefix (request-id +
// error-status + error-index).
//
// Exact and O(1), so the encode loop can test each candidate binding without
// assembling anything. An estimate would be the wrong tool here: every bug in
// this family has been a mismatch between a predicted size and an emitted one.
func snmpMessageSizeFor(msgPrefix, pduPrefix, varBindLen int) int {
	vbSeq := 1 + lenBytesFor(varBindLen) + varBindLen
	pduContents := pduPrefix + vbSeq
	pdu := 1 + lenBytesFor(pduContents) + pduContents
	msgContents := msgPrefix + pdu
	return 1 + lenBytesFor(msgContents) + msgContents
}

// createGetBulkResponse encodes a GETBULK response, truncating to fit the
// datagram budget (RFC 3416 §4.2.3).
func (s *SNMPServer) createGetBulkResponse(oids []string, responses []string, requestData []byte) []byte {
	return s.createVarbindResponse(oids, responses, requestData, varbindResponseRules{
		overflow:    overflowTruncate,
		v1Diversion: v1DivertNothing,
	})
}

// createGetResponse encodes a GET response, returning tooBig rather than a
// partial one when it will not fit (RFC 3416 §4.2.1).
func (s *SNMPServer) createGetResponse(oids []string, responses []string, requestData []byte) []byte {
	return s.createVarbindResponse(oids, responses, requestData, varbindResponseRules{
		overflow:    overflowTooBig,
		v1Diversion: v1DivertSentinelAndCounter64,
	})
}

// createGetNextResponse encodes a GETNEXT response (RFC 3416 §4.2.2).
//
// `names` is the request's variable-binding list and `oids` the successor found
// for each of them, one for one and in the same order. The two differ, which is
// the whole reason this constructor exists: the v1 noSuchName echo must carry
// the names the manager SENT, while the bindings carry the successors.
//
// Overflow is tooBig, not truncation. A GETNEXT is a walk STEP: the manager
// asked for N specific positions and has no resume point for the bindings a
// truncated response would drop, so RFC 3416 §4.2.1's rule applies here as it
// does to GET. Counter64 does NOT divert — see v1DivertSentinel.
func (s *SNMPServer) createGetNextResponse(names, oids, responses []string, requestData []byte) []byte {
	return s.createVarbindResponse(oids, responses, requestData, varbindResponseRules{
		overflow:    overflowTooBig,
		v1Diversion: v1DivertSentinel,
		echoNames:   names,
	})
}

// createTooBigResponse answers a request whose response cannot fit the datagram
// without building one (RFC 3416 §4.2.1: error-status tooBig, empty binding
// list).
//
// The GETNEXT dispatcher uses it to refuse, WITHOUT WALKING, a request naming
// more bindings than minVarbindSize allows to fit — at which point tooBig is
// already decided and every walk step is work spent on a response that would be
// discarded (nl6#542 review R3). Byte-identical to what createVarbindResponse
// produces on the same input, which TestTooBigShortCircuitMatchesTheBuilder
// pins, because two ways of saying tooBig is exactly the drift this repo keeps
// getting bitten by.
func (s *SNMPServer) createTooBigResponse(requestData []byte) []byte {
	return s.encodeGetResponse(s.parseIncomingRequest(requestData), nil, snmpErrTooBig)
}

// createVarbindResponse builds a multi-variable-binding GetResponse bounded by
// maxSNMPResponseSize.
//
// `rules` carries every decision that depends on the PDU type, which this
// function cannot see: what happens on overflow (GETBULK truncates, GET and
// GETNEXT return tooBig), which offences divert a v1 response to noSuchName,
// and which names a v1 echo carries. All three MUST be supplied by the caller —
// see snmpOverflowRule and v1DiversionRule for why none of them can be inferred
// here.
//
// Sizing is exact and incremental. Each binding is encoded once, its size added
// to a running total, and the resulting MESSAGE size computed in O(1) via
// snmpMessageSizeFor before it is committed — so nothing is ever assembled and
// then thrown away, and no estimate can drift from the encoder (the drift that
// produced nl6#486 and nl6#490).
func (s *SNMPServer) createVarbindResponse(oids []string, responses []string,
	requestData []byte, rules varbindResponseRules) []byte {
	if len(oids) != len(responses) {
		// Fallback to single response
		return s.createSNMPResponse(".1.3.6.1.2.1.1.1.0", "No data", requestData)
	}

	req := s.parseIncomingRequest(requestData)

	// A rule field left at its zero value is a programming error at a call
	// site, so it is logged once per device and answered under the strictest
	// rules rather than under whichever policy the zero value happened to
	// name (nl6#542 review R7).
	rules, unset := rules.resolveDefaults()
	if unset {
		s.logFirstRulesBug("a varbindResponseRules field was left unset")
	}

	// SNMPv1 diversion, as in createSNMPResponse. RFC 3584 §4.2.2.2.1 sets
	// error-index to the position of the varbind that produced the exception,
	// so report the first one; indices are 1-based (RFC 1157).
	//
	// A Counter64-typed OID diverts the same way ON A GET (RFC 3584 §4.2.2.1,
	// nl6#524). Counter64 does not exist in SNMPv1, and encodeTypedValue picks
	// the tag from the OID alone, so without this a v1 GET of an ifHC* column
	// answered tag 0x46 under error-status noError. On a GETNEXT it must NOT:
	// rules.v1Diversion is what says so, and v1DiversionRule carries the
	// reasoning.
	//
	// Both offences are tested in ONE pass, deliberately. Two sequential loops
	// would let an offence late in the list beat an earlier one, and RFC 1157
	// wants the FIRST offending binding.
	//
	// The test is on the OID's declared type, not on what the value happens to
	// encode as. encodeTypedValue only emits 0x46 when the value parses as a
	// uint64, so a Counter64 column holding a non-numeric value used to go out
	// as an OCTET STRING, which is legal in v1. It still diverts: the object's
	// MIB type is what a v1 manager cannot represent, and a bad stored value
	// should not quietly soften protocol semantics.
	//
	// The version test comes FIRST and the sentinel test comes before
	// snmpTypeTag, which is a linear scan of the ~50-row type table that
	// concatenates a string per row. A v2c fleet must never reach it.
	//
	// The echo skips the datagram budget deliberately. `echoed` is the
	// request's own varbind list, and OID + NULL is exactly how the request
	// encoded each binding, so the response is byte-for-byte the size of a
	// request the socket already accepted. Running it through the sizing loop
	// would produce a partial noSuchName echo, which is a wrong answer.
	if req.Version == snmpVersion1 && rules.v1Diversion != v1DivertNothing {
		// GETNEXT's bindings are successors, not the request's names, so the
		// echo takes the names the caller supplied. NIL means the caller's
		// `oids` are themselves the request's names (GET, GETBULK).
		names := rules.echoNames
		if names == nil {
			names = oids
		}
		// A non-nil slice of the WRONG length is a bug, not a shape any caller
		// produces: error-index below counts positions in `oids`, so echoing a
		// differently-sized list points the manager at a binding that is not
		// there. Answered with an EMPTY binding list, which carries no name and
		// so cannot misinform, and logged once per device. Echoing `oids`
		// instead — what this did before nl6#542 review R6 — would send the
		// SUCCESSORS, names the manager never asked for.
		if len(names) != len(oids) {
			s.logFirstRulesBug("echoNames length does not match the binding count")
			names = nil
		}
		for i := range oids {
			// Index oids, not responses: the Counter64 test is on the OID.
			offends := isSNMPExceptionValue(responses[i])
			if !offends && rules.v1Diversion == v1DivertSentinelAndCounter64 {
				offends = snmpTypeTag(oids[i]) == ASN1_COUNTER64
			}
			if offends {
				var echoed []byte
				for _, o := range names {
					echoed = append(echoed, encodeVarBind(o, encodeNull())...)
				}
				return s.encodeGetResponseAt(req, echoed, snmpErrNoSuchName, i+1)
			}
		}
	}

	// Fixed prefixes, needed to size the message without assembling it.
	msgPrefix := len(encodeInteger(req.Version)) + len(encodeOctetString(req.Community))
	pduPrefix := len(encodeInteger(req.RequestID)) + len(encodeInteger(0)) + len(encodeInteger(0))

	var varBindList []byte
	truncated := false
	for i, oid := range oids {
		valueBytes := encodeTypedValue(oid, responses[i])
		oidBytes := encodeOID(oid)
		varBindingContents := append(oidBytes, valueBytes...)

		varBinding := []byte{ASN1_SEQUENCE}
		varBinding = append(varBinding, encodeLength(len(varBindingContents))...)
		varBinding = append(varBinding, varBindingContents...)

		if snmpMessageSizeFor(msgPrefix, pduPrefix, len(varBindList)+len(varBinding)) > maxSNMPResponseSize {
			truncated = true
			// Under TRUNCATE only, always emit at least one binding: a response
			// with an empty binding list and no error stalls a collector's walk
			// forever with no signal, which is worse than one oversized
			// datagram. Reachable at a low -datagram-mtu (the flag accepts 576,
			// giving a 548 B budget) with an ordinary long ifAlias.
			//
			// NOT under tooBig. Emitting the binding there would produce an
			// oversized datagram carrying error-status noError — the fragmenting
			// response this bound exists to prevent, and a violation of RFC 3416
			// §4.2.1, which this same function enforces two lines below. A GET
			// that cannot be answered within one datagram must say so
			// (nl6#489 review).
			if len(varBindList) == 0 && rules.overflow == overflowTruncate {
				varBindList = append(varBindList, varBinding...)
			}
			break
		}
		varBindList = append(varBindList, varBinding...)
	}

	if truncated && rules.overflow == overflowTooBig {
		// RFC 3416 §4.2.1: the requester asked for specific bindings and cannot
		// resume, so report the failure instead of answering partially.
		return s.encodeGetResponse(req, nil, snmpErrTooBig)
	}
	return s.encodeGetResponse(req, varBindList, snmpErrNoError)
}

// encodeGetResponse wraps an already-encoded variable-binding list in the PDU
// and message framing. Split out so the tooBig path and the normal path cannot
// drift in their framing.
func (s *SNMPServer) encodeGetResponse(req SNMPRequest, varBindList []byte, errStatus int) []byte {
	return s.encodeGetResponseAt(req, varBindList, errStatus, 0)
}

// encodeGetResponseAt is encodeGetResponse with an explicit error-index.
//
// tooBig carries index 0 (the failure is the whole message), but the SNMPv1
// noSuchName mapping requires the position of the offending variable binding
// — RFC 3584 §4.2.2.2 sets error-index to the varbind that produced the
// exception. Indices are 1-based per RFC 1157.
func (s *SNMPServer) encodeGetResponseAt(req SNMPRequest, varBindList []byte, errStatus, errIndex int) []byte {
	varBindSequence := []byte{ASN1_SEQUENCE}
	varBindSequence = append(varBindSequence, encodeLength(len(varBindList))...)
	varBindSequence = append(varBindSequence, varBindList...)

	var pduContents []byte
	pduContents = append(pduContents, encodeInteger(req.RequestID)...)
	pduContents = append(pduContents, encodeInteger(errStatus)...) // error-status
	pduContents = append(pduContents, encodeInteger(errIndex)...)  // error-index
	pduContents = append(pduContents, varBindSequence...)

	pdu := []byte{SNMP_GET_RESPONSE}
	pdu = append(pdu, encodeLength(len(pduContents))...)
	pdu = append(pdu, pduContents...)

	msgContents := []byte{}
	msgContents = append(msgContents, encodeInteger(req.Version)...)
	msgContents = append(msgContents, encodeOctetString(req.Community)...)
	msgContents = append(msgContents, pdu...)

	return encodeSequence(msgContents)
}

// decryptScopedPDU decrypts an encrypted scoped PDU
func (s *SNMPServer) decryptScopedPDU(encryptedPDU []byte, privParams []byte) ([]byte, error) {
	if s.v3Config.PrivProtocol == SNMPV3_PRIV_NONE {
		return encryptedPDU, nil
	}

	// log.Printf("SNMPv3: Attempting to decrypt scoped PDU with privacy protocol")

	// Decrypt based on the configured privacy protocol
	switch s.v3Config.PrivProtocol {
	case SNMPV3_PRIV_DES:
		// log.Printf("SNMPv3: Using DES decryption")
		return s.decryptDES(encryptedPDU, privParams)
	case SNMPV3_PRIV_AES128:
		// log.Printf("SNMPv3: Using AES128 decryption")
		return s.decryptAES128(encryptedPDU, privParams)
	default:
		return nil, fmt.Errorf("unsupported privacy protocol: %d", s.v3Config.PrivProtocol)
	}
}

// generateDESKey generates a DES key from the privacy password using RFC 3414 method
func (s *SNMPServer) generateDESKey() []byte {
	// RFC 3414 compatible key derivation for SNMPv3 privacy
	// This is a simplified version that should work with standard SNMP clients

	// Step 1: Create auth key from password using MD5
	password := s.v3Config.PrivPassword
	if len(password) == 0 {
		password = s.v3Config.Password // Fallback to main password
	}

	// Create 1MB buffer with repeated password (RFC 3414)
	passwordBytes := []byte(password)
	// RFC 3414 §A.2.1 derives the key by repeating the password to fill the
	// buffer, which has no meaning for an empty password — and the modulo
	// below divides by zero. Return nil rather than a zero-filled key of the
	// right length: des.NewCipher rejects nil with a KeySizeError the caller
	// already handles, whereas a plausible-looking all-zero key would encrypt
	// successfully under a key the config never asked for. Configs reaching
	// here empty are rejected at device creation (SNMPv3Config.Validate); this
	// is the backstop for any path that bypasses it.
	if len(passwordBytes) == 0 {
		return nil
	}
	keyBuffer := make([]byte, 1048576) // 1MB
	for i := 0; i < len(keyBuffer); i++ {
		keyBuffer[i] = passwordBytes[i%len(passwordBytes)]
	}

	// Hash the 1MB buffer with MD5
	authKey := md5.Sum(keyBuffer)

	// Step 2: Localize the key with engine ID
	engineID := s.v3Config.EngineID
	if len(engineID) == 0 {
		engineID = "800000090300AABBCCDD" // Default engine ID
	}

	// Convert hex engine ID to bytes
	engineIDBytes, _ := s.parseHexEngineID(engineID)

	// Localize: MD5(authKey + engineID + authKey)
	localizeInput := append(append(authKey[:], engineIDBytes...), authKey[:]...)
	localizedKey := md5.Sum(localizeInput)

	// Step 3: For privacy key, derive from localized auth key
	// Privacy key = first 8 bytes of localized key for DES
	return localizedKey[:8]
}

// parseHexEngineID converts hex engine ID string to bytes
func (s *SNMPServer) parseHexEngineID(hexEngineID string) ([]byte, error) {
	// Remove any spaces or colons
	clean := ""
	for _, c := range hexEngineID {
		if (c >= '0' && c <= '9') || (c >= 'A' && c <= 'F') || (c >= 'a' && c <= 'f') {
			clean += string(c)
		}
	}

	// Convert hex pairs to bytes
	if len(clean)%2 != 0 {
		return nil, fmt.Errorf("invalid hex engine ID length")
	}

	result := make([]byte, len(clean)/2)
	for i := 0; i < len(clean); i += 2 {
		var b byte
		for j := 0; j < 2; j++ {
			c := clean[i+j]
			b <<= 4
			if c >= '0' && c <= '9' {
				b |= c - '0'
			} else if c >= 'A' && c <= 'F' {
				b |= c - 'A' + 10
			} else if c >= 'a' && c <= 'f' {
				b |= c - 'a' + 10
			}
		}
		result[i/2] = b
	}

	return result, nil
}

// getDESKey returns the cached DES key, computing and caching it on first call
func (s *SNMPServer) getDESKey() []byte {
	if s.cachedDESKey != nil {
		return s.cachedDESKey
	}
	s.cachedDESKey = s.generateDESKey()
	return s.cachedDESKey
}

// decryptDES performs basic DES decryption (simplified for simulation)
func (s *SNMPServer) decryptDES(encryptedData []byte, privParams []byte) ([]byte, error) {
	if len(privParams) < 8 {
		return nil, fmt.Errorf("invalid DES privacy parameters length: %d", len(privParams))
	}

	// Use cached DES key derived from privacy password using RFC 3414 method
	key := s.getDESKey()
	iv := privParams[:8] // Use privacy parameters as IV

	// log.Printf("SNMPv3: DES decryption - key: %d bytes, IV: %d bytes, data: %d bytes",
	//	len(key), len(iv), len(encryptedData))

	// For simulation purposes, implement basic DES-CBC decryption
	// In a real implementation, you'd need proper key derivation from the password

	// Create DES cipher
	block, err := des.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("failed to create DES cipher: %v", err)
	}

	if len(encryptedData)%8 != 0 {
		return nil, fmt.Errorf("encrypted data length must be multiple of 8 bytes")
	}

	// Decrypt using CBC mode
	mode := cipher.NewCBCDecrypter(block, iv)
	decrypted := make([]byte, len(encryptedData))
	mode.CryptBlocks(decrypted, encryptedData)

	// Remove PKCS padding (simplified)
	if len(decrypted) > 0 {
		paddingLen := int(decrypted[len(decrypted)-1])
		if paddingLen <= len(decrypted) && paddingLen <= 8 {
			decrypted = decrypted[:len(decrypted)-paddingLen]
		}
	}

	// log.Printf("SNMPv3: DES decryption completed - result: %d bytes", len(decrypted))

	return decrypted, nil
}
