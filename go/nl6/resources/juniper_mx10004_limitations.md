# Juniper MX10004 NETCONF Limitations

The `juniper_mx10004` profile serves NETCONF over SSH and over mutual TLS when you start nl6 with `-netconf-enable`.
It emulates the Junos dialect of a vJunos-router.
This page says where the simulation ends.
See the [NETCONF reference](../../../docs/reference/netconf.md) for the wire behavior.

## Link events only

nl6 sends the mib2d `SNMP_TRAP_LINK_DOWN` and `SNMP_TRAP_LINK_UP` events and nothing else.
A real device also sends the rest of its syslog stream over NETCONF, such as chassisd, mgd and UI messages.
That background stream is absent here.

## A logical unit going down sends nothing

A logical unit that comes up sends `SNMP_TRAP_LINK_UP` at severity `INFORMATIONAL`.
No capture shows what a device sends when a unit goes down, so nl6 sends nothing.

## Delivery is immediate

nl6 sends each event as the state engine changes the interface.
The vJunos reference lagged the event by about 20 seconds because its feed carried the whole syslog stream.

## Reduced configuration

`get` without a captured filter and `get-configuration` return a `<configuration>` with only `<version>` and `<system><host-name>`.
The device sends its whole configuration.
The `database-status-information` block of the device is absent too.

## Few RPCs

nl6 serves `close-session`, `kill-session`, `create-subscription` on the `NETCONF` stream, `get` with the streams filter, `get` with the `netconf-state` capabilities filter, unfiltered `get` and `get-configuration`.
Every other RPC gets the Junos `syntax error` refusal.
This includes `get-interface-information`, `get-schema` and replay.
The reply to `kill-session` was never captured.
nl6 answers it as RFC 6241 says.

## Client identity

nl6 maps a client certificate only through the `specified` map type: a fingerprint table and one default username.
It has no mapping from the certificate subject or SAN to a username.
The username only names the session in the hello comment.
nl6 has no per-user authorisation.
The table is one for the whole fleet.
A change applies to new connections and running sessions keep their user.

## Framing

The session uses base 1.0 end-of-message framing only.
nl6 never switches to chunked framing, even when the client advertises base 1.1.
This is the Junos default.
The `rfc-compliant` and `version-1.1` settings are not emulated.

## TLS differences

- The transport is TLS 1.2 only, with a required client certificate, as on Junos.
- The alert bytes differ. For a TLS 1.3-only client Go sends `protocol_version` and for a missing client certificate it sends `bad_certificate`, where Junos sends `handshake_failure` for both. The connection is refused in each case.
- The server sends its own certificate only. Junos sends its certificate and the CA.
- The shared server certificate carries only a `0.0.0.0` IP SAN. A client that verifies the host name against the device IP fails. Skip host-name verification and pin the CA from `GET /api/v1/tls/ca`.
- With no client CA configured, every handshake is refused. The listener is still open.
