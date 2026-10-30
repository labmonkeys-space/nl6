# NETCONF reference

nl6 serves NETCONF on two device profiles.
`cisco_catalyst_9500` serves the IOS XE dialect over SSH.
A client opens an IOS XE style `establish-subscription` and receives a notification each time the interface state engine changes an interface.
`juniper_mx10004` serves a Junos dialect over SSH and over mutual TLS (RFC 7589).
A client opens a `create-subscription` on the `NETCONF` stream and receives the mib2d link events of the interface state engine.
The subsystem is off by default.
A default fleet behaves exactly as without it.

## Flags

| Name | Type | Default | Description |
|------|------|---------|-------------|
| `-netconf-enable` | bool | `false` | Enable the NETCONF subsystem. `cisco_catalyst_9500` devices listen on `-netconf-port`. `juniper_mx10004` devices listen on `-netconf-port` and on `-netconf-tls-port`. |
| `-netconf-port` | int | `830` | TCP port of the per-device NETCONF over SSH listener. |
| `-netconf-tls-port` | int | `6513` | TCP port of the per-device NETCONF over TLS listener. |
| `-netconf-tls-client-ca` | path | empty | PEM file with the CA that must have signed the client certificates. The path is flag-only. Requires `-netconf-enable`. |
| `-netconf-tls-client-identity` | `fingerprint=username` | none | One entry of the client identity table. Repeat the flag for more entries. The fingerprint is the SHA-256 of the client certificate, with or without the `04:` prefix. Requires `-netconf-enable`. |
| `-netconf-tls-default-username` | string | empty | NETCONF user for a client certificate that is not in the identity table. Empty means such a client is refused. Requires `-netconf-enable`. |

Only `cisco_catalyst_9500` and `juniper_mx10004` devices open NETCONF ports.
Other device types never do.
The three identity flags are global and apply to the whole fleet.

## Connect

The sections Connect, Subscribe and Notifications describe the IOS XE dialect of `cisco_catalyst_9500`.
The Junos dialect has its own section below.

The login is the device SSH login (`simadmin` / `simadmin`).
The host key is the shared simulator host key.
The server accepts only the `netconf` SSH subsystem.
It refuses `shell`, `exec` and every other request.
One NETCONF session runs per SSH connection.
The connection closes when the session ends.
A session lives as long as the client keeps it, and nl6 does not close idle sessions.

```bash
ssh -s -p 830 simadmin@10.42.0.1 netconf
```

The hello advertises base 1.0 and 1.1, `notification`, `interleave`, the draft `ietf-event-notifications`, `ietf-yang-push`, the two Cisco deviation modules `cisco-xe-ietf-event-notifications-deviation` and `cisco-xe-ietf-yang-push-deviation`, and `ietf-interfaces`.
Framing switches to chunked after both sides advertise base 1.1.

## Subscribe

nl6 follows the IOS XE draft dialect.

```xml
<establish-subscription xmlns="urn:ietf:params:xml:ns:yang:ietf-event-notifications"
                        xmlns:yp="urn:ietf:params:xml:ns:yang:ietf-yang-push">
  <stream>yp:yang-push</stream>
  <yp:xpath-filter>/interfaces-ios-xe-oper:interfaces/interface[name='GigabitEthernet1/0/24']/oper-status</yp:xpath-filter>
  <yp:dampening-period>0</yp:dampening-period>
</establish-subscription>
```

### Accepted paths

The module is `interfaces-ios-xe-oper`, backed by `Cisco-IOS-XE-interfaces-oper`.
Leave out the `[name=...]` predicate to watch every interface.
The predicate accepts single or double quotes.

| Path | Pushes |
|------|--------|
| `/interfaces-ios-xe-oper:interfaces/interface[name=K]/oper-status` | The oper-status leaf. |
| `/interfaces-ios-xe-oper:interfaces/interface[name=K]/admin-status` | The admin-status leaf. |
| `/interfaces-ios-xe-oper:interfaces/interface[name=K]` | The interface row. |

The subscription must carry `<stream>`, an `xpath-filter` and `dampening-period` 0.
A subscription to an interface that does not exist is accepted and gets one empty `push-update`.
Statistics changes alone never push.

### Replies

| Request | Reply |
|---------|-------|
| Accepted subscription | `subscription-result` `notif-bis:ok` and a `subscription-id`. IDs start at 2147483648. |
| Missing `<stream>`, unknown module, a path below `interface` that is not a leaf above | `notif-bis:error-no-such-option` |
| Container `/interfaces-ios-xe-oper:interfaces` | `notif-bis:error-no-such-option` |
| Path under `/if:interfaces-state` (`ietf-interfaces`) | `notif-bis:error-other` |
| Malformed XPath, or neither `dampening-period` nor `period` | `notif-bis:error-other` |
| Missing `xpath-filter` | `notif-bis:error-other` |
| Periodic subscription (`period`) | `notif-bis:error-no-such-option` |
| `dampening-period` other than 0 | `rpc-error`, type `protocol`, tag `invalid-value`, `bad-element` `dampening-period` |
| `establish-subscription` in the RFC 8639 namespace | `rpc-error`, tag `unknown-namespace` |
| More than 256 subscriptions in one session | `notif-bis:error-other` |
| `delete-subscription` of a live ID | `notif-bis:ok` |
| `delete-subscription` of an unknown or deleted ID | `notif-bis:error-no-such-subscription` |
| `kill-session` of another session | `<ok/>` |
| `kill-session` of the own session or an unknown ID | `rpc-error`, tag `invalid-value`, `bad-element` `session-id` |
| `close-session` | `<ok/>`, then the connection closes |
| Any other operation, including `get` and `create-subscription` | `rpc-error`, tag `operation-not-supported` |

## Notifications

Right after the reply, each subscription receives the current value of its selection.
The first interface (lowest ifIndex) arrives as `push-update`.
Every other interface arrives as `push-change-update`.

### push-update

```xml
<notification xmlns="urn:ietf:params:xml:ns:netconf:notification:1.0"><eventTime>2026-10-29T11:10:17.42Z</eventTime><push-update xmlns="urn:ietf:params:xml:ns:yang:ietf-yang-push"><subscription-id>2147483648</subscription-id><datastore-contents-xml><interfaces xmlns="http://cisco.com/ns/yang/Cisco-IOS-XE-interfaces-oper"><interface><name>AppGigabitEthernet1/0/1</name><oper-status>if-oper-state-ready</oper-status></interface></interfaces></datastore-contents-xml></push-update></notification>
```

A subscription to a missing interface gets `<datastore-contents-xml/>`.

### push-change-update

```xml
<notification xmlns="urn:ietf:params:xml:ns:netconf:notification:1.0"><eventTime>2026-10-29T11:12:49.20Z</eventTime><push-change-update xmlns="urn:ietf:params:xml:ns:yang:ietf-yang-push"><subscription-id>2147483651</subscription-id><datastore-changes-xml><yang-patch xmlns="urn:ietf:params:xml:ns:yang:ietf-yang-patch"><patch-id>null</patch-id><edit><edit-id>edit1</edit-id><operation>merge</operation><target>/interfaces/interface=GigabitEthernet1%2F0%2F24</target><value><interface xmlns="http://cisco.com/ns/yang/Cisco-IOS-XE-interfaces-oper"><oper-status>if-oper-state-lower-layer-down</oper-status></interface></value></edit></yang-patch></datastore-changes-xml></push-change-update></notification>
```

`eventTime` has two fractional digits and a `Z` suffix.
The interface name in `<target>` is percent-encoded, so `/` becomes `%2F`.
`last-change` and `discontinuity-time` in a row use six fractional digits and `+00:00`.

### State values

| nl6 state | `admin-status` | `oper-status` |
|-----------|----------------|---------------|
| Admin up, link up | `if-state-up` | `if-oper-state-ready` |
| Admin up, link down | `if-state-up` | `if-oper-state-lower-layer-down` |
| Admin down | `if-state-down` | `if-oper-state-no-pass` |
| Admin testing | `if-state-test` | `if-oper-state-test` |
| Link testing, admin up | `if-state-up` | `if-oper-state-test` |
| Link unknown, dormant or not present | `if-state-up` | `if-oper-state-unknown`, `-dormant`, `-not-present` |

A change pushes one notification per affected subscription, newest subscription first.
`no shutdown` sends `if-oper-state-invalid`, then `if-oper-state-lower-layer-down`, then `if-oper-state-ready`.
nl6 sends the first two steps to each subscription in turn, newest subscription first.
Then it sends `if-oper-state-ready` to all of them, again newest first.
The captures cannot tell this order apart from an order by leaf type (row, admin leaf, oper leaf).
An `admin-status` subscription re-sends its unchanged value when anything else in the row changes.

## Junos dialect

`juniper_mx10004` devices serve this dialect over SSH and over TLS.
nl6 follows the behaviour of a vJunos-router 25.4R1.12 and puts the profile's own Junos version (`24.2R1.17`) in the `junos` namespace of every reply.
The two transports differ only in how the session starts.

### Connect over SSH

The login is the device SSH login (`simadmin` / `simadmin`) and the subsystem is `netconf`, as on the IOS XE profile.

```bash
ssh -s -p 830 simadmin@10.42.0.1 netconf
```

### Hello

The server writes its hello first, as soon as the transport is ready.
Over SSH that is when the `netconf` subsystem is requested.
Over TLS there is no subsystem step, so it is right after the handshake.
Two comment lines come before the hello.
The second names the NETCONF user.
The hello lists 19 capabilities, among them `notification`, `interleave`, `ietf-netconf-monitoring` and the Junos `http://xml.juniper.net/netconf/junos/1.0`.

```xml
<!-- No zombies were killed during the creation of this user interface -->
<!-- user ncuser, class j-super-user -->
<hello xmlns="urn:ietf:params:xml:ns:netconf:base:1.0">
  <capabilities>
    <capability>urn:ietf:params:netconf:base:1.0</capability>
    ...
  </capabilities>
  <session-id>22853</session-id>
</hello>
```

Framing is base 1.0 end-of-message (`]]>]]>`) only.
nl6 never switches to chunked framing, even when the client advertises base 1.1.

### RPCs

| Request | Reply |
|---------|-------|
| `create-subscription` with `<stream>NETCONF</stream>` (or no stream) | `<ok/>`. Link events follow. A second one adds nothing. |
| `create-subscription` with any other stream | `rpc-error` `syntax error`, `bad-element` `create-subscription` |
| `get` with the RFC 5277 streams filter (`urn:ietf:params:xml:ns:netmod:notification`) | An empty `<data>`. |
| `get` with a `netconf-state` filter (`ietf-netconf-monitoring`) | `<data>` with the hello capabilities under `netconf-state/capabilities`. |
| `get` with any other filter, or none | `<data>` with a reduced `<configuration>`. |
| `get-configuration` | The same reduced `<configuration>` without the `<data>` wrapper. |
| `close-session` | `<ok/>`, then the comment `<!-- session end at ... -->`, then the connection closes. |
| `kill-session` of another session | `<ok/>` and the other session closes. |
| `establish-subscription` (draft or RFC 8639 namespace) | `rpc-error` `syntax error`, repeated twice in one reply. |
| Anything else, including `get-interface-information` and `kill-session` of the own or an unknown ID | `rpc-error` `syntax error` with the request name as `bad-element`. |

The refusal has this shape:

```xml
<rpc-error>
<error-type>protocol</error-type>
<error-tag>operation-failed</error-tag>
<error-severity>error</error-severity>
<error-message>syntax error</error-message>
<error-info>
<bad-element>bogus-rpc</bad-element>
</error-info>
</rpc-error>
```

The reduced `<configuration>` holds only `<version>` and `<system><host-name>`.

### Link events

A derived oper change on an interface sends two notifications, back to back, with the same `eventTime`.
The event is a mib2d `SNMP_TRAP_LINK_DOWN` or `SNMP_TRAP_LINK_UP`.
The first notification is the `state-system-syslog` form.

```xml
<notification xmlns="urn:ietf:params:xml:ns:netconf:notification:1.0">
<eventTime>2026-10-30T16:51:31+00:00</eventTime>
<state-system-syslog>
<state>
  <system>
    <syslog>
      <messages>
        <message>
          <timestamp>1793379091841089</timestamp>
          <id>SNMP_TRAP_LINK_DOWN</id>
          <severity>WARNING</severity>
          <facility>DAEMON</facility>
          <priority>28</priority>
          <pid>18896</pid>
          <log-message>SNMP_TRAP_LINK_DOWN: ifIndex 529, ifAdminStatus down(2), ifOperStatus down(2), ifName ge-0/0/1</log-message>
          <application>mib2d</application>
          <structured-data>
            <parameters>
              <parameter><name>snmp-interface-index</name><value>529</value></parameter>
              <parameter><name>admin-status</name><value>down(2)</value></parameter>
              <parameter><name>operational-status</name><value>down(2)</value></parameter>
              <parameter><name>interface-name</name><value>ge-0/0/1</value></parameter>
            </parameters>
          </structured-data>
        </message>
      </messages>
    </syslog>
  </system>
</state>
</state-system-syslog>
</notification>
```

The second is the `syslog/junos/events/event` form.

```xml
<notification xmlns="urn:ietf:params:xml:ns:netconf:notification:1.0">
<eventTime>2026-10-30T16:51:31+00:00</eventTime>
<syslog>
<junos>
  <events>
    <event>
      <id>SNMP_TRAP_LINK_DOWN</id>
      <type>2</type>
      <priority>28</priority>
      <facility>3</facility>
      <timestamp>
        <seconds>1793379091</seconds>
        <microseconds>841089</microseconds>
      </timestamp>
      <pid>18896</pid>
      <message>SNMP_TRAP_LINK_DOWN: ifIndex 529, ifAdminStatus down(2), ifOperStatus down(2), ifName ge-0/0/1</message>
      <daemon>mib2d</daemon>
      <hostname>r1</hostname>
      <attributes><key>snmp-interface-index</key><value>529</value></attributes>
      <attributes><key>admin-status</key><value>down(2)</value></attributes>
      <attributes><key>operational-status</key><value>down(2)</value></attributes>
      <attributes><key>interface-name</key><value>ge-0/0/1</value></attributes>
    </event>
  </events>
</junos>
</syslog>
</notification>
```

The wire form has the XML on fewer lines.
`eventTime` is whole seconds with a `+00:00` offset.
`hostname` is the device `sysName`.

| Change | Event |
|--------|-------|
| Physical interface oper up to down | `SNMP_TRAP_LINK_DOWN`, severity `WARNING`, priority 28. |
| Physical interface oper down to up | `SNMP_TRAP_LINK_UP`, severity `NOTICE`, priority 29. |
| Logical unit oper down to up | `SNMP_TRAP_LINK_UP`, severity `INFORMATIONAL`, priority 30. |
| Logical unit oper up to down | Nothing. |
| Admin change that leaves oper as it was | Nothing. |

nl6 sends each event at once.

## NETCONF over TLS

Each `juniper_mx10004` device listens on `-netconf-tls-port` when `-netconf-enable` is set.
The listener binds whether or not a client CA is configured.
The transport follows RFC 7589 and the behaviour of Junos.

- TLS 1.2 only. A TLS 1.3-only client is refused.
- Mutual TLS. A client without a certificate, or with one from another CA, is refused at the handshake.
- The server certificate is the shared simulator certificate, the same one the HTTPS REST surface and gNMI use.
- With no client CA configured, every handshake is refused. The startup log says so. A later `PUT /api/v1/netconf/tls` with a CA applies to the next connection.

### Client identity

A client certificate that passes the handshake maps to a NETCONF user by its SHA-256 fingerprint.
nl6 looks in the identity table first and then uses the default username.
With neither, the handshake completes and the connection closes with no hello, as Junos does.
The user only names the session in the hello comment.
nl6 has no per-user authorisation.

A fingerprint is `04:` followed by the 32 SHA-256 bytes as upper-case hex pairs.
Input may also be bare hex or colon-separated pairs without the prefix, in any case.
The table is fleet-wide.
A change applies to new connections and running sessions keep their user.

```bash
sudo ./nl6 -netconf-enable \
  -netconf-tls-client-ca client-ca.pem \
  -netconf-tls-client-identity 04:AA:BB:...=ncuser \
  -netconf-tls-default-username guest
```

### REST

| Endpoint | Purpose |
|----------|---------|
| `GET /api/v1/netconf/tls` | The client CA PEM, the identity table and the default username. Fingerprints use the `04:` spelling. Answers 404 when the subsystem is off. |
| `PUT /api/v1/netconf/tls` | Replace the whole table. An omitted field clears it. Answers 404 when the subsystem is off, 400 for a bad body. |
| `GET /api/v1/tls/ca` | The PEM of the CA that signed the shared server certificate. Content type `application/x-pem-file`. |

```json
{
  "ca_pem": "-----BEGIN CERTIFICATE-----\n...\n-----END CERTIFICATE-----\n",
  "identities": {"04:AA:BB:...": "ncuser"},
  "default_username": "guest"
}
```

`ca_pem` is inline, never a path.
It may hold certificate blocks only.
Any other PEM block, such as a private key, is a 400.

### Trust the server

The shared server certificate carries only a `0.0.0.0` IP SAN.
A client that verifies the host name against the device IP fails.
Skip host-name verification and pin the CA from `GET /api/v1/tls/ca` instead.

```bash
curl -s http://localhost:8080/api/v1/tls/ca > nl6-ca.pem
```

## Status endpoint

`GET /api/v1/netconf/status` reports the subsystem.

```json
{
  "subsystem_active": true,
  "listeners": 4,
  "sessions": 1,
  "subscriptions": 3,
  "notifications_sent": 12,
  "notifications_dropped": 0,
  "listeners_tls": 2,
  "sessions_tls": 1,
  "tls_handshake_failures": 0
}
```

| Field | Meaning |
|-------|---------|
| `subsystem_active` | `true` when `-netconf-enable` is set. All other fields are zero when `false`. |
| `listeners` | Devices with an open NETCONF listener. |
| `sessions` | Open NETCONF sessions. |
| `subscriptions` | Live subscriptions across all sessions. |
| `notifications_sent` | Notifications written to a client. |
| `notifications_dropped` | Notifications dropped because a slow client let its queue of 100 fill. The oldest is dropped first. |
| `listeners_tls` | Devices with an open NETCONF over TLS listener. |
| `sessions_tls` | Open NETCONF sessions over TLS. |
| `tls_handshake_failures` | TLS handshakes that failed. This also counts benign TCP probes and aborts at the idle deadline, as the gNMI counter does. |

A push can also be lost one stage earlier, before it is rendered.
Each session listens to the interface state engine on a 16-deep channel.
An event dropped there is not counted in `notifications_dropped`.
It appears in `state_events_dropped` of `GET /api/v1/gnmi/status`, the counter that state-change fan-out to gNMI and NETCONF shares.

## Limitations

nl6 emulates one real device per profile and serves less where it has no capture.
The IOS XE list is in [Cisco Catalyst 9500 NETCONF limitations](https://github.com/labmonkeys-space/nl6/blob/main/go/nl6/resources/cisco_catalyst_9500_limitations.md).
The first entry there matters most.
An admin change on a link-down interface sends a trap and a syslog message but no NETCONF notification, as on the real switch.

The Junos list is in [Juniper MX10004 NETCONF limitations](https://github.com/labmonkeys-space/nl6/blob/main/go/nl6/resources/juniper_mx10004_limitations.md).
The main points are these.

- nl6 sends link events only. The background syslog stream of a real device is absent.
- `get` and `get-configuration` return a reduced configuration and every other RPC is a `syntax error`.
- Only a fingerprint table plus a default username maps a client. There is no mapping by certificate name.
- The framing is base 1.0 only.
- The TLS alert bytes differ from Junos. The refusal is the same.

`make test-interop-netconf-junos` diffs the Junos dialect against a real vJunos-router over TLS and SSH: the hello, the RPCs and the link events of one interface disable and enable.
