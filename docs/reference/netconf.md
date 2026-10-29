# NETCONF reference

nl6 can serve NETCONF over SSH on `cisco_catalyst_9500` devices.
A client opens an IOS XE style `establish-subscription` and receives a notification each time the interface state engine changes an interface.
The subsystem is off by default.
A default fleet behaves exactly as without it.

## Flags

| Name | Type | Default | Description |
|------|------|---------|-------------|
| `-netconf-enable` | bool | `false` | Enable the NETCONF over SSH subsystem. `cisco_catalyst_9500` devices then listen on `-netconf-port`. |
| `-netconf-port` | int | `830` | TCP port of the per-device NETCONF listener. |

Only `cisco_catalyst_9500` devices open the port.
Other device types never do.

## Connect

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

## Status endpoint

`GET /api/v1/netconf/status` reports the subsystem.

```json
{
  "subsystem_active": true,
  "listeners": 4,
  "sessions": 1,
  "subscriptions": 3,
  "notifications_sent": 12,
  "notifications_dropped": 0
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

A push can also be lost one stage earlier, before it is rendered.
Each session listens to the interface state engine on a 16-deep channel.
An event dropped there is not counted in `notifications_dropped`.
It appears in `state_events_dropped` of `GET /api/v1/gnmi/status`, the counter that state-change fan-out to gNMI and NETCONF shares.

## Limitations

nl6 emulates one real device, a Catalyst 9300, and serves less where it has no capture.
The list is in [Cisco Catalyst 9500 NETCONF limitations](https://github.com/labmonkeys-space/nl6/blob/main/go/nl6/resources/cisco_catalyst_9500_limitations.md).
The first entry there matters most.
An admin change on a link-down interface sends a trap and a syslog message but no NETCONF notification, as on the real switch.
