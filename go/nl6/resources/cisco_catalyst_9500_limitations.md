# Cisco Catalyst 9500 NETCONF Limitations

The `cisco_catalyst_9500` profile serves NETCONF over SSH when you start nl6 with `-netconf-enable`.
It emulates the IOS XE draft dialect of a real Catalyst 9300.
This page says where the simulation ends.
See the [NETCONF reference](../../../docs/reference/netconf.md) for the wire behavior.

## An admin change on a link-down interface sends no NETCONF notification

This one is not obvious, so it comes first.
Say an operator runs `shutdown` or `no shutdown` on an unplugged port.
nl6 sends a trap and a syslog message.
nl6 sends no NETCONF notification.
A real Catalyst 9300 behaves the same way.
The state still changes, so SNMP, gNMI and a NETCONF client that reads the state see the new value.
Interfaces whose link is up push admin changes as usual.

## Fast flaps are reported

nl6 sends every change at once.
A real Catalyst 9300 pushes about 2 seconds after a change.
It merges a `shutdown` followed by a `no shutdown` within 1 second into one push with the final state.
OpenNMS can see down and up events in testing that a real switch would hide.

## Subscriptions

- nl6 accepts `establish-subscription` in the 2016 `ietf-event-notifications` namespace only, as the device does.
- nl6 refuses on-change on `ietf-interfaces`, and the RFC 8639 namespace, as the device does.
- Only on-change with `dampening-period` 0 on `Cisco-IOS-XE-interfaces-oper` is served.
- nl6 refuses `create-subscription` (RFC 5277) and periodic `period` subscriptions, although the device accepts them.
- nl6 refuses `get` and every other operation except `delete-subscription`, `close-session` and `kill-session`.
- A session holds at most 256 subscriptions. The cap is nl6's own.
- The hello lists only the capabilities nl6 serves. It does not list the full device set and it has no `yang-library` capability.

## No TLS

IOS XE does not serve NETCONF over TLS, so this profile does not either.
The listener is SSH only, with the device SSH login and the shared host key.

## Rows carry only the leaves nl6 has data for

A row subscription sends these leaves.

- `interface-type`, `admin-status`, `oper-status`, `last-change`, `if-index`, `phys-address`, `speed`
- `statistics`: `discontinuity-time` and the 12 basic in/out counters

The device sends more.
nl6 omits these leaves because it has no real source for them.

- In `statistics`: `in-unknown-protos`, `rx-pps`, `rx-kbps`, `tx-pps`, `tx-kbps`, `num-flaps`, `in-crc-errors`, `in-discards-64`, `in-errors-64`, `in-unknown-protos-64`, `out-octets-64`, `resets`
- `vrf`, `ipv4`, `ipv4-subnet-mask`, `description`, `mtu`, `input-security-acl`, `output-security-acl`
- `v4-protocol-stats`, `v6-protocol-stats`
- `bia-address`, `ipv4-tcp-adjust-mss`, `ipv6-tcp-adjust-mss`
- `intf-ext-state-support`, `intf-ext-state`, `storm-control`
- `auto-upstream-bandwidth`, `auto-downstream-bandwidth`, `bw-up-util`, `bw-down-util`
- `eee-capable`, `eee-status`, `eee-caps`
- `ether-state`, `ether-stats`

Counter changes alone never trigger a push, as on the device.

## Never captured

A cabled Catalyst 9300 port was never captured.
The silence rule above comes from an unplugged port and an up loopback.
nl6 pushes admin changes on an interface with a link because a router showed it.
