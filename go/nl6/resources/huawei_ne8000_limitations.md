# Huawei NE8000 YANG-Push Limitations

The `huawei_ne8000` profile streams YANG-Push over UDP-notif when a device opts in with the `yang_push` block.
It serves NETCONF over SSH when you start nl6 with `-netconf-enable`.
It models Huawei VRP R025C00.
This page says where the simulation ends.
See the [YANG-Push reference](../../../docs/reference/yang-push-udp-notif.md) for the wire behavior.

## Subscription 10 has no capture

Subscription 10 is on-change for `oper-status` and `admin-status`, with dampening 0 and sync on start.
The real device advertises on-change, but no capture shows it on the wire.
nl6 builds it from RFC 8641 and the envelope of the captured subscriptions.
Its sync-on-start `push-update` carries only `name`, `admin-status` and `oper-status`.
The filter reference `ONCHANGEINTERFACE` is nl6's own.

## Statistics cover every interface

Subscription 8 reports statistics for every interface.
The device in the capture sent statistics for a subset.

## A guessed module revision

The `ietf-udp-client` revision `2025-05-14` is a guess.
The device library lists none.
Two `augmented-by` rows under `ietf-subscribed-notifications` come from an MA5800T capture.

## Fixed subscriptions

The three subscriptions are fixed, with IDs 8, 9 and 10.
The period is 60 s and the anchor time is `2025-01-01T00:00:30Z`.
A collector cannot create, change or delete subscriptions over NETCONF.
nl6 serves `get`, `get-schema`, `close-session` and `kill-session`.
Every other RPC, such as `establish-subscription` or `edit-config`, gets `operation-not-supported`.
An XPath filter on `get` gets the same refusal.
NETCONF sends no notifications, because the subscriptions stream over UDP-notif.

## Beyond strict filtering

A `get` on a subscription by ID also returns its `receiver-instances`.
An unknown ID returns an empty `<data/>`.
NetGauze reports that as a parse error.

## Fidelity and scenarios

`-fidelity` mutes all three subscriptions.
The `subscription-started` notification waits for the first unmuted activity.
The subscriptions do not take part in a load-test scenario window.

## One burst a minute

Every device fires subscription 8 at the same wall-clock second and subscription 9 three seconds later.
A large fleet sends a synchronized burst each minute.
nl6 gives every device the captured anchor, so the whole fleet bursts together.
A real fleet does only if every device is configured with one anchor.

## Other vendors

Only Huawei VRP R025C00 and later, and Cisco IOS XR 25.3.1 and later, ship YANG-Push over UDP-notif among the types nl6 models.
The Catalyst 9500 and Junos MX do not.
Cisco IOS XR is the planned next profile.
