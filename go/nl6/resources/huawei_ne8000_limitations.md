# Huawei NE8000 YANG-Push Limitations

The `huawei_ne8000` profile streams YANG-Push over UDP-notif when a device opts in with the `yang_push` block.
It serves NETCONF over SSH when you start nl6 with `-netconf-enable`.
It models Huawei VRP R025C00.
This page says where the simulation ends.
See the [YANG-Push reference](../../../docs/reference/yang-push-udp-notif.md) for the wire behavior.

## Subscription 10 follows a capture, with four differences

Subscription 10 is the on-change subscription of a captured VRP router: the whole interface entry, dampening 5 seconds.
Four things differ from the capture.

- `higher-layer-if` and `lower-layer-if` are not sent.
- The sync `push-update` goes out right after `subscription-started`, not 5 seconds later.
- `patch-id` counts the change-updates of a device from 0.
  The capture has one change-update and cannot confirm the counter.
- Changes inside a dampening period are collected into one update with one edit per interface.
  The capture cannot confirm this either.

The ID 10 and the filter reference `ONCHANGEINTERFACE` are nl6's own.

Only a change of `admin-status` or `oper-status` triggers a change-update.
A new `description`, for example after a topology link is added, appears in subscription 9 and not in subscription 10 until that interface changes state.

## Statistics cover every interface

Subscription 8 reports statistics for every interface.
A real NE8000 sends statistics for a subset.

## A guessed module revision

The `ietf-udp-client` revision `2025-05-14` is a guess.
`ietf-yang-push-revision` is served at revision `2025-08-29`, the revision NetGauze v0.13.0 bundled when the fixtures were written. NetCalyx v0.4.0 bundles 2025-12-07, not yet checked against nl6. The NE library does not list the module. Its payload keys `module-version` by `name`, which only 2025-08-29 defines (2024-12-17 used `module-name`).
The device library lists none.
Two `augmented-by` rows under `ietf-subscribed-notifications` follow a Huawei MA5800T, not the NE8000.

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
NetCalyx reports that as a parse error.

## Fidelity and scenarios

`-fidelity` mutes all three subscriptions.
The `subscription-started` notification waits for the first unmuted activity.
The subscriptions do not take part in a load-test scenario window.

## One burst a minute

Every device fires subscription 8 at the same wall-clock second and subscription 9 three seconds later.
A large fleet sends a synchronized burst each minute.
nl6 gives every device the same anchor, so the whole fleet bursts together.
A real fleet does only if every device is configured with one anchor.

## Other vendors

Only Huawei VRP R025C00 and later, and Cisco IOS XR 25.3.1 and later, ship YANG-Push over UDP-notif among the types nl6 models.
The Catalyst 9500 and Junos MX do not.
Cisco IOS XR is the planned next profile.
