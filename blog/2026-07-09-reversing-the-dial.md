---
title: "Reversing the dial: the many faces of gNMI dial-out"
authors: ronny
tags: [gnmi, networking, monitoring, udp-notif, nl6, dial-out, streaming-telemetry, yang]
---

Ask five vendors how they do "gNMI dial-out" and you'll get five different
answers.
You'll find everything a custom gRPC service here, an opaque protobuf envelope there, a
generic tunnel over on the standards track.
When I started to work on **gNMI dial-out** in [nl6](https://github.com/labmonkeys-space/nl6), I wanted the whole map, not just the one corner I'd already implemented.
Here's the map.

The punchline up front, because it reframes everything: **gNMI has no dial-out.**

## Wait — gNMI doesn't have dial-out?

Correct, and this is the single fact that makes the landscape legible.

The gNMI specification defines exactly one way to stream telemetry: the `Subscribe` RPC, where the collector is the gRPC client and the device is the server.
The collector reaches in, opens a subscription, and the device answers on that same connection.
That's dial-in.
It's the only mode the `gnmi.proto` service knows about.

But dial-in has a real operational problem.
If your device sits behind NAT, or behind a firewall that won't allow inbound connections, or you simply don't want to run an always-listening management service on thousands of edge boxes, then "the collector connects to the device" is exactly backwards.
You want the device to reach out.

So every vendor built that themselves.
And because they built it independently, "gNMI dial-out" isn't a protocol — it's a category with three families.

## The three families

### 1. Reverse-gNMI: keep the payload, flip the roles

The cleanest trick: define a brand-new gRPC service whose whole job is to carry gNMI's *existing* `SubscribeResponse` message — but with the roles reversed.
The device becomes the client and dials out; the collector runs the server.

Arista's `gNMIReverse` is the poster child.
Its service is almost insultingly simple:

```protobuf
service gNMIReverse {
  rpc Publish(stream gnmi.SubscribeResponse) returns (google.protobuf.Empty);
  rpc PublishGet(stream gnmi.GetResponse)    returns (google.protobuf.Empty);
}
```

The device streams the same `SubscribeResponse` messages a dial-in `Subscribe` would have produced, and the server just says `Empty` — no per-message ack, fire-and-forget.
Nokia's SR OS made the identical structural choice: a separate `Publish` RPC that reuses `SubscribeResponse`, because (in Nokia's own words) the gNMI proto doesn't define dial-out.

The beauty of this family is interoperability.
The bytes on the wire are ordinary gNMI notifications, so any collector that already understands gNMI can decode them.
No special protos, no vendor SDK.

### 2. MDT envelope: telemetry in a paper bag

Cisco's Model-Driven Telemetry takes a different tack.
Its dial-out service carries an opaque payload:

```protobuf
service gRPCMdtDialout {
  rpc MdtDialout(stream MdtDialoutArgs) returns (stream MdtDialoutArgs);
}
message MdtDialoutArgs { int64 ReqId=1; bytes data=2; string errors=3; int32 totalSize=4; }
```

The actual telemetry lives inside `data` as a serialized `Telemetry` message, and to decode it you need Cisco's `.proto` files.
This is the world of GPB encoding variants: compact GPB (smallest, but the collector needs the exact per-path proto), and key-value / self-describing GPB (carries field names, one `telemetry.proto` decodes everything).
Cisco recommends KV-GPB as the sensible midpoint, and honestly, having stared at the alternative, they're right.

Huawei (CloudEngine) and H3C ship the same shape — an RPC layer, a telemetry layer, and a service-data layer, all in separate protos that must match on both ends.
Which brings us to my favorite footgun in the entire space: Cisco prepends an internal header before the protobuf payload — 12 bytes on IOS-XR, 6 bytes on NX-OS.
Feed those bytes straight into a protobuf decoder, and it fails, cryptically.
Somewhere out there is an engineer who lost an afternoon to this or maybe several.

### 3. The gRPC tunnel: don't touch gNMI at all

The OpenConfig community looked at all this and made a deliberate call: rather than bolt a dial-out mode onto gNMI, define a generic gRPC tunnel that reverses the TCP direction and let the unmodified gNMI server run back through it.
The device dials out to a tunnel server and registers its "targets"; the tunnel server then acts as an ordinary gNMI (or gNOI, or SSH!) client through the established tunnel.

The elegance here is that nothing about gNMI changes.
Your existing gNMI server runs untouched; a separate little tunnel-client binary forwards traffic over a local loopback.
And because the tunnel is generic, the same mechanism carries gNMI, gNOI, and SSH.
Cisco IOS-XE adopted exactly this from 17.11.1 onward, and OpenConfig's own `gnmic` collector embeds the tunnel server.

If reverse-gNMI is the pragmatic hack and MDT is the vendor silo, the gRPC tunnel is the standards-track answer.

(Juniper's JTI is a historical fourth shape — config-driven proprietary export via `services analytics`, with `native-grpc-gpb` over TCP or `native-udp-*` over UDP.
It predates the message-reuse idea, and Juniper's gNMI story leans dial-in.)

## The differences that actually bite

Families aside, a handful of axes decide how these behave in production:

- **Transport.** Only **Cisco XR and Juniper** offer UDP dial-out — lowest overhead, no TLS, no delivery guarantee. Everyone else rides gRPC over HTTP/2 over TLS.
- **Lifecycle.** Dial-out subscriptions are **persistent**: configured on the device, they survive a session drop, and the *device* owns reconnection (Cisco retries every ~30s). Dial-in subscriptions are dynamic and die with the session.
- **The 100-stream wall.** This one is universal and nasty. A single gRPC connection rides one HTTP/2 connection, and HTTP/2 defaults to `MAX_CONCURRENT_STREAMS = 100`. Exceed it and your calls don't error — they **silently queue**. The correct pattern for a fleet is one connection and one stream *per device*. Nokia even bounds it on the box: 8 sessions, 225 channels.
- **HA topology.** Because the device dials out, you can point a whole fleet at a single **anycast VIP** and let BFD steer each device to the nearest healthy collector. Dial-in simply can't do that. Swisscom runs exactly this pattern. But anycast only buys you the *first* handshake. A dial-out stream is long-lived and sticky, so when a collector dies or you want to rebalance, nothing moves until the device tears the session down and re-dials — usually because a draining collector waved it off with an HTTP/2 `GOAWAY`. The state lives in the session, so HA here is less about *where* sessions land and more about *how fast you can churn them*.
- **Security, and who trusts whom.** TLS everywhere on gRPC, and mTLS is common — and mTLS cuts both ways by definition: before the device ever shows its own client cert, it checks the collector's cert against its local CA bundle. So the client cert proves the device *to* the collector; trusting the collector back is a separate job the CA bundle does. The twist with dial-out is *where that trust has to live*. Every device now needs the right CA anchors baked in to verify the collector — and pushing trust onto thousands of boxes is the kind of chore that's a one-liner in a diagram and a genuine headache in production.

## So what does this mean for a simulator?

nl6 simulates network devices, and it speaks today the Arista `gNMIReverse` flavor.
This map tells me where to go and I'll probably add Nokia's `Publish` next.
It is nearly free and goes into the same reverse-gNMI family, same `SubscribeResponse` payload.
The Cisco MDT KV-GPB is the genuinely different, higher-effort option.
It has a whole new envelope and encoding and needs to take care of these internal headers.

## Where the puck is going

Streaming telemetry is displacing SNMP polling across the board, and AI/GPU fabrics are pouring gasoline on the fire.
You can't catch a microburst or a RoCE credit pause with a five-minute poll.
gNMI dominates telemetry today.

The interesting challenger isn't another gRPC dialect at all: it's the IETF's YANG-Push over UDP-Notif, which streams straight from the line cards IPFIX-style, with rich metadata for correlating against flows and topology.
And that's the whole point: drop the heavy TCP/HTTP/2 state machine off the line card and telemetry can pour straight out of the forwarding hardware — the same trick that let IPFIX run at wire rate for years while everything stateful stayed up on the route processor.
That's a different transport paradigm, and it's on nl6's list.

But that's a post for another day.

