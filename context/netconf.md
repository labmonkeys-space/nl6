# NETCONF over SSH (IOS XE dialect)

Engineering record for the NETCONF subsystem.
Files: `go/nl6/netconf_*.go`.
Operator reference: `docs/reference/netconf.md`.
Limitations: `go/nl6/resources/cisco_catalyst_9500_limitations.md`.

## Shape

One listener per `cisco_catalyst_9500` device on `-netconf-port`, bound inside the device netns.
It reuses the device SSH login and `sharedSSHSigner`, and accepts only the `netconf` subsystem.
A session is a hello, an RPC loop and one `InterfaceState` listener that turns `StateChange` events into pushes.
RPC replies are written under the session write mutex.
Pushes go through a 100-deep oldest-drop queue and one writer goroutine.
The sync-on-start burst writes directly on the RPC goroutine so it is never dropped.
When a session ends, the whole SSH connection closes.

## Captures

- A c8000v on IOS XE 26.01.02 gave the dialect, the refusals, the all-interface subscriptions and the `no shutdown` sequence.
- A Catalyst 9300 (C9300LM-24U-4Y, IOS XE 26.02.1) gave the hello, percent-encoded targets, row leaves, the RPC table and the silent admin change on an unplugged port.
- Both live in the planning artifacts of the NETCONF design, not in this repo.
- The golden fixtures in `go/nl6/testdata/netconf/` are the Cat9300 notifications.

## Decisions

- D1: nl6 is the integration target for the OpenNMS NETCONF client.
- D2: SSH first, TLS second.
- D3: "broader TLS support" is false in general and true only for Nokia Lightspan.
- D4: Orange reads Altiplano's northbound interface, which nl6 cannot honestly emulate.
- D5: Emulate the IOS XE dialect byte for byte, not the RFC 8639 shape.
- D6: TLS moves to the Junos profiles.
- D7: Start fresh. A fork branch with TLS and RFC 8639 matched no real device and is not ported.
- D8: Push admin changes on link-down ports. Superseded by D10.
- D9: Send notifications immediately, with no simulated device delay.
- D10: Match the Cat9300. No notification for admin changes on an interface whose link is down, and document it.
- D11: The OpenNMS client starts with the IOS XE draft dialect.
- D12: Keep reporting every change at once and document the fast-flap difference.

## Rulings made while building

- R4: sync-on-start sends `push-update` only for the device's first interface. Every other interface gets `push-change-update`, keyed or keyless. This matches all three captures.
- R9: `last-change` and `discontinuity-time` use six fractional digits in pushes.
- R11 and R14: the hello lists only capabilities nl6 serves, each byte-identical to the Cat9300 hello. It has no `yang-library` and no `Cisco-IOS-XE-interfaces-oper` line, because the real hello has none.
- R13: `create-subscription` and `period` stay refused.
- R15: `error-info` matches the device form.
- R17: `no shutdown` sends `invalid` then `lower-layer-down` per subscription in reverse creation order, then `ready`.
- R18: an admin and oper pair from `ApplyAdminStatus` merges into one push per subscription.
- R19: the 9500 profile has no loopbacks or SVIs, so the no-invalid-step rule for loopbacks is not implemented. Add it if a profile gains loopbacks.
- R21: one NETCONF session per SSH connection.
- R25: the live link-up and shutdown comparison against the c8000v is incomplete. Those sequences are pinned by unit tests built from the c8000v capture and the Cat9300 captures.

## Traps

- `SSHServer.handleConnection` in `ssh.go` sets an absolute 5-minute connection deadline for the interactive shell.
- A NETCONF session sits quiet for hours, so reusing that path would kill it at 5 minutes.
- The NETCONF listener has its own accept loop. It uses the 5-minute deadline for the handshake only, clears it, and relies on TCP keepalive.
- `TestNetconfSessionOutlivesSSHIdleDeadline` pins this. `sshIdleTimeoutOverride` is atomic because port 22 goroutines read it.
- The engine listener (`AddListener`) counts emitted and dropped events into the same `state_events_emitted` and `state_events_dropped` totals that `GET /api/v1/gnmi/status` reports, so those totals include NETCONF listeners.
- `RemoveListener` must run before the listener channel is closed.
- `SetNotify` belongs to the Tier C traps and syslog. NETCONF never calls it.
- The NETCONF subsystem does not apply `-fidelity` silencing.

## Testing against a real device

- `make test-interop-netconf` diffs normalised replies and notifications between an in-process 9500 and a reference IOS XE device.
- The reference is a c8000v VM. Its subscription limit is about 128 per device.
- Its `pubd` process crashes after pushing interface changes on 26.01.02. It restarts on its own.
- A dropped probe session leaks subscriptions on the VM, which then answers "application communication failure". Reboot the VM to clear it.
- Do not run a 257-subscription cap probe against the c8000v.

## Scale

Idle-session cost, measured with `BenchmarkNetconfIdleSessions` (2026-10-29, Linux 6.x aarch64 in a privileged OrbStack container, Go 1.27.3, one cisco_catalyst_9500 device on loopback).
Each session is an SSH connect, hello and one keyless on-change subscription (`/interfaces-ios-xe-oper:interfaces/interface/oper-status`, dampening 0), then idle.
The clients run in a child process, so the numbers are the server half only.
They are the parent's heap and goroutine growth after a forced GC, divided by N.

| Sessions | Heap per session | Goroutines per session |
|---|---|---|
| 1000 | 36.6 KB | 10 |
| 5000 | 36.5 KB | 10 |

Heap is about 1.1x the 2026-10-14 spike (33 KB, plain SSH sessions).
Goroutines are 10, not the spike's 4.
SSH itself holds about 4 per connection (mux loop, kex loop, transport read, channel buffer read).
The session adds about 6: the connection accept wait, request discard, channel request handler, `Serve` input reader, writer and state listener.

Run it with `NL6_NETCONF_BENCH_N=5000 go test ./nl6/ -run '^$' -bench NetconfIdleSessions -benchtime 1x` on Linux.
Raise `ulimit -n` first.
