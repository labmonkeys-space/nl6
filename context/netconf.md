# NETCONF over SSH (IOS XE dialect)

Engineering record for the NETCONF subsystem.
Files: `go/nl6/netconf_*.go`.
Operator reference: `docs/reference/netconf.md`.
Limitations: `go/nl6/resources/cisco_catalyst_9500_limitations.md` and `go/nl6/resources/juniper_mx10004_limitations.md`.

## Shape

One listener per `cisco_catalyst_9500` device on `-netconf-port`, bound inside the device netns.
It reuses the device SSH login and `sharedSSHSigner`, and accepts only the `netconf` subsystem.
A session is a hello and an RPC loop.
One state-change dispatcher per device holds the single `InterfaceState` listener and calls every session's push handler for each event; the first session starts it and the last one stops it.
RPC replies are written under the session write mutex.
Pushes go through a 100-deep oldest-drop queue and one writer goroutine.
The sync-on-start burst writes directly on the RPC goroutine so it is never dropped.
When a session ends, the whole SSH connection closes.

## Captures

- A c8000v on IOS XE 26.01.02 gave the dialect, the refusals, the all-interface subscriptions and the `no shutdown` sequence.
- A Catalyst 9300 (C9300LM-24U-4Y, IOS XE 26.02.1) gave the hello, percent-encoded targets, row leaves, the RPC table and the silent admin change on an unplugged port.
- Both live in the planning artifacts of the NETCONF design, not in this repo.
- The silence rule for admin changes comes from an unplugged Cat9300 port and an up loopback. A cabled Cat9300 port was never captured. nl6 pushes admin changes on an interface with a link because the c8000v router showed it.
- The `/rpc` error-path of the `unknown-namespace` reply to an RFC 8639 `establish-subscription` is confirmed on the c8000v only.
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
- R17 ambiguity: the captures cannot tell the per-subscription grouping apart from an order by leaf type (row, admin leaf, oper leaf). Every captured sequence fits both. `netconf_events.go` implements the grouping: one push per affected subscription, newest first, every `no shutdown` step but the last per subscription, then `ready` across all.
- R25: the live link-up and shutdown comparison against the c8000v is incomplete. Those sequences are pinned by unit tests built from the c8000v capture and the Cat9300 captures.

## Traps

- `SSHServer.handleConnection` in `ssh.go` sets an absolute 5-minute connection deadline for the interactive shell.
- A NETCONF session sits quiet for hours, so reusing that path would kill it at 5 minutes.
- The NETCONF listener has its own accept loop. The 5-minute deadline bounds the handshake and the wait for the `netconf` subsystem. It is cleared when the session starts, and TCP keepalive takes over.
- `TestNetconfSessionOutlivesSSHIdleDeadline` and `TestNetconfDeadlineUntilSubsystem` pin this. `sshIdleTimeoutOverride` is atomic because port 22 goroutines read it.
- The engine listener (`AddListener`) counts emitted and dropped events into the same `state_events_emitted` and `state_events_dropped` totals that `GET /api/v1/gnmi/status` reports, so those totals include NETCONF listeners.
- So a drop on the 16-deep listener channel never reaches `notifications_dropped` in `GET /api/v1/netconf/status`. That stage shows only in the shared fan-out counter `state_events_dropped` of `GET /api/v1/gnmi/status`. The engine counters stay shared by design.
- `RemoveListener` must run before the listener channel is closed.
- `SetNotify` belongs to the Tier C traps and syslog. NETCONF never calls it.
- The NETCONF subsystem does not apply `-fidelity` silencing.

## Testing against a real device

- `make test-interop-netconf` diffs normalised replies and notifications between an in-process 9500 and a reference IOS XE device.
- The reference is a c8000v VM. Its subscription limit is about 128 per device.
- The lab record: the c8000v at 192.168.11.71, VM 8601 on the Proxmox host `root@192.168.10.92`, second NIC `virtio=BC:24:11:55:44:BC,bridge=vmbr1`. The test has no defaults. Set `NL6_NETCONF_REF`, `NL6_NETCONF_REF_PASSWORD`, `NL6_NETCONF_REF_PVE`, `NL6_NETCONF_REF_VMID` and `NL6_NETCONF_REF_NIC`, or it skips.
- Use the Proxmox host's IP, not its name. The Cisco VPN breaks `*.labmonkeys.tech` DNS.
- The test restores the reference link and admin state on a normal exit and on a test failure. A `-timeout` or Ctrl-C leaves them as they were.
- Its `pubd` process crashes after pushing interface changes on 26.01.02. It restarts on its own.
- A dropped probe session leaks subscriptions on the VM, which then answers "application communication failure". Reboot the VM to clear it.
- Do not run a 257-subscription cap probe against the c8000v.
- `make test-interop-netconf-junos` diffs the Junos dialect between an in-process mx10004 and a reference vJunos-router 25.4R1.12, over TLS and over SSH, with one Go client. Phases: the hello, the Junos RPC table without `kill-session`, `close-session` and its trailer, then `create-subscription` across one `set interfaces <if> disable` and one `delete interfaces <if> disable`. nl6 moves the admin status of xe-0/0/0, because `disable` is an admin change and both report `ifAdminStatus down(2)`.
- The Junos lab record: the `vj` containerlab on mad-monkey. From a workstation, forward the ports with `ssh -f -N -L 16513:172.20.20.2:6513 -L 10830:172.20.20.2:830 -L 10022:172.20.20.3:22 root@mad-monkey.labmonkeys.tech`. The client certificate, key and CA are in `/root/nc-lab/tls/` on mad-monkey. The reference maps the certificate to `ncuser`; its CLI and SSH NETCONF login is `admin`. Never commit the key.
- The Junos test has no defaults. Set `NL6_NETCONF_JUNOS_REF`, `NL6_NETCONF_JUNOS_REF_SSH`, `NL6_NETCONF_JUNOS_CLI`, `NL6_NETCONF_JUNOS_CLI_USER`, `NL6_NETCONF_JUNOS_CLI_PASSWORD`, `NL6_NETCONF_JUNOS_CLIENT_CERT`, `NL6_NETCONF_JUNOS_CLIENT_KEY`, `NL6_NETCONF_JUNOS_CA` and `NL6_NETCONF_JUNOS_REF_IF`, or it skips. It enables the interface again on a normal exit and on a test failure. A `-timeout` or Ctrl-C leaves it as it was.
- The reference feed carries about 1150 syslog notifications per 60 s window. The test keeps only `SNMP_TRAP_LINK_UP` and `SNMP_TRAP_LINK_DOWN` on the interface under test.
- 2026-10-30, first run: the diff found four nl6 defects, all fixed the same day:
  - nl6 sent every link-event pair twice on an admin change. `ApplyAdminStatus` broadcasts an admin event and an oper event that both carry the oper move. The Junos session now drops the twin oper event through `twinOperEvent`, as the IOS XE session always did.
  - A `get` with an `ietf-interfaces` `interfaces-state` filter got the unfiltered reply. It now gets one `syntax error` with `bad-element` `interfaces-state`, as the reference sends.
  - The unfiltered `get` lacked the empty `<database-status-information>` the reference sends after the configuration.
  - The close-session trailer lacked its leading newline. The capture missed it: the probe read the trailer from the connection, and its buffered reader already held the newline.
- 2026-10-30 re-run after the fixes: PASS over both transports in 258 s, 19 rows equal over TLS and 18 over SSH, every message compared raw with values normalised. The divergences that remain, each logged by the test:
  - Configuration bodies: nl6's 3 element paths are a subset of the reference's 76, by decision.
  - nl6's xe-0/0/0 has the VRF units .100, .200 and .999. Their link-up pairs are not compared.
  - The reference's unit .0 `SNMP_TRAP_LINK_UP` (INFORMATIONAL) came on one subscription and not on the other in one earlier run. When it is absent, nl6's is not compared.
  - The reference sends its certificate and the CA, nl6 its leaf only. Both negotiated TLS 1.2 with `TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256`.
  - Delivery lag: the reference sends link events seconds after the commit, nl6 at once. The sequence is compared.
- The vJunos CLI over SSH sometimes prints nothing to a non-interactive session, while still committing. The test keeps stdin open until it sees `Exiting configuration mode`.

## Scale

Idle-session cost, measured with `BenchmarkNetconfIdleSessions` (2026-10-31, Linux 7.2.12-orbstack aarch64 in a privileged OrbStack container, Go 1.27.3, one cisco_catalyst_9500 device on loopback; first measured 2026-10-29 before the shared dispatcher).
Each session is an SSH connect, hello and one keyless on-change subscription (`/interfaces-ios-xe-oper:interfaces/interface/oper-status`, dampening 0), then idle.
The clients run in a child process, so the numbers are the server half only.
They are the parent's heap and goroutine growth after a forced GC, divided by N.

| Sessions | Heap per session | Goroutines per session |
|---|---|---|
| 1000 | 31.9 KB | 5 |
| 5000 | 31.8 KB | 5 |

Heap is about 0.97x the 2026-10-14 spike (33 KB, plain SSH sessions).
Before the shared dispatcher (2026-10-29) a session cost 34.5 KB and 6 goroutines.
An idle session held 6 goroutines when first measured.
Three belong to x/crypto/ssh: the mux loop, the kex loop and the transport read loop.
Three were nl6's:

- the connection's dispatch loop (`serveConn`), which refuses global requests, answers channel requests and waits for the subsystem;
- the session reader (`serveChannel`), blocked in the framer's `ReadMessage`;
- the state listener.

The state listener has since moved into one dispatcher per device (`netconfDispatcher`), shared by every session on that device, so an idle session now holds 5 goroutines and a device with sessions holds one more.
The dispatcher is refcounted by the session registry: the first session starts it and the last one stops it, so an idle device holds none.
Membership changes go through the dispatcher goroutine; a join first drains the queued events to the sessions already present, so a session never receives an event broadcast before it registered.
Registration happens right after the hello, so a change in that window goes to the older sessions only, as it did when each session registered its own listener.
The interface name and the whole row are built once per event and shared by every session on the device.
The 16-deep listener channel is now per device, not per session: one event costs one dispatch to N sessions, so the depth still bounds events, but a device with many sessions spends longer per event on the one goroutine and reaches the engine's drop-oldest sooner than N parallel listeners did.
The table above is the re-run after that change; the benchmark asserts one state listener for the device, however many sessions it carries.

No writer runs while the send queue is empty.
The first push starts one and it exits once the queue drains.
The ctx watch is a `context.AfterFunc`, not a goroutine.
`TestNetconfIdleSessionGoroutines` pins two nl6 goroutines per session plus one per device, with and without a push.

The first measurement was 10 per session, with one goroutine each for global request discard, channel requests, the ctx watch and the writer.

Run it with `NL6_NETCONF_BENCH_N=5000 go test ./nl6/ -run '^$' -bench NetconfIdleSessions -benchtime 1x` on Linux.
Raise `ulimit -n` first.

## Junos dialect and TLS

`juniper_mx10004` serves a Junos dialect over SSH on `-netconf-port` and over mutual TLS (RFC 7589) on `-netconf-tls-port`.
The table in `netconf_dialect.go` is the contract: a dialect is a hello, an RPC handler and a push encoder, and a profile not in the table serves nothing.
Files: `netconf_junos_wire.go`, `netconf_junos_session.go`, `netconf_junos_events.go`, `netconf_tls.go`, `netconf_tls_identity.go`, `netconf_tls_api.go`.
The session takes any `io.ReadWriter`, so a `*tls.Conn` is the transport and the TLS path has no channel dispatch.
The push path is the IOS XE one: the per-device dispatcher, the 100-deep oldest-drop queue and the writer goroutine.
The Junos session holds one sentinel subscription, set by the first `create-subscription`.

### Decisions

- D13: the mx10004 serves both transports. Junos serves one dialect over both, and a TLS-only profile would be a device that does not exist.
- D14: link events only. The device also sends its whole syslog stream, which was 2442 notifications in 150 s on vJunos and is an artefact of that image. nl6 sends `SNMP_TRAP_LINK_DOWN` and `SNMP_TRAP_LINK_UP` and nothing else.
- D15: listeners are always bound. With `-netconf-enable` every mx10004 binds both listeners at start, CA or no CA. The client CA pool and the identity table are read per handshake through `GetConfigForClient`. A `PUT` of the table applies to the next connection and never walks the fleet, binds a listener or takes `createBatchGate`. With no CA every handshake is refused and the startup log says so.
- D16: reduced configuration replies. Unfiltered `get` and `get-configuration` return `<version>` and `<system><host-name>` with the `junos:` commit attributes. The device sends its whole configuration. Add to it when a consumer needs more.
- D17: the refusal, not the alert byte, is the handshake contract. Go's `crypto/tls` sends `protocol_version` for a TLS 1.3-only client and `bad_certificate` for a missing client certificate where Junos sends `handshake_failure`. Tests pin that the handshake fails and the connection closes. Hand-written alert records in front of `tls.Server` are not wanted.
- Only the `specified` map type plus a default identity. A fingerprint that is unknown with no default completes the handshake and closes with no hello, as Junos does.
- Framing stays base 1.0. The IOS XE base 1.1 switch is IOS XE only.
- The shared server certificate (`sharedTLSCert`) has only a `0.0.0.0` IP SAN, so clients skip host-name verification and pin the CA from `GET /api/v1/tls/ca`. The same limit applies to gNMI dial-in. A fix is a per-device certificate.
- The server presents its leaf only. Junos sends the leaf and the CA.
- `tls_handshake_failures` also counts benign TCP probes and idle-deadline aborts, as the gNMI counter does.
- A unit going down sends nothing, because no capture shows what the device sends.
- The deadline rule above holds on TLS: the idle deadline bounds the handshake only, then TCP keepalive.

### Junos probe record

Reference: vJunos-router 25.4R1.12 in containerlab (`vj`) on mad-monkey, left running, the same role the c8000v lab plays for IOS XE.
The lab has two links so the probe runs over ge-0/0/0 while ge-0/0/1 flaps.
Port 6513 is reachable only over a data interface from the peer container, because vrnetlab forwards only fixed ports into the VM.
The probe client is a small Go program, because ncclient has no TLS transport.
The captures, the lab files and the probe client live in the planning artifacts of the design, not in this repo.

- TLS 1.3 only: alert 40 `handshake_failure`, no ServerHello. Without a client certificate: ServerHello, then alert 40. From an unknown CA: alert 48 `unknown_ca`. An ECDSA client certificate signed by the trusted CA is accepted.
- The server sends its certificate and the CA.
- A known fingerprint maps to its username. An unknown fingerprint with no default identity completes the handshake and then closes with no hello. With a default identity it maps to that user.
- The hello is written at once, with two comment lines and 19 capabilities when `notification interleave` is set.
- `close-session` replies `<ok/>`, then `\n<!-- session end at ... -->\n`, then closes. The first capture missed the leading newline; the interop test found it.
- `establish-subscription`, in the draft or the RFC 8639 namespace, gets the `syntax error` `rpc-error` twice in one reply. Other unknown RPCs get it once.
- With `system syslog file messages any notice` and `structured-data` configured, the mib2d link traps arrive over `create-subscription`. Without a syslog config the 2026-10-15 capture saw none.
- Each link event arrives in both forms, with the same `eventTime`. Delivery lagged by 21 to 23 s on vJunos.
- A logical unit sends `SNMP_TRAP_LINK_UP` at INFORMATIONAL on enable. No unit down was seen on disable.
- Not probed: `kill-session`, `version-1.1` framing, replay, `get-schema`, a cabled carrier loss (vrnetlab passes no carrier), unit down on disable, idle keepalive behaviour.
