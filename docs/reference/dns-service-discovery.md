# DNS service discovery

nl6 can publish the simulated fleet to DNS so consumers refer to devices by
name instead of raw `10.42.x.x` management IPs, and reverse lookups resolve to a
hostname. nl6 acts as a **hidden DNS primary**: a [CoreDNS](https://coredns.io)
secondary transfers the zones and serves clients. The subsystem is **off by
default** — enable it with `-dns-enable`.

```
                     device create/delete
                            │  (debounced ~1s)
   ┌── nl6 (hidden primary, :5353) ──────────────┐
   │  derived zones over the live device set      │
   │  SOA · NS · A · PTR · AXFR · NOTIFY          │
   └───────────────┬──────────────────────────────┘
                   │ NOTIFY  ▲ AXFR (SOA poll → transfer)
                   ▼         │
   ┌── CoreDNS (secondary, :53) ─────────────────┐
   │  serves clients from the transferred copy    │
   └──────────────────────────────────────────────┘
```

## Naming scheme

| Lookup | Name | Answer |
|--------|------|--------|
| Forward | `<device-name>.nl6.local` | device management IP (`A`) |
| Forward | `ip4.mgmt.<device-name>.nl6.local` | same IP (`A`) — the PTR target, so reverse round-trips |
| Reverse | `<ip>.in-addr.arpa` | `ip4.mgmt.<device-name>.nl6.local` (`PTR`) |

`<device-name>` is the device's `sysName`, sanitised to a valid DNS label
(lowercased; characters outside `[a-z0-9-]` become `-`; truncated to 63
octets). The `ip4` and `mgmt` labels denote the address family and the (single)
management interface the IP lives on — forward-compatible seams for a future
`ip6.` / real-interface-name expansion.

Because `sysName` is randomly assembled and can repeat across the fleet,
duplicate names are **disambiguated deterministically**: ordered by ascending
management IP, the first device keeps the bare label and each subsequent
collider gets an IP-derived suffix (e.g. `edge-swh-01-0-9`). Every forward name
and every PTR target is therefore unique.

## Zones and boundaries

nl6 is authoritative for one **forward** zone (`-dns-domain`, default
`nl6.local`) and a configured set of **reverse** zones (`-dns-reverse-zone`,
default `42.10.in-addr.arpa`, matching the default flat `10.42.0.0/16`
management plane). A device whose IP falls within no configured reverse zone
still gets its forward `A` record but **no PTR**; the omission is counted in the
status endpoint and logged.

A CoreDNS secondary must know its zone list at config time, so the reverse-zone
set is configured, not auto-derived. To address devices across multiple subnets,
list each matching reverse zone on both nl6 (`-dns-reverse-zone`) and CoreDNS.

## Flags

| Flag | Default | Purpose |
|------|---------|---------|
| `-dns-enable` | `false` | Enable the DNS service-discovery server. |
| `-dns-domain` | `nl6.local` | Forward zone apex (`<device>.<domain>`). |
| `-dns-listen` | `:5353` | Bind address (host:port) in the container's default netns. `:5353` avoids needing privileged `:53`. |
| `-dns-reverse-zone` | `42.10.in-addr.arpa` | Comma-separated `in-addr.arpa` reverse zone(s). |
| `-dns-notify` | _(empty)_ | Comma-separated secondary NOTIFY targets (`host:port`). Empty disables NOTIFY. |
| `-dns-debounce` | `1s` | Quiescence window to coalesce a burst of device changes into one zone update + NOTIFY. |

The server binds in the container's **default** network namespace (like the
`:8080` web API), never inside the `nl6sim` device namespace.

## Change propagation

Every device create/delete marks the zones dirty. A debounced worker waits for
`-dns-debounce` of quiescence, then bumps the SOA serial **once** and sends a
DNS `NOTIFY` to each secondary, which responds with an SOA probe and pulls a
full `AXFR`. A 30,000-device auto-start batch thus produces a single serial bump
and a single transfer, not 30,000. `IXFR` requests are answered with a full
`AXFR`.

> **Serial caveat.** The SOA serial is epoch-seeded at start and **not
> persisted**. If the process restarts while the system clock is rolled back, a
> secondary that cached the older-but-numerically-higher serial may treat the
> new zone as stale (RFC 1982). This is inherent to stateless epoch serials and
> acceptable for a simulator; restart the secondary if it diverges.

## Status

```bash
curl -s http://localhost:8080/api/v1/dns/status | jq
```

```json
{
  "subsystem_active": true,
  "domain": "nl6.local",
  "listen": ":5353",
  "zones": [
    { "origin": "nl6.local.", "kind": "forward", "serial": 1782300000 },
    { "origin": "42.10.in-addr.arpa.", "kind": "reverse", "serial": 1782300000 }
  ],
  "secondaries": ["coredns:53"],
  "devices_published": 10,
  "ptrs_emitted": 10,
  "ptrs_omitted": 0,
  "names_disambiguated": 0,
  "zone_bumps": 1,
  "notifies_sent": 2,
  "notify_errors": 0
}
```

`subsystem_active=false` means `-dns-enable` was not set. `ptrs_omitted`
counts device IPs outside every configured reverse zone. `zone_bumps` is the
number of coalesced change rounds; `notifies_sent` / `notify_errors` are the
cumulative NOTIFY tallies (one NOTIFY per zone per secondary per round).

## CoreDNS sidecar

A complete `docker compose` stack lives in
[`examples/coredns-sidecar/`](https://github.com/labmonkeys-space/nl6/tree/main/examples/coredns-sidecar).
The CoreDNS `Corefile` configures one `secondary` block per zone:

```
nl6.local:53 {
    secondary {
        transfer from nl6:5353
    }
    log
    errors
}
42.10.in-addr.arpa:53 {
    secondary {
        transfer from nl6:5353
    }
    log
    errors
}
```

Then, against CoreDNS:

```bash
dig @coredns core-rtr-01.nl6.local +short      # -> 10.42.0.5
dig @coredns -x 10.42.0.5 +short               # -> ip4.mgmt.core-rtr-01.nl6.local.
```

## Scope

Read-only authoritative DNS; nl6 answers only its own zones. Out of scope:
`ip6.*` reverse records and per-interface IP addressing (one IPv4 per device
today), IXFR incremental transfer, and DNSSEC / TSIG-authenticated transfers
(the sidecar is a trusted co-located peer).
