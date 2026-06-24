# Resolve devices by name

Out of the box you address simulated devices by their `10.42.x.x` management
IPs. With the **CoreDNS sidecar** you can resolve them by name instead — forward
`<device-name>.nl6.local` and reverse `PTR`s — kept up to date automatically as
devices come and go.

nl6 runs an authoritative DNS server as a **hidden primary**; a stock
[CoreDNS](https://coredns.io) runs as a **secondary**, transferring the zones
via AXFR and refreshing on NOTIFY. No custom CoreDNS plugin.

```
 dig @localhost  ──►  CoreDNS :53 (secondary)  ──AXFR/NOTIFY──►  nl6 :5353 (primary)
                                                                  derived from the
                                                                  live device set
```

- **Forward** `<device-name>.nl6.local` → device management IP
- **Reverse** `<ip>` (PTR) → `ip4.mgmt.<device-name>.nl6.local`, which resolves
  forward to the same IP (round-trips)

## Prerequisites

- Docker with Compose v2 (`docker compose`). The sidecar stack runs nl6 in a
  container, so you don't need host TUN/netns setup — see [Docker](./docker.md).
- `dig` (or any DNS client) and `curl` on the host to verify.

## Run the stack

The repo ships a ready-to-run stack at
[`examples/coredns-sidecar/`](https://github.com/labmonkeys-space/nl6/tree/main/examples/coredns-sidecar):

```bash
git clone https://github.com/labmonkeys-space/nl6
cd nl6/examples/coredns-sidecar
docker compose up -d
```

It auto-starts a 10-device demo fleet (`10.42.0.1`–`10.42.0.10`) with the DNS
subsystem enabled. On every device create/delete nl6 bumps the zone serial
(debounced ~1s) and NOTIFYs CoreDNS, which re-transfers.

The `nl6` service runs with these DNS flags (see the
[CLI flags](../reference/cli-flags.md) for the full set):

```yaml
command:
  - -dns-enable
  - -dns-domain=nl6.local
  - -dns-reverse-zone=42.10.in-addr.arpa
  - -dns-notify=coredns:53
```

…and the CoreDNS `Corefile` is a stock `secondary` block per zone:

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

## Verify

```bash
# List the running fleet to pick a real name/IP (names are random per run):
curl -s localhost:8080/api/v1/devices | jq -r '.data[].ip'
dig @localhost -p 5353 nl6.local AXFR | grep ' A '   # the forward names + IPs

# Forward + reverse against CoreDNS (host :53):
dig @localhost core-rtr-01.nl6.local +short          # device name -> 10.42.0.x
dig @localhost -x 10.42.0.5 +short                   # 10.42.0.5  -> ip4.mgmt.<name>.nl6.local.

# Publish + NOTIFY counters:
curl -s localhost:8080/api/v1/dns/status | jq
```

:::tip[Names are synthesised]
nl6 generates each device's `sysName` randomly, so the exact forward names
change per run. Read them from the AXFR (`dig @localhost -p 5353 nl6.local AXFR`)
or from `/api/v1/devices`. Duplicate names are disambiguated deterministically
(lowest IP keeps the bare label).
:::

## How it stays current

Creating or deleting a device marks the zones dirty. A debounced worker waits
for a quiescence window (`-dns-debounce`, default 1s), then bumps the SOA serial
**once** and NOTIFYs each secondary — so a large batch coalesces into a single
transfer rather than one per device. Try it:

```bash
# Create a device, then watch the serial advance and CoreDNS pick it up.
curl -s -XPOST localhost:8080/api/v1/devices \
  -H 'content-type: application/json' \
  -d '{"device_count":1,"start_ip":"10.42.0.50"}'
curl -s localhost:8080/api/v1/dns/status | jq '.zones, .zone_bumps'
```

## Adjust

- **Different domain / subnets** — change `-dns-domain` and `-dns-reverse-zone`
  on the `nl6` service, and add/rename the matching `secondary` blocks in the
  `Corefile`. A CoreDNS secondary needs one block per zone. Device IPs outside
  every configured reverse zone resolve forward-only (no PTR).
- **No NOTIFY** — drop `-dns-notify`; CoreDNS still picks up changes on its SOA
  refresh interval, just less promptly.

## Next

- [DNS service discovery reference](../reference/dns-service-discovery.md) — the
  full naming scheme, flags, zone boundaries, and operational caveats.
