# coredns-sidecar

A `docker compose` stack that makes an nl6 fleet resolvable by name. nl6 runs an
authoritative DNS server as a **hidden primary**; **CoreDNS** runs as a stock
`secondary`, transferring the zones via AXFR and refreshing on NOTIFY — no
custom CoreDNS plugin.

```
 dig @localhost  ──►  CoreDNS :53 (secondary)  ──AXFR/NOTIFY──►  nl6 :5353 (primary)
                                                                  derived from the
                                                                  live device set
```

- **Forward** `<device-name>.nl6.local` → device management IP
- **Reverse** `<ip>` (PTR) → `ip4.mgmt.<device-name>.nl6.local`, which resolves
  forward to the same IP (round-trips)

See the [DNS service-discovery reference](../../docs/reference/dns-service-discovery.md)
for the naming scheme, flags, and zone semantics.

## Run

```bash
cd examples/coredns-sidecar
docker compose up -d
```

The stack auto-starts a 10-device demo fleet (`10.42.0.1`–`10.42.0.10`). On every
device create/delete nl6 bumps the zone serial (debounced ~1s) and NOTIFYs
CoreDNS, which re-transfers.

## Verify

```bash
# Pick a real device name from the running fleet:
curl -s localhost:8080/api/v1/devices | jq -r '.data[0]' 2>/dev/null

# Forward + reverse against CoreDNS (host :53):
NAME=$(curl -s localhost:8080/api/v1/devices | jq -r '.data[0].ip' 2>/dev/null)
dig @localhost core-rtr-01.nl6.local +short          # device name -> 10.42.0.x
dig @localhost -x 10.42.0.5 +short                   # 10.42.0.5  -> ip4.mgmt.<name>.nl6.local.

# Publish + NOTIFY counters:
curl -s localhost:8080/api/v1/dns/status | jq

# Transfer straight from the primary (skipping CoreDNS):
dig @localhost -p 5353 nl6.local AXFR
```

> The exact device names are random per run (nl6 synthesises `sysName`). List
> them with `curl -s localhost:8080/api/v1/devices | jq -r '.data[].ip'` and the
> matching forward names from `dig @localhost -p 5353 nl6.local AXFR`.

## Adjust

- **Different domain / subnets** — change `-dns-domain` and `-dns-reverse-zone`
  on the `nl6` service, and add/rename the matching `secondary` blocks in
  `Corefile`. A CoreDNS secondary must have a block per zone.
- **Bigger fleet** — raise `-auto-count` (and pick a base `-auto-start-ip`
  inside a configured reverse zone, else those devices resolve forward-only).
- **No NOTIFY** — drop `-dns-notify`; CoreDNS still picks up changes on its SOA
  refresh interval, just less promptly.

## Notes

- nl6's DNS server binds in the container's default netns (not the `nl6sim`
  device namespace), so CoreDNS reaches it at `nl6:5353` over the compose
  network.
- CoreDNS only transfers zone *data*; it needs no L3 reachability to the
  simulated device IPs.
- `-dns-listen` defaults to `:5353` to avoid a privileged port inside the
  container; CoreDNS still serves clients on `:53`.
