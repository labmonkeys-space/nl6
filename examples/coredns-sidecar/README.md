# coredns-sidecar

A `docker compose` stack that makes an nl6 fleet resolvable by name: nl6 runs an
authoritative DNS server as a **hidden primary** and **CoreDNS** runs as a stock
`secondary`, transferring the zones via AXFR and refreshing on NOTIFY.

- **Forward** `<device-name>.nl6.local` → device management IP
- **Reverse** `<ip>` (PTR) → `ip4.mgmt.<device-name>.nl6.local` (round-trips)

```bash
docker compose up -d
dig @localhost -x 10.42.0.5 +short            # -> ip4.mgmt.<name>.nl6.local.
curl -s localhost:8080/api/v1/dns/status | jq
```

📖 **Full walkthrough:** [Getting Started → Resolve devices with DNS](https://nl6.eu/getting-started/dns)
— bring up the stack, verify forward/reverse resolution, and watch zones update
live. For the naming scheme, flags, and zone semantics see the
[DNS service-discovery reference](https://nl6.eu/reference/dns-service-discovery).

## Files

- `compose.yml` — nl6 (`-dns-enable`, 10-device demo fleet) + CoreDNS secondary.
- `Corefile` — one `secondary { transfer from nl6:5353 }` block per zone.
