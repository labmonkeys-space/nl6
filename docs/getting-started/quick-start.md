# Quick start

Get a small fleet of simulated devices running on a Linux host in three
commands. For full flag docs see [CLI flags](../reference/cli-flags.md); for
container workflows see [Docker](docker.md).

## Prerequisites

- Linux host with root access (TUN interface and network-namespace creation
  require privileges).
- Go 1.26 or later. The canonical version is pinned in
  [`go/go.mod`](https://github.com/labmonkeys-space/nl6/blob/main/go/go.mod).
- Basic networking tools: `ip`, `iptables`.

:::tip[Skip host setup]
For a zero-prerequisite path, run the published container image — see
[Docker](./docker.md), which bundles the dependencies and TUN/TAP support.
On bare metal, install the prerequisites above; for large fleets see the
host tuning in [Scaling](../ops/scaling.md).
:::

## Build

```bash
git clone https://github.com/labmonkeys-space/nl6.git
cd nl6/go
go mod tidy
cd nl6
go build -o nl6 .
```

## Run

```bash
# Server only — create devices later via the REST API.
sudo ./nl6

# Auto-create 5 devices starting from 192.168.100.1 on a flat /16 (the default).
sudo ./nl6 -auto-start-ip 192.168.100.1 -auto-count 5
```

Once the simulator is up, open the web UI at [http://localhost:8080/](http://localhost:8080/) or
drive it via the REST API — see [Web API](../reference/web-api.md).

## Verify

```bash
# SNMP v2c query against the first auto-created device
snmpget -v2c -c public 192.168.100.1 1.3.6.1.2.1.1.1.0

# Walk interface table
snmpwalk -v2c -c public 192.168.100.1 1.3.6.1.2.1.2.2.1

# SSH (VT100 terminal emulation). Password: simadmin
ssh simadmin@192.168.100.1
```

See [SNMP reference](../reference/snmp.md) for the protocol coverage and the
dynamic HC counter layout.

## Next steps

- **Scale up** — [Scaling](../ops/scaling.md) covers the 30k-device tuning.
- **Flow export** — [Flow export (operator guide)](../ops/flow-export.md) to
  plug nl6 into a NetFlow / IPFIX / sFlow collector.
- **Device types** — [Device types](../reference/device-types.md) lists the
  28 simulated devices across 8 categories.
