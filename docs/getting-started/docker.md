# Docker

The simulator is published as a single container image at
`ghcr.io/labmonkeys-space/nl6:latest`, built from the root
`Dockerfile` and pushed to the GitHub Container Registry on push to
`main` and on release tags.

## Pull and run the simulator

```bash
docker pull ghcr.io/labmonkeys-space/nl6:latest

# The simulator needs TUN + netns privileges. --network=host isn't strictly
# required but makes the HTTP control plane reachable on :8080 directly.
docker run --rm -it \
  --cap-add=NET_ADMIN \
  --device=/dev/net/tun \
  --network=host \
  ghcr.io/labmonkeys-space/nl6:latest \
  -auto-start-ip 192.168.100.1 -auto-count 10
```

:::warning[Host FORWARD policy]
On hosts with Docker installed, the default `FORWARD` chain in iptables
is `DROP`. The simulator inserts a `FORWARD -i veth-sim-host -j ACCEPT`
rule at startup so per-device flow exporters can reach external
collectors. On clean shutdown the rule is removed. See
[Flow export → Prerequisites](../ops/flow-export.md#prerequisites-for-per-device-source-ip).
:::

## Build locally

```bash
# Host platform
make docker-build

# Multi-platform, pushed to the registry
make docker-push
```

The `docker-push` target pushes `linux/amd64` + `linux/arm64` — override the
tag list with `DOCKER_TAGS="..."`.

## docker-compose

```bash
make docker-up     # docker compose up --build
make docker-down   # docker compose down
```
