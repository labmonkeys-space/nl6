# NetGauze collector for `make test-interop-yangpush` (see compose.yml and config.yaml).
#
# NetGauze publishes no container image, so this installs the v0.13.0 release
# .deb. The .deb is built on Debian 13, so the base is debian:13-slim. Both the
# base and the .deb are pinned by digest so the gate's collector cannot move
# under a green CI. Dependabot (docker ecosystem, /examples/netgauze) bumps the
# base. Bump the .deb by hand with the release's asset digest:
#   gh release view vX.Y.Z -R NetGauze/NetGauze --json assets -q '.assets[]|select(.name|endswith(".deb"))|.digest'
FROM debian:13-slim@sha256:f6b08b09a05725f9431502d3b5714f5c4576e82c1a84fa1debe0c24a7e0c3ec4

ARG NETGAUZE_VERSION=0.13.0
ARG NETGAUZE_DEB_SHA256=1a5c8956626260f32e1a802eb7597128db1b6c2330fe7d5a14679918379723cb

ADD --checksum=sha256:${NETGAUZE_DEB_SHA256} \
    https://github.com/NetGauze/NetGauze/releases/download/v${NETGAUZE_VERSION}/netgauze-collector_${NETGAUZE_VERSION}-1_amd64.deb \
    /tmp/netgauze-collector.deb

RUN apt-get update \
 && apt-get install -y --no-install-recommends /tmp/netgauze-collector.deb \
 && rm -rf /var/lib/apt/lists/* /tmp/netgauze-collector.deb

COPY config.yaml /etc/netgauze/config.yaml

ENTRYPOINT ["netgauze-collector", "/etc/netgauze/config.yaml"]
