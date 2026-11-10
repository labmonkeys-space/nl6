# NetCalyx collector for `make test-interop-yangpush` (see compose.yml and config.yaml).
#
# NetCalyx publishes no container image, so this installs the v0.4.0 release
# .deb. The .deb is built with cargo-deb on ubuntu-latest and depends on the
# t64 libcurl and OpenSSL packages, which debian:13-slim provides. Both the
# base and the .deb are pinned by digest so the gate's collector cannot move
# under a green CI. Dependabot (docker ecosystem, /examples/netcalyx) bumps the
# base. Bump the .deb by hand with the release's asset digest:
#   gh release view vX.Y.Z -R network-analytics/NetCalyx --json assets -q '.assets[]|select(.name|endswith(".deb"))|.digest'
FROM debian:13-slim@sha256:a72b4433de1cf7d6bae0c4cee74d0547f58601a643b3375f070c51600d63b6b2

ARG NETCALYX_VERSION=0.4.0
ARG NETCALYX_DEB_SHA256=1ec6dc688bb3244b8b928daf8475b322102af69dc2cf835e74fb2f604b392ab0

ADD --checksum=sha256:${NETCALYX_DEB_SHA256} \
    https://github.com/network-analytics/NetCalyx/releases/download/v${NETCALYX_VERSION}/netcalyx-collector_${NETCALYX_VERSION}-1_amd64.deb \
    /tmp/netcalyx-collector.deb

RUN apt-get update \
 && apt-get install -y --no-install-recommends /tmp/netcalyx-collector.deb \
 && rm -rf /var/lib/apt/lists/* /tmp/netcalyx-collector.deb \
 && mkdir -p /tmp/netcalyx-udpnotif-cache

COPY config.yaml /etc/netcalyx/config.yaml

ENTRYPOINT ["netcalyx-collector", "/etc/netcalyx/config.yaml"]
