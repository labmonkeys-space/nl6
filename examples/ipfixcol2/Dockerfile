# IPFIXcol2 for `make test-interop-ipfix` (see compose.yml and ipfixcol2.xml).
#
# Debian testing (forky) is the nearest distribution that PACKAGES ipfixcol2
# (2.8.0+20260701); Ubuntu 24.04, the CI runner, does not, and building from
# source in CI is minutes per run against a moving target. The Debian package
# bundles libfds with its system element definitions, including
# /etc/libfds/system/elements/cisco.xml, which is what lets the collector
# resolve PEN 9 IEs 12235 and 9357 BY NAME with no help from nl6. That is the
# point of the gate: an independent implementation's own definitions decide.
#
# Pinned by digest so the gate's collector cannot move under a green CI;
# Dependabot (docker ecosystem, /examples/ipfixcol2) bumps the pin.
FROM debian:forky-slim@sha256:7bb96d9b4ccd7f46f54853c258a56df0c6b628a63e65c2317959da18fd36932c

RUN apt-get update \
 && apt-get install -y --no-install-recommends ipfixcol2 \
 && rm -rf /var/lib/apt/lists/*

COPY ipfixcol2.xml /etc/ipfixcol2/nl6.xml

ENTRYPOINT ["ipfixcol2", "-c", "/etc/ipfixcol2/nl6.xml", "-v"]
