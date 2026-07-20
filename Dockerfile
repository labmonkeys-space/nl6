# Build stage runs on the host platform (native, no emulation needed).
# The binary is cross-compiled for the target platform.
# Digest-pinned (tag is in the reference; the `docker` Dependabot ecosystem
# keeps the digest current). Dockerfile has no inline comments, so the tag note
# lives on its own line.
FROM --platform=${BUILDPLATFORM} golang:1.26-alpine@sha256:0178a641fbb4858c5f1b48e34bdaabe0350a330a1b1149aabd498d0699ff5fb2 AS build

ARG TARGETARCH
# APP_VERSION is the build-time version string. The Makefile's docker
# targets pass it through from APP_VERSION resolved via
# `git describe --tags --abbrev=0` (or the CI tag-event override);
# unset here means the binary self-reports "dev".
ARG APP_VERSION=dev

WORKDIR /src

COPY go/ .

RUN CGO_ENABLED=0 GOOS=linux GOARCH=${TARGETARCH} go build \
    -ldflags "-X main.Version=${APP_VERSION}" \
    -o /nl6 ./nl6

# ----

# Digest-pinned (see note on the build stage above).
FROM alpine:3.24@sha256:28bd5fe8b56d1bd048e5babf5b10710ebe0bae67db86916198a6eec434943f8b

RUN apk add --no-cache iproute2 iptables

WORKDIR /app

COPY --from=build /nl6 /usr/local/bin/nl6
COPY go/nl6/resources/ /app/resources/
COPY go/nl6/web/ /app/web/

EXPOSE 8080/tcp 161/udp

ENTRYPOINT ["/usr/local/bin/nl6"]
