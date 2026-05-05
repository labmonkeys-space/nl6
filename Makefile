BINARY       := nl6
BUILD_DIR    := go/nl6
GO_DIR       := go
SIM_IMAGE    := ghcr.io/labmonkeys-space/nl6:latest
# Space-separated list of -t tags for docker-push; override in CI with release tags.
DOCKER_TAGS  ?= $(SIM_IMAGE)

# Simulator uses Linux-only syscalls (TUN, network namespaces).
# Cross-compile by default so the binary runs in the container / on Linux hosts.
GOOS   ?= linux
GOARCH ?= amd64

# Version resolution: APP_VERSION env > `git describe --tags` > "dev".
# Both variables use `?=` so CI (which exports APP_VERSION on tag
# events) wins cleanly. A shallow clone with no tags falls through to
# "dev"; a binary built by `go build` directly (bypassing this
# Makefile) also reports "dev" — an obvious signal that ldflags did
# not run.
#
# We deliberately omit `--abbrev=0` so HEAD that is ahead of the last
# tag bakes the commit-distance form (e.g. `v0.4.1-11-g0356c42`). This
# is a conscious deviation from docusaurus.config.ts:resolveAppVersion
# which uses the cleaner `--abbrev=0` form — on the binary we prefer
# dev-build honesty (a post-tag commit never masquerades as the tag
# itself). See openspec/changes/expose-simulator-version/design.md D6.
VERSION     ?= $(shell git describe --tags 2>/dev/null || echo dev)
APP_VERSION ?= $(VERSION)

# Guard against shell-metachar / whitespace injection through APP_VERSION
# into the -ldflags string. Allowed grammar tracks the characters that
# appear in real git tags (semver + pre-release + build-metadata).
ifneq ($(shell printf '%s' '$(APP_VERSION)' | grep -Eq '^[A-Za-z0-9._+-]+$$' && echo ok),ok)
$(error APP_VERSION "$(APP_VERSION)" contains unsafe characters; allowed grammar: [A-Za-z0-9._+-]+)
endif

LDFLAGS     := -X main.Version=$(APP_VERSION)

# Docs toolchain (Docusaurus). Contributors install Node dependencies into
# ./node_modules via `npm ci`; Node version is pinned in .nvmrc.
NPM ?= npm

UNAME_S := $(shell uname -s)

.PHONY: all build run test tidy check-tidy dist clean docker-build docker-push docker-up docker-down help version \
        check-go check-docker check-buildx check-linux check-node \
        docs-install docs-serve docs-build docs-clean

all: build

## build: Cross-compile the simulator binary for Linux (GOOS=linux GOARCH=amd64)
build: check-go
	cd $(BUILD_DIR) && CGO_ENABLED=0 GOOS=$(GOOS) GOARCH=$(GOARCH) go build -ldflags "$(LDFLAGS)" -o $(BINARY) .

## version: Print the resolved version string (useful for CI diagnostics)
version:
	@echo $(APP_VERSION)

## tidy: Sync go.mod and go.sum
tidy: check-go
	cd $(GO_DIR) && go mod tidy

## check-tidy: Verify go.mod and go.sum are up to date (fails if tidy would change them)
check-tidy: check-go
	cd $(GO_DIR) && go mod tidy
	git diff --exit-code $(GO_DIR)/go.mod $(GO_DIR)/go.sum || { \
	  echo "go.mod or go.sum is out of date — run 'make tidy' and commit the result."; \
	  exit 1; \
	}

## dist: Build release binaries for linux/amd64 and linux/arm64 into dist/
dist: check-go
	mkdir -p dist
	cd $(GO_DIR) && CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -ldflags "$(LDFLAGS)" -o ../dist/$(BINARY)-linux-amd64 ./nl6
	cd $(GO_DIR) && CGO_ENABLED=0 GOOS=linux GOARCH=arm64 go build -ldflags "$(LDFLAGS)" -o ../dist/$(BINARY)-linux-arm64 ./nl6

## test: Run tests (nl6 package requires Linux)
test: check-go
ifneq ($(UNAME_S),Linux)
	@echo "Note: no tests to run on $(UNAME_S) — the simulator package uses"
	@echo "      Linux-only syscalls (TUN, network namespaces). Use a Linux"
	@echo "      host or container for test coverage."
else
	cd $(GO_DIR) && go test ./...
endif

## run: Build and run the simulator (Linux only — requires root for TUN interfaces)
run: check-linux build
	cd $(BUILD_DIR) && sudo ./$(BINARY)

## docker-build: Build the simulator Docker image for the host platform
docker-build: check-docker
	docker build --build-arg APP_VERSION=$(APP_VERSION) -t $(SIM_IMAGE) .

## docker-push: Build and push a multi-platform image (linux/amd64 + linux/arm64)
docker-push: check-buildx
	docker buildx build \
	  --platform linux/amd64,linux/arm64 \
	  --build-arg APP_VERSION=$(APP_VERSION) \
	  --push \
	  $(addprefix -t ,$(DOCKER_TAGS)) \
	  .

## docker-up: Start the simulator with docker compose
docker-up: check-docker
	docker compose up --build

## docker-down: Stop and remove the simulator container
docker-down: check-docker
	docker compose down

## clean: Remove build artefacts (binary and dist/)
clean:
	rm -f $(BUILD_DIR)/$(BINARY)
	rm -rf dist/

## docs-install: Install the Docusaurus toolchain via npm ci
docs-install: check-node node_modules/.package-lock.json

# node_modules/.package-lock.json is created by `npm ci`/`npm install` and
# rewritten on every install. Using it as the make target for
# node_modules freshness means `docs-serve` / `docs-build` automatically
# re-install when package-lock.json changes, without forcing `npm ci` on
# every invocation. Contributors with a stale tree no longer silently
# run against old deps.
node_modules/.package-lock.json: package-lock.json | check-node
	$(NPM) ci

## docs-serve: Run docusaurus start (live-reload) on http://localhost:3000
docs-serve: node_modules/.package-lock.json
	$(NPM) run start

## docs-build: Build the docs site (onBrokenLinks=throw; fails on broken links / warnings)
docs-build: node_modules/.package-lock.json
	$(NPM) run build

## docs-clean: Remove built docs artefacts and installed Node dependencies
docs-clean:
	rm -rf build/ .docusaurus/ node_modules/

## help: Show this help
help:
	@sed -n 's/^## //p' $(MAKEFILE_LIST) | column -t -s ':' | sed -e 's/^/ /'

# ---------------------------------------------------------------------------
# Dependency guards
# ---------------------------------------------------------------------------

check-go:
	@command -v go >/dev/null 2>&1 || { \
	  echo "Error: 'go' not found."; \
	  echo "       Install Go from https://golang.org/dl/ and ensure it is on your PATH."; \
	  exit 1; \
	}

check-docker:
	@command -v docker >/dev/null 2>&1 || { \
	  echo "Error: 'docker' not found."; \
	  echo "       Install Docker from https://docs.docker.com/get-docker/ and ensure it is on your PATH."; \
	  exit 1; \
	}
	@docker info >/dev/null 2>&1 || { \
	  echo "Error: Docker daemon is not running."; \
	  echo "       Start Docker Desktop (or the Docker service) and retry."; \
	  exit 1; \
	}

check-buildx: check-docker
	@docker buildx version >/dev/null 2>&1 || { \
	  echo "Error: 'docker buildx' not available."; \
	  echo "       Install Docker Desktop >= 2.1 or the buildx plugin."; \
	  exit 1; \
	}
	@# On Linux, multi-platform emulation requires binfmt_misc + QEMU.
	@# On macOS, Docker Desktop and Orbstack provide this natively — no check needed.
	@if [ "$(UNAME_S)" = "Linux" ]; then \
	  docker buildx ls | grep -q 'linux/arm64' || { \
	    echo "Error: active buildx builder does not support linux/arm64."; \
	    echo "       Run: docker run --privileged --rm tonistiigi/binfmt --install all"; \
	    echo "       Then: docker buildx create --use --name multiplatform"; \
	    exit 1; \
	  }; \
	fi

check-linux:
	@[ "$(UNAME_S)" = "Linux" ] || { \
	  echo "Error: 'make run' requires Linux."; \
	  echo "       The simulator uses TUN interfaces and network namespaces"; \
	  echo "       that are not available on $(UNAME_S)."; \
	  echo "       Run it inside a Linux container or VM instead."; \
	  exit 1; \
	}

check-node:
	@command -v $(NPM) >/dev/null 2>&1 || { \
	  echo "Error: '$(NPM)' not found."; \
	  echo "       Install Node 20 LTS (see .nvmrc) — e.g. 'nvm install && nvm use'"; \
	  echo "       or 'brew install node@20' / the installer at https://nodejs.org/."; \
	  exit 1; \
	}
