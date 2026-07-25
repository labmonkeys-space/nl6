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
# A CI caller may pass APP_VERSION as an empty string (an unset reusable-workflow
# input renders to ""); fall back to the git-describe VERSION so the guard below
# never sees a blank value.
APP_VERSION := $(or $(strip $(APP_VERSION)),$(VERSION))

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

# Node runtime for the framework-free web unit tests (go/nl6/web/*.test.js).
NODE    ?= node
WEB_DIR := go/nl6/web

UNAME_S := $(shell uname -s)

.PHONY: all build reconcile run test test-web tidy check-tidy dist packages smoke set-nix-version clean docker-build docker-push docker-up docker-down help version \
        check-go check-docker check-buildx check-linux check-node check-node-runtime \
        docs-install docs-serve docs-build docs-check-orphans docs-audit-overrides docs-clean \
        tools-quality fmt-check lint vuln sec lint-actions quality

all: build

## build: Cross-compile the simulator binary for Linux (GOOS=linux GOARCH=amd64)
build: check-go
	cd $(BUILD_DIR) && CGO_ENABLED=0 GOOS=$(GOOS) GOARCH=$(GOARCH) go build -ldflags "$(LDFLAGS)" -o $(BINARY) .

## reconcile: Build the nl6-reconcile CLI (report ⋈ received-counts loss diff)
reconcile: check-go
	cd $(GO_DIR) && CGO_ENABLED=0 GOOS=$(GOOS) GOARCH=$(GOARCH) go build -ldflags "$(LDFLAGS)" -o nl6-reconcile ./cmd/nl6-reconcile

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

## dist: Build release binaries into dist/ — the simulator (linux amd64/arm64)
## and the nl6-reconcile CLI (linux/darwin/windows × amd64/arm64)
dist: check-go
	mkdir -p dist
	cd $(GO_DIR) && CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -ldflags "$(LDFLAGS)" -o ../dist/$(BINARY)-linux-amd64 ./nl6
	cd $(GO_DIR) && CGO_ENABLED=0 GOOS=linux GOARCH=arm64 go build -ldflags "$(LDFLAGS)" -o ../dist/$(BINARY)-linux-arm64 ./nl6
	# nl6-reconcile is pure Go (no TUN/netns/root) and runs where the operator
	# diffs — laptop, CI, monitor host — so ship it for every OS/arch, unlike
	# the Linux-only simulator.
	@for os in linux darwin windows; do \
	  for arch in amd64 arm64; do \
	    ext=""; [ "$$os" = "windows" ] && ext=".exe"; \
	    echo "dist: nl6-reconcile-$$os-$$arch$$ext"; \
	    ( cd $(GO_DIR) && CGO_ENABLED=0 GOOS=$$os GOARCH=$$arch go build -ldflags "$(LDFLAGS)" -o ../dist/nl6-reconcile-$$os-$$arch$$ext ./cmd/nl6-reconcile ) || exit 1; \
	  done; \
	done

# Native OS packages (.deb + .rpm) are built with nfpm from a single spec at
# deploy/packages/nfpm.yaml. Pinned so local and CI builds match; not tracked
# by Dependabot's `go install` blind spot.
NFPM_VERSION ?= v2.43.0
PKG_DIR      := deploy/packages
# nfpm/rpm versions must not carry a leading `v`. APP_VERSION is already
# validated against [A-Za-z0-9._+-]+ above.
PKG_VERSION  := $(patsubst v%,%,$(APP_VERSION))

## packages: Build .deb and .rpm packages (amd64 + arm64) into dist/ via nfpm
packages: dist
	GOBIN=$(GOBIN_DIR) go install github.com/goreleaser/nfpm/v2/cmd/nfpm@$(NFPM_VERSION)
	@for arch in amd64 arm64; do \
	  cp dist/$(BINARY)-linux-$$arch dist/nl6-pkgstage; \
	  for fmt in deb rpm; do \
	    echo "nfpm: nl6 $(PKG_VERSION) $$arch ($$fmt)"; \
	    VERSION=$(PKG_VERSION) ARCH=$$arch $(GOBIN_DIR)/nfpm package \
	      -f $(PKG_DIR)/nfpm.yaml -p $$fmt -t dist/ || exit 1; \
	  done; \
	done; \
	rm -f dist/nl6-pkgstage

# Distro images exercised by `make smoke`. Override to trim/extend the matrix.
SMOKE_DEB_IMAGES ?= debian:13 ubuntu:26.04
SMOKE_RPM_IMAGES ?= quay.io/rockylinux/rockylinux:10 almalinux:10 quay.io/centos/centos:stream10

## smoke: Install the built packages in clean distro containers and assert (requires docker)
smoke: packages check-docker
	@case $$(uname -m) in \
	  aarch64|arm64) deb=$$(ls -t dist/*_arm64.deb | head -1); rpm=$$(ls -t dist/*.aarch64.rpm | head -1) ;; \
	  x86_64|amd64)  deb=$$(ls -t dist/*_amd64.deb | head -1); rpm=$$(ls -t dist/*.x86_64.rpm  | head -1) ;; \
	  *) echo "smoke: unsupported host arch $$(uname -m)"; exit 1 ;; \
	esac; \
	for img in $(SMOKE_DEB_IMAGES); do $(PKG_DIR)/smoke-test.sh "$$deb" "$$img" || exit 1; done; \
	for img in $(SMOKE_RPM_IMAGES); do $(PKG_DIR)/smoke-test.sh "$$rpm" "$$img" || exit 1; done

## set-nix-version: Write the release version (from APP_VERSION) into the Nix package
#
# Release helper so the Nix `version` is never hand-edited: it tracks the same
# APP_VERSION the deb/rpm/Docker artifacts use. Run before tagging, e.g.
#   make set-nix-version APP_VERSION=vX.Y.Z
# then commit the change. The `git describe` dev form (vX.Y.Z-N-gSHA) is
# rejected — pass an explicit release tag.
set-nix-version:
	@case '$(PKG_VERSION)' in \
	  *-[0-9]*-g[0-9a-f]*) \
	    echo "set-nix-version: APP_VERSION '$(APP_VERSION)' is a dev version ($(PKG_VERSION))."; \
	    echo "                 Pass an explicit release tag: make set-nix-version APP_VERSION=vX.Y.Z"; \
	    exit 1 ;; \
	esac
	@sed -E 's/(version [?] )"[^"]*"/\1"$(PKG_VERSION)"/' $(PKG_DIR)/nix/package.nix > $(PKG_DIR)/nix/package.nix.tmp \
	  && mv $(PKG_DIR)/nix/package.nix.tmp $(PKG_DIR)/nix/package.nix
	@echo "set-nix-version: deploy/packages/nix/package.nix -> $(PKG_VERSION)"
	@grep -nE 'version [?] "' $(PKG_DIR)/nix/package.nix

## test: Run the web JS unit tests (all platforms) + Go tests (nl6 package requires Linux)
test: check-go test-web
ifneq ($(UNAME_S),Linux)
	@echo "Note: no Go tests to run on $(UNAME_S) — the simulator package uses"
	@echo "      Linux-only syscalls (TUN, network namespaces). Use a Linux"
	@echo "      host or container for Go test coverage. (Web tests ran above.)"
else
	cd $(GO_DIR) && go test ./...
endif

## test-web: Run the framework-free web unit tests (pure JS, runs on any platform)
test-web: check-node-runtime
	cd $(WEB_DIR) && for t in *.test.js; do \
	  echo "node $$t"; $(NODE) "$$t" || exit 1; \
	done

## bench-baseline: Capture the scenario fire-path benchmark (10 runs) for the benchstat baseline
## Output is committed as go/nl6/testdata/scenario-bench-baseline.txt — capture on the CI
## runner class (workflow: bench-baseline.yml), never on a laptop; benchstat comparisons
## must use the same runner class (scenario PR0 / NFR-P1).
bench-baseline: check-go
	cd $(GO_DIR) && go test ./nl6/ -bench=BenchmarkSyslogExporterFire -benchmem -count=10 -run='^$$' -timeout=20m

## run: Build and run the simulator (Linux only — requires root for TUN interfaces)
run: check-linux build
	cd $(BUILD_DIR) && sudo ./$(BINARY)

# ---------------------------------------------------------------------------
# Code quality tooling
# ---------------------------------------------------------------------------

# Tool versions are pinned here so local developers and CI run the same
# binaries. Bump in lockstep across all environments; Dependabot does not
# track these `go install` versions today.
GOLANGCI_LINT_VERSION ?= v2.12.2
GOVULNCHECK_VERSION   ?= v1.1.4
GOSEC_VERSION         ?= v2.26.1
GOIMPORTS_VERSION     ?= v0.45.0

GOBIN_DIR := $(shell go env GOPATH)/bin

## tools-quality: Install pinned code-quality tools (golangci-lint, govulncheck, gosec, goimports)
tools-quality: check-go
	GOBIN=$(GOBIN_DIR) go install github.com/golangci/golangci-lint/v2/cmd/golangci-lint@$(GOLANGCI_LINT_VERSION)
	GOBIN=$(GOBIN_DIR) go install golang.org/x/vuln/cmd/govulncheck@$(GOVULNCHECK_VERSION)
	GOBIN=$(GOBIN_DIR) go install github.com/securego/gosec/v2/cmd/gosec@$(GOSEC_VERSION)
	GOBIN=$(GOBIN_DIR) go install golang.org/x/tools/cmd/goimports@$(GOIMPORTS_VERSION)

## fmt-check: Verify Go sources are gofmt- and goimports-clean
fmt-check: check-go
	@unformatted=$$(cd $(GO_DIR) && gofmt -l .); \
	if [ -n "$$unformatted" ]; then \
	  echo "The following files need 'gofmt -w':"; \
	  echo "$$unformatted"; \
	  exit 1; \
	fi
	@unimported=$$(cd $(GO_DIR) && $(GOBIN_DIR)/goimports -l .); \
	if [ -n "$$unimported" ]; then \
	  echo "The following files need 'goimports -w':"; \
	  echo "$$unimported"; \
	  exit 1; \
	fi

## lint: Run golangci-lint over the Go module
lint: check-go
	cd $(GO_DIR) && $(GOBIN_DIR)/golangci-lint run ./...

## vuln: Run govulncheck against the Go module
vuln: check-go
	cd $(GO_DIR) && $(GOBIN_DIR)/govulncheck ./...

## sec: Run gosec static security analysis over the Go module
#
# Excluded rules and rationale:
#   G104 — duplicates golangci-lint errcheck; configured there.
#   G115 — integer overflow conversions: high false-positive rate on
#          SNMP/gNMI protocol encoding paths that already validate
#          ranges.
#   G404 — math/rand is intentional for non-crypto simulator paths
#          (flap timing, scenario jitter). crypto/rand is used where
#          it matters (SNMPv3 IV, TLS cert gen).
#   G204 — `exec.Command` with variable args: invocations pass
#          operator-controlled (CLI/REST) values only. Subprocess
#          execution is an explicit design choice for namespace / TUN
#          management.
#   G304 — file paths into `resources/`: internal data files only.
#   G401/G405/G501/G502/G505 — DES/MD5/SHA1 are MANDATED by SNMPv3
#          (RFC 3414/3826) for privacy and authentication; refusing
#          them would break interoperability with every SNMPv3 mgr.
#   G103 — unsafe.Pointer usage for TUN ioctl is required by the
#          ifr struct layout.
#   G706 — log injection via taint analysis: REST handlers parse
#          `ip` through net.ParseIP and `ifIndex` as int before any
#          log call, so no untrusted control characters can reach
#          log.Printf. gosec's taint analyzer does not follow the
#          validation, producing false positives.
sec: check-go
	cd $(GO_DIR) && $(GOBIN_DIR)/gosec \
	  -exclude=G104,G115,G404,G204,G304,G401,G405,G501,G502,G505,G103,G706 \
	  ./...

# GitHub Actions linters. actionlint (static + shellcheck on run-blocks) via
# `go install`; zizmor (security auditor) via `pipx run` — both preinstalled on
# GitHub's ubuntu runners.
ACTIONLINT_VERSION ?= v1.7.12
ZIZMOR_VERSION     ?= 1.28.0

## lint-actions: Lint the GitHub Actions workflows (actionlint + zizmor)
lint-actions: check-go
	GOBIN=$(GOBIN_DIR) go install github.com/rhysd/actionlint/cmd/actionlint@$(ACTIONLINT_VERSION)
	$(GOBIN_DIR)/actionlint
	pipx run zizmor==$(ZIZMOR_VERSION) --persona=regular --config .github/zizmor.yml .github/workflows/

## quality: Run all code-quality checks (fmt-check, lint, vuln, sec)
quality: fmt-check lint vuln sec

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

## docs-check-orphans: Fail if any docs/ page is missing from sidebars.ts (orphaned)
docs-check-orphans: check-node
	node scripts/check-doc-orphans.mjs

## docs-build: Build the docs site (onBrokenLinks=throw; fails on broken links / warnings / orphaned pages)
docs-build: node_modules/.package-lock.json docs-check-orphans
	$(NPM) run build

## docs-audit-overrides: Report which package.json overrides still change resolution (report-only, needs network)
# Deliberately NOT part of the CI gates: the result depends on the npm registry
# rather than on the commit, so it can change without anyone touching the repo.
docs-audit-overrides: check-node
	node scripts/check-npm-overrides.mjs

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

check-node-runtime:
	@command -v $(NODE) >/dev/null 2>&1 || { \
	  echo "Error: '$(NODE)' not found."; \
	  echo "       Install Node 20 LTS (see .nvmrc) — e.g. 'nvm install && nvm use'"; \
	  echo "       or 'brew install node@20' / the installer at https://nodejs.org/."; \
	  exit 1; \
	}
