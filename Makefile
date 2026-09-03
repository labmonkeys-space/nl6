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
#
# Order matters. The grammar check below interpolates the value into a
# single-quoted shell word, so a value containing a single quote would close
# that quoting and run the remainder — reject the quote first, with Make's own
# $(findstring), before any shell sees the value. With no quote present, every
# other metacharacter is inert inside the single quotes.
#
# What this guard structurally CANNOT catch: a value carrying Make syntax.
# APP_VERSION arrives from the environment or the command line, so Make has
# already expanded `$(...)` in it by the time any check here runs — the guard
# only ever sees the result. The pre-expansion grammar check therefore belongs
# in the caller, which is why .github/workflows/gates.yml validates
# GITHUB_REF_NAME before invoking make. Git ref names permit `$`, `(` and `)`.
_SQUOTE := '
ifeq ($(strip $(APP_VERSION)),)
$(error APP_VERSION must not be empty)
endif
ifneq (,$(findstring $(_SQUOTE),$(APP_VERSION)))
$(error APP_VERSION "$(APP_VERSION)" contains a single quote; allowed grammar: [A-Za-z0-9._+-]+)
endif
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

.PHONY: all build reconcile run test test-race test-web check-guard-file tidy check-tidy dist packages smoke set-nix-version nix-vendor-hash sbom-curate check-sbom-coverage clean docker-build docker-push docker-up docker-down help version \
        check-go check-docker check-buildx check-linux check-node check-node-runtime \
        docs-install docs-serve docs-build docs-check-orphans docs-check-csp docs-audit-overrides docs-clean \
        tools-quality fmt-check lint vuln sec lint-actions check-check-run-names quality

all: build

## build: Cross-compile the simulator binary for Linux (GOOS=linux GOARCH=amd64)
# GOTOOLCHAIN=auto is Go's own default, stated explicitly because callers do
# override it: CodeQL sets GOTOOLCHAIN=local, and with a bundled Go older than
# go.mod requires the build aborts with "go.mod requires go >= 1.27.0".
#
# This line is NOT what fixes CodeQL — .github/workflows/codeql.yml sets the
# variable job-wide, which is the only place that also reaches the extractor's
# own go invocations. It is kept because a build target should be able to
# honour the toolchain its go.mod pins whatever the caller's environment says.
build: check-go
	cd $(BUILD_DIR) && GOTOOLCHAIN=auto CGO_ENABLED=0 GOOS=$(GOOS) GOARCH=$(GOARCH) go build -ldflags "$(LDFLAGS)" -o $(BINARY) .

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
# quay.io/centos/centos:stream10 is removed on purpose (nl6#610). On 2026-09-02
# the CentOS Stream 10 tags were republished broken: the image's single "layer"
# is an OCI image layout (blobs/, index.json, oci-layout) rather than a root
# filesystem, so the container has no userland at all and `docker run` fails at
# init with `exec: "bash": executable file not found in $PATH`. Both stream10
# and stream10-minimal are affected and stream9 is not, which is what localises
# the fault to the upstream publish rather than to smoke-test.sh. Quay no
# longer serves the previous manifest, so there is no good digest to pin.
# EL10 coverage is unchanged: rockylinux:10 and almalinux:10 both remain.
# Restore the image once this prints ok:
#   docker run --rm quay.io/centos/centos:stream10 sh -c 'echo ok'
SMOKE_RPM_IMAGES ?= quay.io/rockylinux/rockylinux:10 almalinux:10

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

## nix-vendor-hash: Print the correct buildGoModule vendorHash for package.nix
# Required after ANY go.mod/go.sum change (Dependabot bumps included) — a
# stale vendorHash makes the Nix build substitute the previous cached vendor
# tree and fail with "inconsistent vendoring". Runs Nix inside Docker, so no
# local Nix install is needed. The fake-hash substitution runs on the host
# into a mktemp file bind-mounted over package.nix (nixos/nix:latest ships no
# sed in PATH, and the real work tree is never modified either way). Copy the
# printed "got:" value into `vendorHash` in deploy/packages/nix/package.nix.
nix-vendor-hash: check-docker
	@echo "nix-vendor-hash: probing (builds the Go vendor set once; a few minutes)..."
	@tmp=$$(mktemp); \
	sed 's|vendorHash = ".*"|vendorHash = "sha256-AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="|' \
	  $(PKG_DIR)/nix/package.nix > $$tmp; \
	out=$$(docker run --rm -v "$(CURDIR)":/repo:ro \
	  -v "$$tmp":/repo/deploy/packages/nix/package.nix:ro nixos/nix:latest sh -c "\
	  cp -r /repo /src && \
	  nix --extra-experimental-features 'nix-command flakes' build 'path:/src?dir=deploy/packages/nix#nl6' --no-link 2>&1"); \
	rm -f $$tmp; \
	echo "$$out" | grep -E 'specified:|got:' || { echo "$$out" | tail -20; exit 1; }
	@echo "nix-vendor-hash: copy the 'got:' value into vendorHash in $(PKG_DIR)/nix/package.nix"

## sbom-curate: Fill the product-SBOM licenses no module cache can resolve (SBOM=<path>)
# The main module, stdlib, and the scanned binary's file-root package are not
# downloadable modules, so syft can never resolve them; the script fills their
# declared/concluded licenses and fails if any target is absent. Runs in
# release.yml between SBOM generation and the blitsbom render, so the HTML
# reflects the curated document.
sbom-curate: check-node-runtime
	$(NODE) scripts/curate-product-sbom.mjs $(SBOM)

## check-sbom-coverage: Assert nl6-reconcile links no module the nl6 binary doesn't
# The release SBOM is derived from the nl6 binary alone (amd64/arm64 sets are
# identical). reconcile ships in the same release, so its third-party module
# set must stay a subset of nl6's or the SBOM under-reports what ships. Runs
# in release.yml before the SBOM step.
check-sbom-coverage: check-go
	@set -e; cd $(GO_DIR); \
	tmp_nl6=$$(mktemp); tmp_rec=$$(mktemp); \
	trap 'rm -f "$$tmp_nl6" "$$tmp_rec"' EXIT; \
	go list -deps -f '{{if and .Module (not .Module.Main)}}{{.Module.Path}}{{end}}' ./nl6 | sort -u > "$$tmp_nl6"; \
	go list -deps -f '{{if and .Module (not .Module.Main)}}{{.Module.Path}}{{end}}' ./cmd/nl6-reconcile | sort -u > "$$tmp_rec"; \
	[ -s "$$tmp_nl6" ] || { echo "check-sbom-coverage: go list produced no modules for ./nl6 - the check cannot have run"; exit 1; }; \
	extra=$$(comm -13 "$$tmp_nl6" "$$tmp_rec"); \
	if [ -n "$$extra" ]; then \
	  echo "check-sbom-coverage: nl6-reconcile links modules absent from the nl6 binary,"; \
	  echo "so the binary-derived release SBOM would under-report what ships:"; \
	  echo "$$extra"; \
	  echo "Extend the SBOM strategy (per-binary SBOMs) before adding such a dependency."; \
	  exit 1; \
	fi; \
	echo "check-sbom-coverage: reconcile module set is a subset of the nl6 binary set"

## check-guard-file: Assert nl6#577's anti-test-deletion guard still exists
# go/nl6/test_inventory_test.go carries the test-count floor, the load-bearing
# guard manifest and the build-constraint census. It is the only thing that
# notices when a test disappears, and deleting the FILE removes all three plus
# its own four tests, with nothing left in the package to fail. That is nl6#577's
# asymmetry one level up, so the anchor has to sit outside the package.
#
# The Makefile was chosen over a CI-only grep because CI invokes Makefile targets
# here, so this runs identically on a laptop; and over CODEOWNERS because that
# asks a human to notice rather than failing. It runs on every platform, which
# matters: `make test` skips the Go suite entirely off Linux.
check-guard-file:
	@f=$(GO_DIR)/nl6/test_inventory_test.go; \
	if [ ! -f "$$f" ]; then \
	  echo "check-guard-file: $$f is gone."; \
	  echo "  It is nl6#577's guard against silent test loss: the count floor, the"; \
	  echo "  load-bearing guard manifest and the build-constraint census. Deleting it"; \
	  echo "  removes every signal that a test has disappeared, and nothing inside the"; \
	  echo "  package can notice, which is why this check lives here. Restore it, or"; \
	  echo "  remove this target in the same commit and say what replaces it."; \
	  exit 1; \
	fi; \
	missing=""; \
	for t in TestPackageTestInventoryHasNotShrunk TestLoadBearingGuardsArePresent \
	         TestBuildConstrainedTestFilesAreTheCommittedSet TestGuardManifestIsCurated; do \
	  grep -q "^func $$t(" "$$f" || missing="$$missing $$t"; \
	done; \
	if [ -n "$$missing" ]; then \
	  echo "check-guard-file: $$f exists but no longer declares:$$missing"; \
	  echo "  The file's own guards are as deletable as the ones they protect."; \
	  exit 1; \
	fi; \
	echo "check-guard-file: nl6#577 guard present with all four checks"

## test: Run the web JS unit tests (all platforms) + Go tests (nl6 package requires Linux)
test: check-go check-guard-file test-web
ifneq ($(UNAME_S),Linux)
	@echo "Note: 'make test' runs Go tests on Linux only (CI parity). The suite"
	@echo "      itself passes on $(UNAME_S) — run 'cd $(GO_DIR) && go test ./...'"
	@echo "      directly; only the TUN/netns runtime paths are Linux-only."
	@echo "      (Web tests ran above.)"
else
	cd $(GO_DIR) && go test ./...
endif

## test-race: Run the Go tests under the race detector (Linux; CI gate — see gates.yml)
test-race: check-go check-guard-file
ifneq ($(UNAME_S),Linux)
	@echo "Note: 'make test-race' runs on Linux only (CI parity). The suite"
	@echo "      itself passes on $(UNAME_S) — run 'cd $(GO_DIR) && go test -race ./...'"
	@echo "      directly."
else
	cd $(GO_DIR) && go test -race ./...
endif

## test-interop: Poll nl6's SNMPv3 stack with net-snmp (needs snmpget on PATH)
##
## THE ONLY CHECK THAT IS NOT nl6 READING ITS OWN OUTPUT. Every other SNMPv3
## test in the package parses nl6's bytes with nl6's parser, so a shared
## misunderstanding of RFC 3414 passes all of them — which is exactly how a v3
## stack that computed no digest stayed green for years (nl6#624/#625).
## net-snmp derives its own key, verifies our digest and builds its own IV.
test-interop: check-go
	@command -v snmpget >/dev/null 2>&1 || { \
	  echo "snmpget not found. Install net-snmp:"; \
	  echo "  Debian/Ubuntu: sudo apt-get install -y snmp"; \
	  echo "  macOS:         it ships with the system, or 'brew install net-snmp'"; \
	  exit 1; }
	@snmpget --version 2>&1 | head -1
	cd $(GO_DIR) && NL6_SNMP_INTEROP=1 go test ./nl6/ -run TestUSMInterop -count=1 -v

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
GOLANGCI_LINT_VERSION ?= v2.13.1
GOVULNCHECK_VERSION   ?= v1.7.0
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
# The simulator is Linux-only (TUN/netns syscalls), and much of the package —
# including whole test files — sits behind `//go:build linux`. Linting with the
# host's own GOOS therefore analyses a DIFFERENT build than CI does, and reports
# findings CI will never see: code reachable only from a linux-tagged test reads
# as `unused` on macOS. Pin GOOS so a local run and CI agree by construction.
# CGO_ENABLED=0 is required to cross-analyse (cgo preprocessing cannot target
# linux from a darwin toolchain).
#
# Every static analyser here shares it, not just the linter. gosec and
# govulncheck are reachability-based: analysing the host build silently narrows
# what they inspect rather than reporting a false finding, so the failure mode is
# a MISSED vulnerability, not a noisy one. Measured on a darwin host, gosec saw
# 39,054 lines against 40,082 under GOOS=linux — 1,028 lines of Linux-only code
# were never scanned. Both were clean, so nothing was actually missed; the
# exposure was.
ANALYSIS_ENV := CGO_ENABLED=0 GOOS=linux

lint: check-go
	@cd $(GO_DIR) && $(ANALYSIS_ENV) $(GOBIN_DIR)/golangci-lint run ./... || { \
		status=$$?; \
		echo ""; \
		echo "lint failed — retrying once with a clean analysis cache."; \
		echo "A stale golangci-lint cache can report findings that do not exist"; \
		echo "(observed: ~100 phantom SA5011s on an otherwise clean tree)."; \
		$(GOBIN_DIR)/golangci-lint cache clean; \
		$(ANALYSIS_ENV) $(GOBIN_DIR)/golangci-lint run ./...; \
	}

## vuln: Run govulncheck against the Go module
vuln: check-go
	cd $(GO_DIR) && $(ANALYSIS_ENV) $(GOBIN_DIR)/govulncheck ./...

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
	cd $(GO_DIR) && $(ANALYSIS_ENV) $(GOBIN_DIR)/gosec \
	  -exclude=G104,G115,G404,G204,G304,G401,G405,G501,G502,G505,G103,G706 \
	  ./...

# GitHub Actions linters. actionlint (static + shellcheck on run-blocks) via
# `go install`; zizmor (security auditor) via `pipx run` — both preinstalled on
# GitHub's ubuntu runners.
ACTIONLINT_VERSION ?= v1.7.12
ZIZMOR_VERSION     ?= 1.28.0

# dependabot-vendorhash.yml picks the Nix Cache check runs out of a head SHA
# by a literal name prefix, and that prefix is nix-cache.yml's job `name:`
# before matrix expansion. Nothing in either file references the other, so
# renaming the job would leave the sweep matching zero check runs. It would
# then treat "no build has reported" as "not green", rebuild every candidate,
# and push onto branches whose build was already fine, with no error anywhere.
# Cheap to assert, invisible otherwise.
CHECK_RUN_NAME ?= Build & push

## check-check-run-names: Assert nix-cache.yml's job name still matches what dependabot-vendorhash.yml filters on
check-check-run-names:
	@grep -qF 'name: $(CHECK_RUN_NAME) (' .github/workflows/nix-cache.yml || { \
	  echo "lint: nix-cache.yml no longer defines a job named '$(CHECK_RUN_NAME) (...)'."; \
	  echo "      dependabot-vendorhash.yml selects its check runs by that prefix; update both."; \
	  exit 1; }
	@grep -qF 'startswith("$(CHECK_RUN_NAME)")' .github/workflows/dependabot-vendorhash.yml || { \
	  echo "lint: dependabot-vendorhash.yml no longer filters check runs on '$(CHECK_RUN_NAME)'."; \
	  echo "      That prefix is nix-cache.yml's job name; update both."; \
	  exit 1; }

## lint-actions: Lint the GitHub Actions workflows (actionlint + zizmor)
lint-actions: check-go check-check-run-names
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

## docs-build: Build the docs site (onBrokenLinks=throw; fails on broken links / warnings / orphaned pages / missing CSP)
docs-build: node_modules/.package-lock.json docs-check-orphans
	$(NPM) run build
	node scripts/check-csp.mjs build

## docs-check-csp: Verify every built page carries an enforceable CSP (needs a build in build/)
docs-check-csp: check-node
	node scripts/check-csp.mjs build

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
