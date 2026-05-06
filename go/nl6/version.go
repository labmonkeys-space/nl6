/*
 * Copyright 2026 Ronny Trommer <ronny@no42.org>
 * SPDX-License-Identifier: Apache-2.0
 */

package main

// Version is the simulator's self-reported build identity. It is
// populated at link time via `-ldflags "-X main.Version=<value>"`.
// Resolution precedence (driven by the Makefile):
//
//  1. APP_VERSION environment variable (CI tag-build override)
//  2. `git describe --tags` — tagged commit → `vX.Y.Z`; HEAD ahead of
//     the last tag → `vX.Y.Z-N-g<sha>` so ahead-of-tag dev builds
//     never masquerade as the tag itself
//  3. the literal string "dev" (fallback for shallow / untagged clones)
//
// A binary built by `go build` directly (bypassing `make build`)
// carries the zero-value "dev" — an obvious signal that ldflags
// injection did not run.
var Version = "dev"
