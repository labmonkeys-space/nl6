//go:build !linux

/*
 * Copyright 2025 Ronny Trommer <ronny@no42.org>
 * SPDX-License-Identifier: Apache-2.0
 */

// Non-Linux stubs for Linux-specific route-script generation helpers.
// The full implementations live in web_routes_linux.go (auto-excluded on non-Linux).
package main

func generateDebianRouteSection(_ map[string]bool) string { return "" }
func generateRHELRouteSection(_ map[string]bool) string   { return "" }
func generateSUSERouteSection(_ map[string]bool) string   { return "" }
