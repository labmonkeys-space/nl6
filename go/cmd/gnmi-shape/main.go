/*
 * Copyright 2026 Ronny Trommer <ronny@no42.org>
 * SPDX-License-Identifier: Apache-2.0
 */

// Command gnmi-shape works with a gnmic capture without publishing its
// values. `reduce` writes a value-free shape fixture; `leak` refuses
// a change or a text that carries a token from the capture. Neither prints
// capture content.
package main

import (
	"flag"
	"fmt"
	"io"
	"os"
	"strings"
)

func runReduce(args []string, stdout io.Writer) int {
	fs := flag.NewFlagSet("reduce", flag.ContinueOnError)
	fs.SetOutput(stdout)
	in := fs.String("in", "", "gnmic --format json capture file")
	subtree := fs.String("subtree", "", "fixture subtree name")
	release := fs.String("release", "", "software release of the reference, e.g. 24.2.2")
	unionList := fs.String("union", "", "comma-separated wildcarded leaf paths YANG types as unions; they may carry several classes")
	if err := fs.Parse(args); err != nil || *in == "" || *subtree == "" || *release == "" {
		_, _ = fmt.Fprintln(stdout, "usage: gnmi-shape reduce -in FILE -subtree NAME -release VERSION > fixture.json")
		return 2
	}
	f, err := os.Open(*in)
	if err != nil {
		fmt.Fprintf(os.Stderr, "reduce: %v\n", err)
		return 2
	}
	defer f.Close()
	unions := map[string]bool{}
	for _, l := range strings.Split(*unionList, ",") {
		if l = strings.TrimSpace(l); l != "" {
			unions[l] = true
		}
	}
	fx, err := reduceCaptureUnions(f, *subtree, *release, unions)
	if err != nil {
		fmt.Fprintf(os.Stderr, "%v\n", err)
		return 1
	}
	b, err := marshalFixture(fx)
	if err != nil {
		fmt.Fprintf(os.Stderr, "reduce: %v\n", err)
		return 1
	}
	_, _ = stdout.Write(b)
	return 0
}

func main() {
	if len(os.Args) < 2 {
		fmt.Fprintln(os.Stderr, "usage: gnmi-shape reduce|leak [flags]")
		os.Exit(2)
	}
	switch os.Args[1] {
	case "reduce":
		os.Exit(runReduce(os.Args[2:], os.Stdout))
	case "leak":
		os.Exit(runLeak(os.Args[2:], os.Stdout))
	}
	fmt.Fprintln(os.Stderr, "usage: gnmi-shape reduce|leak [flags]")
	os.Exit(2)
}
