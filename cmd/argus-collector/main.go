// Command argus-collector is the edge agent: identity, policy, metric
// producer, durable spool, and the outbound mTLS transport (ADR-005).
//
// Subcommands: run | enroll | doctor | version.
package main

import (
	"fmt"
	"os"

	"github.com/argus-platform/argus/internal/platform/buildinfo"
)

func main() {
	os.Exit(run(os.Args[1:]))
}

func run(args []string) int {
	if len(args) == 0 {
		usage()
		return 2
	}
	switch args[0] {
	case "run":
		return cmdRun(args[1:])
	case "enroll":
		return cmdEnroll(args[1:])
	case "doctor":
		return cmdDoctor(args[1:])
	case "version":
		fmt.Printf("argus-collector %s (commit %s, built %s)\n", buildinfo.Version, buildinfo.Commit, buildinfo.Date)
		return 0
	default:
		usage()
		return 2
	}
}

func usage() {
	fmt.Fprint(os.Stderr, `argus-collector - Argus edge collector

Usage:
  argus-collector run       Enroll (if needed), spool metrics, stream telemetry
  argus-collector enroll    Perform one-time enrollment and exit
  argus-collector doctor    Diagnose configuration, identity, CA, spool, connectivity
  argus-collector version   Print build metadata
`)
}
