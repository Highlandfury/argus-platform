// Command argus-collector is the edge agent: identity, policy, metric producer,
// durable spool, and the outbound mTLS transport (ADR-005).
//
// M0 scope: process skeleton, configuration, data-directory preparation, identity
// detection, and an idle heartbeat. Enrollment (M3) and the metric spine (M4) plug
// into this structure without changing the entrypoint contract.
package main

import (
	"context"
	"flag"
	"fmt"
	"net"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"
	"time"

	"github.com/argus-platform/argus/internal/platform/buildinfo"
	"github.com/argus-platform/argus/internal/platform/config"
	"github.com/argus-platform/argus/internal/platform/logging"
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
	case "doctor":
		return cmdDoctor(args[1:])
	case "version":
		fmt.Printf("argus-collector %s (commit %s, built %s)\n", buildinfo.Version, buildinfo.Commit, buildinfo.Date)
		return 0
	case "enroll":
		fmt.Fprintln(os.Stderr, "enroll: not implemented yet (arrives in M3 with the enrollment service)")
		return 1
	default:
		usage()
		return 2
	}
}

func cmdRun(args []string) int {
	fs := flag.NewFlagSet("run", flag.ContinueOnError)
	if err := fs.Parse(args); err != nil {
		return 2
	}
	cfg, err := config.LoadCollector()
	if err != nil {
		fmt.Fprintln(os.Stderr, "config:", err)
		return 1
	}
	logger, err := logging.New(cfg.LogLevel, os.Stdout)
	if err != nil {
		fmt.Fprintln(os.Stderr, "logger:", err)
		return 1
	}
	if err := os.MkdirAll(cfg.DataDir, 0o750); err != nil {
		fmt.Fprintln(os.Stderr, "data dir:", err)
		return 1
	}
	hasIdentity := identityPresent(cfg.DataDir)

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	start := time.Now()
	logger.Info("argus-collector starting",
		"component", "argus-collector",
		"version", buildinfo.Version,
		"commit", buildinfo.Commit,
		"data_dir", cfg.DataDir,
		"stream_addr", cfg.StreamAddr,
		"spool_max_bytes", cfg.SpoolMaxBytes,
		"has_identity", hasIdentity,
		"mode", mode(hasIdentity),
	)
	if !hasIdentity {
		logger.Info("no identity yet; enrollment arrives in M3 — running idle")
	}

	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			logger.Info("shutdown requested")
			return 0
		case <-ticker.C:
			logger.Info("heartbeat",
				"mode", mode(hasIdentity),
				"uptime_s", int64(time.Since(start).Seconds()),
				"data_dir", cfg.DataDir,
			)
		}
	}
}

func cmdDoctor(args []string) int {
	fs := flag.NewFlagSet("doctor", flag.ContinueOnError)
	if err := fs.Parse(args); err != nil {
		return 2
	}
	cfg, err := config.LoadCollector()
	if err != nil {
		fmt.Println("config      : FAIL", err)
		return 1
	}
	fmt.Println("config      : OK")

	if err := os.MkdirAll(cfg.DataDir, 0o750); err != nil {
		fmt.Println("data dir    : FAIL", err)
		return 1
	}
	probe := filepath.Join(cfg.DataDir, ".doctor-probe")
	if err := os.WriteFile(probe, []byte("ok"), 0o600); err != nil {
		fmt.Println("data dir    : FAIL not writable:", err)
		return 1
	}
	_ = os.Remove(probe)
	fmt.Println("data dir    : OK", cfg.DataDir)

	if identityPresent(cfg.DataDir) {
		fmt.Println("identity    : OK (cert.pem, key.pem, collector.json present)")
	} else {
		fmt.Println("identity    : WARN not enrolled yet (expected until M3)")
	}

	conn, err := net.DialTimeout("tcp", cfg.StreamAddr, 3*time.Second)
	if err != nil {
		fmt.Println("stream addr : WARN unreachable:", cfg.StreamAddr, "-", err)
	} else {
		_ = conn.Close()
		fmt.Println("stream addr : OK", cfg.StreamAddr)
	}
	return 0
}

func identityPresent(dataDir string) bool {
	for _, f := range []string{"cert.pem", "key.pem", "collector.json"} {
		if _, err := os.Stat(filepath.Join(dataDir, f)); err != nil {
			return false
		}
	}
	return true
}

func mode(hasIdentity bool) string {
	if hasIdentity {
		return "ready"
	}
	return "idle"
}

func usage() {
	fmt.Fprint(os.Stderr, `argus-collector — Argus edge collector

Usage:
  argus-collector run       Run the collector (idle until identity exists)
  argus-collector enroll    Enroll with a one-time token (M3)
  argus-collector doctor    Diagnose configuration, data dir, identity, connectivity
  argus-collector version   Print build metadata
`)
}
