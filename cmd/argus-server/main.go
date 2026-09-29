// Command argus-server is the control plane: API, ops surface, and (from M3) the
// enrollment and collector gRPC listeners — one process, modular internals (ADR-001).
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/argus-platform/argus/internal/api"
	"github.com/argus-platform/argus/internal/platform/buildinfo"
	"github.com/argus-platform/argus/internal/platform/config"
	"github.com/argus-platform/argus/internal/platform/logging"
	"github.com/argus-platform/argus/internal/platform/telemetry"
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
	case "serve":
		return cmdServe(args[1:])
	case "healthcheck":
		return cmdHealthcheck(args[1:])
	case "version":
		fmt.Printf("argus-server %s (commit %s, built %s)\n", buildinfo.Version, buildinfo.Commit, buildinfo.Date)
		return 0
	case "migrate":
		fmt.Fprintln(os.Stderr, "migrate: not implemented yet (arrives in M1 with migrations/ and the owner DSN)")
		return 1
	case "seed-dev":
		fmt.Fprintln(os.Stderr, "seed-dev: not implemented yet (arrives in M1)")
		return 1
	default:
		usage()
		return 2
	}
}

func cmdServe(args []string) int {
	fs := flag.NewFlagSet("serve", flag.ContinueOnError)
	if err := fs.Parse(args); err != nil {
		return 2
	}

	cfg, err := config.LoadServer()
	if err != nil {
		fmt.Fprintln(os.Stderr, "config:", err)
		return 1
	}
	logger, err := logging.New(cfg.LogLevel, os.Stdout)
	if err != nil {
		fmt.Fprintln(os.Stderr, "logger:", err)
		return 1
	}

	tel := telemetry.New("server", buildinfo.Version, buildinfo.Commit)

	// M1 replaces this with the real pool ping + migration-state check.
	var readiness []api.Check
	_ = cfg

	opts := api.Options{
		Logger:    logger,
		Telemetry: tel,
		Version:   buildinfo.Version,
		Commit:    buildinfo.Commit,
		Readiness: readiness,
	}

	httpSrv := &http.Server{
		Addr:              cfg.HTTPAddr,
		Handler:           api.NewRouter(opts),
		ReadHeaderTimeout: 5 * time.Second,
	}
	opsSrv := &http.Server{
		Addr:              cfg.OpsAddr,
		Handler:           api.NewOpsRouter(opts),
		ReadHeaderTimeout: 5 * time.Second,
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	logger.Info("argus-server starting",
		"component", "argus-server",
		"version", buildinfo.Version,
		"commit", buildinfo.Commit,
		"env", cfg.Env,
		"http_addr", cfg.HTTPAddr,
		"ops_addr", cfg.OpsAddr,
	)

	errCh := make(chan error, 2)
	go func() {
		if err := httpSrv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			errCh <- fmt.Errorf("http listener: %w", err)
		}
	}()
	go func() {
		if err := opsSrv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			errCh <- fmt.Errorf("ops listener: %w", err)
		}
	}()

	var runErr error
	select {
	case <-ctx.Done():
		logger.Info("shutdown requested")
	case runErr = <-errCh:
		logger.Error("listener failed", "error", runErr)
	}

	shutdownCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	_ = httpSrv.Shutdown(shutdownCtx)
	_ = opsSrv.Shutdown(shutdownCtx)
	logger.Info("argus-server stopped")
	if runErr != nil {
		return 1
	}
	return 0
}

func cmdHealthcheck(args []string) int {
	fs := flag.NewFlagSet("healthcheck", flag.ContinueOnError)
	url := fs.String("url", "http://127.0.0.1:8080/v1/healthz", "health endpoint URL")
	timeout := fs.Duration("timeout", 3*time.Second, "request timeout")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	client := &http.Client{Timeout: *timeout}
	resp, err := client.Get(*url)
	if err != nil {
		fmt.Fprintln(os.Stderr, "healthcheck:", err)
		return 1
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		fmt.Fprintf(os.Stderr, "healthcheck: status %d\n", resp.StatusCode)
		return 1
	}
	return 0
}

func usage() {
	fmt.Fprint(os.Stderr, `argus-server — Argus control plane

Usage:
  argus-server serve        Start API + ops listeners
  argus-server healthcheck  Probe the local health endpoint (exit 0 when healthy)
  argus-server migrate      Apply database migrations (M1)
  argus-server seed-dev     Seed a development org/site/user (M1)
  argus-server version      Print build metadata
`)
}
