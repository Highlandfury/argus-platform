// Command argus-server is the control plane: API, ops surface, and (from M3) the
// enrollment and collector gRPC listeners — one process, modular internals (ADR-001).
package main

import (
	"context"
	"crypto/tls"
	"errors"
	"flag"
	"fmt"
	"net"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/keepalive"

	collectorv1 "github.com/argus-platform/argus/gen/go/argus/collector/v1"
	"github.com/argus-platform/argus/internal/api"
	"github.com/argus-platform/argus/internal/modules/collectors"
	"github.com/argus-platform/argus/internal/modules/identity"
	"github.com/argus-platform/argus/internal/modules/ingest"
	"github.com/argus-platform/argus/internal/modules/tenancy"
	"github.com/argus-platform/argus/internal/platform/buildinfo"
	"github.com/argus-platform/argus/internal/platform/config"
	"github.com/argus-platform/argus/internal/platform/database"
	"github.com/argus-platform/argus/internal/platform/logging"
	"github.com/argus-platform/argus/internal/platform/ratelimit"
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
		return cmdMigrate(args[1:])
	case "seed-dev":
		return cmdSeedDev(args[1:])
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

	// Pools + readiness (SPEC §17): readyz reflects DB reachability, auth-role
	// reachability, and schema state.
	var (
		readiness []api.Check
		appPool   *pgxpool.Pool
		authPool  *pgxpool.Pool
	)
	if cfg.DBDSN == "" {
		readiness = append(readiness, api.Check{Name: "database", Fn: func(context.Context) error {
			return errors.New("ARGUS_SERVER_DB_DSN is not configured")
		}})
	} else {
		var poolErr error
		appPool, poolErr = database.NewPool(context.Background(), cfg.DBDSN, "argus-server", database.DefaultPoolConfig())
		if poolErr != nil {
			fmt.Fprintln(os.Stderr, "database:", poolErr)
			return 1
		}
		defer appPool.Close()
		readiness = append(readiness, api.Check{Name: "database", Fn: func(ctx context.Context) error {
			return database.CheckSchema(ctx, appPool)
		}})
	}
	if cfg.AuthDBDSN == "" {
		readiness = append(readiness, api.Check{Name: "auth_database", Fn: func(context.Context) error {
			return errors.New("ARGUS_SERVER_AUTH_DB_DSN is not configured")
		}})
	} else {
		var poolErr error
		authPool, poolErr = database.NewPool(context.Background(), cfg.AuthDBDSN, "argus-server-auth", database.DefaultPoolConfig())
		if poolErr != nil {
			fmt.Fprintln(os.Stderr, "auth database:", poolErr)
			return 1
		}
		defer authPool.Close()
		readiness = append(readiness, api.Check{Name: "auth_database", Fn: func(ctx context.Context) error {
			return authPool.Ping(ctx)
		}})
	}

	// Domain services (M2). Without both pools the API runs degraded: routes
	// answer 503 instead of failing at startup.
	var (
		tenancySvc  *tenancy.Service
		identitySvc *identity.Service
	)
	if appPool != nil && authPool != nil {
		tenancySvc = tenancy.New(appPool, authPool)
		identitySvc, err = identity.New(appPool, authPool, tenancySvc)
		if err != nil {
			fmt.Fprintln(os.Stderr, "identity:", err)
			return 1
		}
	}

	// Collector control plane (M3): internal CA + both gRPC listeners.
	ca, err := collectors.LoadOrCreateCA(cfg.CADir, cfg.GRPCSANs)
	if err != nil {
		fmt.Fprintln(os.Stderr, "collector ca:", err)
		return 1
	}
	var (
		collectorsSvc  *collectors.Service
		sessions       *collectors.SessionRegistry
		enrollGRPC     *grpc.Server
		streamGRPC     *grpc.Server
		enrollListener net.Listener
		streamListener net.Listener
	)
	if appPool != nil && authPool != nil {
		collectorsSvc = collectors.New(appPool, authPool, ca, tel)
		sessions = collectors.NewSessionRegistry()

		enrollGRPC = grpc.NewServer(
			grpc.Creds(credentials.NewTLS(&tls.Config{
				Certificates: []tls.Certificate{*ca.ServerTLS()},
				MinVersion:   tls.VersionTLS12,
			})),
			grpc.MaxRecvMsgSize(1<<20),
		)
		collectorv1.RegisterEnrollmentServiceServer(enrollGRPC,
			collectors.NewEnrollmentServer(collectorsSvc, ratelimit.New(10, 6*time.Second), logger))

		streamGRPC = grpc.NewServer(
			grpc.Creds(credentials.NewTLS(&tls.Config{
				Certificates: []tls.Certificate{*ca.ServerTLS()},
				ClientAuth:   tls.RequireAndVerifyClientCert,
				ClientCAs:    ca.RootPool(),
				MinVersion:   tls.VersionTLS12,
			})),
			grpc.MaxRecvMsgSize(16<<20),
			grpc.KeepaliveParams(keepalive.ServerParameters{Time: 30 * time.Second, Timeout: 10 * time.Second}),
			grpc.KeepaliveEnforcementPolicy(keepalive.EnforcementPolicy{MinTime: 10 * time.Second, PermitWithoutStream: false}),
		)
		collectorv1.RegisterCollectorServiceServer(streamGRPC,
			collectors.NewStreamServer(collectorsSvc, sessions, ingest.New(appPool, nil, tel, logger), logger))

		if enrollListener, err = net.Listen("tcp", cfg.EnrollAddr); err != nil {
			fmt.Fprintln(os.Stderr, "enrollment listener:", err)
			return 1
		}
		if streamListener, err = net.Listen("tcp", cfg.GRPCAddr); err != nil {
			fmt.Fprintln(os.Stderr, "collector stream listener:", err)
			return 1
		}
	} else {
		logger.Warn("collector control plane disabled: database pools not configured")
	}

	opts := api.Options{
		Logger:            logger,
		Telemetry:         tel,
		Version:           buildinfo.Version,
		Commit:            buildinfo.Commit,
		Readiness:         readiness,
		SecureCookies:     cfg.Env == config.EnvProd,
		Identity:          identitySvc,
		Tenancy:           tenancySvc,
		Collectors:        collectorsSvc,
		CollectorSessions: sessions,
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

	errCh := make(chan error, 4)
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
	if enrollGRPC != nil {
		go func() {
			logger.Info("enrollment listening", "addr", cfg.EnrollAddr)
			if err := enrollGRPC.Serve(enrollListener); err != nil {
				errCh <- fmt.Errorf("enrollment listener: %w", err)
			}
		}()
		go func() {
			logger.Info("collector stream listening", "addr", cfg.GRPCAddr)
			if err := streamGRPC.Serve(streamListener); err != nil {
				errCh <- fmt.Errorf("collector stream listener: %w", err)
			}
		}()
	}

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
	if sessions != nil {
		sessions.DisconnectAll(collectors.DisconnectMsg{
			Code:   collectorv1.Disconnect_CODE_SERVER_SHUTDOWN,
			Reason: "server shutting down",
		})
	}
	stopGRPC := func(srv *grpc.Server) {
		done := make(chan struct{})
		go func() {
			srv.GracefulStop()
			close(done)
		}()
		select {
		case <-done:
		case <-time.After(5 * time.Second):
			srv.Stop()
		}
	}
	if enrollGRPC != nil {
		stopGRPC(enrollGRPC)
	}
	if streamGRPC != nil {
		stopGRPC(streamGRPC)
	}
	logger.Info("argus-server stopped")
	if runErr != nil {
		return 1
	}
	return 0
}

func cmdMigrate(args []string) int {
	fs := flag.NewFlagSet("migrate", flag.ContinueOnError)
	down := fs.Int("down", 0, "step down N migrations instead of applying all pending")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	cfg, err := config.LoadServer()
	if err != nil {
		fmt.Fprintln(os.Stderr, "config:", err)
		return 1
	}
	if cfg.MigrateDSN == "" {
		fmt.Fprintln(os.Stderr, "ARGUS_SERVER_MIGRATE_DSN is required (owner-role DSN)")
		return 1
	}
	if *down > 0 {
		if err := database.MigrateDown(cfg.MigrateDSN, *down); err != nil {
			fmt.Fprintln(os.Stderr, "migrate down:", err)
			return 1
		}
		fmt.Printf("migrate: stepped down %d migration(s)\n", *down)
		return 0
	}
	version, err := database.MigrateUp(cfg.MigrateDSN)
	if err != nil {
		fmt.Fprintln(os.Stderr, "migrate up:", err)
		return 1
	}
	fmt.Printf("migrate: schema at version %d\n", version)
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
