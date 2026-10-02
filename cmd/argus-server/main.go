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
	grpccreds "google.golang.org/grpc/credentials"
	"google.golang.org/grpc/keepalive"

	collectorv1 "github.com/argus-platform/argus/gen/go/argus/collector/v1"
	"github.com/argus-platform/argus/internal/api"
	"github.com/argus-platform/argus/internal/modules/alerts"
	"github.com/argus-platform/argus/internal/modules/checks"
	"github.com/argus-platform/argus/internal/modules/collectors"
	"github.com/argus-platform/argus/internal/modules/credentials"
	"github.com/argus-platform/argus/internal/modules/identity"
	"github.com/argus-platform/argus/internal/modules/ingest"
	"github.com/argus-platform/argus/internal/modules/inventory"
	"github.com/argus-platform/argus/internal/modules/metrics"
	"github.com/argus-platform/argus/internal/modules/notify"
	"github.com/argus-platform/argus/internal/modules/pollhealth"
	"github.com/argus-platform/argus/internal/modules/tenancy"
	"github.com/argus-platform/argus/internal/platform/authz"
	"github.com/argus-platform/argus/internal/platform/buildinfo"
	"github.com/argus-platform/argus/internal/platform/config"
	"github.com/argus-platform/argus/internal/platform/database"
	"github.com/argus-platform/argus/internal/platform/grpcx"
	"github.com/argus-platform/argus/internal/platform/logging"
	"github.com/argus-platform/argus/internal/platform/ratelimit"
	"github.com/argus-platform/argus/internal/platform/secrets"
	"github.com/argus-platform/argus/internal/platform/telemetry"
)

func main() {
	os.Exit(run(os.Args[1:]))
}

// enrollLimiter builds the enrollment token bucket: burst 10, then one token
// per 60s/rate (default 10/min/IP per SPEC §8.1). Load environments may raise
// the sustained rate explicitly via ARGUS_SERVER_ENROLL_RATE_PER_MIN; every
// load report states when that override was active.
func enrollLimiter(perMin int) *ratelimit.Limiter {
	if perMin <= 0 {
		perMin = 10
	}
	return ratelimit.New(10, time.Minute/time.Duration(perMin))
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
	case "metrics-maintenance":
		return cmdMetricsMaintenance(args[1:])
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
	argus := telemetry.NewArgus(tel)
	metrics.RegisterSeriesMetrics(tel)
	metrics.RegisterGuardMetrics(tel)
	alerts.RegisterMetrics(tel)
	notify.RegisterMetrics(tel)

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
		poolCfg := database.DefaultPoolConfig()
		poolCfg.MaxConns = int32(cfg.DBMaxConns) //nolint:gosec // validated to 1..80
		appPool, poolErr = database.NewPool(context.Background(), cfg.DBDSN, "argus-server", poolCfg)
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

	// Secrets vault (M7-S2/P2-D2) and the M9-S3 dispatch resolver. Built before
	// the collector service so policy materialization and the credentials API
	// share one vault instance. Failure disables both credential routes
	// (degraded mode, explicit 503) and leaves policy bundles without a
	// session block.
	var (
		credentialsSvc     *credentials.Service
		credentialResolver *credentials.Resolver
		secretsVault       secrets.SecretsVault
	)
	if appPool != nil {
		kek, err := secrets.LoadOrCreateLocalKMS(secrets.LocalConfig{
			Path:          cfg.SecretsKeyFile,
			KeyID:         cfg.SecretsKeyID,
			AllowGenerate: cfg.Env == config.EnvDev,
			Logger:        logger,
		})
		if err != nil {
			logger.Error("credentials API disabled: secrets vault unavailable", "error", err)
		} else {
			vault := secrets.New(kek)
			secretsVault = vault
			credentialsSvc = credentials.New(appPool, vault, credentials.SlogAudit{Logger: logger})
			credentialResolver = credentials.NewResolver(appPool, vault)
		}
	}
	var (
		collectorsSvc  *collectors.Service
		sessions       *collectors.SessionRegistry
		checksSvc      *checks.Service
		metricsQuery   *metrics.QueryService
		enrollGRPC     *grpc.Server
		streamGRPC     *grpc.Server
		enrollListener net.Listener
		streamListener net.Listener
	)
	if appPool != nil && authPool != nil {
		collectorOpts := []collectors.Option{collectors.WithLogger(logger)}
		if credentialResolver != nil {
			collectorOpts = append(collectorOpts, collectors.WithCredentialResolver(credentialResolver))
		}
		collectorsSvc = collectors.New(appPool, authPool, ca, tel, collectorOpts...)
		sessions = collectors.NewSessionRegistry()
		// On-demand checks (M10-S0): the session registry is the live push
		// path; the checks service is also the reconnect redelivery source and
		// the idempotent result sink wired into the stream server below.
		checksSvc = checks.New(appPool, sessions)
		metricsQuery = metrics.NewQueryService(appPool, collectorsSvc, argus)

		enrollGRPC = grpc.NewServer(
			grpc.Creds(grpccreds.NewTLS(&tls.Config{
				Certificates: []tls.Certificate{*ca.ServerTLS()},
				MinVersion:   tls.VersionTLS12,
			})),
			grpc.MaxRecvMsgSize(1<<20),
			grpc.ChainUnaryInterceptor(grpcx.UnaryServerInterceptor()),
			grpc.ChainStreamInterceptor(grpcx.StreamServerInterceptor()),
		)
		collectorv1.RegisterEnrollmentServiceServer(enrollGRPC,
			collectors.NewEnrollmentServer(collectorsSvc, enrollLimiter(cfg.EnrollRatePerMin), logger))

		streamGRPC = grpc.NewServer(
			grpc.Creds(grpccreds.NewTLS(&tls.Config{
				Certificates: []tls.Certificate{*ca.ServerTLS()},
				ClientAuth:   tls.RequireAndVerifyClientCert,
				ClientCAs:    ca.RootPool(),
				MinVersion:   tls.VersionTLS12,
			})),
			grpc.MaxRecvMsgSize(16<<20),
			grpc.ChainUnaryInterceptor(grpcx.UnaryServerInterceptor()),
			grpc.ChainStreamInterceptor(grpcx.StreamServerInterceptor()),
			grpc.KeepaliveParams(keepalive.ServerParameters{Time: 30 * time.Second, Timeout: 10 * time.Second}),
			grpc.KeepaliveEnforcementPolicy(keepalive.EnforcementPolicy{MinTime: 10 * time.Second, PermitWithoutStream: false}),
		)
		streamServer := collectors.NewStreamServer(collectorsSvc, sessions, ingest.New(appPool, nil, argus, logger, ingest.WithAudit(inventory.SlogAudit{Logger: logger})), logger)
		streamServer.Checks = checksSvc
		streamServer.CheckResults = checksSvc
		collectorv1.RegisterCollectorServiceServer(streamGRPC, streamServer)

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

	// Inventory API (M7): device/interface/group CRUD with audit evidence.
	var inventorySvc *inventory.Service
	if appPool != nil {
		inventorySvc = inventory.New(appPool, inventory.SlogAudit{Logger: logger})
	}

	// Poll health API (M9-S1): device-scoped read of persisted poll outcomes.
	var pollHealthSvc *pollhealth.Service
	if appPool != nil {
		pollHealthSvc = pollhealth.New(appPool)
	}

	// Alert engine (M11-S1): rules/alerts API plus the in-process evaluator
	// (P2-D3, no NATS). The evaluator runs on its own goroutine below; the
	// scheduler is a no-op until both DB pools are configured.
	var (
		alertsSvc    *alerts.Service
		alertEval    *alerts.Evaluator
		alertSched   *alerts.Scheduler
		alertsStream *alerts.StreamHub
	)
	if appPool != nil {
		alertsSvc = alerts.New(appPool, authz.New(appPool))
		alertEval = alerts.NewEvaluator(appPool, alerts.EvaluatorOptions{Logger: logger})
		alertsStream = alerts.NewStreamHub(alerts.StreamOptions{Logger: logger})
		alertsSvc.AddSink(alertsStream)
		alertEval.AddSink(alertsStream)
	}
	if appPool != nil && authPool != nil {
		alertSched = alerts.NewScheduler(appPool, authPool, alertEval, logger)
	}

	// Notification engine (M11-S2): consumes the alerts transition sink,
	// persists deliveries and runs the retry/breaker worker. Secrets go
	// through the shared M7 vault; without it channels still work but
	// secret-bearing operations fail closed.
	var (
		notifySvc    *notify.Service
		notifyEngine *notify.Engine
	)
	if appPool != nil {
		notifySvc = notify.New(appPool, secretsVault)
		notifySvc.SetAuthorizer(authz.New(appPool))
		notifyEngine = notify.NewEngine(appPool, secretsVault, notify.EngineOptions{
			Logger: logger,
			Auth:   authPool,
		})
		if alertsSvc != nil {
			alertsSvc.AddSink(notifyEngine)
		}
		if alertEval != nil {
			alertEval.AddSink(notifyEngine)
		}
		if alertSched != nil && alertsSvc != nil {
			alertSched.SetDefaultsSeeder(alertsSvc)
		}
	}

	opts := api.Options{
		Logger:            logger,
		Telemetry:         tel,
		Argus:             argus,
		Version:           buildinfo.Version,
		Commit:            buildinfo.Commit,
		Readiness:         readiness,
		SecureCookies:     cfg.Env == config.EnvProd,
		Identity:          identitySvc,
		Tenancy:           tenancySvc,
		Collectors:        collectorsSvc,
		CollectorSessions: sessions,
		MetricsQuery:      metricsQuery,
		Inventory:         inventorySvc,
		Credentials:       credentialsSvc,
		PollHealth:        pollHealthSvc,
		Checks:            checksSvc,
		Alerts:            alertsSvc,
		AlertsStream:      alertsStream,
		Notify:            notifySvc,
		NotifyEngine:      notifyEngine,
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

	// §15 DB-derived collector gauges (30 s cadence; stale computed from
	// heartbeat age so an idle collector is never reported healthy).
	if appPool != nil && authPool != nil {
		gauges := telemetry.NewCollectorGauges(appPool, authPool, tel)
		go gauges.Run(ctx, 30*time.Second)
	}
	// Alert evaluator (M11-S1): in-process scheduler, per-rule cadence.
	if alertSched != nil {
		go alertSched.Run(ctx, 15*time.Second)
	}
	// Notification retry/breaker worker (M11-S2).
	if notifyEngine != nil {
		go notifyEngine.Run(ctx, 15*time.Second)
	}

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

// cmdMetricsMaintenance is the M8 verification/maintenance entry point
// (P2-AC-09): it applies the configured raw retention window and retires
// inactive series under the owner role, then verifies the storage policies
// against timescaledb_information and exits non-zero on any mismatch — the
// nightly `metrics-maintenance` CI job runs the same checks against a real
// TimescaleDB.
func cmdMetricsMaintenance(args []string) int {
	fs := flag.NewFlagSet("metrics-maintenance", flag.ContinueOnError)
	verifyOnly := fs.Bool("verify-only", false, "verify policies without applying retention or retirement")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	cfg, err := config.LoadServer()
	if err != nil {
		fmt.Fprintln(os.Stderr, "config:", err)
		return 1
	}
	if cfg.MigrateDSN == "" {
		fmt.Fprintln(os.Stderr, "ARGUS_SERVER_MIGRATE_DSN is required (owner-role DSN with BYPASSRLS)")
		return 1
	}
	ctx := context.Background()
	pool, err := database.NewPool(ctx, cfg.MigrateDSN, "metrics-maintenance", database.DefaultPoolConfig())
	if err != nil {
		fmt.Fprintln(os.Stderr, "database:", err)
		return 1
	}
	defer pool.Close()

	rawRetention := time.Duration(cfg.MetricsRawRetentionDays) * 24 * time.Hour
	if !*verifyOnly {
		if err := metrics.ApplyRawRetention(ctx, pool, rawRetention); err != nil {
			fmt.Fprintln(os.Stderr, "metrics-maintenance apply:", err)
			return 1
		}
		retired, err := metrics.RetireInactiveSeries(ctx, pool, metrics.SeriesRetirementAge)
		if err != nil {
			fmt.Fprintln(os.Stderr, "metrics-maintenance retire:", err)
			return 1
		}
		fmt.Printf("metrics-maintenance: raw retention %d d, retired series %d\n",
			cfg.MetricsRawRetentionDays, retired)
	}
	if err := metrics.VerifyPolicies(ctx, pool, metrics.VerifyOptions{RawRetention: rawRetention}); err != nil {
		fmt.Fprintln(os.Stderr, "metrics-maintenance verification failed:", err)
		return 1
	}
	fmt.Println("metrics-maintenance: policies verified")
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
  argus-server serve               Start API + ops listeners
  argus-server healthcheck         Probe the local health endpoint (exit 0 when healthy)
  argus-server migrate             Apply database migrations (M1)
  argus-server metrics-maintenance Apply retention/retirement + verify metrics policies (M8)
  argus-server seed-dev            Seed a development org/site/user (M1)
  argus-server version             Print build metadata
`)
}
