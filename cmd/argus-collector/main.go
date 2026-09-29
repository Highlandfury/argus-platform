// Command argus-collector is the edge agent: identity, policy, metric producer,
// durable spool, and the outbound mTLS transport (ADR-005).
//
// M3 scope: enrollment (one-time token -> certificate), identity persistence,
// mTLS control stream with policy delivery/ack, heartbeats, reconnect with
// backoff, terminal revocation handling, and the explicit lifecycle state
// machine.
package main

import (
	"context"
	"encoding/base64"
	"flag"
	"fmt"
	"log/slog"
	"net"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/argus-platform/argus/internal/collector"
	"github.com/argus-platform/argus/internal/collector/enrollclient"
	"github.com/argus-platform/argus/internal/collector/identity"
	"github.com/argus-platform/argus/internal/collector/stream"
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

func cmdRun(args []string) int {
	fs := flag.NewFlagSet("run", flag.ContinueOnError)
	if err := fs.Parse(args); err != nil {
		return 2
	}
	cfg, logger, err := loadConfig()
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	if err := os.MkdirAll(cfg.DataDir, 0o750); err != nil {
		fmt.Fprintln(os.Stderr, "data dir:", err)
		return 1
	}

	machine := collector.NewMachine(collector.StateNew, logger)
	idStore := identity.NewStore(cfg.DataDir)

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	id, enrolled, err := idStore.Load()
	if err != nil {
		logger.Error("identity load failed", "error", err)
		_ = machine.Transition(collector.StateFailed)
		return 1
	}

	if !enrolled {
		token := loadEnrollToken(cfg)
		if token == "" {
			logger.Warn("no identity and no enrollment token; running idle until provisioned")
			<-ctx.Done()
			return 0
		}
		if err := machine.Transition(collector.StateEnrolling); err != nil {
			logger.Error("state", "error", err)
			return 1
		}
		id, err = enrollWithRetry(ctx, cfg, idStore, token, machine, logger)
		if err != nil {
			logger.Error("enrollment failed", "error", err)
			_ = machine.Transition(collector.StateFailed)
			return 1
		}
		logger.Info("enrolled", "collector_id", id.CollectorID, "cert_not_after", id.CertNotAfter)
	} else {
		logger.Info("identity loaded",
			"collector_id", id.CollectorID,
			"cert_not_after", id.CertNotAfter,
			"policy_version", id.PolicyVersion)
	}

	keyDER, err := base64.StdEncoding.DecodeString(id.PolicyKeyDERB64)
	if err != nil || len(keyDER) == 0 {
		logger.Error("identity is missing the pinned policy signing key")
		return 1
	}
	certPath, keyPath, _, _ := idStore.Paths()

	if machine.State() != collector.StateReconnecting {
		if err := machine.Transition(collector.StateReconnecting); err != nil {
			logger.Error("state", "error", err)
			return 1
		}
	}
	client := stream.New(stream.Config{
		StreamAddr:     cfg.StreamAddr,
		CAFile:         cfg.CAFile,
		CertFile:       certPath,
		KeyFile:        keyPath,
		CollectorID:    id.CollectorID,
		AgentVersion:   buildinfo.Version,
		PolicyDir:      filepath.Join(cfg.DataDir, "policy"),
		Log:            logger,
		AppliedVersion: id.PolicyVersion,
		PolicyKeyDER:   keyDER,
		OnPolicyApplied: func(version int64) {
			if err := idStore.UpdatePolicyVersion(id, version); err != nil {
				logger.Error("persist policy version", "error", err)
			}
		},
	}, machine)

	if err := client.Run(ctx); err != nil {
		logger.Error("stream terminated", "error", err)
		_ = machine.Transition(collector.StateFailed)
		return 1
	}
	logger.Info("collector stopped", "state", machine.State())
	return 0
}

func cmdEnroll(args []string) int {
	fs := flag.NewFlagSet("enroll", flag.ContinueOnError)
	tokenFlag := fs.String("token", "", "enrollment token (defaults to ARGUS_ENROLL_TOKEN / token file)")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	cfg, logger, err := loadConfig()
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	if err := os.MkdirAll(cfg.DataDir, 0o750); err != nil {
		fmt.Fprintln(os.Stderr, "data dir:", err)
		return 1
	}
	machine := collector.NewMachine(collector.StateNew, logger)
	idStore := identity.NewStore(cfg.DataDir)
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	if _, enrolled, _ := idStore.Load(); enrolled {
		fmt.Fprintln(os.Stderr, "already enrolled; remove", cfg.DataDir, "to re-enroll (operator flow)")
		return 1
	}
	token := *tokenFlag
	if token == "" {
		token = loadEnrollToken(cfg)
	}
	if token == "" {
		fmt.Fprintln(os.Stderr, "no enrollment token (use -token, ARGUS_ENROLL_TOKEN, or the token file)")
		return 1
	}
	if err := machine.Transition(collector.StateEnrolling); err != nil {
		return 1
	}
	id, err := enrollWithRetry(ctx, cfg, idStore, token, machine, logger)
	if err != nil {
		fmt.Fprintln(os.Stderr, "enrollment failed:", err)
		return 1
	}
	fmt.Printf("enrolled collector %s (cert expires %s)\n", id.CollectorID, id.CertNotAfter.Format(time.RFC3339))
	return 0
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

	if raw, err := os.ReadFile(cfg.CAFile); err != nil {
		fmt.Println("pinned CA   : FAIL", err)
	} else if len(raw) == 0 {
		fmt.Println("pinned CA   : FAIL empty file")
	} else {
		fmt.Println("pinned CA   : OK", cfg.CAFile)
	}

	idStore := identity.NewStore(cfg.DataDir)
	if id, enrolled, err := idStore.Load(); err != nil {
		fmt.Println("identity    : FAIL", err)
	} else if enrolled {
		days := int(time.Until(id.CertNotAfter).Hours() / 24)
		fmt.Printf("identity    : OK collector=%s cert_expires_in=%dd policy_v%d\n", id.CollectorID, days, id.PolicyVersion)
	} else {
		fmt.Println("identity    : WARN not enrolled yet")
		token := loadEnrollToken(cfg)
		if token == "" {
			fmt.Println("token       : WARN none available (set the token file or ARGUS_ENROLL_TOKEN)")
		} else {
			fmt.Println("token       : OK available")
		}
	}

	if conn, err := dialTCP(cfg.StreamAddr); err != nil {
		fmt.Println("stream addr : FAIL", err)
	} else {
		_ = conn.Close()
		fmt.Println("stream addr : OK", cfg.StreamAddr)
	}
	return 0
}

func loadConfig() (config.Collector, *slog.Logger, error) {
	cfg, err := config.LoadCollector()
	if err != nil {
		return cfg, nil, fmt.Errorf("config: %w", err)
	}
	logger, err := logging.New(cfg.LogLevel, os.Stdout)
	if err != nil {
		return cfg, nil, fmt.Errorf("logger: %w", err)
	}
	return cfg, logger, nil
}

func loadEnrollToken(cfg config.Collector) string {
	if token := strings.TrimSpace(os.Getenv("ARGUS_ENROLL_TOKEN")); token != "" {
		return token
	}
	if cfg.EnrollTokenFile == "" {
		return ""
	}
	raw, err := os.ReadFile(cfg.EnrollTokenFile)
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(raw))
}

// enrollWithRetry retries transient failures; invalid/expired/used tokens and
// name collisions are terminal and surfaced with distinct messages.
func enrollWithRetry(ctx context.Context, cfg config.Collector, store *identity.Store, token string, machine *collector.Machine, logger *slog.Logger) (identity.Identity, error) {
	backoff := 2 * time.Second
	for attempt := 1; ; attempt++ {
		hostname, _ := os.Hostname()
		res, err := enrollclient.Enroll(ctx, enrollclient.Config{
			EnrollURL:    cfg.EnrollURL,
			CAFile:       cfg.CAFile,
			Token:        token,
			Name:         cfg.Name,
			AgentVersion: buildinfo.Version,
			Hostname:     hostname,
			OS:           "linux",
			Timeout:      20 * time.Second,
		})
		if err == nil {
			id := identity.Identity{
				CollectorID:     res.CollectorID,
				Name:            cfg.Name,
				ServerEnrollURL: cfg.EnrollURL,
				StreamAddr:      cfg.StreamAddr,
				AgentVersion:    buildinfo.Version,
				CertNotAfter:    res.CertNotAfter,
				EnrolledAt:      time.Now().UTC(),
				PolicyVersion:   res.PolicyVersion,
				PolicyKeyDERB64: base64.StdEncoding.EncodeToString(res.PolicyKeyDER),
			}
			if err := store.Save(id, res.CertPEM, res.KeyPEM, res.CAPEM); err != nil {
				return identity.Identity{}, err
			}
			if err := machine.Transition(collector.StateReconnecting); err != nil {
				return identity.Identity{}, err
			}
			return id, nil
		}
		switch status.Code(err) {
		case codes.PermissionDenied:
			return identity.Identity{}, fmt.Errorf("token was rejected (invalid, expired, or already used): %w", err)
		case codes.InvalidArgument, codes.AlreadyExists:
			return identity.Identity{}, err
		}
		if ctx.Err() != nil {
			return identity.Identity{}, ctx.Err()
		}
		if attempt >= 30 {
			return identity.Identity{}, fmt.Errorf("giving up after %d attempts: %w", attempt, err)
		}
		logger.Warn("enrollment attempt failed; retrying", "attempt", attempt, "backoff", backoff, "error", err)
		select {
		case <-time.After(backoff):
		case <-ctx.Done():
			return identity.Identity{}, ctx.Err()
		}
		if backoff < 30*time.Second {
			backoff *= 2
		}
	}
}

func dialTCP(addr string) (net.Conn, error) {
	return net.DialTimeout("tcp", addr, 3*time.Second)
}

func usage() {
	fmt.Fprint(os.Stderr, `argus-collector - Argus edge collector

Usage:
  argus-collector run       Enroll (if needed) then run the control stream
  argus-collector enroll    Perform one-time enrollment and exit
  argus-collector doctor    Diagnose configuration, identity, CA, connectivity
  argus-collector version   Print build metadata
`)
}
