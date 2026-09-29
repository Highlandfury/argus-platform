// Package config loads and validates process configuration from the environment.
//
// Rules (see docs/phase-1/PHASE_1_SPEC.md §3.6):
//   - Environment variables only; no hidden config files.
//   - Fail fast: every Load* returns a descriptive error for invalid input.
//   - M0 scope: validation covers what the skeleton consumes; later milestones extend
//     the structs without changing the loading pattern.
package config

import (
	"errors"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"strings"

	"github.com/argus-platform/argus/internal/platform/logging"
)

const (
	// EnvDev enables developer conveniences (seeding, verbose defaults).
	EnvDev = "dev"
	// EnvProd is the hardened production mode.
	EnvProd = "prod"
)

// Server holds argus-server configuration.
type Server struct {
	Env        string
	LogLevel   string
	HTTPAddr   string
	OpsAddr    string
	GRPCAddr   string // collector stream (mTLS)
	EnrollAddr string // enrollment (token-gated TLS)
	GRPCSANs   []string
	// EnrollRatePerMin relaxes the enrollment limiter for load environments
	// (default 10 attempts/min/IP per SPEC §8.1; the S-01 test still validates
	// the default). Recorded whenever non-default.
	EnrollRatePerMin int
	DBDSN            string // runtime role (argus_app_login), RLS-enforced
	AuthDBDSN        string // auth role (argus_auth_login), pre-auth lookups only
	MigrateDSN       string // owner role (argus_owner); used only by `migrate`
	CADir            string // internal CA material; required from M3
	DevSeed          bool
}

// LoadServer reads server configuration from the environment.
func LoadServer() (Server, error) {
	cfg := Server{
		Env:              env("ARGUS_ENV", EnvDev),
		LogLevel:         env("ARGUS_LOG_LEVEL", "info"),
		HTTPAddr:         env("ARGUS_SERVER_HTTP_ADDR", ":8080"),
		OpsAddr:          env("ARGUS_SERVER_OPS_ADDR", ":9090"),
		GRPCAddr:         env("ARGUS_SERVER_GRPC_ADDR", ":8443"),
		EnrollAddr:       env("ARGUS_SERVER_ENROLL_ADDR", ":8444"),
		GRPCSANs:         splitCSV(env("ARGUS_SERVER_GRPC_SANS", "localhost,server,127.0.0.1")),
		EnrollRatePerMin: int(envInt64("ARGUS_SERVER_ENROLL_RATE_PER_MIN", 10)),
		DBDSN:            env("ARGUS_SERVER_DB_DSN", ""),
		AuthDBDSN:        env("ARGUS_SERVER_AUTH_DB_DSN", ""),
		MigrateDSN:       env("ARGUS_SERVER_MIGRATE_DSN", ""),
		CADir:            env("ARGUS_SERVER_CA_DIR", "./.dev/ca"),
		DevSeed:          envBool("ARGUS_DEV_SEED", false),
	}

	if cfg.Env != EnvDev && cfg.Env != EnvProd {
		return cfg, fmt.Errorf("ARGUS_ENV: must be %q or %q, got %q", EnvDev, EnvProd, cfg.Env)
	}
	if _, err := logging.ParseLevel(cfg.LogLevel); err != nil {
		return cfg, fmt.Errorf("ARGUS_LOG_LEVEL: %w", err)
	}
	for name, addr := range map[string]string{
		"ARGUS_SERVER_HTTP_ADDR":   cfg.HTTPAddr,
		"ARGUS_SERVER_OPS_ADDR":    cfg.OpsAddr,
		"ARGUS_SERVER_GRPC_ADDR":   cfg.GRPCAddr,
		"ARGUS_SERVER_ENROLL_ADDR": cfg.EnrollAddr,
	} {
		if strings.TrimSpace(addr) == "" {
			return cfg, fmt.Errorf("%s: must not be empty", name)
		}
	}
	if cfg.Env == EnvProd {
		if cfg.DBDSN == "" {
			return cfg, errors.New("ARGUS_SERVER_DB_DSN is required when ARGUS_ENV=prod")
		}
		if !strings.Contains(cfg.DBDSN, "sslmode=") {
			return cfg, errors.New("ARGUS_SERVER_DB_DSN must set sslmode explicitly in prod")
		}
	}
	return cfg, nil
}

// Collector holds argus-collector configuration.
type Collector struct {
	LogLevel        string
	EnrollURL       string // e.g. https://server:8444 (enrollment)
	StreamAddr      string // e.g. server:8443 (mTLS stream)
	DataDir         string
	CAFile          string // pinned server CA (operator-distributed)
	Name            string
	MetricsAddr     string // loopback-only self-observability endpoint (SPEC §15)
	SpoolMaxBytes   int64
	FsyncIntervalMS int
	EnrollTokenFile string // read once when enrolling; never persisted
}

// LoadCollector reads collector configuration from the environment.
func LoadCollector() (Collector, error) {
	cfg := Collector{
		LogLevel:        env("ARGUS_LOG_LEVEL", "info"),
		EnrollURL:       env("ARGUS_COLLECTOR_SERVER", ""),
		StreamAddr:      env("ARGUS_COLLECTOR_STREAM", ""),
		DataDir:         env("ARGUS_COLLECTOR_DATA_DIR", defaultCollectorDataDir()),
		CAFile:          env("ARGUS_COLLECTOR_CA_FILE", ""),
		Name:            env("ARGUS_COLLECTOR_NAME", defaultCollectorName()),
		MetricsAddr:     env("ARGUS_COLLECTOR_METRICS_ADDR", "127.0.0.1:9091"),
		SpoolMaxBytes:   envInt64("ARGUS_COLLECTOR_SPOOL_MAX_BYTES", 64<<20),
		FsyncIntervalMS: int(envInt64("ARGUS_COLLECTOR_FSYNC_INTERVAL_MS", 1000)),
		EnrollTokenFile: env("ARGUS_ENROLL_TOKEN_FILE", ""),
	}

	if _, err := logging.ParseLevel(cfg.LogLevel); err != nil {
		return cfg, fmt.Errorf("ARGUS_LOG_LEVEL: %w", err)
	}
	if cfg.StreamAddr == "" {
		return cfg, errors.New("ARGUS_COLLECTOR_STREAM must be set (e.g. server:8443)")
	}
	if cfg.EnrollURL == "" {
		return cfg, errors.New("ARGUS_COLLECTOR_SERVER must be set (e.g. https://server:8444)")
	}
	u, err := url.Parse(cfg.EnrollURL)
	if err != nil {
		return cfg, fmt.Errorf("ARGUS_COLLECTOR_SERVER: %w", err)
	}
	if u.Scheme != "https" {
		return cfg, fmt.Errorf("ARGUS_COLLECTOR_SERVER: scheme must be https, got %q", u.Scheme)
	}
	if strings.TrimSpace(cfg.CAFile) == "" {
		return cfg, errors.New("ARGUS_COLLECTOR_CA_FILE must be set (pinned server CA)")
	}
	if strings.TrimSpace(cfg.DataDir) == "" {
		return cfg, errors.New("ARGUS_COLLECTOR_DATA_DIR must not be empty")
	}
	if cfg.SpoolMaxBytes <= 0 {
		return cfg, errors.New("ARGUS_COLLECTOR_SPOOL_MAX_BYTES must be > 0")
	}
	if cfg.FsyncIntervalMS < 0 || cfg.FsyncIntervalMS > 10_000 {
		return cfg, fmt.Errorf("ARGUS_COLLECTOR_FSYNC_INTERVAL_MS must be within [0,10000], got %d", cfg.FsyncIntervalMS)
	}
	return cfg, nil
}

func defaultCollectorName() string {
	host, err := os.Hostname()
	if err != nil || host == "" {
		return "collector"
	}
	return host
}

func defaultCollectorDataDir() string {
	if base, err := os.UserConfigDir(); err == nil && base != "" {
		return filepath.Join(base, "argus-collector")
	}
	return filepath.Join(".", "data")
}

func env(key, def string) string {
	if v, ok := os.LookupEnv(key); ok {
		return v
	}
	return def
}

func envBool(key string, def bool) bool {
	v, ok := os.LookupEnv(key)
	if !ok {
		return def
	}
	return v == "1" || strings.EqualFold(v, "true")
}

func envInt64(key string, def int64) int64 {
	v, ok := os.LookupEnv(key)
	if !ok || v == "" {
		return def
	}
	var n int64
	if _, err := fmt.Sscanf(v, "%d", &n); err != nil {
		return def
	}
	return n
}

func splitCSV(s string) []string {
	parts := strings.Split(s, ",")
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		if t := strings.TrimSpace(p); t != "" {
			out = append(out, t)
		}
	}
	return out
}
