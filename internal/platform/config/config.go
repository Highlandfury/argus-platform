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
	// DBMaxConns bounds the runtime (app) connection pool. Default 10 keeps
	// the Phase-1 sizing; ADR-016 measured the fleet scenario at this and a
	// larger bound and set the documented default (docs/phase-2/M8_EVIDENCE.md).
	DBMaxConns int
	CADir      string // internal CA material; required from M3
	DevSeed    bool
	// SecretsKeyFile is the master-key file backing the SecretsVault
	// envelope encryption (M7-S2, P2-D2: local file KMS binding for Phase 2;
	// an external KMS/HSM arrives in V2 behind the same interface).
	SecretsKeyFile string
	// SecretsKeyID is the wrapping key identifier recorded in the
	// kms_key_id column of every sealed credential envelope.
	SecretsKeyID string
	// MetricsRawRetentionDays is the on-prem raw metric_samples retention
	// window (P2-AC-09: 30-90 days, default 30). Applied by
	// `argus-server metrics-maintenance` under the owner role.
	MetricsRawRetentionDays int
}

// LoadServer reads server configuration from the environment.
func LoadServer() (Server, error) {
	cfg := Server{
		Env:                     env("ARGUS_ENV", EnvDev),
		LogLevel:                env("ARGUS_LOG_LEVEL", "info"),
		HTTPAddr:                env("ARGUS_SERVER_HTTP_ADDR", ":8080"),
		OpsAddr:                 env("ARGUS_SERVER_OPS_ADDR", ":9090"),
		GRPCAddr:                env("ARGUS_SERVER_GRPC_ADDR", ":8443"),
		EnrollAddr:              env("ARGUS_SERVER_ENROLL_ADDR", ":8444"),
		GRPCSANs:                splitCSV(env("ARGUS_SERVER_GRPC_SANS", "localhost,server,127.0.0.1")),
		EnrollRatePerMin:        int(envInt64("ARGUS_SERVER_ENROLL_RATE_PER_MIN", 10)),
		DBDSN:                   env("ARGUS_SERVER_DB_DSN", ""),
		AuthDBDSN:               env("ARGUS_SERVER_AUTH_DB_DSN", ""),
		MigrateDSN:              env("ARGUS_SERVER_MIGRATE_DSN", ""),
		DBMaxConns:              int(envInt64("ARGUS_SERVER_DB_MAX_CONNS", 10)),
		CADir:                   env("ARGUS_SERVER_CA_DIR", "./.dev/ca"),
		DevSeed:                 envBool("ARGUS_DEV_SEED", false),
		SecretsKeyFile:          env("ARGUS_SECRETS_KEY_FILE", "./.dev/secrets/master.key"),
		SecretsKeyID:            env("ARGUS_SECRETS_KEY_ID", "argus-local"),
		MetricsRawRetentionDays: int(envInt64("ARGUS_METRICS_RAW_RETENTION_DAYS", 30)),
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
	// M7-S2 secrets vault wiring: a path/key id that is explicitly set to
	// blank is invalid; the key file itself is verified (fail closed) by the
	// vault when the credentials module starts using it.
	if strings.TrimSpace(cfg.SecretsKeyFile) == "" {
		return cfg, errors.New("ARGUS_SECRETS_KEY_FILE: must not be empty")
	}
	if strings.TrimSpace(cfg.SecretsKeyID) == "" {
		return cfg, errors.New("ARGUS_SECRETS_KEY_ID: must not be empty")
	}
	// P2-AC-09: the on-prem raw retention window is bounded; the out-of-range
	// value is rejected instead of silently clamped.
	if cfg.MetricsRawRetentionDays < 30 || cfg.MetricsRawRetentionDays > 90 {
		return cfg, fmt.Errorf("ARGUS_METRICS_RAW_RETENTION_DAYS: must be within [30,90], got %d", cfg.MetricsRawRetentionDays)
	}
	// Pool bound: >0 (pgx rejects 0 as "unlimited" surprises) and well under
	// the server's max_connections budget (default 100) so migrations/other
	// clients are never starved.
	if cfg.DBMaxConns < 1 || cfg.DBMaxConns > 80 {
		return cfg, fmt.Errorf("ARGUS_SERVER_DB_MAX_CONNS: must be within [1,80], got %d", cfg.DBMaxConns)
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

	// M9-S2 SNMP fixture credentials. M9-S3 replaces these with per-device
	// materialization from signed bundles; until then a collector may be
	// configured with one v2c community or one v3 authPriv identity for
	// dev/test. No secret is ever written to disk by the collector.
	SNMPFixtureCommunity   string
	SNMPFixtureV3User      string
	SNMPFixtureV3AuthProto string
	SNMPFixtureV3AuthKey   string
	SNMPFixtureV3PrivProto string
	SNMPFixtureV3PrivKey   string
	SNMPFixtureV3Context   string
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

		SNMPFixtureCommunity:   env("ARGUS_SNMP_FIXTURE_COMMUNITY", ""),
		SNMPFixtureV3User:      env("ARGUS_SNMP_FIXTURE_V3_USER", ""),
		SNMPFixtureV3AuthProto: env("ARGUS_SNMP_FIXTURE_V3_AUTH_PROTO", "SHA-256"),
		SNMPFixtureV3AuthKey:   env("ARGUS_SNMP_FIXTURE_V3_AUTH_KEY", ""),
		SNMPFixtureV3PrivProto: env("ARGUS_SNMP_FIXTURE_V3_PRIV_PROTO", "AES"),
		SNMPFixtureV3PrivKey:   env("ARGUS_SNMP_FIXTURE_V3_PRIV_KEY", ""),
		SNMPFixtureV3Context:   env("ARGUS_SNMP_FIXTURE_V3_CONTEXT", ""),
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
	// M9-S2 fixture credentials: v3 needs both keys; a v3 identity takes
	// precedence over a configured v2c community (canonical preference order).
	if strings.TrimSpace(cfg.SNMPFixtureV3User) != "" {
		if strings.TrimSpace(cfg.SNMPFixtureV3AuthKey) == "" || strings.TrimSpace(cfg.SNMPFixtureV3PrivKey) == "" {
			return cfg, errors.New("ARGUS_SNMP_FIXTURE_V3_AUTH_KEY and ARGUS_SNMP_FIXTURE_V3_PRIV_KEY are required with ARGUS_SNMP_FIXTURE_V3_USER")
		}
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
