package config

import (
	"os"
	"testing"
)

// unset removes environment variables for the duration of a test and restores
// them afterwards, so host environment cannot contaminate assertions.
func unset(t *testing.T, keys ...string) {
	t.Helper()
	for _, k := range keys {
		old, ok := os.LookupEnv(k)
		if err := os.Unsetenv(k); err != nil {
			t.Fatalf("unset %s: %v", k, err)
		}
		t.Cleanup(func() {
			if ok {
				_ = os.Setenv(k, old)
			} else {
				_ = os.Unsetenv(k)
			}
		})
	}
}

func unsetServerEnv(t *testing.T) {
	unset(t,
		"ARGUS_ENV", "ARGUS_LOG_LEVEL",
		"ARGUS_SERVER_HTTP_ADDR", "ARGUS_SERVER_OPS_ADDR",
		"ARGUS_SERVER_GRPC_ADDR", "ARGUS_SERVER_ENROLL_ADDR",
		"ARGUS_SERVER_DB_DSN", "ARGUS_SERVER_AUTH_DB_DSN", "ARGUS_SERVER_MIGRATE_DSN",
		"ARGUS_SERVER_CA_DIR", "ARGUS_DEV_SEED",
		"ARGUS_METRICS_RAW_RETENTION_DAYS",
	)
}

func unsetCollectorEnv(t *testing.T) {
	unset(t,
		"ARGUS_LOG_LEVEL", "ARGUS_COLLECTOR_SERVER", "ARGUS_COLLECTOR_STREAM",
		"ARGUS_COLLECTOR_DATA_DIR", "ARGUS_COLLECTOR_SPOOL_MAX_BYTES",
		"ARGUS_COLLECTOR_FSYNC_INTERVAL_MS", "ARGUS_ENROLL_TOKEN_FILE",
		"ARGUS_COLLECTOR_CA_FILE", "ARGUS_COLLECTOR_NAME",
	)
}

func TestLoadServerDefaults(t *testing.T) {
	unsetServerEnv(t)
	cfg, err := LoadServer()
	if err != nil {
		t.Fatalf("LoadServer: %v", err)
	}
	if cfg.Env != EnvDev || cfg.LogLevel != "info" {
		t.Fatalf("unexpected env/log defaults: %+v", cfg)
	}
	if cfg.HTTPAddr != ":8080" || cfg.OpsAddr != ":9090" || cfg.GRPCAddr != ":8443" || cfg.EnrollAddr != ":8444" {
		t.Fatalf("unexpected address defaults: %+v", cfg)
	}
}

func TestLoadServerRejectsBadEnv(t *testing.T) {
	unsetServerEnv(t)
	t.Setenv("ARGUS_ENV", "staging")
	if _, err := LoadServer(); err == nil {
		t.Fatal("expected error for invalid ARGUS_ENV")
	}
}

func TestLoadServerRejectsBadLogLevel(t *testing.T) {
	unsetServerEnv(t)
	t.Setenv("ARGUS_LOG_LEVEL", "verbose")
	if _, err := LoadServer(); err == nil {
		t.Fatal("expected error for invalid log level")
	}
}

func TestLoadServerProdRequiresDSN(t *testing.T) {
	unsetServerEnv(t)
	t.Setenv("ARGUS_ENV", "prod")
	if _, err := LoadServer(); err == nil {
		t.Fatal("expected error: prod without DSN")
	}
	t.Setenv("ARGUS_SERVER_DB_DSN", "postgres://u:p@db:5432/argus?sslmode=require")
	if _, err := LoadServer(); err != nil {
		t.Fatalf("prod with DSN should load: %v", err)
	}
}

func TestLoadServerRawRetentionBounds(t *testing.T) {
	unsetServerEnv(t)
	cfg, err := LoadServer()
	if err != nil {
		t.Fatalf("LoadServer: %v", err)
	}
	if cfg.MetricsRawRetentionDays != 30 {
		t.Fatalf("raw retention default = %d, want 30", cfg.MetricsRawRetentionDays)
	}
	t.Setenv("ARGUS_METRICS_RAW_RETENTION_DAYS", "90")
	cfg, err = LoadServer()
	if err != nil || cfg.MetricsRawRetentionDays != 90 {
		t.Fatalf("raw retention 90: %d, %v", cfg.MetricsRawRetentionDays, err)
	}
	t.Setenv("ARGUS_METRICS_RAW_RETENTION_DAYS", "29")
	if _, err := LoadServer(); err == nil {
		t.Fatal("expected error for raw retention below 30 d")
	}
	t.Setenv("ARGUS_METRICS_RAW_RETENTION_DAYS", "91")
	if _, err := LoadServer(); err == nil {
		t.Fatal("expected error for raw retention above 90 d")
	}
}

func TestLoadCollectorDefaults(t *testing.T) {
	unsetCollectorEnv(t)
	t.Setenv("ARGUS_COLLECTOR_STREAM", "server:8443")
	t.Setenv("ARGUS_COLLECTOR_SERVER", "https://server:8444")
	t.Setenv("ARGUS_COLLECTOR_CA_FILE", "/etc/argus/ca.pem")
	cfg, err := LoadCollector()
	if err != nil {
		t.Fatalf("LoadCollector: %v", err)
	}
	if cfg.SpoolMaxBytes != 64<<20 {
		t.Fatalf("unexpected spool default: %d", cfg.SpoolMaxBytes)
	}
	if cfg.FsyncIntervalMS != 1000 {
		t.Fatalf("unexpected fsync default: %d", cfg.FsyncIntervalMS)
	}
	if cfg.CAFile != "/etc/argus/ca.pem" {
		t.Fatalf("unexpected CA file: %q", cfg.CAFile)
	}
	if cfg.Name == "" {
		t.Fatal("collector name must default to hostname")
	}
}

func TestLoadCollectorRequiresCAFile(t *testing.T) {
	unsetCollectorEnv(t)
	t.Setenv("ARGUS_COLLECTOR_STREAM", "server:8443")
	t.Setenv("ARGUS_COLLECTOR_SERVER", "https://server:8444")
	if _, err := LoadCollector(); err == nil {
		t.Fatal("expected error when ARGUS_COLLECTOR_CA_FILE is missing")
	}
}

func TestLoadCollectorRequiresHTTPS(t *testing.T) {
	unsetCollectorEnv(t)
	t.Setenv("ARGUS_COLLECTOR_STREAM", "server:8443")
	t.Setenv("ARGUS_COLLECTOR_SERVER", "http://server:8444")
	if _, err := LoadCollector(); err == nil {
		t.Fatal("expected error for non-https enrollment URL")
	}
}

func TestLoadCollectorRequiresEndpoints(t *testing.T) {
	unsetCollectorEnv(t)
	if _, err := LoadCollector(); err == nil {
		t.Fatal("expected error when endpoints are missing")
	}
}

func TestLoadCollectorRejectsBadSpool(t *testing.T) {
	unsetCollectorEnv(t)
	t.Setenv("ARGUS_COLLECTOR_STREAM", "server:8443")
	t.Setenv("ARGUS_COLLECTOR_SERVER", "https://server:8444")
	t.Setenv("ARGUS_COLLECTOR_CA_FILE", "/etc/argus/ca.pem")
	t.Setenv("ARGUS_COLLECTOR_SPOOL_MAX_BYTES", "-1")
	if _, err := LoadCollector(); err == nil {
		t.Fatal("expected error for negative spool size")
	}
}
