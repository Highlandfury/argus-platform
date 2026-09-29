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
	)
}

func unsetCollectorEnv(t *testing.T) {
	unset(t,
		"ARGUS_LOG_LEVEL", "ARGUS_COLLECTOR_SERVER", "ARGUS_COLLECTOR_STREAM",
		"ARGUS_COLLECTOR_DATA_DIR", "ARGUS_COLLECTOR_SPOOL_MAX_BYTES",
		"ARGUS_COLLECTOR_FSYNC_INTERVAL_MS", "ARGUS_ENROLL_TOKEN_FILE",
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

func TestLoadCollectorDefaults(t *testing.T) {
	unsetCollectorEnv(t)
	t.Setenv("ARGUS_COLLECTOR_STREAM", "server:8443")
	t.Setenv("ARGUS_COLLECTOR_SERVER", "https://server:8444")
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
	t.Setenv("ARGUS_COLLECTOR_SPOOL_MAX_BYTES", "-1")
	if _, err := LoadCollector(); err == nil {
		t.Fatal("expected error for negative spool size")
	}
}
