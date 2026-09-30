package config

import (
	"testing"
)

// M7-S2: the SecretsVault wiring (ARGUS_SECRETS_KEY_FILE / ARGUS_SECRETS_KEY_ID)
// loads with defaults and rejects explicitly blank values. The key file itself
// is validated (fail closed) by the vault, not by config loading.

func TestLoadServerSecretsDefaults(t *testing.T) {
	unsetServerEnv(t)
	unset(t, "ARGUS_SECRETS_KEY_FILE", "ARGUS_SECRETS_KEY_ID")
	cfg, err := LoadServer()
	if err != nil {
		t.Fatalf("LoadServer: %v", err)
	}
	if cfg.SecretsKeyFile != "./.dev/secrets/master.key" {
		t.Fatalf("SecretsKeyFile default = %q", cfg.SecretsKeyFile)
	}
	if cfg.SecretsKeyID != "argus-local" {
		t.Fatalf("SecretsKeyID default = %q", cfg.SecretsKeyID)
	}
}

func TestLoadServerSecretsOverrides(t *testing.T) {
	unsetServerEnv(t)
	t.Setenv("ARGUS_SECRETS_KEY_FILE", "/var/lib/argus/secrets/master.key")
	t.Setenv("ARGUS_SECRETS_KEY_ID", "argus-ci")
	cfg, err := LoadServer()
	if err != nil {
		t.Fatalf("LoadServer: %v", err)
	}
	if cfg.SecretsKeyFile != "/var/lib/argus/secrets/master.key" || cfg.SecretsKeyID != "argus-ci" {
		t.Fatalf("overrides not applied: %+v", cfg)
	}
}

func TestLoadServerRejectsBlankSecretsConfig(t *testing.T) {
	unsetServerEnv(t)
	unset(t, "ARGUS_SECRETS_KEY_FILE", "ARGUS_SECRETS_KEY_ID")
	for _, tc := range []struct {
		name  string
		key   string
		value string
	}{
		{"file", "ARGUS_SECRETS_KEY_FILE", "   "},
		{"key_id", "ARGUS_SECRETS_KEY_ID", ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Setenv(tc.key, tc.value)
			if _, err := LoadServer(); err == nil {
				t.Fatalf("blank %s must be rejected", tc.key)
			}
		})
	}
}
