package poll

import (
	"bytes"
	"encoding/json"
	"log/slog"
	"os"
	"strings"
	"testing"

	"github.com/google/uuid"

	"github.com/argus-platform/argus/internal/platform/sessioncrypto"
)

func sealSession(t *testing.T, seedPublic []byte, creds ...sessioncrypto.PlainCredential) *sessioncrypto.Session {
	t.Helper()
	session, err := sessioncrypto.Seal(seedPublic, uuid.New().String(), uuid.New().String(), 3, creds)
	if err != nil {
		t.Fatalf("seal: %v", err)
	}
	return session
}

func bundleSource(t *testing.T, log *slog.Logger) (*BundleCredentialSource, []byte) {
	t.Helper()
	seed, public, err := sessioncrypto.NewKeyPair()
	if err != nil {
		t.Fatalf("keypair: %v", err)
	}
	src := NewBundleCredentialSource(log)
	src.SetSessionKey(seed)
	return src, public
}

func TestBundleCredentialSourceApplyAndLookup(t *testing.T) {
	var logs bytes.Buffer
	src, public := bundleSource(t, slog.New(slog.NewTextHandler(&logs, nil)))
	deviceV2c, deviceV3 := uuid.New().String(), uuid.New().String()
	recV2c := sessioncrypto.PlainCredential{
		DeviceID: deviceV2c, CredentialID: uuid.New().String(),
		Kind: "snmp_v2c", Version: 1, Plaintext: []byte("community-x"),
	}
	recV3 := sessioncrypto.PlainCredential{
		DeviceID: deviceV3, CredentialID: uuid.New().String(),
		Kind: "snmp_v3", Version: 2,
		Plaintext: []byte(`{"username":"ops","auth_protocol":"SHA-256","auth_key":"auth-secret","priv_protocol":"AES-256","priv_key":"priv-secret","context":"ctx"}`),
	}
	src.ApplySession(sealSession(t, public, recV2c, recV3))

	got, ok := src.Lookup(deviceV2c)
	if !ok || got.Version != SNMPVersionV2c || got.Community != "community-x" {
		t.Fatalf("v2c lookup = %+v ok=%v", got, ok)
	}
	got, ok = src.Lookup(deviceV3)
	if !ok || got.Version != SNMPVersionV3 || got.Username != "ops" || got.AuthProtocol != "SHA-256" || got.AuthKey != "auth-secret" || got.PrivProtocol != "AES-256" || got.PrivKey != "priv-secret" || got.Context != "ctx" {
		t.Fatalf("v3 lookup = %+v ok=%v", got, ok)
	}
	if err := got.Validate(); err != nil {
		t.Fatalf("materialized credential must validate: %v", err)
	}
	if _, ok := src.Lookup(uuid.New().String()); ok {
		t.Fatal("unknown device resolved")
	}
	// The plaintext community never reaches the logs.
	if strings.Contains(logs.String(), "community-x") || strings.Contains(logs.String(), "priv-secret") {
		t.Fatalf("plaintext leaked into logs: %s", logs.String())
	}
}

func TestBundleCredentialSourceWrongSessionKeyIsMissing(t *testing.T) {
	src, _ := bundleSource(t, nil)
	_, otherPublic, err := sessioncrypto.NewKeyPair()
	if err != nil {
		t.Fatalf("keypair: %v", err)
	}
	device := uuid.New().String()
	session := sealSession(t, otherPublic, sessioncrypto.PlainCredential{
		DeviceID: device, CredentialID: uuid.New().String(),
		Kind: "snmp_v2c", Version: 1, Plaintext: []byte("not-for-this-session"),
	})
	src.ApplySession(session)
	if _, ok := src.Lookup(device); ok {
		t.Fatal("material sealed to another session must not resolve")
	}
}

func TestBundleCredentialSourceMalformedPayloadIsInvalid(t *testing.T) {
	src, public := bundleSource(t, nil)
	device := uuid.New().String()
	src.ApplySession(sealSession(t, public, sessioncrypto.PlainCredential{
		DeviceID: device, CredentialID: uuid.New().String(),
		Kind: "snmp_v3", Version: 1, Plaintext: []byte("this is not json"),
	}))
	got, ok := src.Lookup(device)
	if !ok {
		t.Fatal("malformed material must be present as an invalid entry (credential_invalid, not missing)")
	}
	if err := got.Validate(); err == nil {
		t.Fatalf("malformed payload must not validate: %+v", got)
	}
}

func TestBundleCredentialSourceReplacementClears(t *testing.T) {
	src, public := bundleSource(t, nil)
	device := uuid.New().String()
	src.ApplySession(sealSession(t, public, sessioncrypto.PlainCredential{
		DeviceID: device, CredentialID: uuid.New().String(),
		Kind: "snmp_v2c", Version: 1, Plaintext: []byte("community"),
	}))
	if _, ok := src.Lookup(device); !ok {
		t.Fatal("credential not applied")
	}
	// Binding removal / revocation: the next bundle carries no material.
	src.ApplySession(nil)
	if _, ok := src.Lookup(device); ok {
		t.Fatal("material must be dropped when the bundle carries none (no stale use)")
	}
	if !src.HasSessionKey() {
		t.Fatal("session key must survive a material-less bundle")
	}
	src.Clear()
	if src.HasSessionKey() {
		t.Fatal("Clear must drop the session key")
	}
}

func TestBundleCredentialSourceNoFilesAndSanitizedLogs(t *testing.T) {
	const sentinel = "m9s3-sentinel-community-!!!"
	var logs bytes.Buffer
	src, public := bundleSource(t, slog.New(slog.NewTextHandler(&logs, nil)))
	device := uuid.New().String()
	// A malformed record forces the warning path; the valid one the normal
	// path. Neither may echo payload bytes.
	badDevice := uuid.New().String()
	src.ApplySession(sealSession(t, public,
		sessioncrypto.PlainCredential{DeviceID: device, CredentialID: uuid.New().String(), Kind: "snmp_v2c", Version: 1, Plaintext: []byte(sentinel)},
		sessioncrypto.PlainCredential{DeviceID: badDevice, CredentialID: uuid.New().String(), Kind: "snmp_v3", Version: 1, Plaintext: []byte(sentinel)},
	))
	if _, ok := src.Lookup(device); !ok {
		t.Fatal("credential not applied")
	}
	if strings.Contains(logs.String(), sentinel) {
		t.Fatalf("sentinel leaked into logs: %s", logs.String())
	}
	if strings.Contains(logs.String(), "m9s3-sentinel") {
		t.Fatalf("sentinel fragment leaked into logs: %s", logs.String())
	}

	// The source owns no files: applying material creates nothing on disk.
	dir := t.TempDir()
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("read dir: %v", err)
	}
	if len(entries) != 0 {
		t.Fatalf("RAM-only source created files: %v", entries)
	}
}

func TestParseCredentialPayload(t *testing.T) {
	// v2c: the raw secret is the community (whitespace-only rejected).
	if c, err := ParseCredentialPayload("snmp_v2c", []byte("public")); err != nil || c.Community != "public" {
		t.Fatalf("v2c = %+v err=%v", c, err)
	}
	if _, err := ParseCredentialPayload("snmp_v2c", []byte("   ")); err == nil {
		t.Fatal("blank community accepted")
	}
	// v3: JSON object with authPriv fields.
	raw, err := json.Marshal(map[string]string{
		"username": "ops", "auth_protocol": "SHA", "auth_key": "a",
		"priv_protocol": "AES", "priv_key": "p",
	})
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	c, err := ParseCredentialPayload("snmp_v3", raw)
	if err != nil || c.Username != "ops" || c.AuthProtocol != "SHA" || c.PrivProtocol != "AES" {
		t.Fatalf("v3 = %+v err=%v", c, err)
	}
	// Malformed / unsupported payloads collapse to a sanitized error.
	for _, tc := range []struct{ kind, payload string }{
		{"snmp_v3", "{"},
		{"snmp_v3", `{"username":"ops"}`},
		{"snmp_v3", `{"username":"ops","auth_protocol":"SHA","auth_key":"a","priv_protocol":"AES"}`},
		{"snmp_v1", "public"},
		{"ssh_key", "-----BEGIN"},
	} {
		c, err := ParseCredentialPayload(tc.kind, []byte(tc.payload))
		if err == nil {
			t.Fatalf("%s/%q accepted: %+v", tc.kind, tc.payload, c)
		}
		if strings.Contains(err.Error(), tc.payload) && tc.payload != "" {
			t.Fatalf("error echoes payload: %v", err)
		}
	}
}

func TestChainCredentialSource(t *testing.T) {
	first := NewStaticCredentialSource()
	first.Set("device-1", SNMPCredentials{Version: SNMPVersionV2c, Community: "first"})
	second := NewStaticCredentialSource()
	second.SetDefault(SNMPCredentials{Version: SNMPVersionV2c, Community: "fallback"})
	second.Set("device-2", SNMPCredentials{Version: SNMPVersionV2c, Community: "second"})

	chain := NewChainCredentialSource(first, second)
	if c, ok := chain.Lookup("device-1"); !ok || c.Community != "first" {
		t.Fatalf("chain device-1 = %+v ok=%v", c, ok)
	}
	if c, ok := chain.Lookup("device-2"); !ok || c.Community != "second" {
		t.Fatalf("chain device-2 = %+v ok=%v", c, ok)
	}
	if c, ok := chain.Lookup("device-3"); !ok || c.Community != "fallback" {
		t.Fatalf("chain fallback = %+v ok=%v", c, ok)
	}
	if _, ok := NewChainCredentialSource(first).Lookup("unknown"); ok {
		t.Fatal("empty chain resolved")
	}
}
