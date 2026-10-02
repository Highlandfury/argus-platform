package notify

// M11-S2 validation unit tests: channel configs/secrets per kind, route match
// canonicalization (unknown keys fail closed), template overrides, channel
// ids, and the outbound-URL SSRF floor.

import (
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
)

func fieldErrs(errs ValidationErrors) map[string]bool {
	out := map[string]bool{}
	for _, e := range errs {
		out[e.Field] = true
	}
	return out
}

func TestValidateChannelSMTP(t *testing.T) {
	t.Run("happy_path_normalizes", func(t *testing.T) {
		config := []byte(`{"host":" smtp.example.test ","from":"argus@example.test","to":["ops@example.test"," noc@example.test "],"username":"argus"}`)
		secret := []byte(`{"password":"pw-` + uuid.NewString() + `"}`)
		cfgOut, secOut, errs := ValidateChannel(KindSMTP, " mail ", config, secret)
		if len(errs) > 0 {
			t.Fatalf("unexpected errors: %v", errs)
		}
		var cfg SMTPConfig
		if err := json.Unmarshal(cfgOut, &cfg); err != nil {
			t.Fatalf("config JSON: %v", err)
		}
		if cfg.Host != "smtp.example.test" || cfg.Port != 25 || len(cfg.To) != 2 || strings.TrimSpace(cfg.To[1]) != "noc@example.test" {
			t.Fatalf("normalized config = %+v", cfg)
		}
		if !strings.Contains(string(secOut), "password") {
			t.Fatalf("secret output = %s", secOut)
		}
	})
	t.Run("required_fields", func(t *testing.T) {
		_, _, errs := ValidateChannel(KindSMTP, "mail", []byte(`{"to":["no-at-sign"]}`), nil)
		fields := fieldErrs(errs)
		for _, want := range []string{"config.host", "config.from", "config.to[0]"} {
			if !fields[want] {
				t.Fatalf("missing %s in %v", want, errs)
			}
		}
	})
	t.Run("username_requires_password", func(t *testing.T) {
		_, _, errs := ValidateChannel(KindSMTP, "mail",
			[]byte(`{"host":"h","from":"a@b.c","to":["c@d.e"],"username":"u"}`), nil)
		if !fieldErrs(errs)["secret.password"] {
			t.Fatalf("expected secret.password error, got %v", errs)
		}
	})
	t.Run("port_range", func(t *testing.T) {
		_, _, errs := ValidateChannel(KindSMTP, "mail",
			[]byte(`{"host":"h","port":70000,"from":"a@b.c","to":["c@d.e"]}`), nil)
		if !fieldErrs(errs)["config.port"] {
			t.Fatalf("expected config.port error, got %v", errs)
		}
	})
	t.Run("unknown_config_key_rejected", func(t *testing.T) {
		_, _, errs := ValidateChannel(KindSMTP, "mail",
			[]byte(`{"host":"h","from":"a@b.c","to":["c@d.e"],"bogus":1}`), nil)
		if !fieldErrs(errs)["config"] {
			t.Fatalf("expected config error, got %v", errs)
		}
	})
	t.Run("keep_existing_secret_patch", func(t *testing.T) {
		cfgOut, errs := ValidateChannelConfig(KindSMTP, "mail",
			[]byte(`{"host":"h","from":"a@b.c","to":["c@d.e"],"username":"u"}`))
		if len(errs) > 0 || len(cfgOut) == 0 {
			t.Fatalf("PATCH keep-secret failed: %v", errs)
		}
	})
}

func TestValidateChannelWebhook(t *testing.T) {
	t.Run("happy_path_defaults_payload", func(t *testing.T) {
		cfgOut, secOut, errs := ValidateChannel(KindWebhook, "hook",
			[]byte(`{"url":"https://hooks.example.test/argus"}`), []byte(`{"signing_secret":"s3cr3t-`+uuid.NewString()+`"}`))
		if len(errs) > 0 {
			t.Fatalf("unexpected errors: %v", errs)
		}
		var cfg WebhookConfig
		if err := json.Unmarshal(cfgOut, &cfg); err != nil || cfg.Payload != PayloadSummary {
			t.Fatalf("config = %+v err=%v", cfg, err)
		}
		if len(secOut) == 0 {
			t.Fatal("signing secret dropped")
		}
	})
	t.Run("signing_secret_required", func(t *testing.T) {
		_, _, errs := ValidateChannel(KindWebhook, "hook", []byte(`{"url":"https://h.test/x"}`), nil)
		if !fieldErrs(errs)["secret.signing_secret"] {
			t.Fatalf("expected secret.signing_secret, got %v", errs)
		}
	})
	t.Run("payload_enum", func(t *testing.T) {
		_, _, errs := ValidateChannel(KindWebhook, "hook",
			[]byte(`{"url":"https://h.test/x","payload":"everything"}`), nil)
		if !fieldErrs(errs)["config.payload"] {
			t.Fatalf("expected config.payload, got %v", errs)
		}
	})
	t.Run("timeout_range", func(t *testing.T) {
		_, _, errs := ValidateChannel(KindWebhook, "hook",
			[]byte(`{"url":"https://h.test/x","timeout_ms":60000}`), nil)
		if !fieldErrs(errs)["config.timeout_ms"] {
			t.Fatalf("expected config.timeout_ms, got %v", errs)
		}
	})
}

func TestValidateChannelSlackTeams(t *testing.T) {
	url := []byte(`{"webhook_url":"https://hooks.slack.com/services/T/B/X"}`)
	cfgOut, secOut, errs := ValidateChannel(KindSlack, "slack", []byte(`{"channel":"#ops"}`), url)
	if len(errs) > 0 || len(secOut) == 0 || !strings.Contains(string(cfgOut), "#ops") {
		t.Fatalf("slack: cfg=%s sec=%s errs=%v", cfgOut, secOut, errs)
	}
	if _, _, errs := ValidateChannel(KindSlack, "slack", []byte(`{}`), nil); !fieldErrs(errs)["secret.webhook_url"] {
		t.Fatalf("slack missing secret: %v", errs)
	}
	if _, _, errs := ValidateChannel(KindTeams, "teams", []byte(`{}`), url); len(errs) > 0 {
		t.Fatalf("teams: %v", errs)
	}
	if _, _, errs := ValidateChannel(KindTeams, "teams", []byte(`{"channel":"x"}`), url); !fieldErrs(errs)["config"] {
		t.Fatalf("teams extra config accepted: %v", errs)
	}
}

func TestValidateChannelCommon(t *testing.T) {
	if _, _, errs := ValidateChannel("pigeon", "x", nil, nil); !fieldErrs(errs)["kind"] {
		t.Fatalf("unknown kind accepted: %v", errs)
	}
	if _, _, errs := ValidateChannel(KindTeams, "", []byte("{}"), nil); !fieldErrs(errs)["name"] {
		t.Fatalf("blank name accepted: %v", errs)
	}
	if _, _, errs := ValidateChannel(KindTeams, strings.Repeat("n", MaxNameLen+1), []byte("{}"), nil); !fieldErrs(errs)["name"] {
		t.Fatalf("overlong name accepted: %v", errs)
	}
	big := []byte(`{"pad":"` + strings.Repeat("x", MaxConfigLen) + `"}`)
	if _, _, errs := ValidateChannel(KindTeams, "x", big, nil); !fieldErrs(errs)["config"] {
		t.Fatalf("oversized config accepted: %v", errs)
	}
}

func TestValidateOutboundURL(t *testing.T) {
	cases := []struct {
		url  string
		ok   bool
		name string
	}{
		{"https://hooks.example.test/x", true, "https hostname"},
		{"http://10.0.0.5:8080/x", true, "private IPv4 is operator-owned in Phase 2"},
		{"http://127.0.0.1:9090/hook", true, "loopback allowed for operator-owned receivers"},
		{"ftp://example.test/x", false, "scheme"},
		{"https://user:pass@example.test/x", false, "embedded credentials"},
		{"http://", false, "missing host"},
		{"http://169.254.169.254/latest/meta-data", false, "link-local metadata"},
		{"http://metadata.google.internal/computeMetadata/v1", false, "GCE metadata"},
		{"http://[fe80::1]/x", false, "link-local IPv6"},
	}
	for _, tc := range cases {
		if err := validateOutboundURL(tc.url); (err == nil) != tc.ok {
			t.Fatalf("%s: validateOutboundURL(%q) err=%v, want ok=%v", tc.name, tc.url, err, tc.ok)
		}
	}
}

func TestParseRouteMatchCanonicalizes(t *testing.T) {
	site := uuid.New()
	dev := uuid.New()
	raw := []byte(`{"severity":["critical","info","critical"],"scope":{"sites":["` + site.String() + `"],"device_ids":["` + dev.String() + `"],"device_kinds":["switch"]}}`)
	match, canonical, errs := ParseRouteMatch(raw)
	if len(errs) > 0 {
		t.Fatalf("errors: %v", errs)
	}
	if len(match.Severities) != 2 || match.Severities[0] != SeverityCritical || match.Severities[1] != SeverityInfo {
		t.Fatalf("severity canonical form = %v", match.Severities)
	}
	if match.Scope.Sites[0] != site || match.Scope.DeviceIDs[0] != dev || match.Scope.DeviceKinds[0] != "switch" {
		t.Fatalf("scope = %+v", match.Scope)
	}
	var round map[string]any
	if err := json.Unmarshal(canonical, &round); err != nil {
		t.Fatalf("canonical JSON: %v", err)
	}
	if _, ok := round["scope"]; !ok {
		t.Fatalf("canonical form lost scope: %s", canonical)
	}

	empty, canonical, errs := ParseRouteMatch(nil)
	if len(errs) > 0 || !empty.Scope.IsEmpty() || string(canonical) != "{}" {
		t.Fatalf("empty match = %+v %s %v", empty, canonical, errs)
	}
}

func TestParseRouteMatchFailsClosed(t *testing.T) {
	cases := map[string]string{
		"unknown top key":     `{"severity":["info"],"labels":{"env":"prod"}}`,
		"unknown scope key":   `{"scope":{"rooms":["x"]}}`,
		"bad severity":        `{"severity":["emergency"]}`,
		"severity not array":  `{"severity":"info"}`,
		"bad uuid":            `{"scope":{"sites":["not-a-uuid"]}}`,
		"bad device kind":     `{"scope":{"device_kinds":[""]}}`,
		"not an object":       `["info"]`,
		"scope not an object": `{"scope":["site"]}`,
	}
	for name, raw := range cases {
		if _, _, errs := ParseRouteMatch([]byte(raw)); len(errs) == 0 {
			t.Fatalf("%s accepted: %s", name, raw)
		}
	}
}

func TestParseTemplateOverrides(t *testing.T) {
	out, errs := ParseTemplateOverrides([]byte(`{"subject_prefix":"[P1]"}`))
	if len(errs) > 0 || string(out) != `{"subject_prefix":"[P1]"}` {
		t.Fatalf("overrides = %s errs=%v", out, errs)
	}
	if out, errs := ParseTemplateOverrides(nil); len(errs) > 0 || string(out) != "{}" {
		t.Fatalf("nil overrides = %s %v", out, errs)
	}
	if _, errs := ParseTemplateOverrides([]byte(`{"bogus":1}`)); len(errs) == 0 {
		t.Fatal("unknown override accepted")
	}
	if _, errs := ParseTemplateOverrides([]byte(`{"subject_prefix":"` + strings.Repeat("x", 101) + `"}`)); len(errs) == 0 {
		t.Fatal("overlong subject_prefix accepted")
	}
}

func TestValidateChannelIDs(t *testing.T) {
	if errs := ValidateChannelIDs(nil); len(errs) == 0 || errs[0].Code != "required" {
		t.Fatalf("empty list = %v", errs)
	}
	tooMany := make([]uuid.UUID, 21)
	for i := range tooMany {
		tooMany[i] = uuid.New()
	}
	if errs := ValidateChannelIDs(tooMany); len(errs) == 0 || errs[0].Code != "too_many" {
		t.Fatalf("too many = %v", errs)
	}
	id := uuid.New()
	if errs := ValidateChannelIDs([]uuid.UUID{id, id}); len(errs) == 0 || errs[0].Code != "duplicate" {
		t.Fatalf("duplicate = %v", errs)
	}
	if errs := ValidateChannelIDs([]uuid.UUID{uuid.Nil}); len(errs) == 0 {
		t.Fatalf("nil id = %v", errs)
	}
	if errs := ValidateChannelIDs([]uuid.UUID{id, uuid.New()}); len(errs) > 0 {
		t.Fatalf("valid list = %v", errs)
	}
}

func TestVocabularyPredicates(t *testing.T) {
	for _, kind := range []string{KindSMTP, KindWebhook, KindSlack, KindTeams} {
		if !ValidKind(kind) {
			t.Fatalf("ValidKind(%q) = false", kind)
		}
	}
	if ValidKind("sms") || !ValidStatus(StatusDeadLetter) || ValidStatus("sent") ||
		!ValidSeverity(SeverityInfo) || ValidSeverity("emergency") {
		t.Fatal("vocabulary predicate drift")
	}
}

func TestParseDeliveryCursorRoundTrip(t *testing.T) {
	id := uuid.New()
	ts := time.Date(2026, 10, 2, 12, 0, 0, 123456789, time.UTC)
	gotTS, gotID, err := decodeDeliveryCursor(encodeDeliveryCursor(ts, id))
	if err != nil || !gotTS.Equal(ts) || gotID != id {
		t.Fatalf("round trip = %s %s err=%v", gotTS, gotID, err)
	}
	if _, _, err := decodeDeliveryCursor("not-base64!"); err == nil {
		t.Fatal("malformed cursor accepted")
	}
}
