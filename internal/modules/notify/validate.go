package notify

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net"
	"net/url"
	"sort"
	"strings"

	"github.com/google/uuid"
)

// ValidKind reports whether kind is a supported channel kind.
func ValidKind(kind string) bool {
	switch kind {
	case KindSMTP, KindWebhook, KindSlack, KindTeams:
		return true
	}
	return false
}

// ValidStatus reports whether s is a delivery status.
func ValidStatus(s string) bool {
	switch s {
	case StatusPending, StatusDelivered, StatusFailed, StatusDeadLetter:
		return true
	}
	return false
}

// ValidSeverity reports whether s is a notification severity.
func ValidSeverity(s string) bool {
	switch s {
	case SeverityInfo, SeverityWarning, SeverityCritical:
		return true
	}
	return false
}

// strictJSON decodes raw into dst rejecting unknown fields.
func strictJSON(raw []byte, dst any) error {
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	if err := dec.Decode(dst); err != nil {
		return err
	}
	// Reject trailing garbage.
	if dec.More() {
		return fmt.Errorf("unexpected trailing JSON")
	}
	return nil
}

// ValidateChannel validates one create input and returns the canonical config
// plus the parsed/normalized secret JSON (nil when no secret is required or
// provided). It never logs or echoes secret values.
func ValidateChannel(kind, name string, config, secret []byte) (configOut, secretOut []byte, errs ValidationErrors) {
	return validateChannel(kind, name, config, secret, true)
}

// ValidateChannelConfig validates only the non-secret config (PATCH that
// keeps the existing sealed secret).
func ValidateChannelConfig(kind, name string, config []byte) (configOut []byte, errs ValidationErrors) {
	out, _, errs := validateChannel(kind, name, config, nil, false)
	return out, errs
}

func validateChannel(kind, name string, config, secret []byte, needSecret bool) (configOut, secretOut []byte, errs ValidationErrors) {
	name = strings.TrimSpace(name)
	switch {
	case name == "":
		errs = append(errs, ValidationError{Field: "name", Code: "required", Message: "name is required"})
	case len(name) > MaxNameLen:
		errs = append(errs, ValidationError{Field: "name", Code: "too_long", Message: fmt.Sprintf("name must be at most %d characters", MaxNameLen)})
	}
	if !ValidKind(kind) {
		errs = append(errs, ValidationError{Field: "kind", Code: "invalid", Message: "allowed: smtp, webhook, slack, teams"})
		return nil, nil, errs
	}
	if len(config) == 0 {
		config = []byte("{}")
	}
	if len(config) > MaxConfigLen {
		errs = append(errs, ValidationError{Field: "config", Code: "too_large", Message: "config must be at most 65536 bytes"})
		return nil, nil, errs
	}
	switch kind {
	case KindSMTP:
		configOut, secretOut, errs = validateSMTP(config, secret, needSecret, errs)
	case KindWebhook:
		configOut, secretOut, errs = validateWebhook(config, secret, needSecret, errs)
	case KindSlack:
		configOut, secretOut, errs = validateSlack(config, secret, needSecret, errs)
	case KindTeams:
		configOut, secretOut, errs = validateTeams(config, secret, needSecret, errs)
	}
	return configOut, secretOut, errs
}

func validateSMTP(config, secret []byte, needSecret bool, errs ValidationErrors) ([]byte, []byte, ValidationErrors) {
	var cfg SMTPConfig
	if err := strictJSON(config, &cfg); err != nil {
		return nil, nil, append(errs, ValidationError{Field: "config", Code: "invalid", Message: "must be an object with host/port/username/from/to/starttls: " + err.Error()})
	}
	cfg.Host = strings.TrimSpace(cfg.Host)
	if cfg.Host == "" {
		errs = append(errs, ValidationError{Field: "config.host", Code: "required", Message: "SMTP host is required"})
	} else if strings.ContainsAny(cfg.Host, "/ \t") {
		errs = append(errs, ValidationError{Field: "config.host", Code: "invalid", Message: "host must be a hostname or IP address"})
	}
	if cfg.Port == 0 {
		cfg.Port = 25
	}
	if cfg.Port < 1 || cfg.Port > 65535 {
		errs = append(errs, ValidationError{Field: "config.port", Code: "range", Message: "port must be between 1 and 65535"})
	}
	if cfg.From = strings.TrimSpace(cfg.From); cfg.From == "" || !strings.Contains(cfg.From, "@") {
		errs = append(errs, ValidationError{Field: "config.from", Code: "invalid", Message: "from must be an email address"})
	}
	if len(cfg.To) == 0 {
		errs = append(errs, ValidationError{Field: "config.to", Code: "required", Message: "at least one recipient is required"})
	}
	if len(cfg.To) > 50 {
		errs = append(errs, ValidationError{Field: "config.to", Code: "too_many", Message: "at most 50 recipients"})
	}
	for i, to := range cfg.To {
		if !strings.Contains(strings.TrimSpace(to), "@") {
			errs = append(errs, ValidationError{Field: fmt.Sprintf("config.to[%d]", i), Code: "invalid", Message: "must be an email address"})
		}
	}
	var sec SMTPSecret
	if len(secret) > 0 {
		if err := strictJSON(secret, &sec); err != nil {
			return nil, nil, append(errs, ValidationError{Field: "secret", Code: "invalid", Message: "must be an object with a password field"})
		}
	}
	if cfg.Username != "" && sec.Password == "" {
		if needSecret {
			errs = append(errs, ValidationError{Field: "secret.password", Code: "required", Message: "password is required when config.username is set"})
		}
	}
	if len(errs) > 0 {
		return nil, nil, errs
	}
	out, _ := json.Marshal(cfg)
	if sec.Password == "" {
		return out, nil, nil
	}
	// #nosec G117 -- SMTP plaintext is the vault Seal input, never logged or stored raw.
	secOut, _ := json.Marshal(sec)
	return out, secOut, nil
}

func validateWebhook(config, secret []byte, needSecret bool, errs ValidationErrors) ([]byte, []byte, ValidationErrors) {
	var cfg WebhookConfig
	if err := strictJSON(config, &cfg); err != nil {
		return nil, nil, append(errs, ValidationError{Field: "config", Code: "invalid", Message: "must be an object with url/payload/timeout_ms: " + err.Error()})
	}
	cfg.URL = strings.TrimSpace(cfg.URL)
	if err := validateOutboundURL(cfg.URL); err != nil {
		errs = append(errs, ValidationError{Field: "config.url", Code: "invalid", Message: err.Error()})
	}
	if cfg.Payload == "" {
		cfg.Payload = PayloadSummary
	}
	if cfg.Payload != PayloadIDs && cfg.Payload != PayloadSummary {
		errs = append(errs, ValidationError{Field: "config.payload", Code: "invalid", Message: "allowed: ids, summary"})
	}
	if cfg.TimeoutMS < 0 || cfg.TimeoutMS > 10000 {
		errs = append(errs, ValidationError{Field: "config.timeout_ms", Code: "range", Message: "must be between 0 and 10000"})
	}
	var sec SigningSecret
	if len(secret) > 0 {
		if err := strictJSON(secret, &sec); err != nil {
			return nil, nil, append(errs, ValidationError{Field: "secret", Code: "invalid", Message: "must be an object with a signing_secret field"})
		}
	}
	if strings.TrimSpace(sec.SigningSecret) == "" && needSecret {
		errs = append(errs, ValidationError{Field: "secret.signing_secret", Code: "required", Message: "signing_secret is required for webhook channels"})
	}
	if len(errs) > 0 {
		return nil, nil, errs
	}
	out, _ := json.Marshal(cfg)
	if strings.TrimSpace(sec.SigningSecret) == "" {
		return out, nil, nil
	}
	secOut, _ := json.Marshal(sec)
	return out, secOut, nil
}

func validateSlack(config, secret []byte, needSecret bool, errs ValidationErrors) ([]byte, []byte, ValidationErrors) {
	var cfg SlackConfig
	if err := strictJSON(config, &cfg); err != nil {
		return nil, nil, append(errs, ValidationError{Field: "config", Code: "invalid", Message: "must be an object with an optional channel field"})
	}
	out, _ := json.Marshal(cfg)
	secOut, secErrs := validateWebhookURLSecret(secret, needSecret, errs)
	if secErrs != nil {
		return nil, nil, secErrs
	}
	return out, secOut, nil
}

func validateTeams(config, secret []byte, needSecret bool, errs ValidationErrors) ([]byte, []byte, ValidationErrors) {
	// Teams has no non-secret fields; only an empty object is accepted.
	trimmed := strings.TrimSpace(string(config))
	if trimmed != "{}" && trimmed != "null" && trimmed != "" {
		errs = append(errs, ValidationError{Field: "config", Code: "invalid", Message: "teams channels have no config fields; the webhook URL lives in secret"})
	}
	secOut, secErrs := validateWebhookURLSecret(secret, needSecret, errs)
	if secErrs != nil {
		return nil, nil, secErrs
	}
	return []byte("{}"), secOut, nil
}

func validateWebhookURLSecret(secret []byte, needSecret bool, errs ValidationErrors) ([]byte, ValidationErrors) {
	var sec WebhookURLSecret
	if len(secret) == 0 {
		if needSecret {
			return nil, append(errs, ValidationError{Field: "secret.webhook_url", Code: "required", Message: "webhook_url is required"})
		}
		return nil, nil
	}
	if err := strictJSON(secret, &sec); err != nil {
		return nil, append(errs, ValidationError{Field: "secret", Code: "invalid", Message: "must be an object with a webhook_url field"})
	}
	if err := validateOutboundURL(strings.TrimSpace(sec.WebhookURL)); err != nil {
		return nil, append(errs, ValidationError{Field: "secret.webhook_url", Code: "invalid", Message: err.Error()})
	}
	if len(errs) > 0 {
		return nil, errs
	}
	secOut, _ := json.Marshal(sec)
	return secOut, nil
}

// validateOutboundURL enforces scheme/host sanity and always blocks the
// cloud-metadata link-local range. Loopback/private targets stay allowed in
// Phase 2 because notification receivers are operator-owned (and the test
// harness uses local sinks); the canonical webhook SSRF hardening (resolve,
// validate, no redirects, TLS-mandatory outbound webhook subscriptions) is
// documented as a V2 deferral in M11_EVIDENCE §S2.
func validateOutboundURL(raw string) error {
	if raw == "" {
		return fmt.Errorf("url is required")
	}
	u, err := url.Parse(raw)
	if err != nil {
		return fmt.Errorf("must be a valid URL")
	}
	if u.Scheme != "http" && u.Scheme != "https" {
		return fmt.Errorf("scheme must be http or https")
	}
	if u.Host == "" {
		return fmt.Errorf("url must include a host")
	}
	if u.User != nil {
		return fmt.Errorf("url must not embed credentials; use the secret fields")
	}
	host := u.Hostname()
	if ip := net.ParseIP(host); ip != nil {
		if ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() {
			return fmt.Errorf("link-local and metadata addresses are not allowed")
		}
	}
	if strings.EqualFold(host, "metadata.google.internal") || strings.EqualFold(host, "metadata") {
		return fmt.Errorf("metadata endpoints are not allowed")
	}
	return nil
}

// ParseRouteMatch parses and validates the match JSON, returning the canonical
// form. Unknown keys fail closed so a typo can never widen a route.
func ParseRouteMatch(raw []byte) (RouteMatch, []byte, ValidationErrors) {
	if len(raw) == 0 {
		raw = []byte("{}")
	}
	var obj map[string]json.RawMessage
	if err := json.Unmarshal(raw, &obj); err != nil {
		return RouteMatch{}, nil, ValidationErrors{{Field: "match", Code: "invalid", Message: "must be a JSON object"}}
	}
	var errs ValidationErrors
	for key := range obj {
		switch key {
		case "severity", "scope":
		default:
			errs = append(errs, ValidationError{Field: "match." + key, Code: "unknown", Message: "unknown match field"})
		}
	}
	var match RouteMatch
	if rawSev, ok := obj["severity"]; ok {
		var sev []string
		if err := json.Unmarshal(rawSev, &sev); err != nil {
			errs = append(errs, ValidationError{Field: "match.severity", Code: "invalid", Message: "must be an array of severities"})
		} else {
			seen := map[string]bool{}
			for _, s := range sev {
				if !ValidSeverity(s) {
					errs = append(errs, ValidationError{Field: "match.severity", Code: "invalid", Message: "allowed: info, warning, critical"})
					continue
				}
				if !seen[s] {
					seen[s] = true
					match.Severities = append(match.Severities, s)
				}
			}
		}
	}
	if rawScope, ok := obj["scope"]; ok {
		var scopeObj map[string]json.RawMessage
		if err := json.Unmarshal(rawScope, &scopeObj); err != nil {
			errs = append(errs, ValidationError{Field: "match.scope", Code: "invalid", Message: "must be a JSON object"})
		} else {
			for key := range scopeObj {
				switch key {
				case "sites", "device_ids", "device_kinds":
				default:
					errs = append(errs, ValidationError{Field: "match.scope." + key, Code: "unknown", Message: "unknown scope field"})
				}
			}
			match.Scope.Sites, errs = parseUUIDList(scopeObj["sites"], "match.scope.sites", errs)
			match.Scope.DeviceIDs, errs = parseUUIDList(scopeObj["device_ids"], "match.scope.device_ids", errs)
			if rawKinds, ok := scopeObj["device_kinds"]; ok {
				var kinds []string
				if err := json.Unmarshal(rawKinds, &kinds); err != nil {
					errs = append(errs, ValidationError{Field: "match.scope.device_kinds", Code: "invalid", Message: "must be an array of strings"})
				} else {
					for _, k := range kinds {
						if strings.TrimSpace(k) == "" || len(k) > 64 {
							errs = append(errs, ValidationError{Field: "match.scope.device_kinds", Code: "invalid", Message: "kinds must be 1..64 characters"})
							continue
						}
						match.Scope.DeviceKinds = append(match.Scope.DeviceKinds, k)
					}
				}
			}
		}
	}
	if len(errs) > 0 {
		return RouteMatch{}, nil, errs
	}
	sort.Strings(match.Severities)
	canonical, _ := json.Marshal(matchJSON(match))
	return match, canonical, nil
}

func matchJSON(m RouteMatch) map[string]any {
	out := map[string]any{}
	if len(m.Severities) > 0 {
		out["severity"] = m.Severities
	}
	scope := map[string]any{}
	if len(m.Scope.Sites) > 0 {
		scope["sites"] = uuidStrings(m.Scope.Sites)
	}
	if len(m.Scope.DeviceIDs) > 0 {
		scope["device_ids"] = uuidStrings(m.Scope.DeviceIDs)
	}
	if len(m.Scope.DeviceKinds) > 0 {
		scope["device_kinds"] = m.Scope.DeviceKinds
	}
	if len(scope) > 0 {
		out["scope"] = scope
	}
	return out
}

func parseUUIDList(raw json.RawMessage, field string, errs ValidationErrors) ([]uuid.UUID, ValidationErrors) {
	if len(raw) == 0 {
		return nil, errs
	}
	var items []string
	if err := json.Unmarshal(raw, &items); err != nil {
		return nil, append(errs, ValidationError{Field: field, Code: "invalid", Message: "must be an array of UUID strings"})
	}
	out := make([]uuid.UUID, 0, len(items))
	for _, item := range items {
		id, err := uuid.Parse(item)
		if err != nil {
			return nil, append(errs, ValidationError{Field: field, Code: "invalid", Message: "must contain UUID strings"})
		}
		out = append(out, id)
	}
	return out, errs
}

func uuidStrings(ids []uuid.UUID) []string {
	out := make([]string, len(ids))
	for i, id := range ids {
		out[i] = id.String()
	}
	return out
}

// ParseTemplateOverrides validates the minimal rendering knobs this slice
// supports. Unknown keys are rejected (canonical per-route templates are V2).
func ParseTemplateOverrides(raw []byte) ([]byte, ValidationErrors) {
	if len(raw) == 0 {
		return []byte("{}"), nil
	}
	var obj map[string]json.RawMessage
	if err := json.Unmarshal(raw, &obj); err != nil {
		return nil, ValidationErrors{{Field: "template_overrides", Code: "invalid", Message: "must be a JSON object"}}
	}
	var errs ValidationErrors
	out := map[string]any{}
	for key, value := range obj {
		switch key {
		case "subject_prefix":
			var s string
			if err := json.Unmarshal(value, &s); err != nil || len(s) > 100 {
				errs = append(errs, ValidationError{Field: "template_overrides.subject_prefix", Code: "invalid", Message: "must be a string of at most 100 characters"})
			} else {
				out[key] = s
			}
		default:
			errs = append(errs, ValidationError{Field: "template_overrides." + key, Code: "unknown", Message: "unknown template override"})
		}
	}
	if len(errs) > 0 {
		return nil, errs
	}
	canonical, _ := json.Marshal(out)
	return canonical, nil
}

// ValidateChannelIDs validates an ordered channel list.
func ValidateChannelIDs(ids []uuid.UUID) ValidationErrors {
	switch {
	case len(ids) == 0:
		return ValidationErrors{{Field: "channel_ids", Code: "required", Message: "at least one channel is required"}}
	case len(ids) > 20:
		return ValidationErrors{{Field: "channel_ids", Code: "too_many", Message: "at most 20 channels per route"}}
	}
	seen := map[uuid.UUID]bool{}
	for _, id := range ids {
		if id == uuid.Nil {
			return ValidationErrors{{Field: "channel_ids", Code: "invalid", Message: "channel ids must be UUIDs"}}
		}
		if seen[id] {
			return ValidationErrors{{Field: "channel_ids", Code: "duplicate", Message: "channel ids must be unique"}}
		}
		seen[id] = true
	}
	return nil
}

// SeverityBucketRate returns the canonical hourly token rate for a severity.
// Unknown severities fall back to the info rate (fail closed: the smallest
// budget).
func SeverityBucketRate(severity string) float64 {
	switch severity {
	case SeverityCritical:
		return BucketCritical
	case SeverityWarning:
		return BucketWarning
	default:
		return BucketInfo
	}
}
