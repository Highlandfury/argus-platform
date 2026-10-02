package alerts

// Curated default rule pack (P2-AC-32) and its idempotent installer.
//
// The pack lives in defaults/default_rules.yaml and is embedded into the
// binary. Every rule is validated through the same ParseRule path as a
// user-created rule, so the pack can never carry a shape the evaluator does
// not understand. Installation writes ordinary immutable version-1 rows with
// `default_key` provenance; patching an installed rule follows the normal
// version N+1 path.

import (
	"context"
	"embed"
	"encoding/json"
	"fmt"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"gopkg.in/yaml.v3"

	"github.com/argus-platform/argus/internal/platform/authz"
	"github.com/argus-platform/argus/internal/platform/database"
)

//go:embed defaults/default_rules.yaml
var defaultPackFS embed.FS

// DefaultRule is one validated pack entry.
type DefaultRule struct {
	Key   string
	Name  string
	Input RuleCreateInput
}

type defaultPackDoc struct {
	Version int `yaml:"version"`
	Rules   []struct {
		Key           string         `yaml:"key"`
		Name          string         `yaml:"name"`
		Type          string         `yaml:"type"`
		Severity      string         `yaml:"severity"`
		ScopeSelector map[string]any `yaml:"scope_selector"`
		Condition     map[string]any `yaml:"condition"`
	} `yaml:"rules"`
}

// DefaultPack parses and validates the embedded pack. Parsing is
// deterministic and pure; tests pin the curated set and its validity.
func DefaultPack() ([]DefaultRule, error) {
	raw, err := defaultPackFS.ReadFile("defaults/default_rules.yaml")
	if err != nil {
		return nil, fmt.Errorf("alerts: read default rule pack: %w", err)
	}
	var doc defaultPackDoc
	if err := yaml.Unmarshal(raw, &doc); err != nil {
		return nil, fmt.Errorf("alerts: parse default rule pack: %w", err)
	}
	if doc.Version != 1 {
		return nil, fmt.Errorf("alerts: unsupported default rule pack version %d", doc.Version)
	}
	if len(doc.Rules) == 0 {
		return nil, fmt.Errorf("alerts: default rule pack is empty")
	}
	out := make([]DefaultRule, 0, len(doc.Rules))
	seen := map[string]bool{}
	for _, r := range doc.Rules {
		if r.Key == "" {
			return nil, fmt.Errorf("alerts: default rule pack entry missing key")
		}
		if seen[r.Key] {
			return nil, fmt.Errorf("alerts: duplicate default rule key %q", r.Key)
		}
		seen[r.Key] = true
		selectorJSON, err := json.Marshal(r.ScopeSelector)
		if err != nil {
			return nil, fmt.Errorf("alerts: default rule %q selector: %w", r.Key, err)
		}
		conditionJSON, err := json.Marshal(r.Condition)
		if err != nil {
			return nil, fmt.Errorf("alerts: default rule %q condition: %w", r.Key, err)
		}
		parsed, errs := ParseRule(r.Name, r.Type, r.Severity, conditionJSON, selectorJSON)
		if len(errs) > 0 {
			return nil, fmt.Errorf("alerts: default rule %q invalid: %w", r.Key, errs)
		}
		out = append(out, DefaultRule{
			Key:  r.Key,
			Name: parsed.Name,
			Input: RuleCreateInput{
				Name: parsed.Name, Type: parsed.Type, Severity: parsed.Severity,
				ConditionJSON: parsed.ConditionJSON, SelectorJSON: parsed.SelectorJSON,
			},
		})
	}
	return out, nil
}

// DefaultInstallResult reports one install run.
type DefaultInstallResult struct {
	Installed int    // newly created rules
	Skipped   int    // keys already present in the org
	Rules     []Rule // the installed rules (version 1)
}

// InstallDefaults installs the curated pack for the org. Every key that
// already exists (any version, enabled or not) is skipped, so the operation
// is idempotent and never rewrites an operator's edits. Scope is enforced
// like CreateRule: the pack selectors are org-wide, so a site-restricted
// caller gets ErrScopeRequired.
func (s *Service) InstallDefaults(ctx context.Context, orgID uuid.UUID, actor Actor, sc authz.Scope) (DefaultInstallResult, error) {
	pack, err := DefaultPack()
	if err != nil {
		return DefaultInstallResult{}, err
	}
	var out DefaultInstallResult
	err = database.WithTenant(ctx, s.app, orgID, func(ctx context.Context, tx pgx.Tx) error {
		out = DefaultInstallResult{}
		for _, dr := range pack {
			var exists bool
			if err := tx.QueryRow(ctx,
				`SELECT EXISTS (SELECT 1 FROM alert_rules WHERE org_id = $1 AND default_key = $2)`,
				orgID, dr.Key).Scan(&exists); err != nil {
				return err
			}
			if exists {
				out.Skipped++
				continue
			}
			parsed, errs := ParseRule(dr.Input.Name, dr.Input.Type, dr.Input.Severity, dr.Input.ConditionJSON, dr.Input.SelectorJSON)
			if len(errs) > 0 {
				return errs
			}
			if err := s.requireSelectorInScope(ctx, tx, parsed.Selector, sc); err != nil {
				return err
			}
			ruleID, err := uuid.NewV7()
			if err != nil {
				return err
			}
			row := tx.QueryRow(ctx, `
				INSERT INTO alert_rules AS r
					(org_id, rule_id, version, name, type, severity, condition, scope_selector, enabled, created_by, default_key)
				VALUES ($1, $2, 1, $3, $4, $5, $6::jsonb, $7::jsonb, true, $8, $9)
				RETURNING `+ruleColumns,
				orgID, ruleID, parsed.Name, parsed.Type, parsed.Severity,
				parsed.ConditionJSON, parsed.SelectorJSON, actorRef(actor), dr.Key)
			rule, err := scanRule(row)
			if err != nil {
				return err
			}
			out.Installed++
			out.Rules = append(out.Rules, rule)
		}
		return nil
	})
	if err != nil {
		return DefaultInstallResult{}, err
	}
	return out, nil
}

// EnsureDefaults seeds an organization that has never had any alert rule row
// (a new tenant). Organizations that once had rules — even if every one was
// disabled — are left untouched so operator deletions cannot resurrect.
// Returns the number of installed rules.
func (s *Service) EnsureDefaults(ctx context.Context, orgID uuid.UUID) (int, error) {
	var installed int
	err := database.WithTenant(ctx, s.app, orgID, func(ctx context.Context, tx pgx.Tx) error {
		var anyRule bool
		if err := tx.QueryRow(ctx,
			`SELECT EXISTS (SELECT 1 FROM alert_rules WHERE org_id = $1)`, orgID).Scan(&anyRule); err != nil {
			return err
		}
		if anyRule {
			return nil
		}
		pack, err := DefaultPack()
		if err != nil {
			return err
		}
		for _, dr := range pack {
			ruleID, err := uuid.NewV7()
			if err != nil {
				return err
			}
			if _, err := tx.Exec(ctx, `
				INSERT INTO alert_rules
					(org_id, rule_id, version, name, type, severity, condition, scope_selector, enabled, default_key, created_at)
				VALUES ($1, $2, 1, $3, $4, $5, $6::jsonb, $7::jsonb, true, $8, now())`,
				orgID, ruleID, dr.Input.Name, dr.Input.Type, dr.Input.Severity,
				dr.Input.ConditionJSON, dr.Input.SelectorJSON, dr.Key); err != nil {
				return err
			}
			installed++
		}
		return nil
	})
	return installed, err
}
