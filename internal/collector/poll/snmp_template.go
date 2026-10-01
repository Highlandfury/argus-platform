package poll

import (
	"embed"
	"fmt"
	"io/fs"
	"sort"
	"strings"

	"gopkg.in/yaml.v3"
)

// Metric types a template entry may declare (canonical docs/07 §12.2: metric
// key, OID, type, scale/unit, dimensions, tier).
const (
	SNMPMetricGauge   = "gauge"
	SNMPMetricCounter = "counter"
	SNMPMetricState   = "state"
	// SNMPMetricString is collected for identity/drift checks only: the
	// platform's numeric metric model has no text series (documented), so
	// string entries are never emitted as samples.
	SNMPMetricString = "string"
)

// Column roles for non-series columns the prober needs.
const (
	SNMPRoleSysUptime     = "sys_uptime"
	SNMPRoleDiscontinuity = "discontinuity"
)

//go:embed templates/core/*.yaml
var coreTemplatesFS embed.FS

// SNMPSelect declares which device kinds a template pack applies to. An empty
// list or "*" matches every kind.
type SNMPSelect struct {
	Kinds []string `yaml:"kinds"`
}

// SNMPIdentity maps one row dimension onto a fallback chain of OID columns
// (canonical docs/07 §12.3: ifName primary, ifAlias, ... — never ifIndex).
type SNMPIdentity struct {
	Dim  string   `yaml:"dim"`
	OIDs []string `yaml:"oids"`
}

// SNMPColumn is one scalar entry or one table column.
type SNMPColumn struct {
	OID     string  `yaml:"oid"`
	Key     string  `yaml:"key"`
	Unit    string  `yaml:"unit"`
	Type    string  `yaml:"type"`
	Width   int     `yaml:"width"`
	MaxRate float64 `yaml:"max_rate"`
	Scale   float64 `yaml:"scale"`
	Role    string  `yaml:"role"`
	Dim     string  `yaml:"dim"`
}

// SNMPTable is one table walk. MaxRows is the static worst-case row bound used
// by the compile-time per-device series-budget check (P2-AC-11 clause
// "template compile-time budget check rejects over-budget templates in CI",
// PHASE_2_SPEC; docs/08 §13.3, docs/07 §12.2 "estimated-series budget per
// template"). It is not a runtime limit: the ingest-time per-device cap (M8)
// remains the hard guard.
type SNMPTable struct {
	Name     string `yaml:"name"`
	Walk     string `yaml:"walk"`
	Required bool   `yaml:"required"`
	MaxRows  int    `yaml:"max_rows"`
}

// SNMPTemplate is one declarative pack. Tables are walked once per poll; rows
// are joined across the pack's columns by their final sub-identifier (the
// core pack's tables are single-level indexed).
type SNMPTemplate struct {
	Name        string         `yaml:"name"`
	Version     int            `yaml:"version"`
	Description string         `yaml:"description"`
	Required    bool           `yaml:"required"`
	Select      SNMPSelect     `yaml:"select"`
	Identity    []SNMPIdentity `yaml:"identity"`
	Scalars     []SNMPColumn   `yaml:"scalars"`
	Tables      []SNMPTable    `yaml:"tables"`
	Columns     []SNMPColumn   `yaml:"columns"`
	// SeriesBudget overrides the default per-device series budget this
	// template may contribute (0 = DefaultSeriesBudget); the compile-time
	// check rejects a template whose estimate exceeds it.
	SeriesBudget int `yaml:"series_budget"`
}

// DefaultSeriesBudget is the canonical per-device series cap adopted by
// PHASE_2_SPEC consistency item 2 (docs/08 §13.3; reconciles docs/11's "200
// typical") and enforced at ingest by M8; templates are checked against it at
// compile time.
const DefaultSeriesBudget = 250

// Emits reports whether a column produces a persisted metric series.
func (c SNMPColumn) Emits() bool {
	return c.Key != "" && c.Type != SNMPMetricString
}

// EffectiveScale returns the column scale (default 1).
func (c SNMPColumn) EffectiveScale() float64 {
	if c.Scale == 0 {
		return 1
	}
	return c.Scale
}

// SeriesBudgetOrDefault returns the template's declared per-device series
// budget, or the canonical default.
func (t SNMPTemplate) SeriesBudgetOrDefault() int {
	if t.SeriesBudget > 0 {
		return t.SeriesBudget
	}
	return DefaultSeriesBudget
}

// EstimatedSeries returns the static worst-case per-device series this
// template may produce: every emitting scalar counts once; every emitting table
// column counts the declared MaxRows of its most specific table walk root
// (docs/07 §12.2 "worst-case series (interfaces × metrics + table rows)";
// docs/08 §13.5 estimation check). A column not under any declared table walk
// counts once.
func (t SNMPTemplate) EstimatedSeries() int {
	n := 0
	for _, c := range t.Scalars {
		if c.Emits() {
			n++
		}
	}
	for _, c := range t.Columns {
		if !c.Emits() {
			continue
		}
		rows := 1
		if idx := t.tableIndexFor(c.OID); idx >= 0 {
			rows = t.Tables[idx].MaxRows
			if rows < 1 {
				rows = 1
			}
		}
		n += rows
	}
	return n
}

// tableIndexFor returns the index of the table whose walk root is the longest
// prefix of oid, or -1 when the column belongs to no declared table.
func (t SNMPTemplate) tableIndexFor(oid string) int {
	oid = strings.TrimPrefix(strings.TrimSpace(oid), ".")
	best, bestLen := -1, -1
	for i, tbl := range t.Tables {
		root := strings.TrimPrefix(strings.TrimSpace(tbl.Walk), ".")
		if root == "" {
			continue
		}
		if oid != root && !strings.HasPrefix(oid, root+".") {
			continue
		}
		if len(root) > bestLen {
			best, bestLen = i, len(root)
		}
	}
	return best
}

// tableEmittingColumnCount returns how many emitting columns a table
// contributes (used by validation to require a row bound).
func (t SNMPTemplate) tableEmittingColumnCount(idx int) int {
	n := 0
	for _, c := range t.Columns {
		if c.Emits() && t.tableIndexFor(c.OID) == idx {
			n++
		}
	}
	return n
}

// SNMPTemplateSet is a loaded, validated collection of template packs.
type SNMPTemplateSet struct {
	packs []SNMPTemplate
}

// CoreTemplateSet parses the embedded core pack (system, IF-MIB incl. HC
// counters + errors/discards, HOST-RESOURCES hrProcessorLoad).
func CoreTemplateSet() (*SNMPTemplateSet, error) {
	return LoadSNMPTemplates(coreTemplatesFS, "templates/core")
}

// LoadSNMPTemplates parses every *.yaml under dir in the given filesystem.
func LoadSNMPTemplates(fsys fs.FS, dir string) (*SNMPTemplateSet, error) {
	entries, err := fs.ReadDir(fsys, dir)
	if err != nil {
		return nil, fmt.Errorf("snmp templates: read %s: %w", dir, err)
	}
	var names []string
	for _, e := range entries {
		if !e.IsDir() && (strings.HasSuffix(e.Name(), ".yaml") || strings.HasSuffix(e.Name(), ".yml")) {
			names = append(names, e.Name())
		}
	}
	sort.Strings(names)
	set := &SNMPTemplateSet{}
	keys := make(map[string]string)
	for _, name := range names {
		raw, err := fs.ReadFile(fsys, dir+"/"+name)
		if err != nil {
			return nil, fmt.Errorf("snmp templates: read %s: %w", name, err)
		}
		var tpl SNMPTemplate
		dec := yaml.NewDecoder(strings.NewReader(string(raw)))
		dec.KnownFields(true)
		if err := dec.Decode(&tpl); err != nil {
			return nil, fmt.Errorf("snmp templates: parse %s: %w", name, err)
		}
		if err := validateSNMPTemplate(&tpl); err != nil {
			return nil, fmt.Errorf("snmp templates: %s: %w", name, err)
		}
		for _, k := range templateMetricKeys(tpl) {
			if prev, ok := keys[k]; ok {
				return nil, fmt.Errorf("snmp templates: metric key %q declared by %s and %s", k, prev, tpl.Name)
			}
			keys[k] = tpl.Name
		}
		set.packs = append(set.packs, tpl)
	}
	if len(set.packs) == 0 {
		return nil, fmt.Errorf("snmp templates: no packs in %s", dir)
	}
	return set, nil
}

// Packs returns the loaded packs (description/validation tests).
func (s *SNMPTemplateSet) Packs() []SNMPTemplate { return s.packs }

// EstimateForKind returns the static worst-case per-device series estimate of
// every pack selected for a device kind. The M9-S4 CI gate asserts it stays
// within the canonical per-device budget (docs/08 §13.3).
func (s *SNMPTemplateSet) EstimateForKind(kind string) int {
	total := 0
	for _, p := range s.Select(kind) {
		total += p.EstimatedSeries()
	}
	return total
}

// Select returns the packs that apply to a device kind. The system pack
// (kinds ["*"]) applies everywhere; network gear gets IF-MIB; host/server
// kinds get HOST-RESOURCES.
func (s *SNMPTemplateSet) Select(kind string) []SNMPTemplate {
	kind = strings.ToLower(strings.TrimSpace(kind))
	var out []SNMPTemplate
	for _, p := range s.packs {
		if p.matches(kind) {
			out = append(out, p)
		}
	}
	return out
}

func (t SNMPTemplate) matches(kind string) bool {
	if len(t.Select.Kinds) == 0 {
		return true
	}
	for _, k := range t.Select.Kinds {
		k = strings.ToLower(strings.TrimSpace(k))
		if k == "*" || k == kind {
			return true
		}
	}
	return false
}

func validateSNMPTemplate(t *SNMPTemplate) error {
	if strings.TrimSpace(t.Name) == "" {
		return fmt.Errorf("template name is required")
	}
	if t.Version <= 0 {
		return fmt.Errorf("template %s version must be positive", t.Name)
	}
	for _, id := range t.Identity {
		if strings.TrimSpace(id.Dim) == "" || len(id.OIDs) == 0 {
			return fmt.Errorf("template %s identity entries need a dim and at least one oid", t.Name)
		}
		for _, oid := range id.OIDs {
			if err := validateOID(oid); err != nil {
				return fmt.Errorf("template %s identity %s: %w", t.Name, id.Dim, err)
			}
		}
	}
	for _, c := range append(append([]SNMPColumn{}, t.Scalars...), t.Columns...) {
		if err := validateSNMPColumn(t.Name, c); err != nil {
			return err
		}
	}
	for i, tbl := range t.Tables {
		if strings.TrimSpace(tbl.Walk) == "" {
			return fmt.Errorf("template %s table %s needs a walk root", t.Name, tbl.Name)
		}
		if err := validateOID(tbl.Walk); err != nil {
			return fmt.Errorf("template %s table %s: %w", t.Name, tbl.Name, err)
		}
		if t.tableEmittingColumnCount(i) > 0 && tbl.MaxRows < 1 {
			return fmt.Errorf("template %s table %s has emitting columns but no max_rows for the series-budget check", t.Name, tbl.Name)
		}
	}
	if len(t.Columns) > 0 && len(t.Tables) == 0 {
		return fmt.Errorf("template %s declares columns but no tables", t.Name)
	}
	if len(t.Identity) > 0 && len(t.Columns) == 0 {
		return fmt.Errorf("template %s declares identity but no columns", t.Name)
	}
	if est, budget := t.EstimatedSeries(), t.SeriesBudgetOrDefault(); est > budget {
		return fmt.Errorf("template %s estimates %d series/device, over its series budget %d (raise series_budget only with an explicit operator override)", t.Name, est, budget)
	}
	return nil
}

func validateSNMPColumn(tplName string, c SNMPColumn) error {
	if err := validateOID(c.OID); err != nil {
		return fmt.Errorf("template %s column %s: %w", tplName, c.Key, err)
	}
	switch c.Type {
	case SNMPMetricGauge, SNMPMetricCounter, SNMPMetricState, SNMPMetricString:
	default:
		return fmt.Errorf("template %s column %s: unknown type %q", tplName, c.Key, c.Type)
	}
	if c.Type != SNMPMetricString && c.Role == "" {
		if strings.TrimSpace(c.Key) == "" {
			return fmt.Errorf("template %s column %s: metric key is required", tplName, c.OID)
		}
		if strings.TrimSpace(c.Unit) == "" {
			return fmt.Errorf("template %s column %s: unit is required", tplName, c.Key)
		}
	}
	if c.Type == SNMPMetricCounter && c.Width != CounterWidth32 && c.Width != CounterWidth64 {
		return fmt.Errorf("template %s column %s: counter width must be 32 or 64", tplName, c.Key)
	}
	if c.MaxRate < 0 {
		return fmt.Errorf("template %s column %s: max_rate must be >= 0", tplName, c.Key)
	}
	if c.Scale < 0 {
		return fmt.Errorf("template %s column %s: scale must be >= 0", tplName, c.Key)
	}
	switch c.Role {
	case "", SNMPRoleSysUptime, SNMPRoleDiscontinuity:
	default:
		return fmt.Errorf("template %s column %s: unknown role %q", tplName, c.Key, c.Role)
	}
	return nil
}

func templateMetricKeys(t SNMPTemplate) []string {
	var keys []string
	for _, c := range append(append([]SNMPColumn{}, t.Scalars...), t.Columns...) {
		if c.Emits() {
			keys = append(keys, c.Key)
		}
	}
	return keys
}

// validateOID accepts dotted numeric OIDs with at least two arcs.
func validateOID(oid string) error {
	s := strings.TrimPrefix(strings.TrimSpace(oid), ".")
	if s == "" {
		return fmt.Errorf("empty OID")
	}
	parts := strings.Split(s, ".")
	if len(parts) < 2 {
		return fmt.Errorf("OID %q has too few arcs", oid)
	}
	for _, p := range parts {
		if p == "" {
			return fmt.Errorf("OID %q has an empty arc", oid)
		}
		if _, err := parseOIDArc(p); err != nil {
			return fmt.Errorf("OID %q has a non-numeric arc %q", oid, p)
		}
	}
	return nil
}
