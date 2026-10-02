package alerts

import (
	"encoding/json"
	"fmt"
	"math"
	"sort"
	"strings"
	"time"

	"github.com/google/uuid"
)

// Rule-condition parsing, validation, canonicalization, and the pure
// semantics helpers (operators, cadence, continuity grid). Everything in this
// file is DB-free so the evaluator semantics are unit-testable.

// ParsedRule is one validated, normalized rule definition.
type ParsedRule struct {
	Name          string
	Type          string
	Severity      string
	Condition     Condition
	Selector      ScopeSelector
	ConditionJSON []byte
	SelectorJSON  []byte
}

// ParseRule validates and normalizes a rule definition. The returned
// ValidationErrors are ordered and deterministic.
func ParseRule(name, ruleType, severity string, conditionJSON, selectorJSON []byte) (ParsedRule, ValidationErrors) {
	var errs ValidationErrors
	name = strings.TrimSpace(name)
	switch {
	case name == "":
		errs = append(errs, ValidationError{Field: "name", Code: "required", Message: "name is required"})
	case len(name) > MaxNameLen:
		errs = append(errs, ValidationError{Field: "name", Code: "too_long", Message: fmt.Sprintf("name must be at most %d characters", MaxNameLen)})
	}
	if !ValidRuleType(ruleType) {
		errs = append(errs, ValidationError{Field: "type", Code: "invalid", Message: "allowed: threshold, absence, rate_of_change"})
	}
	if !ValidSeverity(severity) {
		errs = append(errs, ValidationError{Field: "severity", Code: "invalid", Message: "allowed: info, warning, critical"})
	}
	selector, selErrs := ParseSelectorJSON(selectorJSON)
	errs = append(errs, selErrs...)
	condition, condErrs := ParseConditionJSON(ruleType, conditionJSON)
	errs = append(errs, condErrs...)
	if len(errs) > 0 {
		return ParsedRule{}, errs
	}
	// Cross-field: metric-targeting rule types need a metric key to resolve
	// series.
	if condition.Source != SourcePollHealth && selector.MetricKey == "" {
		errs = append(errs, ValidationError{
			Field: "scope_selector.metric_key", Code: "required",
			Message: "metric_key is required for threshold, rate_of_change and samples-absence rules",
		})
	}
	if len(errs) > 0 {
		return ParsedRule{}, errs
	}
	return ParsedRule{
		Name:          name,
		Type:          ruleType,
		Severity:      severity,
		Condition:     condition,
		Selector:      selector,
		ConditionJSON: condition.canonicalJSON(),
		SelectorJSON:  selector.canonicalJSON(),
	}, nil
}

// ValidRuleType reports whether t is a v1 rule type.
func ValidRuleType(t string) bool {
	switch t {
	case TypeThreshold, TypeAbsence, TypeRateOfChange:
		return true
	}
	return false
}

// ValidSeverity reports whether s is a valid severity.
func ValidSeverity(s string) bool {
	switch s {
	case SeverityInfo, SeverityWarning, SeverityCritical:
		return true
	}
	return false
}

// ValidOp reports whether op is a supported condition operator.
func ValidOp(op string) bool {
	switch op {
	case OpGT, OpGTE, OpLT, OpLTE, OpEQ, OpNE:
		return true
	}
	return false
}

// ApplyOp evaluates `v op threshold`. A nil/NaN v never satisfies the
// condition (missing data is not "true").
func ApplyOp(op string, v, threshold float64) bool {
	if math.IsNaN(v) || math.IsInf(v, 0) {
		return false
	}
	switch op {
	case OpGT:
		return v > threshold
	case OpGTE:
		return v >= threshold
	case OpLT:
		return v < threshold
	case OpLTE:
		return v <= threshold
	case OpEQ:
		return v == threshold
	case OpNE:
		return v != threshold
	default:
		return false
	}
}

// InverseOp is the logical inverse operator used by the default recovery
// condition (docs/10 §17.5).
func InverseOp(op string) string {
	switch op {
	case OpGT:
		return OpLTE
	case OpGTE:
		return OpLT
	case OpLT:
		return OpGTE
	case OpLTE:
		return OpGT
	case OpEQ:
		return OpNE
	case OpNE:
		return OpEQ
	default:
		return ""
	}
}

// DefaultRecoveryDuration is the documented default: the recovery requires
// twice the trigger for_duration (at least the condition window), keeping the
// canonical "longer for_duration" property. A zero trigger for_duration stays
// zero (recovery is immediate on the first inverse evaluation).
func DefaultRecoveryDuration(base, window time.Duration) time.Duration {
	if base <= 0 {
		return 0
	}
	d := 2 * base
	if window > d {
		d = window
	}
	if d > MaxForDuration {
		d = MaxForDuration
	}
	return d
}

// RuleCadence implements docs/10 §17.3: max(30 s, window/2) capped at 5 min;
// absence rules evaluate at 2 × their check interval.
func RuleCadence(r Rule) time.Duration {
	if r.Type == TypeAbsence {
		interval := r.Condition.CheckInterval
		if interval <= 0 {
			interval = DefaultCheckInterval
		}
		return clampCadence(2 * interval)
	}
	return clampCadence(r.Condition.Window / 2)
}

func clampCadence(d time.Duration) time.Duration {
	if d < MinCadence {
		return MinCadence
	}
	if d > MaxCadence {
		return MaxCadence
	}
	return d
}

// GridPoints returns the deterministic continuity-grid instants over
// [from, to]: from, from+step, ..., to. When the span would need more than
// maxPoints instants the step widens to span/(maxPoints-1) so the last point
// stays exactly `to` (documented judgement call: continuity is still checked
// across the whole span, just coarser).
func GridPoints(from, to time.Time, step time.Duration, maxPoints int) []time.Time {
	if step <= 0 {
		step = MinCadence
	}
	if maxPoints < 2 {
		maxPoints = 2
	}
	if !to.After(from) {
		return []time.Time{to}
	}
	span := to.Sub(from)
	if n := int(span/step) + 1; n > maxPoints {
		step = span / time.Duration(maxPoints-1)
		if step <= 0 {
			step = time.Nanosecond
		}
	}
	out := make([]time.Time, 0, 8)
	for t := from; !t.After(to); t = t.Add(step) {
		out = append(out, t)
	}
	if len(out) == 0 || !out[len(out)-1].Equal(to) {
		out = append(out, to)
	}
	return out
}

// Continuous reports whether truth is true at every grid instant over
// [from, to]. Any evaluation error or false instant returns false (fail
// closed; missing data never counts as continuous).
func Continuous(from, to time.Time, step time.Duration, maxPoints int, truth func(t time.Time) (bool, error)) (bool, error) {
	for _, t := range GridPoints(from, to, step, maxPoints) {
		ok, err := truth(t)
		if err != nil {
			return false, err
		}
		if !ok {
			return false, nil
		}
	}
	return true, nil
}

// ParseSelectorJSON parses the canonical scope_selector object. Unknown keys
// are rejected so typos never silently widen a rule's scope.
func ParseSelectorJSON(raw []byte) (ScopeSelector, ValidationErrors) {
	if len(raw) == 0 {
		raw = []byte("{}")
	}
	var obj map[string]json.RawMessage
	if err := json.Unmarshal(raw, &obj); err != nil {
		return ScopeSelector{}, ValidationErrors{{Field: "scope_selector", Code: "invalid", Message: "must be a JSON object"}}
	}
	var errs ValidationErrors
	var sel ScopeSelector
	for key := range obj {
		switch key {
		case "sites", "device_ids", "device_kinds", "metric_key", "metric", "dimensions":
		default:
			errs = append(errs, ValidationError{Field: "scope_selector." + key, Code: "unknown", Message: "unknown selector field"})
		}
	}
	if rawSites, ok := obj["sites"]; ok {
		ids, err := parseUUIDArray(rawSites)
		if err != nil {
			errs = append(errs, ValidationError{Field: "scope_selector.sites", Code: "invalid", Message: err.Error()})
		} else {
			sel.Sites = ids
		}
	}
	if rawDevices, ok := obj["device_ids"]; ok {
		ids, err := parseUUIDArray(rawDevices)
		if err != nil {
			errs = append(errs, ValidationError{Field: "scope_selector.device_ids", Code: "invalid", Message: err.Error()})
		} else {
			sel.DeviceIDs = ids
		}
	}
	if rawKinds, ok := obj["device_kinds"]; ok {
		var kinds []string
		if err := json.Unmarshal(rawKinds, &kinds); err != nil {
			errs = append(errs, ValidationError{Field: "scope_selector.device_kinds", Code: "invalid", Message: "must be an array of strings"})
		} else {
			for i, k := range kinds {
				k = strings.TrimSpace(k)
				if k == "" || len(k) > 100 {
					errs = append(errs, ValidationError{Field: fmt.Sprintf("scope_selector.device_kinds[%d]", i), Code: "invalid", Message: "kind must be 1..100 characters"})
				}
			}
			sel.DeviceKinds = kinds
		}
	}
	for _, key := range []string{"metric_key", "metric"} {
		if v, ok := obj[key]; ok {
			var s string
			if err := json.Unmarshal(v, &s); err != nil {
				errs = append(errs, ValidationError{Field: "scope_selector." + key, Code: "invalid", Message: "must be a string"})
				continue
			}
			if key == "metric" && sel.MetricKey != "" && sel.MetricKey != s {
				errs = append(errs, ValidationError{Field: "scope_selector.metric", Code: "conflict", Message: "metric and metric_key disagree"})
				continue
			}
			sel.MetricKey = strings.TrimSpace(s)
		}
	}
	if sel.MetricKey == "" {
		// metric_key itself was empty or whitespace.
		if _, ok := obj["metric_key"]; ok {
			errs = append(errs, ValidationError{Field: "scope_selector.metric_key", Code: "required", Message: "metric_key must not be empty"})
		}
	} else if len(sel.MetricKey) > 200 {
		errs = append(errs, ValidationError{Field: "scope_selector.metric_key", Code: "too_long", Message: "metric_key must be at most 200 characters"})
	}
	if rawDims, ok := obj["dimensions"]; ok {
		dims := map[string]string{}
		if err := json.Unmarshal(rawDims, &dims); err != nil {
			errs = append(errs, ValidationError{Field: "scope_selector.dimensions", Code: "invalid", Message: "must be an object of string values"})
		} else {
			for k, v := range dims {
				if k == "" || len(k) > 64 || len(v) > 64 {
					errs = append(errs, ValidationError{Field: "scope_selector.dimensions." + k, Code: "invalid", Message: "dimension keys/values must be 1..64 characters"})
				}
			}
			if len(dims) > 8 {
				errs = append(errs, ValidationError{Field: "scope_selector.dimensions", Code: "too_many", Message: "at most 8 dimensions"})
			}
			sel.Dimensions = dims
		}
	}
	if len(errs) > 0 {
		return ScopeSelector{}, errs
	}
	return sel, nil
}

func parseUUIDArray(raw json.RawMessage) ([]uuid.UUID, error) {
	var items []string
	if err := json.Unmarshal(raw, &items); err != nil {
		return nil, fmt.Errorf("must be an array of UUID strings")
	}
	out := make([]uuid.UUID, 0, len(items))
	for _, item := range items {
		id, err := uuid.Parse(item)
		if err != nil {
			return nil, fmt.Errorf("must contain UUID strings")
		}
		out = append(out, id)
	}
	return out, nil
}

// canonicalJSON stores the normalized selector.
func (s ScopeSelector) canonicalJSON() []byte {
	obj := map[string]any{}
	if len(s.Sites) > 0 {
		obj["sites"] = uuidStrings(s.Sites)
	}
	if len(s.DeviceIDs) > 0 {
		obj["device_ids"] = uuidStrings(s.DeviceIDs)
	}
	if len(s.DeviceKinds) > 0 {
		obj["device_kinds"] = s.DeviceKinds
	}
	if s.MetricKey != "" {
		obj["metric_key"] = s.MetricKey
	}
	if len(s.Dimensions) > 0 {
		obj["dimensions"] = s.Dimensions
	}
	return mustMarshal(obj)
}

func uuidStrings(ids []uuid.UUID) []string {
	out := make([]string, len(ids))
	for i, id := range ids {
		out[i] = id.String()
	}
	return out
}

// ParseConditionJSON parses and normalizes the structured condition JSON for
// one rule type.
func ParseConditionJSON(ruleType string, raw []byte) (Condition, ValidationErrors) {
	if len(raw) == 0 {
		return Condition{}, ValidationErrors{{Field: "condition", Code: "required", Message: "condition is required"}}
	}
	var obj map[string]json.RawMessage
	if err := json.Unmarshal(raw, &obj); err != nil {
		return Condition{}, ValidationErrors{{Field: "condition", Code: "invalid", Message: "must be a JSON object"}}
	}
	var allowed map[string]bool
	if ruleType == TypeAbsence {
		allowed = map[string]bool{
			"source": true, "window": true, "for_duration": true,
			"consecutive_failures": true, "recovery_successes": true,
			"check_interval": true, "recovery": true, "recurrence": true,
		}
	} else {
		allowed = map[string]bool{
			"agg": true, "op": true, "value": true, "window": true,
			"for_duration": true, "allow_partial": true, "recovery": true,
			"recurrence": true,
		}
	}
	var errs ValidationErrors
	for key := range obj {
		if !allowed[key] {
			errs = append(errs, ValidationError{Field: "condition." + key, Code: "unknown", Message: "unknown condition field for " + ruleType})
		}
	}
	if rawRec, ok := obj["recurrence"]; ok {
		var rec string
		_ = json.Unmarshal(rawRec, &rec)
		if strings.TrimSpace(rec) != "" {
			errs = append(errs, ValidationError{Field: "condition.recurrence", Code: "unsupported", Message: "recurrence is not implemented in v1"})
		}
	}

	c := Condition{Source: SourceSamples, Agg: AggAvg}
	if ruleType == TypeAbsence {
		if rawSource, ok := obj["source"]; ok {
			var source string
			if err := json.Unmarshal(rawSource, &source); err != nil || (source != SourceSamples && source != SourcePollHealth) {
				errs = append(errs, ValidationError{Field: "condition.source", Code: "invalid", Message: "allowed: samples, poll_health"})
			} else {
				c.Source = source
			}
		}
	} else {
		if rawAgg, ok := obj["agg"]; ok {
			var agg string
			if err := json.Unmarshal(rawAgg, &agg); err != nil || !validAgg(agg) {
				errs = append(errs, ValidationError{Field: "condition.agg", Code: "invalid", Message: "allowed: avg, max, min, sum"})
			} else {
				c.Agg = agg
			}
		}
		c.Op, errs = parseRequiredString(obj, "op", errs, "condition.op")
		if c.Op != "" && !ValidOp(c.Op) {
			errs = append(errs, ValidationError{Field: "condition.op", Code: "invalid", Message: "allowed: gt, gte, lt, lte, eq, ne"})
		}
		if value, err := parseNumber(obj, "value"); err != nil {
			errs = append(errs, ValidationError{Field: "condition.value", Code: "required", Message: "value must be a finite number"})
		} else {
			c.Value = value
		}
		if b, err := parseBool(obj, "allow_partial"); err != nil {
			errs = append(errs, ValidationError{Field: "condition.allow_partial", Code: "invalid", Message: "must be a boolean"})
		} else {
			c.AllowPartial = b
		}
	}

	c.Window, errs = parseDurationField(obj, "window", errs, "condition.window", c.Source != SourcePollHealth)
	c.ForDuration, errs = parseDurationField(obj, "for_duration", errs, "condition.for_duration", false)

	if ruleType == TypeAbsence {
		if c.Source == SourcePollHealth {
			c.ConsecutiveFailures, errs = parseIntField(obj, "consecutive_failures", 2, 1, 100, errs, "condition.consecutive_failures")
			c.RecoverySuccesses, errs = parseIntField(obj, "recovery_successes", 2, 1, 100, errs, "condition.recovery_successes")
			if rawCI, ok := obj["check_interval"]; ok {
				var ci string
				if err := json.Unmarshal(rawCI, &ci); err != nil {
					errs = append(errs, ValidationError{Field: "condition.check_interval", Code: "invalid", Message: "must be a duration string (e.g. 60s)"})
				} else if d, err := time.ParseDuration(ci); err != nil || d <= 0 || d > time.Hour {
					errs = append(errs, ValidationError{Field: "condition.check_interval", Code: "invalid", Message: "must be a positive duration up to 1h"})
				} else {
					c.CheckInterval = d
				}
			}
		}
	}

	// Recovery object (or the documented default).
	if rawRec, ok := obj["recovery"]; ok {
		rec, recErrs := parseRecovery(ruleType, c, rawRec)
		errs = append(errs, recErrs...)
		c.Recovery = rec
	} else {
		c.Recovery = defaultRecovery(ruleType, c)
	}

	// Bounds checks (only meaningful once the durations parsed).
	if c.Window != 0 && (c.Window < MinWindow || c.Window > MaxWindow) {
		errs = append(errs, ValidationError{Field: "condition.window", Code: "range", Message: fmt.Sprintf("window must be between %s and %s", MinWindow, MaxWindow)})
	}
	if c.ForDuration != 0 && (c.ForDuration < 0 || c.ForDuration > MaxForDuration) {
		errs = append(errs, ValidationError{Field: "condition.for_duration", Code: "range", Message: fmt.Sprintf("for_duration must be between 0 and %s", MaxForDuration)})
	}
	if len(errs) > 0 {
		return Condition{}, errs
	}
	return c, nil
}

func validAgg(agg string) bool {
	switch agg {
	case AggAvg, AggMax, AggMin, AggSum:
		return true
	}
	return false
}

func parseRequiredString(obj map[string]json.RawMessage, key string, errs ValidationErrors, field string) (string, ValidationErrors) {
	raw, ok := obj[key]
	if !ok {
		return "", append(errs, ValidationError{Field: field, Code: "required", Message: "is required"})
	}
	var s string
	if err := json.Unmarshal(raw, &s); err != nil {
		return "", append(errs, ValidationError{Field: field, Code: "invalid", Message: "must be a string"})
	}
	return s, errs
}

func parseNumber(obj map[string]json.RawMessage, key string) (*float64, error) {
	raw, ok := obj[key]
	if !ok {
		return nil, fmt.Errorf("missing %s", key)
	}
	var f float64
	if err := json.Unmarshal(raw, &f); err != nil || math.IsNaN(f) || math.IsInf(f, 0) {
		return nil, fmt.Errorf("invalid %s", key)
	}
	return &f, nil
}

func parseBool(obj map[string]json.RawMessage, key string) (bool, error) {
	raw, ok := obj[key]
	if !ok {
		return false, nil
	}
	var b bool
	if err := json.Unmarshal(raw, &b); err != nil {
		return false, err
	}
	return b, nil
}

func parseDurationField(obj map[string]json.RawMessage, key string, errs ValidationErrors, field string, required bool) (time.Duration, ValidationErrors) {
	raw, ok := obj[key]
	if !ok {
		if required {
			return 0, append(errs, ValidationError{Field: field, Code: "required", Message: "is required"})
		}
		return 0, errs
	}
	var s string
	if err := json.Unmarshal(raw, &s); err != nil {
		return 0, append(errs, ValidationError{Field: field, Code: "invalid", Message: "must be a Go duration string (e.g. 1m, 90s)"})
	}
	d, err := time.ParseDuration(s)
	if err != nil {
		return 0, append(errs, ValidationError{Field: field, Code: "invalid", Message: "must be a Go duration string (e.g. 1m, 90s)"})
	}
	return d, errs
}

func parseIntField(obj map[string]json.RawMessage, key string, def, minV, maxV int, errs ValidationErrors, field string) (int, ValidationErrors) {
	raw, ok := obj[key]
	if !ok {
		return def, errs
	}
	var n int
	if err := json.Unmarshal(raw, &n); err != nil || n < minV || n > maxV {
		return def, append(errs, ValidationError{Field: field, Code: "range", Message: fmt.Sprintf("must be an integer between %d and %d", minV, maxV)})
	}
	return n, errs
}

func parseRecovery(ruleType string, c Condition, raw json.RawMessage) (*Recovery, ValidationErrors) {
	var obj map[string]json.RawMessage
	if err := json.Unmarshal(raw, &obj); err != nil {
		return nil, ValidationErrors{{Field: "condition.recovery", Code: "invalid", Message: "must be a JSON object"}}
	}
	var errs ValidationErrors
	for key := range obj {
		switch key {
		case "op", "value", "for_duration", "window":
		default:
			errs = append(errs, ValidationError{Field: "condition.recovery." + key, Code: "unknown", Message: "unknown recovery field"})
		}
	}
	rec := &Recovery{}
	if ruleType == TypeAbsence {
		if _, ok := obj["op"]; ok {
			errs = append(errs, ValidationError{Field: "condition.recovery.op", Code: "unsupported", Message: "absence recovery is presence-based; op is not used"})
		}
		if _, ok := obj["value"]; ok {
			errs = append(errs, ValidationError{Field: "condition.recovery.value", Code: "unsupported", Message: "absence recovery is presence-based; value is not used"})
		}
		if rawWin, ok := obj["window"]; ok {
			var s string
			if err := json.Unmarshal(rawWin, &s); err != nil {
				errs = append(errs, ValidationError{Field: "condition.recovery.window", Code: "invalid", Message: "must be a Go duration string"})
			} else if d, err := time.ParseDuration(s); err != nil || d <= 0 || d > MaxWindow {
				errs = append(errs, ValidationError{Field: "condition.recovery.window", Code: "range", Message: "must be a positive duration up to 7d"})
			} else {
				rec.Window = d
			}
		}
	} else {
		if rawOp, ok := obj["op"]; ok {
			var op string
			if err := json.Unmarshal(rawOp, &op); err != nil || !ValidOp(op) {
				errs = append(errs, ValidationError{Field: "condition.recovery.op", Code: "invalid", Message: "allowed: gt, gte, lt, lte, eq, ne"})
			} else {
				rec.Op = op
			}
		}
		if rawValue, ok := obj["value"]; ok {
			var f float64
			if err := json.Unmarshal(rawValue, &f); err != nil || math.IsNaN(f) || math.IsInf(f, 0) {
				errs = append(errs, ValidationError{Field: "condition.recovery.value", Code: "invalid", Message: "must be a finite number"})
			} else {
				rec.Value = &f
			}
		}
		if rec.Op != "" && rec.Value == nil {
			errs = append(errs, ValidationError{Field: "condition.recovery.value", Code: "required", Message: "value is required when recovery.op is set"})
		}
		if rec.Op == "" && rec.Value != nil {
			rec.Op = InverseOp(c.Op) // explicit threshold, implied inverse op
		}
		if rec.Op == "" {
			rec.Op = InverseOp(c.Op)
		}
		if rec.Value == nil {
			rec.Value = c.Value
		}
	}
	if rawDur, ok := obj["for_duration"]; ok {
		var s string
		if err := json.Unmarshal(rawDur, &s); err != nil {
			errs = append(errs, ValidationError{Field: "condition.recovery.for_duration", Code: "invalid", Message: "must be a Go duration string"})
		} else if d, err := time.ParseDuration(s); err != nil || d < 0 || d > MaxForDuration {
			errs = append(errs, ValidationError{Field: "condition.recovery.for_duration", Code: "range", Message: "must be a duration between 0 and 7d"})
		} else {
			rec.ForDuration = d
		}
	} else {
		rec.ForDuration = DefaultRecoveryDuration(c.ForDuration, c.Window)
	}
	if len(errs) > 0 {
		return nil, errs
	}
	return rec, nil
}

func defaultRecovery(ruleType string, c Condition) *Recovery {
	rec := &Recovery{ForDuration: DefaultRecoveryDuration(c.ForDuration, c.Window)}
	if ruleType == TypeAbsence {
		rec.Window = c.Window
		return rec
	}
	rec.Op = InverseOp(c.Op)
	rec.Value = c.Value
	return rec
}

// canonicalJSON stores the normalized condition.
func (c Condition) canonicalJSON() []byte {
	obj := map[string]any{}
	if c.Source == SourcePollHealth {
		obj["source"] = c.Source
	}
	if c.Agg != "" && c.Agg != AggAvg {
		obj["agg"] = c.Agg
	}
	if c.Op != "" {
		obj["op"] = c.Op
	}
	if c.Value != nil {
		obj["value"] = *c.Value
	}
	if c.Window > 0 {
		obj["window"] = c.Window.String()
	}
	obj["for_duration"] = c.ForDuration.String()
	if c.AllowPartial {
		obj["allow_partial"] = true
	}
	if c.Source == SourcePollHealth {
		obj["consecutive_failures"] = c.ConsecutiveFailures
		obj["recovery_successes"] = c.RecoverySuccesses
		if c.CheckInterval > 0 {
			obj["check_interval"] = c.CheckInterval.String()
		}
	}
	if c.Recovery != nil {
		rec := map[string]any{}
		if c.Recovery.Op != "" {
			rec["op"] = c.Recovery.Op
		}
		if c.Recovery.Value != nil {
			rec["value"] = *c.Recovery.Value
		}
		if c.Recovery.Window > 0 {
			rec["window"] = c.Recovery.Window.String()
		}
		rec["for_duration"] = c.Recovery.ForDuration.String()
		obj["recovery"] = rec
	}
	return mustMarshal(obj)
}

func mustMarshal(v any) []byte {
	b, err := json.Marshal(v)
	if err != nil {
		return []byte("{}")
	}
	return b
}

// sortedDimensions returns the canonical (sorted-key) JSON of a dimension
// map; store and fingerprint both use it so byte identity is stable.
func sortedDimensions(dims map[string]string) []byte {
	if len(dims) == 0 {
		return []byte("{}")
	}
	keys := make([]string, 0, len(dims))
	for k := range dims {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	obj := make(map[string]string, len(dims))
	for _, k := range keys {
		obj[k] = dims[k]
	}
	return mustMarshal(obj)
}
