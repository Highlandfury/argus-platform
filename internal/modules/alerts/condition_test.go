package alerts

import (
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
)

func TestRuleCadenceCanonical(t *testing.T) {
	cases := []struct {
		name   string
		rule   Rule
		expect time.Duration
	}{
		{"window 1m -> 30s floor", Rule{Type: TypeThreshold, Condition: Condition{Window: time.Minute}}, 30 * time.Second},
		{"window 2m -> 60s", Rule{Type: TypeThreshold, Condition: Condition{Window: 2 * time.Minute}}, time.Minute},
		{"window 4m -> 2m", Rule{Type: TypeThreshold, Condition: Condition{Window: 4 * time.Minute}}, 2 * time.Minute},
		{"window 20m -> 5m cap", Rule{Type: TypeThreshold, Condition: Condition{Window: 20 * time.Minute}}, 5 * time.Minute},
		{"absence 60s check -> 120s", Rule{Type: TypeAbsence, Condition: Condition{CheckInterval: time.Minute}}, 2 * time.Minute},
		{"absence 10s check -> 30s floor", Rule{Type: TypeAbsence, Condition: Condition{CheckInterval: 10 * time.Second}}, 30 * time.Second},
		{"absence 10m check -> 5m cap", Rule{Type: TypeAbsence, Condition: Condition{CheckInterval: 10 * time.Minute}}, 5 * time.Minute},
		{"absence default check -> 120s", Rule{Type: TypeAbsence, Condition: Condition{}}, 2 * time.Minute},
	}
	for _, tc := range cases {
		if got := RuleCadence(tc.rule); got != tc.expect {
			t.Errorf("%s: cadence = %s, want %s", tc.name, got, tc.expect)
		}
	}
}

func TestGridPointsBoundaryAndCap(t *testing.T) {
	from := time.Date(2026, 10, 1, 12, 0, 0, 0, time.UTC)
	to := from.Add(3 * time.Minute)
	pts := GridPoints(from, to, 30*time.Second, 240)
	if len(pts) != 7 {
		t.Fatalf("3m at 30s grid = %d points, want 7", len(pts))
	}
	if !pts[len(pts)-1].Equal(to) {
		t.Fatalf("last grid point = %s, want %s", pts[len(pts)-1], to)
	}
	if !pts[0].Equal(from) {
		t.Fatalf("first grid point = %s, want %s", pts[0], from)
	}

	// Widening: a span needing more points than the cap keeps the endpoints
	// and never exceeds the cap.
	wide := GridPoints(from, from.Add(24*time.Hour), 30*time.Second, 10)
	if len(wide) > 10 {
		t.Fatalf("capped grid has %d points, want <= 10", len(wide))
	}
	if !wide[len(wide)-1].Equal(from.Add(24 * time.Hour)) {
		t.Fatalf("capped grid last point = %s", wide[len(wide)-1])
	}

	// Zero span: exactly the instant.
	if pts := GridPoints(to, to, time.Minute, 240); len(pts) != 1 || !pts[0].Equal(to) {
		t.Fatalf("zero span grid = %v", pts)
	}
}

func TestContinuousNoTwoLuckySamples(t *testing.T) {
	from := time.Date(2026, 10, 1, 12, 0, 0, 0, time.UTC)
	to := from.Add(time.Minute)
	// true, true, false, true: the dip must break continuity even though the
	// first and last evaluations are true.
	dips := map[int]bool{2: false}
	ok, err := Continuous(from, to, 30*time.Second, MaxGridPoints, func(t time.Time) (bool, error) {
		i := int(t.Sub(from) / (30 * time.Second))
		_, dip := dips[i]
		return !dip, nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if ok {
		t.Fatal("a mid-span false evaluation must break continuity")
	}

	ok, err = Continuous(from, to, 30*time.Second, MaxGridPoints, func(time.Time) (bool, error) { return true, nil })
	if err != nil || !ok {
		t.Fatalf("all-true continuity = %v err=%v", ok, err)
	}

	sentinel := errors.New("probe failed")
	_, err = Continuous(from, to, 30*time.Second, MaxGridPoints, func(time.Time) (bool, error) { return true, sentinel })
	if !errors.Is(err, sentinel) {
		t.Fatalf("error must propagate, got %v", err)
	}
}

func TestApplyOpAndInverse(t *testing.T) {
	cases := []struct {
		op   string
		v    float64
		want bool
	}{
		{OpGT, 5.1, true}, {OpGT, 5.0, false}, {OpGTE, 5.0, true},
		{OpLT, 4.9, true}, {OpLTE, 2.0, true}, {OpEQ, 2.0, true}, {OpNE, 2.0, false},
	}
	for _, tc := range cases {
		if got := ApplyOp(tc.op, tc.v, 5.0); tc.op == OpGT || tc.op == OpGTE {
			if got != tc.want {
				t.Errorf("ApplyOp(%s, %v, 5) = %v want %v", tc.op, tc.v, got, tc.want)
			}
		}
	}
	if !ApplyOp(OpLT, 4.9, 5.0) || !ApplyOp(OpLTE, 5, 5) || !ApplyOp(OpEQ, 5, 5) || ApplyOp(OpNE, 5, 5) {
		t.Fatal("operator matrix failed")
	}
	if !ApplyOp(OpGT, 1, 0) {
		t.Fatal("gt sanity")
	}
	pairs := map[string]string{OpGT: OpLTE, OpGTE: OpLT, OpLT: OpGTE, OpLTE: OpGT, OpEQ: OpNE, OpNE: OpEQ}
	for op, want := range pairs {
		if got := InverseOp(op); got != want {
			t.Errorf("InverseOp(%s) = %s, want %s", op, got, want)
		}
	}
}

func TestDefaultRecoveryDuration(t *testing.T) {
	if got := DefaultRecoveryDuration(0, time.Minute); got != 0 {
		t.Fatalf("zero base -> %s, want 0", got)
	}
	if got := DefaultRecoveryDuration(3*time.Minute, time.Minute); got != 6*time.Minute {
		t.Fatalf("3m base with 1m window -> %s, want 6m (longer than the trigger)", got)
	}
	if got := DefaultRecoveryDuration(time.Minute, 24*time.Hour); got != 24*time.Hour {
		t.Fatalf("window larger than 2x base -> %s, want the window", got)
	}
}

func TestParseRuleThresholdValid(t *testing.T) {
	cond := []byte(`{"agg":"avg","op":"gt","value":5,"window":"1m","for_duration":"3m"}`)
	sel := []byte(`{"sites":["` + uuid.New().String() + `"],"metric_key":"net.icmp.loss_pct","dimensions":{"circuit":"wan-1"}}`)
	parsed, errs := ParseRule(" WAN loss ", TypeThreshold, SeverityCritical, cond, sel)
	if len(errs) > 0 {
		t.Fatalf("unexpected validation errors: %v", errs)
	}
	if parsed.Name != "WAN loss" || parsed.Condition.Op != OpGT || parsed.Condition.Value == nil || *parsed.Condition.Value != 5 {
		t.Fatalf("parsed = %+v", parsed)
	}
	if parsed.Condition.Recovery == nil || parsed.Condition.Recovery.Op != OpLTE {
		t.Fatalf("default recovery = %+v", parsed.Condition.Recovery)
	}
	if parsed.Condition.Recovery.ForDuration != 6*time.Minute {
		t.Fatalf("default recovery for_duration = %s, want 6m", parsed.Condition.Recovery.ForDuration)
	}
	if parsed.Selector.MetricKey != "net.icmp.loss_pct" || len(parsed.Selector.Sites) != 1 {
		t.Fatalf("parsed selector = %+v", parsed.Selector)
	}
	if len(parsed.ConditionJSON) == 0 || len(parsed.SelectorJSON) == 0 {
		t.Fatal("canonical JSON not stored")
	}
}

func TestParseRuleRejectsBadShapes(t *testing.T) {
	base := func(cond string) (ParsedRule, ValidationErrors) {
		return ParseRule("r", TypeThreshold, SeverityWarning, []byte(cond),
			[]byte(`{"metric_key":"m"}`))
	}
	cases := []struct {
		name    string
		cond    string
		wantSub string
	}{
		{"missing op", `{"value":1,"window":"1m"}`, "condition.op"},
		{"bad op", `{"op":"around","value":1,"window":"1m"}`, "condition.op"},
		{"missing value", `{"op":"gt","window":"1m"}`, "condition.value"},
		{"unknown key", `{"op":"gt","value":1,"window":"1m","nope":true}`, "condition.nope"},
		{"bad window", `{"op":"gt","value":1,"window":"banana"}`, "condition.window"},
		{"tiny window", `{"op":"gt","value":1,"window":"1s"}`, "condition.window"},
		{"recurrence", `{"op":"gt","value":1,"window":"1m","recurrence":"FREQ=DAILY"}`, "condition.recurrence"},
		{"bad recovery", `{"op":"gt","value":1,"window":"1m","recovery":{"op":"lte"}}`, "condition.recovery.value"},
	}
	for _, tc := range cases {
		_, errs := base(tc.cond)
		if len(errs) == 0 {
			t.Errorf("%s: expected validation error", tc.name)
			continue
		}
		found := false
		for _, e := range errs {
			if strings.Contains(e.Field, tc.wantSub) {
				found = true
			}
		}
		if !found {
			t.Errorf("%s: errors %v do not mention %s", tc.name, errs, tc.wantSub)
		}
	}

	// Metric key required for series rules.
	_, errs := ParseRule("r", TypeThreshold, SeverityInfo,
		[]byte(`{"op":"gt","value":1,"window":"1m"}`), []byte(`{}`))
	if len(errs) == 0 || errs[0].Field != "scope_selector.metric_key" {
		t.Fatalf("missing metric_key must fail: %v", errs)
	}
	// Unknown selector key.
	_, errs = ParseRule("r", TypeThreshold, SeverityInfo,
		[]byte(`{"op":"gt","value":1,"window":"1m"}`), []byte(`{"metric_key":"m","banana":1}`))
	if len(errs) == 0 {
		t.Fatal("unknown selector key must fail")
	}
}

func TestParseAbsencePollHealthDefaults(t *testing.T) {
	parsed, errs := ParseRule("device down", TypeAbsence, SeverityCritical,
		[]byte(`{"source":"poll_health"}`), []byte(`{}`))
	if len(errs) > 0 {
		t.Fatalf("unexpected errors: %v", errs)
	}
	c := parsed.Condition
	if c.Source != SourcePollHealth || c.ConsecutiveFailures != 2 || c.RecoverySuccesses != 2 {
		t.Fatalf("poll-health defaults = %+v", c)
	}
	if c.Window != 0 || c.Recovery == nil {
		t.Fatalf("window/recovery = %+v", c)
	}

	// Samples absence requires a window (and, separately, a metric key; the
	// parser fails fast on the window first).
	_, errs = ParseRule("silence", TypeAbsence, SeverityWarning, []byte(`{}`), []byte(`{}`))
	if len(errs) == 0 || errs[0].Field != "condition.window" {
		t.Fatalf("samples absence without window = %v", errs)
	}
	parsed, errs = ParseRule("silence", TypeAbsence, SeverityWarning,
		[]byte(`{"window":"5m","for_duration":"30s"}`), []byte(`{"metric_key":"net.icmp.rtt_ms"}`))
	if len(errs) > 0 {
		t.Fatalf("samples absence errors: %v", errs)
	}
	if parsed.Condition.Recovery == nil || parsed.Condition.Recovery.Window != 5*time.Minute {
		t.Fatalf("samples absence default recovery = %+v", parsed.Condition.Recovery)
	}
}

func TestSelectorCanonicalJSONStable(t *testing.T) {
	id := uuid.MustParse("01890000-0000-7000-8000-000000000001")
	s1 := ScopeSelector{MetricKey: "m", Sites: []uuid.UUID{id}, Dimensions: map[string]string{"b": "2", "a": "1"}}
	s2 := ScopeSelector{MetricKey: "m", Sites: []uuid.UUID{id}, Dimensions: map[string]string{"a": "1", "b": "2"}}
	if string(s1.canonicalJSON()) != string(s2.canonicalJSON()) {
		t.Fatalf("selector canonical JSON is not key-order stable:\n%s\n%s", s1.canonicalJSON(), s2.canonicalJSON())
	}
}
