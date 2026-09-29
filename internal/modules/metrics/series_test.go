package metrics

import (
	"strconv"
	"strings"
	"testing"
)

func TestCanonicalizeDimensionsDeterministic(t *testing.T) {
	a, hashA, err := CanonicalizeDimensions(map[string]string{"if": "ether1", "cpu": "0"})
	if err != nil {
		t.Fatalf("canonicalize: %v", err)
	}
	b, hashB, err := CanonicalizeDimensions(map[string]string{"cpu": "0", "if": "ether1"})
	if err != nil {
		t.Fatalf("canonicalize: %v", err)
	}
	if string(a) != string(b) || hashA != hashB {
		t.Fatalf("canonicalization must be order-independent: %s/%x vs %s/%x", a, hashA, b, hashB)
	}
	if string(a) != `{"cpu":"0","if":"ether1"}` {
		t.Fatalf("canonical JSON = %s (keys must be sorted)", a)
	}
	if hashA == 0 {
		t.Fatal("hash must not be zero for non-empty dims")
	}
	empty, hashEmpty, err := CanonicalizeDimensions(nil)
	if err != nil || string(empty) != "{}" {
		t.Fatalf("empty dims = %s, %v", empty, err)
	}
	if hashEmpty == hashA {
		t.Fatal("different dims must hash differently")
	}
}

func TestCanonicalizeDimensionsLimits(t *testing.T) {
	nine := map[string]string{}
	for i := 0; i < 9; i++ {
		nine[string(rune('a'+i))] = "v"
	}
	if _, _, err := CanonicalizeDimensions(nine); err == nil || !strings.Contains(err.Error(), "too many dimensions") {
		t.Fatalf("9 dims: %v", err)
	}
	long := map[string]string{"k": strings.Repeat("x", MaxDimensionLen+1)}
	if _, _, err := CanonicalizeDimensions(long); err == nil || !strings.Contains(err.Error(), "too long") {
		t.Fatalf("long value: %v", err)
	}
	longKey := map[string]string{strings.Repeat("k", MaxDimensionLen+1): "v"}
	if _, _, err := CanonicalizeDimensions(longKey); err == nil || !strings.Contains(err.Error(), "too long") {
		t.Fatalf("long key: %v", err)
	}
	if _, _, err := CanonicalizeDimensions(map[string]string{"": "v"}); err == nil {
		t.Fatal("empty key must be rejected")
	}
	if _, _, err := CanonicalizeDimensions(map[string]string{"k": string([]byte{0xff, 0xfe})}); err == nil {
		t.Fatal("invalid UTF-8 value must be rejected")
	}
}

func TestSeriesSpecKeyStable(t *testing.T) {
	sp := SeriesSpec{MetricKey: "collector_cpu_percent", DimHash: -1234567890}
	if sp.Key() != "collector_cpu_percent|"+strconv.FormatInt(-1234567890, 16) {
		t.Fatalf("series key = %q", sp.Key())
	}
}
