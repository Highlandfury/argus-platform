package api

import "testing"

func TestLoginLimiterBurstAndDeny(t *testing.T) {
	l := newLoginLimiter()
	for i := 1; i <= 10; i++ {
		if ok, _ := l.allow("203.0.113.10"); !ok {
			t.Fatalf("attempt %d unexpectedly denied within burst", i)
		}
	}
	ok, retry := l.allow("203.0.113.10")
	if ok {
		t.Fatal("11th rapid attempt must be denied")
	}
	if retry <= 0 {
		t.Fatalf("denied attempt must carry a retry hint, got %v", retry)
	}
	if ok, _ := l.allow("203.0.113.99"); !ok {
		t.Fatal("another key must be unaffected by the first key's exhaustion")
	}
}
