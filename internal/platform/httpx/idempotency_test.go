package httpx

import (
	"testing"
	"time"
)

func TestIdempotencyCacheRoundTrip(t *testing.T) {
	c := NewIdempotencyCache(time.Hour, 2)

	if _, _, ok := c.Get("k1"); ok {
		t.Fatal("empty cache must miss")
	}
	c.Put("k1", 201, []byte(`{"token":"a"}`))
	status, body, ok := c.Get("k1")
	if !ok || status != 201 || string(body) != `{"token":"a"}` {
		t.Fatalf("round trip = (%d,%s,%v)", status, body, ok)
	}

	// The stored body is copied on read and write (no aliasing).
	body[0] = 'X'
	if _, again, _ := c.Get("k1"); string(again) != `{"token":"a"}` {
		t.Fatal("returned body must not alias cached storage")
	}
}

func TestIdempotencyCacheEviction(t *testing.T) {
	c := NewIdempotencyCache(time.Hour, 2)
	c.Put("a", 201, []byte("1"))
	c.Put("b", 201, []byte("2"))
	c.Put("c", 201, []byte("3")) // evicts "a"

	if _, _, ok := c.Get("a"); ok {
		t.Fatal("oldest entry must be evicted")
	}
	if _, body, ok := c.Get("c"); !ok || string(body) != "3" {
		t.Fatal("newest entry must be present")
	}
}

func TestIdempotencyCacheExpiry(t *testing.T) {
	c := NewIdempotencyCache(time.Millisecond, 8)
	c.Put("k", 201, []byte("v"))
	time.Sleep(5 * time.Millisecond)
	if _, _, ok := c.Get("k"); ok {
		t.Fatal("expired entry must miss")
	}
}

func TestIdempotencyCacheNilSafe(t *testing.T) {
	var c *IdempotencyCache
	if _, _, ok := c.Get("k"); ok {
		t.Fatal("nil cache must miss")
	}
	c.Put("k", 201, []byte("v")) // must not panic
}
