package database

import (
	"context"
	"errors"
	"testing"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

func TestWithTenantRequiresOrg(t *testing.T) {
	called := false
	err := WithTenant(context.Background(), nil, uuid.Nil, func(context.Context, pgx.Tx) error {
		called = true
		return nil
	})
	if !errors.Is(err, ErrNoTenant) {
		t.Fatalf("want ErrNoTenant, got %v", err)
	}
	if called {
		t.Fatal("callback must not run without a tenant")
	}
}

func TestWithTenantNilPool(t *testing.T) {
	err := WithTenant(context.Background(), nil, uuid.New(), func(context.Context, pgx.Tx) error {
		return nil
	})
	if err == nil || errors.Is(err, ErrNoTenant) {
		t.Fatalf("want nil-pool error, got %v", err)
	}
}

func TestWithAuthTxNilPool(t *testing.T) {
	err := WithAuthTx(context.Background(), nil, func(context.Context, pgx.Tx) error {
		return nil
	})
	if err == nil {
		t.Fatal("want error for nil auth pool")
	}
}

func TestNewPoolRejectsEmptyDSN(t *testing.T) {
	if _, err := NewPool(context.Background(), "", "test", DefaultPoolConfig()); err == nil {
		t.Fatal("want error for empty DSN")
	}
}

func TestNewPoolRejectsBadDSN(t *testing.T) {
	if _, err := NewPool(context.Background(), "not-a-dsn", "test", DefaultPoolConfig()); err == nil {
		t.Fatal("want error for malformed DSN")
	}
}
