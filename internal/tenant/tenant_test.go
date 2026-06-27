package tenant

import (
	"context"
	"testing"
)

func TestFrom_DefaultWhenUnset(t *testing.T) {
	if got := From(context.Background()); got != Default {
		t.Fatalf("From(empty) = %q, want %q", got, Default)
	}
}

func TestWithAndFrom(t *testing.T) {
	ctx := With(context.Background(), "acme")
	if got := From(ctx); got != "acme" {
		t.Fatalf("From = %q, want acme", got)
	}
}

func TestFrom_EmptyStringFallsBackToDefault(t *testing.T) {
	ctx := With(context.Background(), "")
	if got := From(ctx); got != Default {
		t.Fatalf("empty tenant should fall back to default, got %q", got)
	}
}
