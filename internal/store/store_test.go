package store_test

import (
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/terragohan/mcptunnels/internal/store"
	"github.com/terragohan/mcptunnels/internal/store/storetest"
)

func TestServicesAndAgentKeys(t *testing.T) {
	st := storetest.Open(t)
	if err := st.CreateTenant("q-acme", ""); err != nil {
		t.Fatal(err)
	}

	if _, err := st.CreateService("nope", &store.Service{Name: "mcp"}); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("CreateService on missing tenant: %v, want ErrNotFound", err)
	}

	key, err := st.CreateService("q-acme", &store.Service{Name: "mcp"})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(key, "tun_agent_") {
		t.Fatalf("agent key %q lacks tun_agent_ prefix", key)
	}
	if _, err := st.CreateService("q-acme", &store.Service{Name: "mcp"}); !errors.Is(err, store.ErrExists) {
		t.Fatalf("duplicate service: %v, want ErrExists", err)
	}

	svc, err := st.ValidateAgentKey("q-acme", "mcp", key)
	if err != nil {
		t.Fatal(err)
	}
	if svc.Name != "mcp" {
		t.Fatalf("ValidateAgentKey returned %+v", svc)
	}
	if _, err := st.ValidateAgentKey("q-acme", "mcp", "tun_agent_wrong"); !errors.Is(err, store.ErrInvalidAgentKey) {
		t.Fatalf("wrong key: %v, want ErrInvalidAgentKey", err)
	}
	if _, err := st.ValidateAgentKey("q-acme", "other", key); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("unknown service: %v, want ErrNotFound", err)
	}

	// Deleting the tenant cascades to its services.
	if ok, err := st.DeleteTenant("q-acme"); !ok || err != nil {
		t.Fatalf("DeleteTenant = (%v, %v)", ok, err)
	}
	if _, err := st.GetService("q-acme", "mcp"); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("service of deleted tenant: %v, want ErrNotFound", err)
	}
}

// TestTenantExpiry exercises the ephemeral-tenant (quick tunnel) lifecycle:
// expires_at round trip plus DeleteExpiredTenants.
func TestTenantExpiry(t *testing.T) {
	st := storetest.Open(t)
	exp := time.Now().Add(time.Hour).Truncate(time.Second)
	if err := st.CreateTenantExpiry("q-temp", "quick tunnel", &exp); err != nil {
		t.Fatal(err)
	}
	if err := st.CreateTenant("q-keep", ""); err != nil {
		t.Fatal(err)
	}

	// Round trip via GetTenant.
	tn, err := st.GetTenant("q-temp")
	if err != nil {
		t.Fatal(err)
	}
	if tn.ExpiresAt == nil || !tn.ExpiresAt.Equal(exp) {
		t.Fatalf("expires_at = %v, want %v", tn.ExpiresAt, exp)
	}
	tn, err = st.GetTenant("q-keep")
	if err != nil {
		t.Fatal(err)
	}
	if tn.ExpiresAt != nil {
		t.Fatalf("non-expiring tenant expires_at = %v, want nil", tn.ExpiresAt)
	}

	// Not yet expired: nothing deleted.
	slugs, err := st.DeleteExpiredTenants(time.Now())
	if err != nil || len(slugs) != 0 {
		t.Fatalf("premature sweep: slugs=%v err=%v, want none", slugs, err)
	}

	// Give the ephemeral tenant a service; deletion must cascade.
	if _, err := st.CreateService("q-temp", &store.Service{Name: "mcp"}); err != nil {
		t.Fatal(err)
	}
	slugs, err = st.DeleteExpiredTenants(exp.Add(time.Minute))
	if err != nil {
		t.Fatal(err)
	}
	if len(slugs) != 1 || slugs[0] != "q-temp" {
		t.Fatalf("sweep slugs = %v, want [q-temp]", slugs)
	}
	if _, err := st.GetTenant("q-temp"); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("tenant after sweep: %v, want ErrNotFound", err)
	}
	if _, err := st.GetService("q-temp", "mcp"); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("service after sweep: %v, want ErrNotFound (cascade)", err)
	}
	// The tenant without expiry survives.
	if _, err := st.GetTenant("q-keep"); err != nil {
		t.Fatalf("non-expiring tenant swept: %v", err)
	}
}

// TestCountLiveTenants verifies only non-expired ephemeral tenants count.
func TestCountLiveTenants(t *testing.T) {
	st := storetest.Open(t)
	now := time.Now()
	future := now.Add(time.Hour)
	past := now.Add(-time.Hour)

	if n, err := st.CountLiveTenants(now); err != nil || n != 0 {
		t.Fatalf("empty store: (%d, %v), want (0, nil)", n, err)
	}
	if err := st.CreateTenantExpiry("q-live", "", &future); err != nil {
		t.Fatal(err)
	}
	if err := st.CreateTenantExpiry("q-dead", "", &past); err != nil {
		t.Fatal(err)
	}
	if err := st.CreateTenant("q-keep", ""); err != nil {
		t.Fatal(err)
	}
	n, err := st.CountLiveTenants(now)
	if err != nil || n != 1 {
		t.Fatalf("CountLiveTenants = (%d, %v), want (1, nil)", n, err)
	}
}

// TestQuickRateHit exercises the persisted quick-tunnel rate-limit counter:
// hits accumulate within the hour window, windows are per-IP, and windows
// older than two hours are pruned.
func TestQuickRateHit(t *testing.T) {
	st := storetest.Open(t)
	now := time.Now()

	for want := 1; want <= 3; want++ {
		got, err := st.QuickRateHit("203.0.113.1", now)
		if err != nil || got != want {
			t.Fatalf("hit #%d = (%d, %v), want (%d, nil)", want, got, err, want)
		}
	}
	// A different IP has its own window.
	if got, err := st.QuickRateHit("203.0.113.2", now); err != nil || got != 1 {
		t.Fatalf("other ip: (%d, %v), want (1, nil)", got, err)
	}
	// The next hour window starts a fresh count.
	if got, err := st.QuickRateHit("203.0.113.1", now.Add(time.Hour)); err != nil || got != 1 {
		t.Fatalf("next window: (%d, %v), want (1, nil)", got, err)
	}
	// A hit far in the future prunes windows older than two hours; the old
	// count is gone and does not carry over.
	if got, err := st.QuickRateHit("203.0.113.1", now.Add(5*time.Hour)); err != nil || got != 1 {
		t.Fatalf("after prune: (%d, %v), want (1, nil)", got, err)
	}
}
