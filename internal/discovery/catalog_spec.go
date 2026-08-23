package discovery

import (
	"context"
	"time"

	"api-gateway/internal/tenant"
)

// SetConfigSpec installs the fallback spec parsed from gateway config
// (discovery.spec_path). It is applied to any tenant without an uploaded spec
// and is swapped on config hot-reload. A nil spec disables the config fallback.
func (c *Catalog) SetConfigSpec(s *Spec) {
	c.specMu.Lock()
	c.cfgSpec = s
	c.specMu.Unlock()
}

// specFor resolves the effective spec for the request's tenant: a per-tenant
// uploaded spec (cached, invalidated by uploaded_at) takes precedence over the
// config fallback. Returns nil when neither is present (drift is then a no-op).
// Always does a real Postgres read (via pg.getSpec) — safe for on-demand
// callers like Drift() where a synchronous DB round trip is acceptable, but
// NOT for the hot request path; see SpecForEnforcement for that.
func (c *Catalog) specFor(ctx context.Context) *Spec {
	tnt := tenant.From(ctx)
	now := time.Now()

	raw, meta, found, err := c.pg.getSpec(ctx, tnt)
	if err != nil {
		c.log.Error("discovery: spec load failed", map[string]any{"error": err.Error(), "tenant": tnt})
		return c.configSpec()
	}
	if !found {
		// Cache the negative result too (with a checkedAt stamp), so
		// SpecForEnforcement's TTL check can skip Postgres for the common
		// case of a tenant relying purely on the config fallback.
		c.specMu.Lock()
		c.specCache[tnt] = specCacheEntry{checkedAt: now}
		c.specMu.Unlock()
		return c.configSpec()
	}

	// Cache hit when the stored spec has not been replaced since we parsed it.
	c.specMu.RLock()
	ce, ok := c.specCache[tnt]
	c.specMu.RUnlock()
	if ok && ce.spec != nil && ce.uploadedAt.Equal(meta.UploadedAt) {
		ce.checkedAt = now
		c.specMu.Lock()
		c.specCache[tnt] = ce
		c.specMu.Unlock()
		return ce.spec
	}

	spec, err := ParseSpec([]byte(raw))
	if err != nil {
		// A stored-but-unparseable spec should not happen (we validate on
		// upload) but never crash the read path over it.
		c.log.Error("discovery: stored spec unparseable", map[string]any{"error": err.Error(), "tenant": tnt})
		return c.configSpec()
	}
	c.specMu.Lock()
	c.specCache[tnt] = specCacheEntry{uploadedAt: meta.UploadedAt, spec: spec, checkedAt: now}
	c.specMu.Unlock()
	return spec
}

// specEnforcementCacheTTL bounds how often SpecForEnforcement re-checks
// Postgres for a given tenant. Without it, wiring per-tenant spec
// enforcement into the request hot path would add a synchronous Postgres
// round trip to EVERY request when schema enforcement is enabled — this
// caps that to at most one check per tenant per TTL.
const specEnforcementCacheTTL = 30 * time.Second

// SpecForEnforcement resolves the effective spec for hot-path request
// validation (middleware.SchemaValidation) — same precedence as specFor
// (per-tenant upload over config fallback), but served from the cache
// without a Postgres round trip when the cache entry is still within
// specEnforcementCacheTTL. A newly uploaded/deleted spec (SetSpec/DeleteSpec)
// still invalidates the cache immediately, so this only bounds the staleness
// window for a tenant nobody has just touched, not a permanent lag.
//
// (Audit finding, 2026-08-22: schema enforcement previously used ONLY the
// single config-level spec — internal/gateway/chain.go's enforcementSpec —
// for every tenant, unconditionally. A tenant's own uploaded spec (PUT
// /api/discovery/spec, correctly tenant-scoped in Postgres) was fed to the
// drift report but never to enforcement itself: an operator who uploaded a
// contract reasonably believed it was now blocking non-conforming requests;
// it was not, for any tenant, ever. This resolves the spec the same way
// specFor/Drift() do, so upload now actually enforces.)
func (c *Catalog) SpecForEnforcement(ctx context.Context) *Spec {
	tnt := tenant.From(ctx)

	c.specMu.RLock()
	ce, ok := c.specCache[tnt]
	c.specMu.RUnlock()
	if ok && time.Since(ce.checkedAt) < specEnforcementCacheTTL {
		if ce.spec != nil {
			return ce.spec
		}
		return c.configSpec()
	}
	return c.specFor(ctx)
}

func (c *Catalog) configSpec() *Spec {
	c.specMu.RLock()
	defer c.specMu.RUnlock()
	return c.cfgSpec
}

// SetSpec validates and stores an uploaded OpenAPI/Swagger document for the
// request's tenant, replacing any previous one, and returns its metadata. The
// raw document is rejected if it does not parse, so a bad upload never becomes
// the stored spec.
func (c *Catalog) SetSpec(ctx context.Context, raw []byte) (SpecInfo, error) {
	spec, err := ParseSpec(raw)
	if err != nil {
		return SpecInfo{}, err
	}
	tnt := tenant.From(ctx)
	if err := c.pg.upsertSpec(ctx, tnt, spec.Version, string(raw), spec.OpCount()); err != nil {
		return SpecInfo{}, err
	}
	// Invalidate the cache so the next read re-parses the new document.
	c.specMu.Lock()
	delete(c.specCache, tnt)
	c.specMu.Unlock()
	return SpecInfo{Version: spec.Version, OpCount: spec.OpCount()}, nil
}

// SpecMeta returns the stored spec metadata for the request's tenant. found is
// false when the tenant has no uploaded spec (the config fallback, if any, is
// not reported here — this describes only the uploaded document).
func (c *Catalog) SpecMeta(ctx context.Context) (SpecInfo, bool, error) {
	_, meta, found, err := c.pg.getSpec(ctx, tenant.From(ctx))
	return meta, found, err
}

// DeleteSpec removes the request tenant's uploaded spec. ok is false when there
// was none. The config fallback (if any) applies again afterwards.
func (c *Catalog) DeleteSpec(ctx context.Context) (bool, error) {
	tnt := tenant.From(ctx)
	ok, err := c.pg.deleteSpec(ctx, tnt)
	if err == nil {
		c.specMu.Lock()
		delete(c.specCache, tnt)
		c.specMu.Unlock()
	}
	return ok, err
}

// Drift computes the documented-vs-observed drift report for the request's
// tenant using the effective spec and the full observed endpoint surface.
func (c *Catalog) Drift(ctx context.Context) (DriftReport, error) {
	spec := c.specFor(ctx)
	eps, err := c.pg.listEndpointKeys(ctx, tenant.From(ctx))
	if err != nil {
		return DriftReport{}, err
	}
	return ComputeDrift(spec, eps), nil
}
