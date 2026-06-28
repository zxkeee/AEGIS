package discovery

import (
	"context"

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
func (c *Catalog) specFor(ctx context.Context) *Spec {
	tnt := tenant.From(ctx)

	raw, meta, found, err := c.pg.getSpec(ctx, tnt)
	if err != nil {
		c.log.Error("discovery: spec load failed", map[string]any{"error": err.Error(), "tenant": tnt})
		return c.configSpec()
	}
	if !found {
		return c.configSpec()
	}

	// Cache hit when the stored spec has not been replaced since we parsed it.
	c.specMu.RLock()
	ce, ok := c.specCache[tnt]
	c.specMu.RUnlock()
	if ok && ce.uploadedAt.Equal(meta.UploadedAt) {
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
	c.specCache[tnt] = specCacheEntry{uploadedAt: meta.UploadedAt, spec: spec}
	c.specMu.Unlock()
	return spec
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
