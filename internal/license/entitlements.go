package license

import (
	"fmt"
	"strings"
)

// RequiresObserve reports whether this license's Tier permits enforcement at
// all. "trial" and "pilot" are pre-commercial, evaluation-only tiers — a
// deployment on one of those is, by definition, still evaluating, so the
// gateway is forced into Observe mode (cmd/gateway wires this the same way
// as an explicit `observe: true` opt-in and an invalid-hardware grace
// period: coerce, don't crash). Only "production" — or an unset/internal
// tier, for your own use — may enforce.
//
// This is intentionally the SAME hard-line posture as the rest of this
// package: a "trial" tier that could still fully enforce would make the
// tier field decorative rather than a real commercial boundary.
func (c Claims) RequiresObserve() bool {
	switch c.Tier {
	case "trial", "pilot":
		return true
	default:
		return false
	}
}

// HasFeature reports whether name is entitled by this license. An EMPTY
// Features list means "no additional restriction beyond Tier" (see Claims'
// doc comment) — every existing license issued before feature-gating existed
// stays fully permissive; only a license that explicitly lists a non-empty
// Features set narrows access to just those entries. Matching is exact and
// case-sensitive, mirroring `cmd/licensegen -features`.
func (c Claims) HasFeature(name string) bool {
	if len(c.Features) == 0 {
		return true
	}
	for _, f := range c.Features {
		if f == name {
			return true
		}
	}
	return false
}

// gatedFeature names a config surface that's off by default and, when an
// operator turns it on, must be entitled by the license's Features.
type gatedFeature struct {
	name    string
	enabled bool
}

// CheckFeatureGates rejects a config that enables a paid feature the license
// doesn't include — the same hard-gate treatment as any other license
// problem in this package (see cmd/gateway/main.go's loadValidatedConfig):
// the gateway does not boot with a feature silently disabled behind the
// operator's back, it refuses to start with an explicit reason, exactly like
// an unsafe config.Validate rejection. This is what turns Claims.Features
// from data the license carries into something actually enforced.
//
// Callers pass plain bools (not config.GatewayConfig) so this leaf package
// stays dependency-free of internal/config, matching internal/tenant's
// "leaf package" convention described in CLAUDE.md.
func CheckFeatureGates(claims Claims, multitenancyEnabled, ssoEnabled bool) error {
	gates := []gatedFeature{
		{name: "multitenancy", enabled: multitenancyEnabled},
		{name: "sso", enabled: ssoEnabled},
	}
	var missing []string
	for _, g := range gates {
		if g.enabled && !claims.HasFeature(g.name) {
			missing = append(missing, g.name)
		}
	}
	if len(missing) == 0 {
		return nil
	}
	return fmt.Errorf("config enables %s, which this license does not include (licensed features: %v) — "+
		"disable it in config or request a license that includes it",
		strings.Join(missing, ", "), claims.Features)
}
