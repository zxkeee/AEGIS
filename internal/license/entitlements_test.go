package license

import "testing"

func TestRequiresObserve_TrialAndPilotForceObserve(t *testing.T) {
	for _, tier := range []string{"trial", "pilot"} {
		c := Claims{Tier: tier}
		if !c.RequiresObserve() {
			t.Errorf("tier %q must RequiresObserve, got false", tier)
		}
	}
}

func TestRequiresObserve_ProductionAndUnsetDoNot(t *testing.T) {
	for _, tier := range []string{"production", "internal", ""} {
		c := Claims{Tier: tier}
		if c.RequiresObserve() {
			t.Errorf("tier %q must NOT RequiresObserve, got true", tier)
		}
	}
}

func TestHasFeature_EmptyListIsUnrestricted(t *testing.T) {
	c := Claims{} // no Features set at all — every pre-existing license
	if !c.HasFeature("multitenancy") || !c.HasFeature("sso") || !c.HasFeature("anything") {
		t.Fatal("an empty Features list must not restrict any feature")
	}
}

func TestHasFeature_NonEmptyListRestricts(t *testing.T) {
	c := Claims{Features: []string{"sso"}}
	if !c.HasFeature("sso") {
		t.Error("sso should be entitled")
	}
	if c.HasFeature("multitenancy") {
		t.Error("multitenancy should NOT be entitled (not in the list)")
	}
}

func TestCheckFeatureGates_UnrestrictedLicensePassesEverything(t *testing.T) {
	c := Claims{} // empty Features
	if err := CheckFeatureGates(c, true, true); err != nil {
		t.Fatalf("unrestricted license should pass all gates, got: %v", err)
	}
}

func TestCheckFeatureGates_MissingFeatureRejected(t *testing.T) {
	c := Claims{Features: []string{"sso"}}   // no "multitenancy"
	err := CheckFeatureGates(c, true, false) // multitenancy enabled, sso not
	if err == nil {
		t.Fatal("expected an error: multitenancy enabled but not entitled")
	}
}

func TestCheckFeatureGates_EntitledFeaturePasses(t *testing.T) {
	c := Claims{Features: []string{"multitenancy", "sso"}}
	if err := CheckFeatureGates(c, true, true); err != nil {
		t.Fatalf("both features entitled, expected no error: %v", err)
	}
}

func TestCheckFeatureGates_DisabledConfigNeedsNoEntitlement(t *testing.T) {
	c := Claims{Features: []string{}} // restrictive-shaped but empty means unrestricted anyway; test with a genuinely non-empty-but-unrelated list
	c.Features = []string{"other-feature"}
	if err := CheckFeatureGates(c, false, false); err != nil {
		t.Fatalf("neither gate is enabled in config, must not require any entitlement: %v", err)
	}
}

func TestCheckFeatureGates_ReportsAllMissingFeatures(t *testing.T) {
	c := Claims{Features: []string{"other-feature"}}
	err := CheckFeatureGates(c, true, true)
	if err == nil {
		t.Fatal("expected an error")
	}
	msg := err.Error()
	if !contains(msg, "multitenancy") || !contains(msg, "sso") {
		t.Fatalf("error should name both missing features, got: %v", msg)
	}
}

func contains(s, sub string) bool {
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return true
		}
	}
	return false
}
