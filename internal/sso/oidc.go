// Package sso implements OpenID Connect single sign-on for the admin console.
// It runs the Authorization Code flow with PKCE against an external identity
// provider, validates the returned ID token, and maps its claims to a tenant +
// console role. The heavy lifting — discovery, token exchange, and ID-token
// signature/issuer/audience/expiry/nonce verification — is delegated to the
// audited golang.org/x/oauth2 and github.com/coreos/go-oidc libraries rather
// than hand-rolled, because subtle bugs in OAuth/OIDC crypto are exactly the
// kind a security product must not ship.
package sso

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"slices"
	"strings"
	"time"

	"api-gateway/internal/config"
	"api-gateway/internal/iam"
	"api-gateway/internal/tenant"

	"github.com/coreos/go-oidc/v3/oidc"
	"golang.org/x/oauth2"
)

// Authenticator holds the provider-specific state built once at startup: the
// OIDC verifier (bound to the provider's JWKS) and the OAuth2 client config.
type Authenticator struct {
	cfg      config.OIDCConfig
	provider *oidc.Provider
	verifier *oidc.IDTokenVerifier
	oauth    oauth2.Config
}

// Identity is the result of a successful SSO login: everything the console
// session needs, already mapped from provider claims to AEGIS's model.
type Identity struct {
	Email      string
	TenantID   string
	Role       iam.Role
	SuperAdmin bool
}

// New performs OIDC discovery against the issuer and returns a ready
// Authenticator. It blocks on a network call, so callers should bound it with a
// context timeout; a failure here means SSO is misconfigured or the IdP is
// unreachable and the gateway should surface it at startup.
func New(ctx context.Context, cfg config.OIDCConfig) (*Authenticator, error) {
	provider, err := oidc.NewProvider(ctx, cfg.Issuer)
	if err != nil {
		return nil, fmt.Errorf("oidc: discovery for %q: %w", cfg.Issuer, err)
	}
	scopes := normaliseScopes(cfg.Scopes)
	return &Authenticator{
		cfg:      cfg,
		provider: provider,
		verifier: provider.Verifier(&oidc.Config{ClientID: cfg.ClientID}),
		oauth: oauth2.Config{
			ClientID:     cfg.ClientID,
			ClientSecret: cfg.ClientSecret,
			RedirectURL:  cfg.RedirectURL,
			Endpoint:     provider.Endpoint(),
			Scopes:       scopes,
		},
	}, nil
}

// normaliseScopes guarantees "openid" is present exactly once and preserves the
// operator's additional scopes (e.g. email, profile, groups).
func normaliseScopes(want []string) []string {
	out := []string{oidc.ScopeOpenID}
	seen := map[string]bool{oidc.ScopeOpenID: true}
	for _, s := range want {
		if s = strings.TrimSpace(s); s != "" && !seen[s] {
			seen[s] = true
			out = append(out, s)
		}
	}
	return out
}

// Flow carries the one-time, per-login secrets that must survive the redirect
// to the IdP and back. It is persisted server-side keyed by `state` and consumed
// exactly once at the callback (defends against CSRF and code injection).
type Flow struct {
	State        string `json:"state"`
	Nonce        string `json:"nonce"`
	CodeVerifier string `json:"code_verifier"`
}

// NewFlow mints fresh state, nonce, and PKCE verifier for one login attempt.
func NewFlow() (Flow, error) {
	state, err := randomToken()
	if err != nil {
		return Flow{}, err
	}
	nonce, err := randomToken()
	if err != nil {
		return Flow{}, err
	}
	verifier, err := randomToken()
	if err != nil {
		return Flow{}, err
	}
	return Flow{State: state, Nonce: nonce, CodeVerifier: verifier}, nil
}

// AuthCodeURL builds the provider authorization URL for this flow, binding the
// nonce (replay defence on the ID token) and the S256 PKCE challenge (defends
// the code exchange even if the redirect leaks).
func (a *Authenticator) AuthCodeURL(f Flow) string {
	challenge := pkceChallenge(f.CodeVerifier)
	return a.oauth.AuthCodeURL(f.State,
		oidc.Nonce(f.Nonce),
		oauth2.SetAuthURLParam("code_challenge", challenge),
		oauth2.SetAuthURLParam("code_challenge_method", "S256"),
	)
}

// Exchange completes the flow: it swaps the authorization code for tokens
// (sending the PKCE verifier), verifies the ID token against the provider JWKS
// (signature, issuer, audience, expiry), checks the nonce, then maps the claims
// to an Identity. Any failure returns an error and no session is established.
func (a *Authenticator) Exchange(ctx context.Context, f Flow, code string) (Identity, error) {
	tok, err := a.oauth.Exchange(ctx, code,
		oauth2.SetAuthURLParam("code_verifier", f.CodeVerifier))
	if err != nil {
		return Identity{}, fmt.Errorf("oidc: token exchange: %w", err)
	}
	rawID, ok := tok.Extra("id_token").(string)
	if !ok || rawID == "" {
		return Identity{}, fmt.Errorf("oidc: token response carried no id_token")
	}
	idToken, err := a.verifier.Verify(ctx, rawID)
	if err != nil {
		return Identity{}, fmt.Errorf("oidc: id_token verification: %w", err)
	}
	if idToken.Nonce != f.Nonce {
		return Identity{}, fmt.Errorf("oidc: id_token nonce mismatch (possible replay)")
	}

	var claims map[string]any
	if err := idToken.Claims(&claims); err != nil {
		return Identity{}, fmt.Errorf("oidc: decode claims: %w", err)
	}
	return a.mapIdentity(claims)
}

// mapIdentity translates raw ID-token claims into AEGIS's tenant/role model
// per the OIDCConfig. It is deliberately separate from the network path so it
// can be unit-tested exhaustively.
func (a *Authenticator) mapIdentity(claims map[string]any) (Identity, error) {
	email, _ := claims["email"].(string)
	email = strings.ToLower(strings.TrimSpace(email))
	if email == "" {
		return Identity{}, fmt.Errorf("oidc: id_token has no email claim (add the 'email' scope)")
	}
	// email_verified may arrive as a bool or, from some providers, as a string.
	// Reject an explicit false in either form; an absent claim is treated as
	// verified (standard — e.g. Azure AD omits it), but a present false must not
	// slip through a type mismatch.
	switch v := claims["email_verified"].(type) {
	case bool:
		if !v {
			return Identity{}, fmt.Errorf("oidc: email %q is not verified at the provider", email)
		}
	case string:
		if strings.EqualFold(strings.TrimSpace(v), "false") {
			return Identity{}, fmt.Errorf("oidc: email %q is not verified at the provider", email)
		}
	}
	if len(a.cfg.AllowedDomains) > 0 && !domainAllowed(email, a.cfg.AllowedDomains) {
		return Identity{}, fmt.Errorf("oidc: email domain for %q is not in allowed_domains", email)
	}

	tenantID := tenant.Default
	if a.cfg.TenantClaim != "" {
		if v, ok := claims[a.cfg.TenantClaim].(string); ok && strings.TrimSpace(v) != "" {
			claimed := strings.TrimSpace(v)
			// With an allowlist configured, a claim value outside it is
			// refused rather than silently auto-provisioning (or joining) an
			// arbitrary tenant — see AllowedTenants' doc comment.
			if len(a.cfg.AllowedTenants) > 0 && !slices.Contains(a.cfg.AllowedTenants, claimed) {
				return Identity{}, fmt.Errorf("oidc: tenant_claim %q for %q is not in allowed_tenants", claimed, email)
			}
			// Shape check, independent of the allowlist — which is optional, so
			// without this a deployment that sets tenant_claim and leaves
			// allowed_tenants empty takes whatever the provider sends. The value
			// becomes a Redis key namespace (gw:t:<tenant>:...) and a row in the
			// tenants table; a separator inside it puts one tenant's state in
			// another's namespace. The same rule already guards the config file
			// and the admin API.
			if !config.ValidTenantID(claimed) {
				return Identity{}, fmt.Errorf("oidc: tenant_claim %q for %q is not a valid tenant id", claimed, email)
			}
			tenantID = claimed
		}
	}

	rolesClaim := a.cfg.RolesClaim
	if rolesClaim == "" {
		rolesClaim = "groups"
	}
	groups := stringSet(claims[rolesClaim])

	role := iam.RoleViewer
	super := false
	mapped := false
	if intersects(groups, a.cfg.SuperAdminRoles) {
		role, super, mapped = iam.RoleAdmin, true, true
	} else if intersects(groups, a.cfg.AdminRoles) {
		role, mapped = iam.RoleAdmin, true
	}
	if !mapped && a.cfg.RequireMappedRole {
		return Identity{}, fmt.Errorf("oidc: %q matches no admin/super-admin role and require_mapped_role is set", email)
	}
	// A super-admin is authoritative for the default tenant regardless of any
	// tenant claim — cross-tenant management is not scoped to one org.
	if super {
		tenantID = tenant.Default
	}
	return Identity{Email: email, TenantID: tenantID, Role: role, SuperAdmin: super}, nil
}

// ── helpers ──────────────────────────────────────────────────────────────────

func randomToken() (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}

func pkceChallenge(verifier string) string {
	sum := sha256.Sum256([]byte(verifier))
	return base64.RawURLEncoding.EncodeToString(sum[:])
}

func domainAllowed(email string, domains []string) bool {
	at := strings.LastIndexByte(email, '@')
	if at < 0 {
		return false
	}
	dom := email[at+1:]
	for _, d := range domains {
		if strings.EqualFold(strings.TrimSpace(d), dom) {
			return true
		}
	}
	return false
}

// stringSet coerces a claim that may be a single string, a []string, or a
// []any of strings (how JSON decodes arrays) into a lookup set.
func stringSet(v any) map[string]bool {
	out := map[string]bool{}
	switch t := v.(type) {
	case string:
		if t != "" {
			out[t] = true
		}
	case []string:
		for _, s := range t {
			if s != "" {
				out[s] = true
			}
		}
	case []any:
		for _, e := range t {
			if s, ok := e.(string); ok && s != "" {
				out[s] = true
			}
		}
	}
	return out
}

func intersects(have map[string]bool, want []string) bool {
	for _, w := range want {
		if have[w] {
			return true
		}
	}
	return false
}

// FlowTTL is how long a login attempt may sit between the redirect to the IdP
// and the callback. Long enough for a human to authenticate + MFA, short enough
// to bound replay of a leaked state parameter.
const FlowTTL = 10 * time.Minute
