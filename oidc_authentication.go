package oauthserver

import (
	"context"
	"slices"
	"sync"
	"time"
)

func authenticationRequested(request AuthorizationRequest) bool {
	return request.Prompt != "" || request.MaxAge != nil
}

func sameAuthorizationRequest(a, b AuthorizationRequest) bool {
	return a.ClientID == b.ClientID && a.RedirectURI == b.RedirectURI && a.State == b.State && a.CodeChallenge == b.CodeChallenge && a.Resource == b.Resource && a.Nonce == b.Nonce && a.Prompt == b.Prompt && slices.Equal(a.Scopes, b.Scopes) && (a.MaxAge == nil && b.MaxAge == nil || a.MaxAge != nil && b.MaxAge != nil && *a.MaxAge == *b.MaxAge)
}

// This invocation-local capture only conserves the child decisions already
// observed before Store waits. It cannot read/renew session authority, execute a
// transition or survive the call. Borrowed callbacks run outside its mutex.
type oidcAuthorizationCall struct {
	mu      sync.Mutex
	seen    bool
	invalid bool
	request AuthorizationRequest
	mode    OIDCAuthenticationRequirement
	until   time.Time
}

func (call *oidcAuthorizationCall) wrap(policy func(context.Context, OIDCAuthorizationInput) (OIDCAuthorizationProjection, error)) func(context.Context, OIDCAuthorizationInput) (OIDCAuthorizationProjection, error) {
	return func(ctx context.Context, input OIDCAuthorizationInput) (OIDCAuthorizationProjection, error) {
		request := input.Request.snapshot()
		input.Request, input.Client = input.Request.snapshot(), input.Client.snapshot()
		projection, err := policy(ctx, input)
		call.mu.Lock()
		defer call.mu.Unlock()
		if call.seen && !sameAuthorizationRequest(call.request, request) {
			call.invalid = true
		}
		if !call.seen {
			call.request = request
			call.seen = true
		}
		if authenticationRequested(request) {
			if err != nil || !projection.Accepted || projection.Authentication != OIDCAuthenticationCurrent && projection.Authentication != OIDCAuthenticationFresh && projection.Authentication != OIDCAuthenticationSilent || projection.Authentication == OIDCAuthenticationFresh && !projection.AuthenticationUntil.IsZero() || (request.Prompt == "none") != (projection.Authentication == OIDCAuthenticationSilent) || projection.Authentication != OIDCAuthenticationFresh && request.MaxAge != nil && *request.MaxAge > 0 && projection.AuthenticationUntil.IsZero() {
				call.invalid = true
			}
			if projection.Authentication == OIDCAuthenticationFresh || call.mode == 0 {
				call.mode = projection.Authentication
			}
			if until := projection.AuthenticationUntil; !until.IsZero() && (call.until.IsZero() || until.Before(call.until)) {
				call.until = until
			}
		}
		return projection, err
	}
}

func (call *oidcAuthorizationCall) check(out AuthorizeResult, request AuthorizationRequest, now time.Time, initial bool) error {
	if out.Outcome == AuthorizationUnknown || out.Outcome == AuthorizationHistorical || out.Outcome == AuthorizationDenied {
		return nil // No successful authentication/credential may be delivered.
	}
	call.mu.Lock()
	defer call.mu.Unlock()
	if !authenticationRequested(request) && (!call.seen || !authenticationRequested(call.request)) {
		return nil // Preserve the existing absent-policy profile.
	}
	if !call.seen || call.invalid || !sameAuthorizationRequest(call.request, request) || !sameAuthorizationRequest(request, out.Request) {
		return ErrUnavailable // An unaware adapter cannot acknowledge this profile.
	}
	if call.mode == OIDCAuthenticationFresh {
		if initial && out.Outcome == FreshAuthenticationRequired {
			return nil
		}
		if initial {
			return ErrUnavailable
		}
		return ErrLoginRequired
	}
	if call.mode == OIDCAuthenticationSilent && out.Outcome != AuthorizationRedirect {
		return ErrUnavailable // No interaction can be substituted for silent policy.
	}
	// OIDC Core1.0 errata2 §3.1.2.1 requires consent for this request, not
	// cached approval. An older/custom Store cannot skip the protected interaction.
	if initial && request.Prompt == "consent" && out.Outcome != ConsentRequired {
		return ErrUnavailable
	}
	if out.Outcome != FreshAuthenticationRequired && !call.until.IsZero() && !now.Before(call.until) {
		return ErrLoginRequired
	}
	return nil
}
