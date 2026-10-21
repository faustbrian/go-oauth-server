package oauthserver

import "errors"

// Called only after exact current client/redirect/request validation. OIDC Core
// 1.0 errata2 §§3.1.2.1/3.1.2.6 forbids UI for none but requires the validated
// redirect/state for its standard login/consent errors. Unknown durability and
// operational failures must not pass this non-mutating protocol-error path.
func (s *Service) silentError(input AuthorizationRequest, condition error) (AuthorizeResult, error) {
	code := AuthorizationLoginRequiredError
	if errors.Is(condition, ErrConsentRequired) {
		code = AuthorizationConsentRequiredError
	} else if !errors.Is(condition, ErrLoginRequired) {
		return AuthorizeResult{}, ErrUnavailable
	}
	return AuthorizeResult{Outcome: AuthorizationProtocolError, ProtocolError: code, RedirectURI: input.RedirectURI, State: input.State, Issuer: s.config.Issuer}, nil
}
