package oauthserver

import "context"

// AuthenticateClient checks the current registered none/Basic client matrix
// without issuing tokens, revoking grants or invoking the durable Store. It
// borrows input only for this bounded call and honors an earlier caller deadline.
// Managed clients use the configured current registry; static clients retain
// their startup-only verifier authority. Dependency errors and panics are redacted.
//
// Success is immediate admission for transport policy such as an authenticated
// client rate bucket, not a proof, lease or renewable authorization. Token,
// introspection and revocation must still perform their own current/native
// authentication and final authority checks. This method authenticates no human
// and grants no tenant, scope or token authority.
func (s *Service) AuthenticateClient(ctx context.Context, clientID string, input ClientAuthentication) (err error) {
	defer func() {
		if recover() != nil {
			err = ErrUnavailable
		}
	}()
	ctx, stop, err := s.bounded(ctx)
	if err != nil {
		return err
	}
	defer stop()
	client, err := s.currentClient(ctx, clientID)
	if err != nil {
		return operationError(ctx, err)
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	return operationError(ctx, s.authenticateClient(ctx, client, input))
}
