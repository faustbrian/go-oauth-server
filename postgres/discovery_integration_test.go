//go:build integration && oauthflow

package oauthpostgres_test

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/url"
	"slices"
	"strings"
	"testing"
	"time"

	identity "github.com/faustbrian/go-identity"
	oauth "github.com/faustbrian/go-oauth-server"
	oauthpostgres "github.com/faustbrian/go-oauth-server/postgres"
	"golang.org/x/oauth2"
)

// Only the in-process transport is a fixture: parsing, current identity/session,
// explicit consent, issuance, refresh, revocation, audit and outbox are real
// public owners. No generic HTTP implementation or UI is supplied by this test.
type discoveryConsumerTransport struct {
	f                                                                authenticatedPasswordFixture
	service                                                          *oauth.Service
	endpoints                                                        oauth.DiscoveryConfig
	metadataReads, authorizations, exchanges, refreshes, revocations int
}

func discoveryResponse(r *http.Request, status int, value any) (*http.Response, error) {
	wire, err := json.Marshal(value)
	if err != nil {
		return nil, err
	}
	return &http.Response{StatusCode: status, Header: http.Header{"Content-Type": {"application/json"}}, Body: io.NopCloser(strings.NewReader(string(wire))), Request: r}, nil
}

func (p *discoveryConsumerTransport) RoundTrip(r *http.Request) (*http.Response, error) {
	if r.Context().Err() != nil {
		return nil, r.Context().Err()
	}
	if r.Method == http.MethodGet && r.URL.String() == p.f.oauth.Protocol.Issuer.String()+"/.well-known/oauth-authorization-server" {
		p.metadataReads++
		out, err := p.service.DiscoveryOauth(r.Context(), oauth.DiscoveryOauthRequest{})
		if err != nil {
			return nil, err
		}
		return discoveryResponse(r, http.StatusOK, out.Metadata)
	}
	endpoint := *r.URL
	endpoint.RawQuery = ""
	if r.Method == http.MethodGet && endpoint.String() == p.endpoints.AuthorizationEndpoint {
		p.authorizations++
		request, err := oauth.ParseAuthorizationQuery(r.URL.RawQuery)
		if err != nil {
			return nil, err
		}
		begin, err := p.service.Authorize(r.Context(), oauth.AuthorizeRequest{TenantID: p.f.tenant, Session: p.f.browser, Request: request, Network: "192.0.2.1"})
		if err != nil || begin.Outcome != oauth.ConsentRequired {
			return nil, errors.New("metadata consumer did not reach real consent")
		}
		continuation, err := begin.Continuation.Reveal()
		if err != nil {
			return nil, err
		}
		approved, err := p.service.Continue(r.Context(), oauth.ContinueRequest{TenantID: p.f.tenant, Session: p.f.browser, CSRF: p.f.csrf, ClientID: request.ClientID, Continuation: continuation, Origin: p.f.oauth.Protocol.Issuer.String(), Network: "192.0.2.1", Approve: true, Scopes: request.Scopes})
		if err != nil || approved.Outcome != oauth.AuthorizationRedirect {
			return nil, errors.New("metadata consumer consent failed")
		}
		location, err := approved.Location()
		if err != nil {
			return nil, err
		}
		return &http.Response{StatusCode: http.StatusFound, Header: http.Header{"Location": {location}}, Body: http.NoBody, Request: r}, nil
	}
	if r.Method != http.MethodPost || r.Body == nil || r.Header.Get("Content-Type") != "application/x-www-form-urlencoded" {
		return nil, errors.New("unselected consumer transport operation")
	}
	defer r.Body.Close()
	body, err := io.ReadAll(io.LimitReader(r.Body, 16385))
	if err != nil || len(body) > 16384 {
		return nil, errors.New("consumer form exceeds protocol bound")
	}
	if r.URL.String() == p.endpoints.TokenEndpoint {
		request, err := oauth.ParseTokenFormWithClientAuthentication(string(body), r.Header.Values("Authorization"))
		if err != nil {
			return nil, err
		}
		request.Network = "192.0.2.1"
		if request.GrantType == oauth.AuthorizationCodeGrant {
			p.exchanges++
		} else if request.GrantType == oauth.RefreshTokenGrant {
			p.refreshes++
		} else {
			return nil, errors.New("consumer attempted unselected grant")
		}
		issued, err := p.service.Token(r.Context(), request)
		if err != nil {
			if errors.Is(err, oauth.ErrInvalidGrant) {
				return discoveryResponse(r, http.StatusBadRequest, map[string]string{"error": "invalid_grant"})
			}
			return nil, err
		}
		if issued.Outcome != identity.CommitOutcomeCommitted || issued.Replayed {
			return nil, errors.New("consumer cannot serialize unknown or replayed delivery")
		}
		access, err := issued.AccessToken.Reveal()
		if err != nil {
			return nil, err
		}
		refresh, err := issued.RefreshToken.Reveal()
		if err != nil {
			return nil, err
		}
		return discoveryResponse(r, http.StatusOK, map[string]any{"access_token": access, "token_type": "Bearer", "refresh_token": refresh, "expires_in": int64(time.Until(issued.ExpiresAt).Seconds()), "scope": strings.Join(issued.Scopes, " "), "resource": issued.Resource})
	}
	if r.URL.String() == p.endpoints.RevocationEndpoint {
		request, err := oauth.ParseRevocationForm(string(body), r.Header.Values("Authorization"))
		if err != nil {
			return nil, err
		}
		request.Network = "192.0.2.1"
		if _, err := p.service.Revoke(r.Context(), request); err != nil {
			return nil, err
		}
		p.revocations++
		return &http.Response{StatusCode: http.StatusOK, Header: make(http.Header), Body: http.NoBody, Request: r}, nil
	}
	return nil, errors.New("unregistered endpoint selected by consumer")
}

func TestNativeDiscoveryIndependentClientCompletesMetadataSelectedFlow(t *testing.T) {
	for _, confidential := range []bool{false, true} {
		t.Run(map[bool]string{false: "public", true: "basic"}[confidential], func(t *testing.T) {
			f := passwordFixture(t)
			registered := f.oauth.Protocol.Clients[0]
			var secret string
			if confidential {
				registered, secret, _ = addConfiguredConfidentialClient(t, &f)
				f.oauth.Protocol.OwningClientIntrospection = true
			}
			issuer := f.oauth.Protocol.Issuer.String()
			f.oauth.Protocol.Discovery = oauth.DiscoveryConfig{Enabled: true, AuthorizationEndpoint: issuer + "/oauth2/authorize", TokenEndpoint: issuer + "/oauth2/token", RevocationEndpoint: issuer + "/oauth2/revoke"}
			if confidential {
				f.oauth.Protocol.Discovery.IntrospectionEndpoint = issuer + "/oauth2/introspect"
			}
			service, err := oauthpostgres.NewService(f.pool, f.oauth, f.keys)
			if err != nil {
				t.Fatal(err)
			}
			transport := &discoveryConsumerTransport{f: f, service: service, endpoints: f.oauth.Protocol.Discovery}
			client := &http.Client{Transport: transport, Timeout: 5 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
			ctx := context.WithValue(f.ctx, oauth2.HTTPClient, client)
			request, _ := http.NewRequestWithContext(ctx, http.MethodGet, issuer+"/.well-known/oauth-authorization-server", nil)
			response, err := client.Do(request)
			if err != nil {
				t.Fatal("discovery retrieval failed", err)
			}
			var metadata oauth.DiscoveryOauthMetadata
			err = json.NewDecoder(io.LimitReader(response.Body, 16384)).Decode(&metadata)
			response.Body.Close()
			if err != nil || response.StatusCode != http.StatusOK || metadata.Issuer != issuer || !slices.Contains(metadata.ResponseTypesSupported, "code") || !slices.Contains(metadata.GrantTypesSupported, "authorization_code") || !slices.Contains(metadata.GrantTypesSupported, "refresh_token") || !slices.Contains(metadata.CodeChallengeMethodsSupported, "S256") || !metadata.AuthorizationResponseISSParameterSupported || len(metadata.ProtectedResources) != 1 || len(metadata.ScopesSupported) == 0 {
				t.Fatal("independent client cannot select supported metadata profile", err)
			}
			method := "none"
			if confidential {
				method = "client_secret_basic"
			}
			if !slices.Contains(metadata.TokenEndpointAuthMethodsSupported, method) || !slices.Contains(metadata.RevocationEndpointAuthMethodsSupported, method) {
				t.Fatal("registered client method absent from consumed metadata")
			}
			style := oauth2.AuthStyleInParams
			if confidential {
				style = oauth2.AuthStyleInHeader
			}
			standard := oauth2.Config{ClientID: registered.ID, ClientSecret: secret, RedirectURL: registered.Redirects[0], Scopes: []string{metadata.ScopesSupported[0]}, Endpoint: oauth2.Endpoint{AuthURL: metadata.AuthorizationEndpoint, TokenURL: metadata.TokenEndpoint, AuthStyle: style}}
			verifier := oauth2.GenerateVerifier()
			authorizationURL := standard.AuthCodeURL("metadata-state", oauth2.S256ChallengeOption(verifier), oauth2.SetAuthURLParam("resource", metadata.ProtectedResources[0]))
			request, _ = http.NewRequestWithContext(ctx, http.MethodGet, authorizationURL, nil)
			response, err = client.Do(request)
			if err != nil {
				t.Fatal("metadata authorization failed", err)
			}
			response.Body.Close()
			callback, err := url.Parse(response.Header.Get("Location"))
			if err != nil || response.StatusCode != http.StatusFound || callback.Scheme+"://"+callback.Host+callback.Path != registered.Redirects[0] || callback.Query().Get("iss") != metadata.Issuer || callback.Query().Get("state") != "metadata-state" || callback.Query().Get("code") == "" {
				t.Fatal("client refused issuer/state/callback substitution")
			}
			issued, err := standard.Exchange(ctx, callback.Query().Get("code"), oauth2.VerifierOption(verifier))
			if err != nil || issued.AccessToken == "" || issued.RefreshToken == "" || issued.Extra("resource") != metadata.ProtectedResources[0] {
				t.Fatal("standard client could not redeem metadata-selected S256 code", err)
			}
			originalRefresh := issued.RefreshToken
			issued.Expiry = time.Now().Add(-time.Minute) // Ask the real standard client to exercise its refresh path.
			rotated, err := standard.TokenSource(ctx, issued).Token()
			if err != nil || rotated.RefreshToken == "" || rotated.RefreshToken == originalRefresh || rotated.AccessToken == issued.AccessToken {
				t.Fatal("standard metadata-selected refresh did not rotate", err)
			}
			form := url.Values{"token": {rotated.RefreshToken}, "token_type_hint": {"refresh_token"}}
			if !confidential {
				form.Set("client_id", standard.ClientID)
			}
			request, _ = http.NewRequestWithContext(ctx, http.MethodPost, metadata.RevocationEndpoint, strings.NewReader(form.Encode()))
			request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
			if confidential {
				request.SetBasicAuth(url.QueryEscape(standard.ClientID), url.QueryEscape(standard.ClientSecret))
			}
			response, err = client.Do(request)
			if err != nil {
				t.Fatal("metadata-selected revoke failed", err)
			}
			response.Body.Close()
			if response.StatusCode != http.StatusOK {
				t.Fatal("revocation endpoint rejected owning client")
			}
			rotated.Expiry = time.Now().Add(-time.Minute)
			if _, err := standard.TokenSource(ctx, rotated).Token(); err == nil {
				t.Fatal("real revoked refresh family remained usable")
			}
			if confidential {
				requireInactiveIntrospection(t, service, f.ctx, oauth.IntrospectRequest{ClientID: registered.ID, ClientAuthentication: confidentialBasic(t, registered.ID, secret), Token: rotated.AccessToken})
			}
			if transport.metadataReads != 1 || transport.authorizations != 1 || transport.exchanges != 1 || transport.refreshes != 2 || transport.revocations != 1 {
				t.Fatal("consumer did not traverse the actual discovered operations")
			}
			var events, audits int
			if err := f.pool.Raw().QueryRow(f.ctx, `SELECT (SELECT count(*) FROM public.outbox_messages WHERE topic='grant.revoked.v1'),(SELECT count(*) FROM audit.records WHERE action='identity.oauth_server.revoke_token' AND outcome=1)`).Scan(&events, &audits); err != nil || events != 1 || audits != 1 {
				t.Fatal("metadata consumer lacked actual atomic revocation lifecycle/audit", err)
			}
		})
	}
}
