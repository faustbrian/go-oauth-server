# Restricted workload access exchange

This finite opt-in profile selects RFC 8693 sections 2.1, 2.2 and 3 over the
existing Golib-owned opaque workload grant. It does not complete M33 or the
shared-issuer JWT/customer/API-key/organization profiles.

Configure `Config.WorkloadExchange = &WorkloadExchangePolicy{MaximumDepth: 4,
ClockUncertainty: time.Second}` for existing confidential `Workload` clients.
Zero depth defaults to four; explicit depth can only lower it. The read timeout
and declared clock uncertainty must total no more than ten seconds. No HTTP
route, default bootstrap or mandatory `Store` method is added.

`ParseTokenFormWithClientAuthentication` accepts the standard
`urn:ietf:params:oauth:grant-type:token-exchange` with one Basic header,
`subject_token`, `subject_token_type=urn:ietf:params:oauth:token-type:access_token`,
one exact configured `resource` **or** `audience`, and optional narrowing `scope`.
`requested_token_type`, if present, must be the same access-token type.
Duplicate fields, both target selectors, actors, arbitrary subjects/tenants,
body credentials and fields from other grants fail closed. The public-none
parser never selects exchange. The returned `TokenResult.IssuedTokenType`
identifies an access token; no refresh or ID token is issued.

Only the issuing client can exchange an original or delegated token. This is
machine authority at the client's configured tenant/resource, never a human
identity or arbitrary customer account. The platform owner, service account,
tenant and client remain distinct immutable bindings. Scope selection intersects
the source, root and current client ceiling. Each child retains its root and
immediate parent, issuer/environment, original scope ceiling and expiry; child
expiry never exceeds parent expiry or five minutes. An active source can produce
independent narrower children. A zero `TokenRequest.CommandID` creates a fresh
native command; trusted callers can supply the original returned ID for an exact
retry. This metadata is never accepted from an RFC form or header. The retained
source/client/scope/target intent must match before historical metadata returns;
neither an exact retry nor recovery reveals an original or replacement secret.

Use the matching native adapter and append `WorkloadExchangeMigrationSource`
after `WorkloadMigrationSource` and any selected `ConsentExpiryMigrationSource`
before activation. The exchange suffix preserves populated silent-code roots;
later consent-expiry activation is rejected during pure history loading, before
database mutation. Configure a distinct native
`WorkloadExchangeClientNamespace` and explicitly initialize each real client
authority to its immutable registration version. Advancing that epoch withdraws
both old lineage and new roots from the unchanged Basic registration. Adoption
of a newer matching registration/secret is an explicit consumer lifecycle.
Replace unaware accepting writers first. Roots issued before activation without
this epoch cannot acquire it through exchange: selected roots must be newly issued.
Existing unselected roots are not relabeled or copied into a new
authorization engine. Root/ancestor access withdrawal, directory and workload
authorization epochs remain the actual authorities. Each exchange/introspection
performs bounded primary reads; unavailable required authority fails closed.
No invalidation message or positive cache is required for withdrawal.

Credential expiry and current-authority observation expiry are distinct.
Native admission preserves a read-start-based observation of at most twenty
seconds, not twenty seconds after response delivery. Copying/exchange preserves
the original source observation provenance. A later genuine primary-owner read
may establish a separate current observation; it does not rewrite the retained
origin or extend credential expiry. This profile exposes no reusable cached
authorization assertion and does not claim the customer JWT verifier profile.

Recovery uses native `Store.Recover` with the original subject token, Basic
credential and returned command ID. Historical commitment is metadata only:
never decrypt/reveal or execute another issuance to replace lost output.

Source: [RFC 8693](https://www.rfc-editor.org/rfc/rfc8693.html), January 2020.
The four-exchange/five-minute and 20/30-second limits are local shared-issuer
profile policy, not limits imposed by RFC 8693.
