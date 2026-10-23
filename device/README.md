# Device authorization

Optional RFC 8628 device authorization composed with the actual
`oauthserver.Service` and its native PostgreSQL owner. The child contains no
client registry, identity/session engine, consent authority or token store.
Base OAuth construction does not require this module or device migrations.

## Quick start

Given an already constructed core service and native store, select the optional
native owner before constructing the child:

```go
native, err := store.DeviceStore(oauthpostgres.DeviceConfig{
    Policy: config, LookupKeys: lookupKeys, ActiveLookupKeyVersion: activeVersion,
})
if err != nil {
    return err
}
flow, err := device.NewService(core, config, native)
```

`core` is the existing `*oauthserver.Service`, not a replacement authority.
`config` is the immutable `device.Config`; `lookupKeys` are dedicated opaque
root-owned digest keys. The full executable native composition and genuine
authenticated journey are in
[`postgres/device_flow_integration_test.go`](../postgres/device_flow_integration_test.go).
The disabled construction example compiles without either owner.

## Selected profile and adoption

The first profile issues unbound device requests to explicitly registered
public (`none`) or confidential (`client_secret_basic`) clients with
`Client.DeviceAuthorization=true`. Zero preserves the existing deny default and
legacy registration fingerprints. Managed creation additionally requires the
configured `ManagedClientPolicy.DeviceAuthorization` ceiling. Redirect
registration remains mandatory for this selected client-registration profile;
redirect possession is never used as device-grant proof.
Changing a static registration's permission requires a new client version and
fresh approval; never reuse an earlier version to restore withdrawn authority.

Compose the existing root service, then select the native store's optional
`DeviceStore(DeviceConfig)` factory and pass it to `device.NewService`.
The immutable `Config` fixes tenant, same-issuer HTTPS verification,
authorization and token endpoints, expiry, initial polling interval, complete
verification-URI byte bound and user-code lookup limit. No proxy or request
parameter can override those authorities. Retain lookup-key versions while
their live or recoverable rows remain.
Rolling lookup-key configurations must retain overlapping original keys.
Collision checks use every retained namespace and at most eight globally
ordered transaction advisory locks, independently of the active version and
native caller-intent key. Disjoint retained sets cannot interoperate and are
unsupported while original requests remain live/recoverable. A collision
rejects that issuance without replacing the original request; a new issuance
generates new codes. Changing the frozen device policy invalidates existing
requests rather than silently renewing or reinterpreting them.

Install the existing shared rate-limit migration and append native
`DeviceMigrationSource` after the ordinary OAuth/consent history before enabling
writers. This first forward history does not support existing workload or
silent-OIDC artifact histories. Stop writers, install the forward history,
replace unaware writers, then activate the selected capability. Do not roll
back to unaware writers after activation. No constructor migrates or starts a
background worker. See the [native adapter](../postgres/README.md).

## API

- `ParseDeviceRequest` and `ParseTokenExchange` bound form input to 16 KiB,
  reject duplicated/conflicting credential channels and preserve only the
  RFC-defined issuance or extension-grant request.
- `Authorize` authenticates the actual current registered client and returns
  reveal-once device custody only after fresh known commitment. Device codes
  contain 32 random bytes in canonical 43-character base64url. User codes use
  eight nonconfusable characters, displayed as `XXXX-XXXX`.
- `Inspect` requires a genuine recent verified password session and returns
  safe client, scopes, resource, displayed code and original expiry. It cannot
  approve, issue consent or create a domain command.
- `Approve` additionally requires explicit matching `ConfirmedUserCode`, exact
  issuer origin and the real session owner's CSRF token. `Deny` uses the same
  current session/origin/CSRF admission.
- `Poll` preserves committed interval metadata alongside typed pending,
  slow-down, denied and expired errors. Only the sole fresh atomic winner
  receives actual root-owned access/refresh tokens.
- `Cancel` permanently withdraws the request using the same client/device
  custody. Canceling a Go context aborts that call; it does not withdraw the
  durable request.
- `Recover` accepts original command correlation and appropriate current client
  or reviewing-session custody. It delegates metadata-only reconciliation to
  the existing sole coordinator; it never reconstructs a lost credential reply.

## Polling and security

RFC 8628 section 3.5 mandates a five-second interval increase for every
`slow_down`. The selected server policy starts at 5–60 seconds. An early poll
that would exceed the 60-second policy bound permanently cancels the request
with `access_denied`; it never returns a clamped `slow_down` interval. Clients
must stop on terminal errors and respect the last returned interval.

The complete verification URI contains only the user code, never the device
bearer. Per RFC 8628 section 5.4, opening that URI is not proof of the user's
intent: the displayed code still needs explicit confirmation. Codes are stored
only as independently versioned issuer/environment/tenant/endpoint-bound keyed
digests. Ordinary formatting and serialization of credential-bearing values
are redacted or rejected. Reveal credentials only at the intended transport
boundary; never log them.

Native mutations retain the actual client actor separately from the approved
human's original session provenance. Current client version, directory,
credential, authorization and consent authority are fenced by their existing
owners. Withdrawal cannot be repaired by replaying an old approval. Required
audit and lifecycle effects share the same transaction as device/grant state.

## Boundaries and FAQ

**Does this provide a device UI or HTTP routes?** No. A transport must render
the safe prompt and implement its own explicit interaction, authenticated
session and CSRF channel. Native capability selection alone is not discovery or
HTTP registration.

**Are pre-bound identities, OIDC claims, workload clients or MFA downgrade
supported?** No. This is the selected unbound, recent verified-password-human
profile. A pre-bound identity profile remains a separate required profile, not
an approximation with a caller-supplied user. Existing MFA sources are never
downgraded into password-only admission.

**Can I blindly retry an unknown response?** No credential replay is provided.
Recover the original command's metadata. For lost issuance, start a new request
after resolving that original command; the inaccessible old request expires.

This profile does not by itself qualify the complete device milestone. HTTP,
reference composition and other selected identity profiles need their own
whole-profile execution evidence.

Specification: [RFC 8628, August 2019](https://www.rfc-editor.org/rfc/rfc8628.html).
