# Native OAuth PostgreSQL adapter

Experimental persistence and public service composition for the
[selected authorization-code profile](../docs/selected-profile.md).
`NewService(pool, Config, keys)` composes the native primary session reader,
OAuth participant and root protocol. `NewStore` exposes that same participant
for explicit composition and metadata-only `Recover`; applications do not
implement a domain store, transaction callback or authentication engine.

## Startup and migrations

Supply an existing primary PostgreSQL pool and actual public native
configuration for the identity coordinator, password-session admission,
authorization policy, risk counters/lockouts, token digests and envelope keys.
Configured clients are immutable platform-owned public registrations. All four
canonical OAuth operations must select the current Privileged risk policy with
exactly `velocity` required. Unavailable additional mandatory providers deny at
construction; CredentialMutation provider custody is not reused for Privileged.

Before enabling calls, install public owners' histories: identity kernel and
generated-output/counter preparation, directory/credential/authorization
authority, password sessions/CSRF, protected counters/lockouts, audit, outbox and
the identity outbox participant. Install this module's `MigrationSource` in a
dedicated schema with a permanently allocated positive migration version.
Use the migration backend's separate **`ForNamespace` history**; do not mix
unrelated owners' histories under the default ledger.

Construction never installs/adopts tables, generates a token or performs IO.
The base OAuth schema requires no device, OIDC, organization or API-key store.
It owns no foreign keys over identity users or local sessions. Durable records
contain keyed bearer digests and bounded nonsecret projections. Only existing
coordinator authenticated encrypted preparation retains generated delivery
custody. Child records retain exact root, parent and issuing-command lineage;
parents cannot be deleted while descendants reference them.

Consent has an independent server-owned ID and positive version. Explicit
approval inserts 0-to-1 or advances that same row's version using a fenced CAS;
it is not derived from a grant ID. The native owner records the actual SQL
mutation in the sole Work, and the real outbox atomically writes the primary
grant event and secondary `consent.created.v1`/`consent.reconfirmed.v1` event.
Failure of either notification rolls back consent, code, success-audit and grant
effects; the coordinator may retain its separate failed-attempt audit.
The exact [owner event catalog](../docs/selected-profile.md#native-lifecycle-owner-catalog)
explains new informational transitions and consumer impact.

Use independently generated versioned keys for token/session lookup, CSRF,
command intent/fingerprints and envelope custody. Retain every key/configuration
required by outstanding grants and command recovery. Client policy/version
changes cannot silently widen historical authority.

## Unknown outcomes

Cancellation, connection failure and lost COMMIT acknowledgement do not prove
rollback. Preserve the returned original `CommandID` and original custody.
Do not retry issuance or generate a replacement token to resolve uncertainty.

`Store.Recover(ctx, RecoveryRequest)` supports exactly selected authorize,
continue, token and revoke canonical operation IDs:

- Initial authorization: original current browser, tenant, configured client
  and command ID. The encrypted original client/session binding is authenticated.
- Consent: the same browser/tenant plus original client-bound continuation and
  its preallocated transition ID.
- Token or revocation: original client-bound protocol bearer and its exact
  preallocated transition/replay ID, without a browser or caller-selected user.

The result contains only outcome, command ID and bounded retry metadata.
Live leases remain observational. Only the original coordinator and unanimous
native participant evidence reconcile noncommit after expiry. Committed
recovery never reveals an unknown code/token, renews authority or executes again.
When committed delivery was lost, start a new authorized interaction instead
of treating historical metadata as a recoverable bearer.

## Verification and ownership

Integration tests are explicitly tagged `integration,oauthflow`; the base
migration test uses `integration`. Explicitly opt into a task-owned disposable
PostgreSQL18 loopback cluster with `OAUTH_POSTGRES_TEST_DSN` and its exact
`OAUTH_POSTGRES_TEST_DATA_DIRECTORY`. Tests create/drop only private databases.
The full consumer also requires all audit roles absent before installation and
removes only roles proven task-created and unused after private DB cleanup.
Never point these fixtures at production or a shared user-owned cluster.

The consumer performs real signup, confirmed email, password sign-in, consent,
code exchange, refresh and revocation. Fault tests withhold actual PostgreSQL
COMMIT acknowledgements and check native reconciliation, not fabricated
outcomes. Contention races real consumption; credential withdrawal uses real
password reauthentication/replacement; browser withdrawal uses the session owner.

The application owns pool/key lifetime, migrations, endpoint rate limits and
transport. Operations are context-bounded. Immutable instances support
concurrent calls with invocation-local participants and serial Work lifetimes.
There is no background cleanup, private coordinator, second command journal,
resource verifier or replacement local-session issuer.
