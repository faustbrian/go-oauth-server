# Changelog

## Unreleased

- Read actual issued opaque access/refresh state for explicitly selected,
  separately authenticated owning-confidential-client introspection. Recheck
  original primary subject/credential authority without caching or
  renewing freshness; inactive and foreign tokens disclose no metadata.
- Verify configured confidential-client Basic credentials before native token,
  revocation or historical token/revocation recovery effects or disclosure.
  Preserve installed unchanged public-client grants when adding confidential
  clients, and retain the existing current-primary-authority fences.
- Bind each explicit consent's independent identity/version to actual SQL and
  a same-transaction secondary lifecycle event. Use canonical transition names,
  distinguish actual scope changes from unchanged authorization, and preserve
  consent identity on explicit reconfirmation.
- Revoke a refresh family when concurrent use observes the winner's completed
  issuance, without credential redelivery or mutation during metadata recovery.
  Consumed refresh possession can withdraw its own surviving family.

- Add native password-session/public-client authorization, explicit consent,
  atomic S256 code exchange, rotating refresh and narrowly scoped revocation
  through the existing identity coordinator and current primary owners.
- Persist digest-only artifacts with exact root/parent/command lineage,
  explicit consent, immutable participant effects and forward-only migrations.
- Add metadata-only original-command recovery without credential regeneration
  or redelivery after ambiguous commits. Install native owner histories and
  retain original keys/configuration for outstanding grants and recovery.
