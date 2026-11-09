# Changelog

## Unreleased

- Document the native populated workload/OIDC/exchange coexistence profile and
  its separate immutable forward history. Existing ordinary-history consumers
  retain the original device migration and protocol APIs unchanged.

- Add separately composed native RFC 8628 device authorization for explicitly
  enabled public/Basic clients and recent authenticated password humans, with
  explicit comparison/CSRF, bounded polling and metadata-only unknown recovery.
  Adopt matching root/native versions and the optional forward migration;
  existing base OAuth bootstrap remains device-free. The selected profile is
  unbound and OAuth-only; pre-bound, HTTP/reference and OIDC profiles remain
  separate.
