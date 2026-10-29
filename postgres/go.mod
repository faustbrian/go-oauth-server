module github.com/faustbrian/go-oauth-server/postgres

go 1.27.0

require (
	github.com/coreos/go-oidc/v3 v3.21.0
	github.com/faustbrian/go-audit v1.0.0
	github.com/faustbrian/go-audit/postgres v1.0.2-0.20261015062502-d62df280d85e
	github.com/faustbrian/go-authentication/v2 v2.0.2-0.20261015052822-d9f5132c7f68
	github.com/faustbrian/go-authorization/v3 v3.0.1-0.20261015052455-a55bbebb1060
	github.com/faustbrian/go-capability/postgres/identity v0.0.0-20261025210917-9c2e20446169
	github.com/faustbrian/go-capability/v2 v2.0.2-0.20261015044219-caab644d2fec
	github.com/faustbrian/go-clock v1.2.0
	github.com/faustbrian/go-http-client/v2 v2.1.0
	github.com/faustbrian/go-identifier/v2 v2.0.3-0.20261015083104-9892f17723c0
	github.com/faustbrian/go-identity v0.0.0-20261025171642-473945c93248
	github.com/faustbrian/go-identity/delivery v0.0.0-20261015061706-1f0b46ab1053
	github.com/faustbrian/go-identity/delivery/postgres v0.0.0-20261015104034-f16881100907
	github.com/faustbrian/go-identity/email v0.0.0-20261018110349-e38aa409e7d8
	github.com/faustbrian/go-identity/http v0.0.0-20261026224707-56253b26455f
	github.com/faustbrian/go-identity/http/email v0.0.0-20261018014422-615ac00e2231
	github.com/faustbrian/go-identity/http/password v0.0.0-20261019015043-422b56d1052b
	github.com/faustbrian/go-identity/http/session v0.0.0-20261021120851-ab3f4a286f93
	github.com/faustbrian/go-identity/otp v0.0.0-20261023111815-6bc180019089
	github.com/faustbrian/go-identity/otp/postgres v0.0.0-20261023131125-38648609fbb6
	github.com/faustbrian/go-identity/password v0.0.0-20261023192729-324d7aeea43e
	github.com/faustbrian/go-identity/password/postgres v0.0.0-20261023214952-58d491b11060
	github.com/faustbrian/go-identity/phone v0.0.0-20261020215141-387cc56b91f6
	github.com/faustbrian/go-identity/postgres v0.0.0-20261025193805-9ccf9a606602
	github.com/faustbrian/go-identity/reference v0.0.0-20261028180115-9a0e8a020cce
	github.com/faustbrian/go-identity/risk v0.0.0-20261024004351-b030e8e364ac
	github.com/faustbrian/go-identity/risk/hibp v0.0.0-20261026030542-4e0bab3755d5
	github.com/faustbrian/go-identity/risk/postgres v0.0.0-20261024005826-5910465e0e2e
	github.com/faustbrian/go-identity/session v0.0.0-20261024134726-e9528953435b
	github.com/faustbrian/go-identity/session/postgres v0.0.0-20261025174242-49fde04d4b1b
	github.com/faustbrian/go-migrations/v3 v3.1.1-0.20261015110643-ca105f265cfc
	github.com/faustbrian/go-oauth-server v0.0.0-20261029102506-5102ba3e77c4
	github.com/faustbrian/go-oauth-server/device v0.0.0-20261023095306-ca7b0b8a9b26
	github.com/faustbrian/go-oauth-server/oidc v0.0.0-20261026095351-baa3ff6f2bf5
	github.com/faustbrian/go-password/v2 v2.0.2-0.20261015050515-4eb0fefa60ff
	github.com/faustbrian/go-postgres v1.1.1-0.20260912090843-61261695bcc7
	github.com/faustbrian/go-rate-limit/v2 v2.0.1-0.20261015090634-0ebce3975fe1
	github.com/faustbrian/go-secret-envelope/v2 v2.0.1
	github.com/faustbrian/go-transactional-outbox/postgres/identity v0.0.0-20261026011803-e03d6969b19b
	github.com/jackc/pgx/v5 v5.11.0
	golang.org/x/oauth2 v0.37.0
)

require (
	github.com/cespare/xxhash/v2 v2.3.0 // indirect
	github.com/dlclark/regexp2/v2 v2.8.2 // indirect
	github.com/faustbrian/go-circuit-breaker v1.0.1 // indirect
	github.com/faustbrian/go-http-middleware/v2 v2.0.2-0.20261014105810-969bbbf00668 // indirect
	github.com/faustbrian/go-identity/anonymous v0.0.0-20261023043948-50a36bd23473 // indirect
	github.com/faustbrian/go-identity/anonymous/postgres v0.0.0-20261023055944-d2f004fd7b32 // indirect
	github.com/faustbrian/go-identity/http/anonymous v0.0.0-20261021120851-ab3f4a286f93 // indirect
	github.com/faustbrian/go-identity/http/magiclink v0.0.0-20261015110443-ed660e780fdc // indirect
	github.com/faustbrian/go-identity/http/mfa v0.0.0-20261025150519-83149c8dcdf6 // indirect
	github.com/faustbrian/go-identity/http/organization v0.0.0-20261027002442-b1f1fed03d25 // indirect
	github.com/faustbrian/go-identity/http/otp v0.0.0-20261019052145-b88e7097fe0f // indirect
	github.com/faustbrian/go-identity/http/passkey v0.0.0-20261025150519-83149c8dcdf6 // indirect
	github.com/faustbrian/go-identity/http/phone v0.0.0-20261020215928-da005d59c806 // indirect
	github.com/faustbrian/go-identity/magiclink v0.0.0-20261015110443-ed660e780fdc // indirect
	github.com/faustbrian/go-identity/magiclink/postgres v0.0.0-20261015113658-456332dee9d2 // indirect
	github.com/faustbrian/go-identity/mfa v0.0.0-20261025081547-dcd89dfc3e34 // indirect
	github.com/faustbrian/go-identity/mfa/postgres v0.0.0-20261025194758-fdf6e3f9e868 // indirect
	github.com/faustbrian/go-identity/risk/valkey v0.0.0-20261015094324-5d5bf8236eb3 // indirect
	github.com/faustbrian/go-identity/username v0.0.0-20261018153841-d825f044ef94 // indirect
	github.com/faustbrian/go-json-schema/v2 v2.0.0 // indirect
	github.com/faustbrian/go-migrations/v2 v2.0.0 // indirect
	github.com/faustbrian/go-openapi/v2 v2.0.3-0.20261015044355-77bfaaffc820 // indirect
	github.com/faustbrian/go-organization v0.0.0-20261026235409-4f99657f4775 // indirect
	github.com/faustbrian/go-organization/postgres v0.0.0-20261027002207-d1f72f54441c // indirect
	github.com/faustbrian/go-passkey v0.0.0-20261025074150-30bf01583c86 // indirect
	github.com/faustbrian/go-passkey/postgres v0.0.0-20261025200953-935ddaffedb1 // indirect
	github.com/faustbrian/go-transactional-outbox/v2 v2.1.1-0.20261022172917-6ed5e0861542 // indirect
	github.com/faustbrian/go-webauthn v0.0.0-20261020074004-ed89b240ab20 // indirect
	github.com/faustbrian/go-webauthn/postgres v0.0.0-20261024120438-4801d794c5dc // indirect
	github.com/felixge/httpsnoop v1.1.0 // indirect
	github.com/go-jose/go-jose/v4 v4.1.4 // indirect
	github.com/jackc/pgpassfile v1.0.0 // indirect
	github.com/jackc/pgservicefile v0.0.0-20240606120523-5a60cdf6a761 // indirect
	github.com/jackc/puddle/v2 v2.2.2 // indirect
	github.com/mfridman/interpolate v0.0.2 // indirect
	github.com/nyaruka/phonenumbers/v2 v2.0.14 // indirect
	github.com/pressly/goose/v3 v3.28.0 // indirect
	github.com/sethvargo/go-retry v0.4.0 // indirect
	go.opentelemetry.io/otel v1.47.0 // indirect
	go.opentelemetry.io/otel/metric v1.47.0 // indirect
	go.opentelemetry.io/otel/trace v1.47.0 // indirect
	go.uber.org/multierr v1.11.0 // indirect
	go.yaml.in/yaml/v3 v3.0.5 // indirect
	golang.org/x/crypto v0.57.0 // indirect
	golang.org/x/net v0.60.0 // indirect
	golang.org/x/sync v0.23.0 // indirect
	golang.org/x/sys v0.48.0 // indirect
	golang.org/x/text v0.42.0 // indirect
	google.golang.org/protobuf v1.36.12 // indirect
)
