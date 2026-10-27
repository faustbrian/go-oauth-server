module github.com/faustbrian/go-oauth-server/postgres

go 1.27.0

require (
	github.com/coreos/go-oidc/v3 v3.21.0
	github.com/faustbrian/go-audit v1.0.0
	github.com/faustbrian/go-audit/postgres v1.0.2-0.20261015062502-d62df280d85e
	github.com/faustbrian/go-authentication/v2 v2.0.2-0.20261015052822-d9f5132c7f68
	github.com/faustbrian/go-authorization/v3 v3.0.1-0.20261015052455-a55bbebb1060
	github.com/faustbrian/go-capability/postgres/identity v0.0.0-20261020152056-34ff02997fad
	github.com/faustbrian/go-capability/v2 v2.0.2-0.20261015044219-caab644d2fec
	github.com/faustbrian/go-clock v1.2.0
	github.com/faustbrian/go-http-client/v2 v2.1.0
	github.com/faustbrian/go-identifier/v2 v2.0.3-0.20261015083104-9892f17723c0
	github.com/faustbrian/go-identity v0.0.0-20261021074754-2eafc2592af0
	github.com/faustbrian/go-identity/delivery v0.0.0-20261015061706-1f0b46ab1053
	github.com/faustbrian/go-identity/delivery/postgres v0.0.0-20261015104034-f16881100907
	github.com/faustbrian/go-identity/email v0.0.0-20261018110349-e38aa409e7d8
	github.com/faustbrian/go-identity/http v0.0.0-20261025165940-ba26dedec95f
	github.com/faustbrian/go-identity/http/email v0.0.0-20261016125815-ad15f570f5a7
	github.com/faustbrian/go-identity/http/password v0.0.0-20261018164858-91ea1f9395f6
	github.com/faustbrian/go-identity/http/session v0.0.0-20261015110443-ed660e780fdc
	github.com/faustbrian/go-identity/otp v0.0.0-20261020215141-387cc56b91f6
	github.com/faustbrian/go-identity/otp/postgres v0.0.0-20261020215141-387cc56b91f6
	github.com/faustbrian/go-identity/password v0.0.0-20261020120243-19670fe0ec13
	github.com/faustbrian/go-identity/password/postgres v0.0.0-20261020215928-da005d59c806
	github.com/faustbrian/go-identity/phone v0.0.0-20261020215141-387cc56b91f6
	github.com/faustbrian/go-identity/postgres v0.0.0-20261023090537-c9d9dd761138
	github.com/faustbrian/go-identity/reference v0.0.0-20261016130230-88c81066b084
	github.com/faustbrian/go-identity/risk v0.0.0-20261021021214-46ae60703809
	github.com/faustbrian/go-identity/risk/hibp v0.0.0-20261015094324-5d5bf8236eb3
	github.com/faustbrian/go-identity/risk/postgres v0.0.0-20261020123641-81bbbbbffa8e
	github.com/faustbrian/go-identity/session v0.0.0-20261021074754-2eafc2592af0
	github.com/faustbrian/go-identity/session/postgres v0.0.0-20261023090842-cf1f8c1d8e20
	github.com/faustbrian/go-migrations/v3 v3.1.1-0.20261015110643-ca105f265cfc
	github.com/faustbrian/go-oauth-server v0.0.0-20261027010115-6c34ccf12a5a
	github.com/faustbrian/go-oauth-server/device v0.0.0-20261023095306-ca7b0b8a9b26
	github.com/faustbrian/go-oauth-server/oidc v0.0.0-20261026095351-baa3ff6f2bf5
	github.com/faustbrian/go-password/v2 v2.0.2-0.20261015050515-4eb0fefa60ff
	github.com/faustbrian/go-postgres v1.1.1-0.20260912090843-61261695bcc7
	github.com/faustbrian/go-rate-limit/v2 v2.0.1-0.20261015090634-0ebce3975fe1
	github.com/faustbrian/go-secret-envelope/v2 v2.0.1
	github.com/faustbrian/go-transactional-outbox/postgres/identity v0.0.0-20261020135213-493107bf82af
	github.com/jackc/pgx/v5 v5.11.0
	golang.org/x/oauth2 v0.37.0
)

require (
	github.com/cespare/xxhash/v2 v2.3.0 // indirect
	github.com/dlclark/regexp2/v2 v2.8.2 // indirect
	github.com/faustbrian/go-circuit-breaker v1.0.1 // indirect
	github.com/faustbrian/go-http-middleware/v2 v2.0.2-0.20261014105810-969bbbf00668 // indirect
	github.com/faustbrian/go-identity/http/magiclink v0.0.0-20261015110443-ed660e780fdc // indirect
	github.com/faustbrian/go-identity/http/mfa v0.0.0-20261016111510-a2bc669715c6 // indirect
	github.com/faustbrian/go-identity/http/otp v0.0.0-20261016084404-80e379c107f1 // indirect
	github.com/faustbrian/go-identity/magiclink v0.0.0-20261015110443-ed660e780fdc // indirect
	github.com/faustbrian/go-identity/magiclink/postgres v0.0.0-20261015113658-456332dee9d2 // indirect
	github.com/faustbrian/go-identity/mfa v0.0.0-20261018013113-bb569ec9d44c // indirect
	github.com/faustbrian/go-identity/mfa/postgres v0.0.0-20261023075430-665a40ff4c1a // indirect
	github.com/faustbrian/go-identity/risk/valkey v0.0.0-20261015094324-5d5bf8236eb3 // indirect
	github.com/faustbrian/go-identity/username v0.0.0-20261018153841-d825f044ef94 // indirect
	github.com/faustbrian/go-json-schema/v2 v2.0.0 // indirect
	github.com/faustbrian/go-migrations/v2 v2.0.0 // indirect
	github.com/faustbrian/go-openapi/v2 v2.0.3-0.20261015044355-77bfaaffc820 // indirect
	github.com/faustbrian/go-transactional-outbox/v2 v2.0.2-0.20261015062550-37ea15436ae9 // indirect
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
