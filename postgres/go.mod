module github.com/faustbrian/go-oauth-server/postgres

go 1.27.0

require (
	github.com/faustbrian/go-audit v1.0.0
	github.com/faustbrian/go-audit/postgres v1.0.2-0.20261015062502-d62df280d85e
	github.com/faustbrian/go-authentication/v2 v2.0.2-0.20261015052822-d9f5132c7f68
	github.com/faustbrian/go-authorization/v3 v3.0.1-0.20261015052455-a55bbebb1060
	github.com/faustbrian/go-capability/postgres/identity v0.0.0-20261015133614-ab21810bd410
	github.com/faustbrian/go-capability/v2 v2.0.2-0.20261015044219-caab644d2fec
	github.com/faustbrian/go-clock v1.2.0
	github.com/faustbrian/go-http-client/v2 v2.1.0
	github.com/faustbrian/go-identifier/v2 v2.0.3-0.20261015083104-9892f17723c0
	github.com/faustbrian/go-identity v0.0.0-20261016003032-9785b1c5a551
	github.com/faustbrian/go-identity/delivery v0.0.0-20261015061706-1f0b46ab1053
	github.com/faustbrian/go-identity/delivery/postgres v0.0.0-20261015104034-f16881100907
	github.com/faustbrian/go-identity/email v0.0.0-20261016125355-af740fb7fb76
	github.com/faustbrian/go-identity/http v0.0.0-20261016072258-33c559fa65a2
	github.com/faustbrian/go-identity/http/email v0.0.0-20261016125815-ad15f570f5a7
	github.com/faustbrian/go-identity/http/password v0.0.0-20261015110443-ed660e780fdc
	github.com/faustbrian/go-identity/http/session v0.0.0-20261015110443-ed660e780fdc
	github.com/faustbrian/go-identity/otp v0.0.0-20261016072258-33c559fa65a2
	github.com/faustbrian/go-identity/otp/postgres v0.0.0-20261016084404-80e379c107f1
	github.com/faustbrian/go-identity/password v0.0.0-20261015110443-ed660e780fdc
	github.com/faustbrian/go-identity/password/postgres v0.0.0-20261016125815-ad15f570f5a7
	github.com/faustbrian/go-identity/postgres v0.0.0-20261018044528-4c83b9a1ca25
	github.com/faustbrian/go-identity/reference v0.0.0-20261016130230-88c81066b084
	github.com/faustbrian/go-identity/risk v0.0.0-20261018030503-26fb47a06e0e
	github.com/faustbrian/go-identity/risk/hibp v0.0.0-20261015094324-5d5bf8236eb3
	github.com/faustbrian/go-identity/risk/postgres v0.0.0-20261015104034-f16881100907
	github.com/faustbrian/go-identity/session v0.0.0-20261016125355-af740fb7fb76
	github.com/faustbrian/go-identity/session/postgres v0.0.0-20261016125355-af740fb7fb76
	github.com/faustbrian/go-migrations/v3 v3.1.1-0.20261015110643-ca105f265cfc
	github.com/faustbrian/go-oauth-server v0.0.0-20261018084256-6e1d2a47ddef
	github.com/faustbrian/go-password/v2 v2.0.2-0.20261015050515-4eb0fefa60ff
	github.com/faustbrian/go-postgres v1.1.1-0.20260912090843-61261695bcc7
	github.com/faustbrian/go-secret-envelope/v2 v2.0.1
	github.com/faustbrian/go-transactional-outbox/postgres/identity v0.0.0-20261018044906-f4380909987d
	github.com/jackc/pgx/v5 v5.11.0
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
	github.com/faustbrian/go-identity/mfa v0.0.0-20261016110849-a4627291653b // indirect
	github.com/faustbrian/go-identity/mfa/postgres v0.0.0-20261016125355-af740fb7fb76 // indirect
	github.com/faustbrian/go-identity/risk/valkey v0.0.0-20261015094324-5d5bf8236eb3 // indirect
	github.com/faustbrian/go-json-schema/v2 v2.0.0 // indirect
	github.com/faustbrian/go-migrations/v2 v2.0.0 // indirect
	github.com/faustbrian/go-openapi/v2 v2.0.3-0.20261015044355-77bfaaffc820 // indirect
	github.com/faustbrian/go-rate-limit/v2 v2.0.1-0.20261015090634-0ebce3975fe1 // indirect
	github.com/faustbrian/go-transactional-outbox/v2 v2.0.2-0.20261015062550-37ea15436ae9 // indirect
	github.com/felixge/httpsnoop v1.1.0 // indirect
	github.com/jackc/pgpassfile v1.0.0 // indirect
	github.com/jackc/pgservicefile v0.0.0-20240606120523-5a60cdf6a761 // indirect
	github.com/jackc/puddle/v2 v2.2.2 // indirect
	github.com/mfridman/interpolate v0.0.2 // indirect
	github.com/pressly/goose/v3 v3.28.0 // indirect
	github.com/sethvargo/go-retry v0.4.0 // indirect
	go.opentelemetry.io/otel v1.47.0 // indirect
	go.opentelemetry.io/otel/metric v1.47.0 // indirect
	go.opentelemetry.io/otel/trace v1.47.0 // indirect
	go.uber.org/multierr v1.11.0 // indirect
	go.yaml.in/yaml/v3 v3.0.5 // indirect
	golang.org/x/crypto v0.57.0 // indirect
	golang.org/x/net v0.60.0 // indirect
	golang.org/x/oauth2 v0.37.0 // indirect
	golang.org/x/sync v0.23.0 // indirect
	golang.org/x/sys v0.48.0 // indirect
	golang.org/x/text v0.42.0 // indirect
)
