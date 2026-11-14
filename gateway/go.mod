module sentinel/gateway

go 1.24.7

// golang.org/x and gopkg.in are fetched through their official GitHub mirrors
// (the build environment only reaches GitHub). Everything is vendored, so
// Docker builds need no network for Go dependencies.
replace (
	golang.org/x/crypto => github.com/golang/crypto v0.28.0
	golang.org/x/mod => github.com/golang/mod v0.21.0
	golang.org/x/net => github.com/golang/net v0.30.0
	golang.org/x/sync => github.com/golang/sync v0.8.0
	golang.org/x/sys => github.com/golang/sys v0.26.0
	golang.org/x/term => github.com/golang/term v0.25.0
	golang.org/x/text => github.com/golang/text v0.19.0
	golang.org/x/tools => github.com/golang/tools v0.26.0
	gopkg.in/check.v1 => github.com/go-check/check v0.0.0-20201130134442-10cb98267c6c
	gopkg.in/yaml.v3 => github.com/go-yaml/yaml/v3 v3.0.1
)

require (
	github.com/corazawaf/libinjection-go v0.2.2
	github.com/jackc/pgx/v5 v5.7.1
	golang.org/x/crypto v0.28.0
)

require (
	github.com/jackc/pgpassfile v1.0.0 // indirect
	github.com/jackc/pgservicefile v0.0.0-20240606120523-5a60cdf6a761 // indirect
	github.com/jackc/puddle/v2 v2.2.2 // indirect
	github.com/skip2/go-qrcode v0.0.0-20200617195104-da1b6568686e // indirect
	golang.org/x/net v0.30.0 // indirect
	golang.org/x/sync v0.8.0 // indirect
	golang.org/x/text v0.19.0 // indirect
	gopkg.in/yaml.v3 v3.0.1 // indirect
)
