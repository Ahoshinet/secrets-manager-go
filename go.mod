module github.com/Ahoshinet/secrets-manager-go

go 1.22

// Pin a toolchain with current net/http, TLS, and X.509 security fixes;
// older toolchains (e.g. go1.26.1) carry advisories reachable from this
// client when talking to a malicious HTTPS endpoint.
toolchain go1.26.4
