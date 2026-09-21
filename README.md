# xpki

[![Go Reference](https://pkg.go.dev/badge/github.com/effective-security/xpki.svg)](https://pkg.go.dev/github.com/effective-security/xpki)

Go library and CLI tools for building PKI: hardware or cloud backed keys
(PKCS#11, AWS KMS, GCP KMS), certificate signing requests, a certificate
authority with policy profiles, OCSP and CRL signing, certificate bundling
and verification, and JWT/DPoP token issuance and validation.

The module is `github.com/effective-security/xpki` and targets Go 1.27.

## Packages

| Package                   | Purpose                                                                                          |
| ------------------------- | ------------------------------------------------------------------------------------------------ |
| `cryptoprov`              | Provider abstraction (`Provider`, `KeyManager`, `Crypto`), config loading, key URIs, PEM helpers |
| `crypto11`                | PKCS#11 provider (HSM, SoftHSM): `crypto.Signer`/`crypto.Decrypter` backed by device keys        |
| `cryptoprov/awskmscrypto` | AWS KMS provider                                                                                 |
| `cryptoprov/gcpkmscrypto` | Google Cloud KMS provider                                                                        |
| `cryptoprov/inmemcrypto`  | In-memory provider for tests and development                                                     |
| `csr`                     | CSR generation and parsing, key requests, SAN and CRL distribution point encoding                |
| `authority`               | Certificate Authority: issuers, certificate profiles, `Sign`, OCSP and CRL signing               |
| `certutil`                | Certificate, PEM, chain and bundle helpers, hashes, OCSP request creation                        |
| `jwt`                     | JWT signing and verification, claims, static and remote JWKS key sets                            |
| `jwt/dpop`                | DPoP proof creation and verification (RFC 9449)                                                  |
| `jwt/accesstoken`         | Opaque access-token helpers on top of `jwt`                                                      |
| `jwt/oauth2client`        | OAuth2 client for token endpoints                                                                |
| `dataprotection`          | Symmetric AEAD protection of small payloads and JSON objects                                     |
| `armor`                   | Armored (PEM-like) block decoding                                                                |
| `oid`                     | Human-readable names for key usages and object identifiers                                       |
| `x/print`                 | Pretty printers for certificates, CSRs, CRLs and OCSP responses                                  |
| `testca`                  | Test-only CA and certificate generator                                                           |

See [`Documentation/codemap.md`](Documentation/codemap.md) for entry points
and invariants per package, [`FINDINGS.md`](FINDINGS.md) for known defects,
and [`ROADMAP.md`](ROADMAP.md) for planned work.

## Install

```sh
go get github.com/effective-security/xpki
go install github.com/effective-security/xpki/cmd/hsm-tool@latest
go install github.com/effective-security/xpki/cmd/xpki-tool@latest
```

## Configuration

### Crypto provider

A provider is described by a small JSON or YAML token config. The
`Manufacturer` selects the registered loader; the remaining fields are
provider specific. Import the provider package for its side-effect
registration.

SoftHSM / PKCS#11 (`crypto11`, manufacturer `SoftHSM`):

```json
{
  "Manufacturer": "SoftHSM",
  "Path": "/usr/lib/softhsm/libsofthsm2.so",
  "TokenLabel": "xpki_unittest",
  "Pin": "file:/home/me/softhsm2/xpki_pin.txt"
}
```

AWS KMS (`awskmscrypto`, manufacturer `AWSKMS`):

```json
{
  "Manufacturer": "AWSKMS",
  "Model": "14555",
  "Attributes": "Endpoint=http://localhost:14555,Region=us-west-2"
}
```

In-memory (`inmemcrypto`, manufacturer `inmem`):

```json
{
  "Manufacturer": "inmem",
  "TokenLabel": "inmem_unittest",
  "Pin": "file:inmem_pin.txt"
}
```

`Pin` accepts a literal value, `file:<path>`, or an environment reference,
see `cryptoprov.TokenConfig` in the code map.

Private keys that live in a provider are referenced by a PKCS#11 style URI
and can be used anywhere a PEM key is accepted (issuer config, JWT config):

```text
pkcs11:manufacturer=AWSKMS;id=c98c624e-3609-4d8f-a615-9031b3a811d4;serial=arn:aws:kms:eu-west-2:111122223333:key/c98c624e-3609-4d8f-a615-9031b3a811d4;type=private
```

### Certificate Authority

```yaml
authority:
  issuers:
    - label: TrustyCA
      type: trusty
      cert: /tmp/xpki/certs/l2_ca.pem
      key: /tmp/xpki/certs/l2_ca.key # PEM file or pkcs11: URI
      ca_bundle: /tmp/xpki/certs/l1_ca.pem
      root_bundle: /tmp/xpki/certs/root_ca.pem
      aia:
        issuer_url: http://localhost:7880/v1/cert/${ISSUER_ID}
        crl_url: http://localhost:7880/v1/crl/${ISSUER_ID}
        ocsp_url: http://localhost:7880/v1/ocsp

profiles:
  server:
    expiry: 168h
    backdate: 30m
    usages: [signing, key encipherment, server auth]
    allowed_extensions:
      - 1.3.6.1.5.5.7.1.1 # AIA
      - 2.5.29.17 # SAN
```

A profile controls validity, key usages, allowed extensions, name and SAN
policies, and path length. Requester CSR fields not permitted by the profile
are dropped or rejected at `Issuer.Sign`.

### JWT provider

```yaml
issuer: trusty-dev.com
token_expiry: 12h
kid: 0
keys:
  - id: 0
    seed: <symmetric seed>
```

or, for an asymmetric signer:

```yaml
issuer: trusty-dev.com
private_key: pkcs11:manufacturer=AWSKMS;id=...;type=private
```

Token verification against an OpenID Connect issuer:

```yaml
issuer: https://accounts.google.com
jwks_uri: https://www.googleapis.com/oauth2/v3/certs
```

## Usage

### Load providers and sign with an HSM key

```go
import (
    "github.com/effective-security/xpki/cryptoprov"
    _ "github.com/effective-security/xpki/crypto11"                 // registers "SoftHSM"
    _ "github.com/effective-security/xpki/cryptoprov/awskmscrypto"  // registers "AWSKMS"
)

crypto, err := cryptoprov.Load("/etc/xpki/softhsm.json", []string{"/etc/xpki/awskms.json"})
if err != nil {
    return err
}
// Load a key by PEM file or by pkcs11: URI, whichever the file holds.
signer, err := crypto.NewSignerFromFromFile("/etc/xpki/ca.key")
```

### Create a key and CSR

```go
prov := csr.NewProvider(crypto.Default())
req := &csr.CertificateRequest{
    CommonName: "localhost",
    SAN:        []string{"localhost", "127.0.0.1", "spiffe://trusty/all"},
    KeyRequest: prov.NewKeyRequest("server", "ECDSA", 256, csr.SigningKey),
    Names:      []csr.X509Name{{Country: "US", Organization: "trusty.com"}},
}
csrPEM, priv, keyID, err := prov.GenerateKeyAndRequest(req)
```

### Run a CA

```go
cfg, err := authority.LoadConfig("/etc/xpki/ca-config.yaml")
if err != nil {
    return err
}
ca, err := authority.NewAuthority(cfg, crypto)
if err != nil {
    return err
}
issuer, err := ca.GetIssuerByProfile("server")
if err != nil {
    return err
}
cert, certPEM, err := issuer.Sign(csr.SignRequest{
    Request: string(csrPEM),
    Profile: "server",
    SAN:     []string{"localhost"},
})
```

`Issuer.SignOCSP` and the CRL helpers produce signed OCSP responses and
CRLs for the issuer's certificates.

### Verify a certificate chain

```go
bundle, status, err := certutil.LoadAndVerifyBundleFromPEM(
    "server.pem", "intermediates.pem", "roots.pem",
    certutil.WithKeyUsages(x509.ExtKeyUsageServerAuth),
)
```

### Issue and verify JWTs

```go
prov, err := jwt.LoadProvider("/etc/xpki/jwtprov.yaml", crypto)
if err != nil {
    return err
}
claims := jwt.CreateClaims("jti-1", "subject", prov.Issuer(), []string{"api"}, time.Hour, nil)
token, err := prov.Sign(ctx, claims)

parsed, err := prov.ParseToken(ctx, token, &jwt.VerifyConfig{
    ExpectedIssuer:   prov.Issuer(),
    ExpectedAudience: []string{"api"},
})
```

Tokens from a third-party OIDC issuer are verified with
`jwt.NewParser(cfg)`, which loads keys from a static JWKS or a `jwks_uri`
and refreshes them on unknown key IDs.

## CLI tools

- [hsm-tool](cmd/hsm-tool/README.md): list, inspect, generate and delete
  keys in an HSM or KMS; create CSRs and sign certificates with those keys.
- [xpki-tool](cmd/xpki-tool/README.md): inspect and validate certificates,
  CSRs, CRLs and OCSP responses.

```sh
hsm-tool --cfg /tmp/xpki/softhsm_unittest.json hsm list
xpki-tool cert info server.pem
```

## Development

Requirements: Go 1.27, a C compiler for PKCS#11/cgo, SoftHSM2
(`softhsm2-util` and its module), and Docker for the local AWS KMS emulator.
Generating a new test PIN also requires `openssl`.

`make hsmconfig` builds `bin/hsm-tool`, initializes the test token using
`softhsm2-util`, then verifies the generated configuration and PIN with
`bin/hsm-tool --cfg /tmp/xpki/softhsm_unittest.json hsm list`.
OpenSC (`pkcs11-tool`) is optional: it is needed only when invoking
`scripts/config-softhsm.sh` directly with `--list-slots` or `--list-object`.

```sh
make tools            # golangci-lint, cov-report, govulncheck
make hsmconfig        # create the SoftHSM token and /tmp/xpki/softhsm_unittest.json
make start-local-kms  # start two local-kms containers on :14555 and :14556
make test             # full test suite (needs the two steps above)
make test RACE=true   # under the race detector
make covtest coverage # coverage report
make lint             # gofmt, go vet, golangci-lint
make build            # builds bin/hsm-tool and bin/xpki-tool
make docs             # regenerate Documentation/*.md (gomarkdoc) and CLI help dumps
make all              # clean, tools, generate, hsmconfig, start-local-kms, covtest
```

The AWS emulator does not check credentials, but the SDK requires them:

```sh
export AWS_ACCESS_KEY_ID=notusedbyemulator
export AWS_SECRET_ACCESS_KEY=notusedbyemulator
export AWS_DEFAULT_REGION=us-west-2
```

CI (`.github/workflows/unittest.yml`) runs `make covtest` with SoftHSM and
local-kms and requires 80% total coverage. Merges to `main` are tagged from
`.VERSION` plus the commit count.

## Contributing

Read [`AGENTS.md`](AGENTS.md) for coding, error handling, testing and
documentation rules, and keep [`Documentation/codemap.md`](Documentation/codemap.md)
current in the same change as the code.

Generated API reference (`make docs`, gomarkdoc, do not edit): [Documentation/api](Documentation/api)

## License

See [LICENSE](LICENSE).
