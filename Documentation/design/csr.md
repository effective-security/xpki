# csr: design

## Purpose and position

`csr` holds the request vocabulary shared by the CA, the JWT package and
the CLIs: what a certificate request looks like as JSON/YAML
(`CertificateRequest`, `KeyRequest`, `X509Subject`, `X509Extension`), what
a registration authority sends to an issuer (`SignRequest`), and the code
that turns a request into a key plus a PEM CSR through a
`cryptoprov.Provider`, or a PEM CSR into an `x509.Certificate` template.
It also owns the subject and SAN rules (`PopulateName`, `ParseSAN`,
`ApplySAN`), the CRL distribution point encoder and the JSON/YAML `OID`
and `Duration` types. It depends on `cryptoprov` and `oid` only; `authority`,
`jwt` and `cmd/hsm-tool` depend on it.

## Core abstractions

| Abstraction                 | File         | Role                                                                                                                                       |
| --------------------------- | ------------ | ------------------------------------------------------------------------------------------------------------------------------------------ |
| `CertificateRequest`        | `csr.go`     | What to put in a CSR: common name, `Names` (C/ST/L/O/OU/email, lowercase keys), serial, `SAN` strings, `KeyRequest`, raw `Extensions`.      |
| `KeyRequest`                | `keyreq.go`  | `label`, `algo` (`RSA`/`ECDSA`, case-insensitive), `size` (bits or curve size), `purpose` (signing/encryption). Carries an unexported provider; `Generate()` dispatches to `GenerateRSAKey`/`GenerateECDSAKey` after validating the size. |
| `Provider`                  | `csrprov.go` | Thin wrapper over one `cryptoprov.Provider`: `GenerateKeyAndRequest`, `CreateRequestAndExportKey`, `SignRequest`, `NewKeyRequest`.          |
| `SignRequest`               | `csr.go`     | RA → issuer: PEM CSR, profile name, optional subject override, SAN list (nil = keep CSR names), raw extensions, optional validity.          |
| `Parse` / `ParsePEM`        | `csr.go`     | Verify the CSR signature and build an `x509.Certificate` template with subject, SANs, public key and every extension except BasicConstraints in `ExtraExtensions`, leaving policy to the issuer. |
| `SAN`, `ParseSAN`, `ApplySAN` | `san.go`   | Classify strings into DNS/IP/email/URI, validate (IDNA, label rules, wildcards), dedupe; strict since XPKI-059.                              |
| `SigAlgo`, `DefaultSigAlgo`, `SignatureAlgorithmer` | `keyreq.go`, `csrprov.go` | Choose the X.509 signature algorithm from the key: RSA 2048/3072 → SHA-256, ≥4096 → SHA-512, ECDSA by curve; a signer may dictate it (`SignatureAlgorithmer`, used by GCP KMS). |
| `OID`, `Duration`           | `types.go`   | JSON/YAML-friendly wrappers used by profiles and requests.                                                                                 |

## Main flows

```mermaid
flowchart LR
    R["CertificateRequest (JSON/YAML or code)"] --> V["Validate (common name)"]
    V --> G["KeyRequest.Generate<br/>validate size → provider.Generate*Key"]
    G --> I["provider.IdentifyKey → keyID, label"]
    I --> S["SignRequest(priv, req)<br/>subject, ParseSAN, extensions,<br/>SignatureAlgorithm = DefaultSigAlgo(priv)"]
    S --> X["x509.CreateCertificateRequest"]
    X --> PEM["CERTIFICATE REQUEST PEM"]
    I --> E["provider.ExportKey(keyID)<br/>PEM bytes (exportable) or pkcs11: URI"]
```

On the receiving side `ParsePEM` → `Parse` verifies the self-signature
(`CheckSignature`), so a CSR whose key does not match its signature is
rejected before any policy runs, and returns a template whose extensions
the issuer filters (`authority`, XPKI-049).

## Design decisions

- **Requests are data.** `KeyRequest` is a plain struct with string and
  int fields so it round-trips through YAML profiles
  (`authority/testdata/csrprofiles/*.yaml`) and CLI flags
  (`hsm-tool hsm generate --algo --size`). The provider is injected by
  `Provider.GenerateKeyAndRequest` for requests decoded from files.
- **`size` is overloaded.** It is the modulus size for RSA and the curve
  size (256/384/521) for ECDSA. Validation happens in `Generate`, before
  the provider is called, so an unsupported size never reaches a token or
  a KMS API.
- **Signature algorithm follows the key, never the request.** `SigAlgo`
  and `DefaultSigAlgo` never return SHA-1 and give RSA-3072 SHA-256
  (XPKI-114) so that GCP KMS keys and local keys sign the same way. A
  signer that only supports one algorithm advertises it through
  `SignatureAlgorithmer`.
- **Strict SANs.** Invalid names fail the request instead of being
  dropped; `SetSAN` keeps the old lenient behavior and is deprecated.
- **`Parse` is policy-free.** It keeps CSR extensions in
  `ExtraExtensions` and leaves allow-listing to the issuer, so the two
  packages have one place each for "what the CSR says" and "what the CA
  accepts".

## Extension points

- **A new key algorithm** touches `KeyRequest.Generate` (a new `case` and
  validator), `SigAlgo` (algo string → `x509.SignatureAlgorithm`) and
  `DefaultSigAlgo` (public key type → algorithm). Everything downstream
  (`SignRequest`, `Parse`) is key-type agnostic as long as `crypto/x509`
  supports the key.
- **Request vocabulary** grows by adding fields with JSON and YAML tags
  (lowercase YAML keys; uppercase keys are silently ignored by the
  decoder).

## Testing

`csrprov_test.go` is the only SoftHSM-dependent test and is gated with
`testenv.RequireFile`; everything else uses `inmemcrypto`. `san_test.go`
and `sigalgo_test.go` are table tests for the SAN rules and the hash
defaults.

## Post-quantum readiness

Implemented in v1.1: `KeyRequest` accepts `algo: ML-DSA` (or `MLDSA`,
case-insensitive) with `size: 44 | 65 | 87` (`AlgoMLDSA`, `MLDSA44/65/87`),
`Generate` calls `cryptoprov.KeyGenerator.GenerateMLDSAKey` after
validating the parameter set, `SigAlgo("ML-DSA", 65)` is `x509.MLDSA65`,
`DefaultSigAlgo` maps an `*mldsa.PublicKey` to the algorithm of its
parameter set, and `IsPostQuantumAlgo` recognises the algorithm names.
`SignRequest` and `Parse` needed no change: `x509.CreateCertificateRequest`
passes the whole TBS with a zero hash, which every ML-DSA signer of the
module accepts. The `DILITHIUM` alias proposed in PR 568 was dropped: the
keys are FIPS 204 ML-DSA, not round-3 Dilithium, and the name would
suggest an interoperability that does not exist.

Key-based detection lives in `certutil` (`IsPostQuantumKey`,
`IsPostQuantumCertificate`), the leaf package `authority`, `jwt` and the
CLIs share.
