# xpki v1.0 release notes

v1.0 closes most of the 2026-09-20 audit (`FINDINGS.md`). This release
fixes a CSR extension bypass in `authority`, deadlocks, data races and panics
in `authority`, `crypto11`, `cryptoprov`, `certutil`, `jwt` and the KMS
providers, and adds opt-in hardening in `jwt/dpop` and `jwt`. Finding IDs
(`XPKI-NNN`) refer to the audit; their full records are in git history before
this release.

## Major fixes

### Security

- **authority** (XPKI-049, 050): `Issuer.Sign` no longer copies CSR
  extensions into the certificate. SKI, KU, SAN, BasicConstraints, AKI, EKU
  and OCSP no-check are always dropped from a CSR. Any other CSR extension
  must be listed in `allowed_extensions`; an empty list allows none. Each
  certificate has one extension per OID: profile `extensions` win over the
  `SignRequest`, and the `SignRequest` wins over the CSR.
- **authority** (XPKI-054): `SignRequest.NotBefore/NotAfter` must be inside
  the profile expiry and the backdate window, and an inverted range is
  rejected.
- **authority** (XPKI-057): a populated `allowed_profiles` now filters every
  profile, not only wildcard ones.
- **certutil** (XPKI-041): the system roots are no longer trusted implicitly
  when no roots are configured.
- **certutil** (XPKI-037, 039): AIA fetches check the status, limit the body
  size, honour a context and fetch each URL at most once per call.
- **certutil** (XPKI-121): `CreateOCSPRequest` checks that the issuer signed
  the certificate, not only that the names match.
- **jwt** (XPKI-070, 071, 072): `RemoteKeySet` has a timeout, a body limit and
  a refresh cooldown. A token without a `kid` is accepted only when one key is
  eligible. `PublicKeys` in the parser config are used.
- **jwt** (XPKI-112): a provider verifies only tokens with its own signing
  algorithm. The HS256 key ring of `NewProvider` no longer accepts HS384 or
  HS512 tokens signed with a ring key, and an RS256 provider no longer
  accepts RS384/RS512 tokens signed with its private key.
- **jwt** (XPKI-109): `Sign` writes `exp`, `iat` and `nbf` as NumericDate
  whatever their Go type, with the new `MapClaims.NormalizeTimeClaims`,
  which `jwt/accesstoken` uses too. Before, a `time.Time` was signed as an
  RFC 3339 string that `ParseToken` could not read, so the check was skipped
  and a token with `nbf` tomorrow was accepted today. `MapClaims.Time` now
  also reads RFC 3339 strings and `NumericDate` values, so such a claim in
  an existing token is validated instead of ignored, and rejects a `uint64`
  above `MaxInt64` instead of wrapping it to a negative time.
- **jwt/dpop** (XPKI-074, 075, 076): all advertised algorithms verify (with
  go-jose). There is an opt-in replay cache, `ath` and `cnf.jkt` binding, a
  trusted `ExternalURL`, and `htu` paths are compared case-sensitively.
- **jwt/dpop** (XPKI-108): the `htm` claim must equal the request method
  exactly, since HTTP methods are case-sensitive (RFC 9110 §9.1); a proof
  for `get` no longer verifies a `GET` request.
- **jwt/accesstoken** (XPKI-078): every new `pat.` token expires.

### Concurrency, deadlocks and panics

- **authority** (XPKI-051, 052, 053): `NewIssuer` no longer deadlocks with
  `aia.delegated_ocsp_profile`. The OCSP responder is published atomically.
  When responder renewal fails, `SignOCSP` keeps using a still-valid responder
  and otherwise returns an error; it never falls back to the CA key.
- **crypto11** (XPKI-001..007, 011): modules are reference-counted per library
  path and finalized on the last `Close`. Session pools are bounded per slot
  and created on demand, and `Init` releases everything on error.
  CK_ULONG decoding is checked. Token selection matches every configured
  selector.
- **cryptoprov** (XPKI-016, 026, 113): the provider registry is synchronized.
  Duplicate and nil providers are errors.
- **authority** (XPKI-055): `Authority` is safe for concurrent use. Its
  issuer and profile maps are an immutable snapshot that `AddIssuer` and
  `AddProfile` replace, so lookups never race with registration (before,
  a profile registered at runtime while another request listed the profiles
  could crash the process with `concurrent map iteration and map write`).
  `Authority.Profiles`, `Authority.Issuers` and `Issuer.Profiles` return
  copies. `AddIssuer` checks before it publishes, so a rejected issuer
  (a label already registered, a profile already registered by another
  issuer, or a nil profile) leaves the registry unchanged instead of
  half-registering the issuer. A registered `*CertProfile` is shared with
  every reader and must not be modified after `AddProfile`; register a
  `Copy` to change one.
- **cmd/hsm-tool** (XPKI-084): an empty (`--cfg ""`), unreadable or invalid
  `--cfg` fails the command with exit status 1 and `hsm-tool: error: use
--cfg flag ...` or `hsm-tool: error: unable to initialize crypto
providers: ...` instead of a panic with a stack trace (exit 2). An omitted
  `--cfg` stays a usage error (exit 80).
- **jwt** (XPKI-125, found by the review of this batch): `Valid`,
  `VerifyExpiresAt`, `VerifyIssuedAt` and `VerifyNotBefore` reject a present
  `exp`, `iat` or `nbf` that is not a time (`invalid exp claim: ...`). Before,
  such a claim was treated as absent, so a verified token with `"exp":
"tomorrow"` or `"exp": true` never expired (RFC 7519 §7.2 requires
  rejecting a claim with an unexpected value). `MapClaims.Time` still returns
  nil for it.
- **cryptoprov/inmemcrypto, testprov, testca** (XPKI-017, 062, 107): key maps
  and counters are synchronized.
- **cryptoprov/awskmscrypto** (XPKI-025, 031..034): `Sign` checks its
  options against the algorithms KMS reports for the key before any RPC, so
  nil options no longer panic. `GenerateRSAKey` rejects encryption keys
  (purpose 2) and unsupported sizes before creating anything, and `GetKey`
  returns an error for an `ENCRYPT_DECRYPT` key or a key pending deletion
  instead of a signer that cannot sign, and a key whose public key cannot
  be fetched after creation is scheduled for deletion. `EnumKeys` applies
  the prefix to the key label (the KMS description), describes keys 8 at a
  time with 1000-key pages, leaves out (and logs) keys the caller may not
  describe, and returns an error instead of a silently incomplete listing
  when a `DescribeKey` is throttled or fails otherwise. `Init` leaves
  credentials to the SDK default chain, which already reads the same
  environment variables first.
- **cryptoprov/gcpkmscrypto** (XPKI-018..025, 116..124): `Close` is safe with
  concurrent calls. Key versions are resolved instead of the hard-coded
  `cryptoKeyVersions/1`. `Sign` enforces the key's KMS algorithm. The
  `Endpoint` attribute is applied. Key ids are sanitized and get a 40-bit
  random suffix. Key generation polls the version state, and the wait ends on
  `Close`.
- **certutil** (XPKI-035, 036, 038, 042, 103, 115): `Bundler` is safe for
  concurrent use. Nil and empty inputs return errors instead of panicking.
  `SortBundlesByExpiration` no longer modifies its input. A wrong PKCS#8
  password is reported as `x509.IncorrectPasswordError`.
- **jwt** (XPKI-066, 104): `NewProviderWithSymmetricKey` verifies its own
  tokens, and `WithHeaders` no longer panics.
- **jwt** (XPKI-073): the JOSE header no longer carries a random `jti`,
  which RFC 7519 defines as a payload claim. `Sign` signs the caller's
  `jti` claim as given and does not generate one.
- **jwt/oauth2client** (XPKI-081): `Provider` is safe for concurrent use.
  `RegisterClient` publishes a registration to the provider, domain and
  email indexes at once, a rejected registration leaves the registry
  unchanged (before, the entries written before the conflict stayed), and
  an `override` removes the previous client of that provider id from every
  index (before, its other domains and emails kept resolving to it).
- **jwt/oauth2client** (XPKI-080): `Client` owns a deep copy of its
  `ClientConfig`, `Config()` returns a copy, and `SetClientSecret`,
  `SetPubKey` and `CreateTokenRequest` are synchronized. The key parsed from
  `PubKey` is returned by the new `PublicKey()`; `PubKey` and `JwksURL` are
  documented as settings for a caller's verifier, since this package verifies
  no tokens. `New(nil)` returns an error instead of panicking.
- **jwt/accesstoken** (XPKI-079): a nil data protection provider returns an
  error instead of panicking.

### Correctness and interoperability

- **csr** (XPKI-059): subject alternative names are validated and
  deduplicated. The new `csr.ParseSAN` classifies each name (URI when it
  contains `://`, then IP, then email, else DNS), rejects an empty, invalid
  or non-ASCII name and drops duplicates (DNS and email case-insensitively,
  IP by value, URI by its serialized form, first occurrence kept). A DNS
  name must be at most 253 characters of labels of 1 to 63 letters, digits,
  hyphens or underscores that neither start nor end with a hyphen, with a
  wildcard only as the whole first label and no trailing dot;
  internationalized names are converted to A-labels. The new `csr.ApplySAN`
  replaces a template's names with the parsed ones (nil keeps the CSR names,
  an empty slice clears them, and every raw SAN extension is removed from a
  copy of `ExtraExtensions`) and returns the error; `SetSAN` is deprecated
  and skips invalid names with an error log. `SAN.Validate` applies the
  same rules to names that are already classified (an email SAN must be a
  bare address `mail.ParseAddress` accepts). `csr.Provider.SignRequest`
  fails on an invalid SAN instead of skipping it, and `authority.Issuer.Sign`
  rejects an invalid name both in `SignRequest.SAN` and among the names
  copied from the CSR (`CSR: invalid SAN ...`) instead of issuing it as a
  bogus DNS name. A URI SAN given as a string must contain `://`; `urn:` or
  `mailto:` values, which were issued as DNS names before, are rejected.
- **csr, gcpkmscrypto** (XPKI-114): `csr.DefaultSigAlgo` and `csr.SigAlgo`
  sign 3072-bit RSA keys with SHA-256 instead of SHA-384 (NIST SP 800-57
  rates RSA-3072 at 128 bits, and GCP KMS offers only SHA-256 algorithms
  for 3072-bit keys, so a 3072-bit GCP key could sign neither a CSR nor a
  certificate). `DefaultSigAlgo` also honours the new
  `csr.SignatureAlgorithmer` interface (`SignatureAlgorithm()
x509.SignatureAlgorithm`), which `gcpkmscrypto.Signer` implements from its
  KMS algorithm, so 4096-bit SHA-256 keys and PSS keys sign with the hash
  and padding KMS accepts.
- **crypto11** (XPKI-110): a `PKCS11Lib` recovers after its token was
  logged out, or removed and reinserted, instead of failing every operation
  until a new `Init`. A pooled session whose handle went stale is replaced
  (with the other idle sessions of the slot) and the operation retried
  once; when the slot `Init` logged in to is found logged out (the
  operation failed with `CKR_USER_NOT_LOGGED_IN`, an invalid object handle
  or a missing key while the session state is public, since private
  objects are invisible without a login, or another caller re-logged in
  meanwhile) it is logged in again once, with the configured PIN, and the
  operation retried. A `CKR_USER_NOT_LOGGED_IN` from a token that is still
  logged in (a key with `CKA_ALWAYS_AUTHENTICATE`) and failures on other
  slots are returned as before. Because a logout invalidates private
  object handles for good (PKCS#11 §5.7.2), `Sign`, `Decrypt` and
  `IdentifyKey` look a key up again by its CKA_ID when its handle is
  rejected with `CKR_OBJECT_HANDLE_INVALID` or `CKR_KEY_HANDLE_INVALID`
  (a key without CKA_ID keeps its handle, and a lookup matching several
  objects is an error rather than a guess); the identity lives in the
  private key types, so `PKCS11Object` keeps its two public fields. A
  generated key pair whose public key cannot be read afterwards is
  destroyed and the failure is not retried, so a failed generation never
  leaves a second pair behind. Concurrent failures cost
  one `C_Login`; a PIN error (`CKR_PIN_INCORRECT` and the other PIN codes)
  is remembered and returned by every later operation without touching the
  token again, so a changed PIN cannot lock it. `PKCS11Lib.Session` is
  replaced by a re-login and must not be cached or closed by callers;
  `PKCS11Object.Handle` may be stale after a logout.
- **cryptoprov** (XPKI-027): `ParseTokenURI` and `ParsePrivateKeyURI`
  implement RFC 7512. The query attributes `pin-value`, `pin-source`,
  `module-name` and `module-path` (`pkcs11:token=T?pin-value=1234`) are
  read (before, everything after `?` was dropped), a literal `+` stays a
  plus (before, it became a space), an unescaped `&` in a path value no
  longer splits it, values are percent-decoded, the URI is trimmed of
  surrounding whitespace, and manufacturer and model are always trimmed of
  padding (before, only when `pin-source` was set). `module-path` overrides
  `module-name` and must be absolute. The four query attributes are still
  accepted in the path, as before, but not in both places. Empty segments
  (a trailing or doubled separator) are still ignored, as before. Error
  messages quote the URI with every `pin-value` redacted to `pin-value=***`;
  an unreadable `pin-source` file keeps its `*fs.PathError` inspectable with
  `errors.Is`/`errors.As`.
- **armor** (XPKI-047): `Decode` accepts an armored block whose CRC24
  checksum line is missing, malformed or wrong, as RFC 9580 §6.1 requires
  (before, it rejected the block). The new `Block.HasCRC` reports a
  well-formed checksum line, `Block.CRCValid()` compares it with the
  decoded bytes, and `armor.CRC24` computes the checksum. The checksum must
  be on its own line, as RFC 9580 §6.1 requires; a payload whose last
  wrapped line is base64 padding only is decoded as payload. Framing and
  base64 validation are unchanged.
- **cmd/xpki-tool** (XPKI-102): `ocsp fetch` exits with status 1 when no
  OCSP endpoint returned a valid response, with `no valid OCSP response from
N endpoint(s)` followed by each `<url>: <reason>`. It still tries every
  endpoint, prints each failure as `<url> : ERROR: ...` on stdout, and
  succeeds when at least one endpoint answers. Failures to write (`--out`)
  or print (`--print`) a response are unchanged.
- **testca** (XPKI-063): `ToPKCS8` uses the standard library and returns a
  `PRIVATE KEY` PEM block (RSA, ECDSA, Ed25519), and `ToPFX`/`Entity.PFX`
  encode PKCS#12 with `software.sslmate.com/src/go-pkcs12` (`Modern2023`:
  PBES2 with PBKDF2-HMAC-SHA-256 and AES-256-CBC, HMAC-SHA-256 MAC, readable
  by OpenSSL 1.1.1+, Java 12+ and Windows Server 2019+). `openssl` is no
  longer needed on `PATH`, and the password may be empty or contain any
  character of the Basic Multilingual Plane (PKCS#12 stores it as a
  BMPString, so a character outside it, such as an emoji, panics). Both
  still panic on failure (test-only contract).

### Tests and tooling

- Integration tests use `internal/testenv`: they skip when SoftHSM or
  local-kms is unavailable, and fail when `XPKI_INTEGRATION=required`, which
  the Makefile sets. This is done for `authority`, `crypto11`, `jwt`,
  `cryptoprov`, `certutil` and `awskmscrypto`, whose unit tests now run
  against an in-memory fake KMS client, and (XPKI-100, complete) for `csr`
  (`csrprov_test.go`) and `cmd/hsm-tool/cli` (`TestCsrSuite`). Every other
  test is fixture-free.
- **cmd/hsm-tool** (XPKI-101): the CLI parser test builds a fresh kong
  parser per case and asserts the `missing flags: --cfg=STRING` error; the
  previous test reused one parser, which kept `--cfg` from an earlier parse.
- **dataprotection** (XPKI-083): the limits of `NewSymmetric` are documented
  in the package documentation and checkable through the new constants
  `SymmetricNonceSize` (12), `SymmetricTagSize` (16), `SymmetricOverhead`
  (28), `SymmetricMinSecretSize` (32, recommended and not enforced) and
  `SymmetricMaxMessagesPerKey` (2^32): the secret is key material of at
  least 32 bytes from `crypto/rand` or a memory-hard KDF (HKDF does not
  harden a passphrase); one secret protects at most 2^32 messages (NIST SP
  800-38D §8.3 random-IV bound) of less than 2^36−32 bytes each; the blob
  is `nonce || ciphertext || tag` without a key id, so the caller records
  which secret protected a blob, keeps old providers to read and re-protects
  on read. The KDF and blob format are unchanged; a versioned format is
  roadmap work.
- **build** (XPKI-096): `make tools` installs golangci-lint v2.13.2,
  cov-report v1.1.0, govulncheck v1.8.0 and gomarkdoc v1.1.0, pinned by the
  `GOLANGCI_LINT_VERSION`, `COV_REPORT_VERSION`, `GOVULNCHECK_VERSION` and
  `GOMARKDOC_VERSION` variables in `Makefile` (override them on the command
  line to try a newer release). The update procedure is documented next to
  the pins.
- **build** (XPKI-095): `make lint` runs `fmt-check`, `go vet`, `govulncheck`
  and `golangci-lint`, and `make covtest`/`make testint` depend on
  `fmt-check` instead of `fmt`, so none of the CI targets modifies the
  checkout; `make fmt` still formats. `make fmt-check` lists and diffs the
  unformatted files and fails.
- **build** (XPKI-098): `docker-compose.yml` pins `nsmithuk/local-kms:3.11.7`,
  drops the obsolete `version:` key and the fixed public-range subnet
  (`168.139.58.0/24`), and lets the two emulators use the project's default
  network; only the published ports `:14555` and `:14556` are part of the
  test contract.
- **CI** (XPKI-094, 095): the `UnitTest` job runs only when `detect-noop`
  did not flag the run as skippable (a pull request that changes only
  Markdown, images or `Documentation/`, or that duplicates an already
  successful run; pushes never skip); a skipped pull request gets a
  successful `code cov` status with the description `skipped: no Go or
.VERSION changes` from the new `code-cov-skipped` job, so a required
  status never stays pending. The job runs `make lint` before the tests and
  checks with `git diff --exit-code` that the build left the checkout
  unchanged.
- The SoftHSM setup script was hardened (XPKI-093). CLI test fixtures are
  isolated per run (XPKI-105).
- `internal/version` (XPKI-097): the CLIs report the version the linker
  sets (`make build` and `make hsmconfig` pass `-ldflags "-X
github.com/effective-security/xpki/internal/version.build=$(GIT_VERSION)"`).
  Without it, a plain `go build` or `go install` reports the module version
  recorded by the go command (a tag, or a pseudo-version with `+dirty`),
  else `devel-<revision>[-dirty]`. `internal/version/current.go` is ordinary
  source: it is no longer generated from `current.template` (removed), so a
  checkout never carries a stale version (it embedded `v0.2.76`), and `make
version` now prints the version. A test builds both CLIs and checks their
  `--version` output.
- **authority** (XPKI-058): `IssuerConfig.Type` has `json`/`yaml` tags. YAML
  already loaded `type:`; the JSON key is now `type` instead of `Type` and is
  omitted when empty. Decoding accepts both spellings.
- Flaky tests fixed: the `dataprotection` tamper test copied one random
  nonce byte over another, which left the input unchanged about once in 256
  runs (XPKI-106); the delegated OCSP slow-failure test released its signer
  from a timer armed before the attempt started (XPKI-111). Both are now
  deterministic.

## New features and behaviour

- `certutil`: `Bundler.BundleContext`, `ChainFromPEMContext`,
  `WithSystemRoots(bool)`, `ErrNoCertificates`, and decryption of
  `ENCRYPTED PRIVATE KEY` (PKCS#8, PBES2 with PBKDF2 and AES-CBC).
- `crypto11`: the `WithMaxSessions(n)` option for `Init`/`ConfigureFromFile`
  (default `DefaultMaxSessions` = 1024).
- `jwt`: `NewRemoteKeySet(url, opts...)` with `WithHTTPClient`,
  `WithRefreshCooldown`, `WithFetchTimeout` and `WithMaxResponseSize`, and
  `AlgorithmKeySet.GetKeyForAlgorithm`.
- `jwt/dpop`: the `VerifyConfig` fields `ReplayCache` (with
  `NewMemoryReplayCache`), `AccessToken`, `ExpectedThumbprint` and
  `ExternalURL`.
- `jwt/accesstoken`: `New(dp, provider, opts...)` with `WithTokenExpiry`,
  `WithAllowNoExpiry`, and the `TokenPrefix` constant.
- `jwt`: `MapClaims.NormalizeTimeClaims()`.
- `jwt/oauth2client`: `Client.PublicKey()`.
- `cryptoprov`: the `ErrNilProvider` and `ErrDuplicateProvider` errors.
- `authority`: `Authority.Profile(label)`. `Authority.Issuers()` is sorted
  by label.
- `awskmscrypto`: `Signer.SigningAlgorithms`, and `KeyInfo.Label` is set to
  the key description by `EnumKeys` and `KeyInfo`.
- `gcpkmscrypto`: key ids are `K` or `K/cryptoKeyVersions/N`. A bare id
  resolves to the newest enabled version for signing and lookup. Destroying a
  bare id destroys every enabled or disabled version.
- `certutil.HTTPClient` is deprecated (it was never read); use
  `WithHTTPClient`.
- `csr`: `SAN` with `Validate`, `ParseSAN`, `ApplySAN` and the
  `SignatureAlgorithmer` interface; `SetSAN` is deprecated.
- `gcpkmscrypto`: `Signer.SignatureAlgorithm()`.
- `armor`: `Block.HasCRC`, `Block.CRCValid()` and `CRC24`.
- `cryptoprov`: RFC 7512 query attributes in `pkcs11:` URIs.
- `dataprotection`: the `SymmetricNonceSize`, `SymmetricTagSize`,
  `SymmetricOverhead`, `SymmetricMinSecretSize` and
  `SymmetricMaxMessagesPerKey` constants.
- `testca`: `ToPFX`/`Entity.PFX` accept any BMP-string password, including
  an empty one.
- `make fmt-check`, and the `GOLANGCI_LINT_VERSION`, `COV_REPORT_VERSION`,
  `GOVULNCHECK_VERSION` and `GOMARKDOC_VERSION` Makefile variables.

## Breaking changes: what clients must change

| Area               | Change                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                          | Action                                                                                                                                                    |
| ------------------ | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | --------------------------------------------------------------------------------------------------------------------------------------------------------- |
| go-jose            | `github.com/go-jose/go-jose/v3` → `v4` (exposed by `jwt.ParserConfig.JWKeySet` and the `jwt/dpop` key functions)                                                                                                                                                                                                                                                                                                                                                                                                                                | Import `github.com/go-jose/go-jose/v4`                                                                                                                    |
| `crypto11`         | `PKCS11Lib.Close()` returns `error`                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                             | Wrap a `func()` use, such as `t.Cleanup(func() { _ = lib.Close() })`                                                                                      |
| `crypto11`         | A config with neither `TokenSerial` nor `TokenLabel` fails. When both are set, a token must match both                                                                                                                                                                                                                                                                                                                                                                                                                                          | Set a selector that matches the token                                                                                                                     |
| `crypto11`         | A malformed CKA_KEY_TYPE/CKA_CLASS fails `EnumKeys`                                                                                                                                                                                                                                                                                                                                                                                                                                                                                             | None, unless you relied on partial listings                                                                                                               |
| `cryptoprov`       | `Load` fails on two token configs with the same manufacturer and model, and on nil providers                                                                                                                                                                                                                                                                                                                                                                                                                                                    | Remove the duplicate configs                                                                                                                              |
| `gcpkmscrypto`     | `KmsClientFactory` is `func(endpoint string) (KmsClient, error)`                                                                                                                                                                                                                                                                                                                                                                                                                                                                                | Update custom factories                                                                                                                                   |
| `gcpkmscrypto`     | `Keyring` is required. Encryption keys (purpose 2) are rejected. A `Sign` whose hash or padding does not match the key's algorithm, nil opts, or `PSSSaltLengthAuto` fails before any RPC                                                                                                                                                                                                                                                                                                                                                       | Pass the key's hash; use `PSSSaltLengthEqualsHash`                                                                                                        |
| `gcpkmscrypto`     | Exported URIs carry the version in `id` (`K/cryptoKeyVersions/N`). An old `id=K` URI now resolves to the newest enabled version, not version 1                                                                                                                                                                                                                                                                                                                                                                                                  | Store the new URIs to pin a version                                                                                                                       |
| `awskmscrypto`     | `GenerateRSAKey` purpose 2 and sizes other than 2048/3072/4096 are rejected; `GetKey` of an `ENCRYPT_DECRYPT` key or a key pending deletion fails. A `Sign` with nil opts, an unsupported hash, a wrong digest length, PSS options on an ECDSA key, a PSS salt other than the hash length (`PSSSaltLengthAuto` included), or an algorithm the key does not support fails before any RPC. `NewSigner` needs the key's KMS-reported `SigningAlgorithms`; with none, `Sign` fails                                                                  | Pass the hash as `crypto.SignerOpts`; use `PSSSaltLengthEqualsHash` for PSS; pass `SigningAlgorithms` from `GetPublicKey` or `DescribeKey` to `NewSigner` |
| `awskmscrypto`     | `EnumKeys` returns only the keys whose label starts with `prefix` (before, `prefix` was ignored), needs `kms:DescribeKey` on the listed keys (a key the caller may not describe is left out), and returns an error instead of a partial listing when a key cannot be described for another reason                                                                                                                                                                                                                                               | Pass an empty prefix to list every signing key; treat the error as a failed listing                                                                       |
| `authority`        | A CSR extension that is not in `allowed_extensions` is rejected, or dropped with `omit_disabled_extensions`. `otherName` SANs from a CSR are no longer issued                                                                                                                                                                                                                                                                                                                                                                                   | Add the needed OIDs to the profile's `allowed_extensions`                                                                                                 |
| `authority`        | A `SignRequest` whose lifetime exceeds the profile expiry, for example `NotAfter = now + expiry` with the default backdate, is rejected                                                                                                                                                                                                                                                                                                                                                                                                         | Send `NotAfter ≤ NotBefore + expiry`                                                                                                                      |
| `authority`        | A populated `allowed_profiles` also filters wildcard profiles and must include the `delegated_ocsp_profile`                                                                                                                                                                                                                                                                                                                                                                                                                                     | List every profile the issuer needs                                                                                                                       |
| `authority`        | `Authority.Profiles()` and `Issuer.Profiles()` return copies: writing to the returned map no longer changes the registry. `Issuers()` is sorted by label. `AddIssuer` rejects an issuer whose label is already registered (before, the label and key id entries were silently replaced while the old issuer kept its profiles), a nil issuer, and an issuer with a nil profile; a rejected issuer registers nothing. A `*CertProfile` must not be modified after `AddProfile`                                                                   | Register each issuer once; change profiles with `AddProfile` (or `Issuer.AddProfile`), passing a `Copy` when starting from a registered profile           |
| `authority`        | `IssuerConfig` marshals `Type` as the JSON key `type` (was `Type`), omitted when empty                                                                                                                                                                                                                                                                                                                                                                                                                                                          | Readers of the JSON form use `type`; decoding accepts both                                                                                                |
| `cmd/hsm-tool/cli` | `Cli.CryptoProv()` returns `(*cryptoprov.Crypto, cryptoprov.Provider, error)` and no longer panics                                                                                                                                                                                                                                                                                                                                                                                                                                              | Return the error from the command                                                                                                                         |
| build              | `internal/version/current.template` is gone and `current.go` is ordinary source; the version is linked with `LDFLAGS` (`-X github.com/effective-security/xpki/internal/version.build=...`)                                                                                                                                                                                                                                                                                                                                                      | Build with `make build`, or pass the same `-ldflags` to `go build`; a plain build reports the module version                                              |
| `jwt`              | A token whose `exp`, `iat` or `nbf` is present but not a time fails `Valid` with `invalid <claim> claim: ...` instead of skipping the check                                                                                                                                                                                                                                                                                                                                                                                                     | Reissue such tokens with a NumericDate                                                                                                                    |
| `certutil`         | `NewBundler(nil, …, WithBundleFlavor(Optimal))` fails without roots                                                                                                                                                                                                                                                                                                                                                                                                                                                                             | Pass `WithSystemRoots(true)` or explicit roots                                                                                                            |
| `certutil`         | `Bundle` of an empty list returns `ErrNoCertificates` instead of `(nil, nil)`. `SortBundlesByExpiration` returns a sorted copy                                                                                                                                                                                                                                                                                                                                                                                                                  | Check the error, and use the return value                                                                                                                 |
| `jwt`              | The error `key not found: <kid>` is now `kid="<kid>": key not found`. A kid-less token against several eligible keys fails. A key published less than 10s after a fetch is refused until the cooldown ends                                                                                                                                                                                                                                                                                                                                      | Match errors with `errors.Is`, not text; tune `WithRefreshCooldown`                                                                                       |
| `jwt`              | Constructors reject an `alg` header that differs from the signing algorithm, and HS providers reject a foreign `kid`                                                                                                                                                                                                                                                                                                                                                                                                                            | Remove conflicting headers                                                                                                                                |
| `jwt`              | `ParseToken` accepts only the provider's own `alg` (`unsupported signing method`). A token from a `NewProvider` ring or a private key that was signed with another hash of the same key fails                                                                                                                                                                                                                                                                                                                                                   | Sign every token with the provider, or verify foreign algorithms with `jwt.NewParser`                                                                     |
| `jwt`              | The JOSE header has no `jti`; `Sign` fails on an `exp`, `iat` or `nbf` it cannot parse as a time, or that is a zero time, and signs a `time.Time` as NumericDate                                                                                                                                                                                                                                                                                                                                                                                | Set the `jti` claim (`CreateClaims`) when a token id is needed; a reader of the header `jti` must read the claim instead                                  |
| `jwt`              | A string `exp`/`nbf`/`iat` in RFC 3339 form is validated. An existing token with such an expired `exp` or future `nbf` is now rejected                                                                                                                                                                                                                                                                                                                                                                                                          | Reissue such tokens                                                                                                                                       |
| `jwt/dpop`         | `htm` must equal the request method exactly; a lowercase `htm` for a `GET` request is rejected                                                                                                                                                                                                                                                                                                                                                                                                                                                  | Sign proofs with the method as sent (Go's `http.Request.Method`)                                                                                          |
| `jwt/oauth2client` | `Client.Config()` returns a copy; changing it no longer changes the client, and `New` copies its argument. `New(nil)` is an error. `RegisterClient(cfg, true)` drops the previous client's other domains and emails. `Client` and `Provider` hold locks and must not be copied by value                                                                                                                                                                                                                                                         | Use `SetClientSecret`/`SetPubKey`, or register a new client, to change one; keep the pointers `New`/`NewProvider` return                                  |
| `jwt/accesstoken`  | `Sign` writes `exp`/`iat`/`nbf` as NumericDate and fails on a value it cannot parse or a zero time, with `invalid <claim> claim: <value>` (in v0.28 a `time.Time` was written as an RFC 3339 string that `ParseToken` did not check, so a zero `exp` never expired)                                                                                                                                                                                                                                                                             | Pass parsable, non-zero times                                                                                                                             |
| `jwt/accesstoken`  | Signing claims without `exp` fails unless `WithTokenExpiry` is set. Old tokens without `exp` are rejected unless `WithAllowNoExpiry` is set                                                                                                                                                                                                                                                                                                                                                                                                     | Set `WithTokenExpiry(d)`; use `WithAllowNoExpiry()` only during migration                                                                                 |
| `jwt/dpop`         | An `htu` path that differs only in case is rejected. A server that serves plain HTTP must set `ExternalURL`, since `https` stays the default scheme                                                                                                                                                                                                                                                                                                                                                                                             | Set `VerifyConfig.ExternalURL`; enable `ReplayCache` for replay safety                                                                                    |
| `csr`              | `Provider.SignRequest` (so `GenerateKeyAndRequest` and `CreateRequestAndExportKey`) fails with `invalid SAN "x": reason` on an empty, invalid or non-ASCII SAN instead of skipping it, and drops duplicate names; cleared name lists are nil instead of empty slices                                                                                                                                                                                                                                                                            | Fix the SAN inputs; call `csr.ParseSAN` to validate them early; use `ApplySAN` instead of the deprecated `SetSAN`                                         |
| `authority`        | `Issuer.Sign` rejects a `SignRequest.SAN` entry, or a name copied from the CSR, that is not a valid URI, IP address, email address or DNS name (before, it was issued as given), and drops duplicates                                                                                                                                                                                                                                                                                                                                           | Validate requester SANs with `csr.ParseSAN`; CSRs with a malformed name must be reissued                                                                  |
| `csr`              | 3072-bit RSA keys are signed with SHA-256 (was SHA-384) by `SigAlgo`, `DefaultSigAlgo` and every caller (CSRs, `authority` certificates and OCSP)                                                                                                                                                                                                                                                                                                                                                                                               | None, unless a policy requires SHA-384: set `SignatureAlgorithm` on the template explicitly                                                               |
| `cmd/xpki-tool`    | `ocsp fetch` exits with status 1 when no endpoint returned a valid OCSP response                                                                                                                                                                                                                                                                                                                                                                                                                                                                | Scripts that ignored the exit status must handle the failure                                                                                              |
| `cryptoprov`       | `ParseTokenURI`/`ParsePrivateKeyURI` reject a duplicated attribute, one of `pin-source`/`pin-value`/`module-name`/`module-path` given in both path and query, `pin-source` together with `pin-value` (even an empty one), a relative `module-path`, a segment without `=`, an attribute name outside `[A-Za-z0-9_-]` and a bad percent escape; a `+` in a value is no longer decoded as a space; a checksum-less `=`-free segment such as a trailing `;` is still ignored; error messages changed (the URI is quoted with `pin-value` redacted) | Fix the URI; match errors with `errors.Is(err, cryptoprov.ErrInvalidURI)`, not text                                                                       |
| `armor`            | `Decode` returns a block whose checksum line is missing, malformed or wrong; a checksum glued to the last data line (not on its own line) is no longer recognized and fails the base64 decoding                                                                                                                                                                                                                                                                                                                                                 | Callers that relied on the checksum being enforced check `Block.CRCValid()`; put the checksum on its own line                                             |
| `testca`           | `ToPKCS8` and `ToPFX` no longer run `openssl`; PFX packets use PBES2 AES-256-CBC with SHA-256 (`go-pkcs12` `Modern2023`), the password is any BMP string (a non-BMP character panics), and `software.sslmate.com/src/go-pkcs12` is a new dependency                                                                                                                                                                                                                                                                                             | Readers of the PFX need OpenSSL 1.1.1+, Java 12+ or Windows Server 2019+                                                                                  |
| build              | `make lint`, `make covtest` and `make testint` fail on unformatted files instead of reformatting them                                                                                                                                                                                                                                                                                                                                                                                                                                           | Run `make fmt` before them                                                                                                                                |
| build              | `make tools` installs pinned tool versions                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                      | Override a `*_VERSION` variable to test a newer release                                                                                                   |

## Still open

Every finding of the 2026-09-20 audit is fixed; [FINDINGS.md](../FINDINGS.md)
and [PLAN.md](../PLAN.md) are empty. Larger follow-up work (context
propagation for providers, KMS encryption keys, DPoP nonces, JWKS refresh,
a versioned `dataprotection` blob format, dependency hygiene) is in
[ROADMAP.md](../ROADMAP.md). Decisions taken while closing the last batch
without a prior approval are listed in FINDINGS.md under "Notes on items
needing approval" for review.
