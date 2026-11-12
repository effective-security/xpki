# xpki v2.0 release notes

v2.0 replaces the key management contract of `cryptoprov`. `KeyManager` lists
keys by page and filter, fills only the fields a caller asks for and never
fetches a public key in a listing; `KeyGenerator` creates every key through
one `GenerateKey`; and every method takes a `context.Context`. The contract
was shaped for cloud KMS and still fits a PKCS#11 token. It is roadmap item
12; the design, what each provider does for a listing and the decisions K1 to
K12 are in [`Documentation/design/keymanager.md`](design/keymanager.md).

It is a **breaking** release for every client: the module path is
`github.com/effective-security/xpki/v2`. v1 continues on the `release-v1`
branch for fixes.

The listings ran against the real AWS KMS and Google Cloud KMS on
2026-11-12, see "Validation". Three runs are still open there: the AWS
Resource Groups Tagging API (`TagSearch`), the RSA and ECDSA key flow on
Google Cloud KMS, and the PKCS#11 v3.2 token. ML-DSA on Google Cloud KMS is
not available: the service does not offer it for HSM keys, see "Constraints".

## Breaking changes

### Module

- The module is `github.com/effective-security/xpki/v2`. Every import path
  gains `/v2`; the `-X` linker flag of the CLIs is
  `github.com/effective-security/xpki/v2/internal/version.build`. The `xlog`
  logger namespace stays `github.com/effective-security/xpki`, so log level
  configuration does not change.

### cryptoprov

- `KeyGenerator` is `GenerateKey(ctx, *GenerateKeyRequest)`,
  `GetKey(ctx, keyID)`, `IdentifyKey(ctx, key)` and `ExportKey(ctx, keyID)`.
  `GenerateRSAKey`, `GenerateECDSAKey` and `GenerateMLDSAKey` are removed. A
  request names the key `Type` (`certutil.KeyTypeRSA`, `KeyTypeECDSA`,
  `KeyTypeMLDSA`), its `Size` (RSA bits, curve size 256, 384 or 521, ML-DSA
  parameter set 44, 65 or 87), its `Usage` (zero means `KeyUsageSign`) and
  its `Tags`. `KeyUsageSign` and `KeyUsageEncrypt` are 1 and 2, the values the
  `purpose int` of v1 had.
- `KeyManager` is `ListKeys(ctx, *ListKeysRequest)`,
  `KeyInfo(ctx, keyID, fields)` and `DestroyKey(ctx, keyID)`. `CurrentSlotID`,
  `EnumTokens`, `EnumKeys`, `DestroyKeyPairOnSlot` and `FindKeyPairOnSlot` are
  removed. Slots are in the optional `TokenManager` (`ListTokens`, `Token`),
  which only `crypto11` implements.
- `KeyInfo(…, includePublic bool)` became a field mask: `KeyFieldMetadata`,
  `KeyFieldState`, `KeyFieldTags` and, for `KeyInfo` only, `KeyFieldPublicKey`.
- `KeyInfo` has new typed fields: `Name`, `Size`, `Usage`, `State` and `Tags`.
  `Label` is the label on every provider (see Google Cloud KMS below), and
  `Type` is empty for a key family the module does not use (symmetric, HMAC,
  secp256k1, Ed25519), whose native spec is in `Meta`.
- `TokenInfo` has `Current`, the token the provider is logged in to.
- `Crypto.LoadPrivateKey`, `NewSignerFromFromFile`, `NewSignerFromPEM`,
  `LoadTLSKeyPair` and `TLSKeyPair` take `ctx` as their first argument.
- A missing key is reported with `ErrKeyNotFound`, a request the backend
  cannot serve with `ErrNotSupported` and a foreign page token with
  `ErrInvalidPageToken`; match them with `errors.Is`. Error texts changed
  where a v1 method was replaced.
- There is no default state filter: a listing returns keys in every state,
  including an AWS key pending deletion and a Google Cloud key whose versions
  are destroyed, unless `KeyFilter.States` says otherwise. v1 hid AWS keys
  pending deletion and Google Cloud keys with a primary version that was not
  enabled.

### crypto11

- `GenerateRSAKey`, `GenerateECDSAKey` and `GenerateMLDSAKey` are replaced by
  `GenerateKey`; `EnumTokens` by `ListTokens`; `EnumKeys`, `KeyInfo` and
  `DestroyKeyPairOnSlot` by `ListKeys`, `KeyInfo` and `DestroyKey`, which work
  on the token the library is logged in to, and by `Token(slotID)` for
  another slot.
- The helpers that borrow a pooled session take `ctx` first:
  `GenerateRSAKeyPair`, `GenerateRSAKeyPairWithLabel`,
  `GenerateRSAKeyPairOnSlot`, the ECDSA and ML-DSA equivalents, `FindKeyPair`,
  `FindKeyPairOnSlot` and `Identify`. The `…OnSession` variants do not.
- `KeyPurpose` and its constants `Undefined`, `Signing` and `Encryption` are
  removed; the RSA helpers take a `cryptoprov.KeyUsage`.
- **Behavior**: an RSA key is created with both permissions set explicitly,
  the one that was not asked for to false. v1 set only the requested one to
  true and left the other to the token, which is true on SoftHSM, so a
  "signing" key could decrypt and reported both usages. A key generated with
  usage zero through the helpers still gets the token's defaults. Keys that
  exist are not changed.
- The session-level `ListKeys(session, class, type)` and
  `FindKeys(session, label, class, type)` are removed.
- `BytesToUlong`, deprecated since v1.0, is removed.
- `PKCS11Object.Handle` is a method. It returns the current handle, which
  follows the refresh after a logout; the field is unexported.
- The error of destroying a missing key is prefixed with
  `unable to destroy key "<id>"`.

### awskmscrypto

- `KmsClient` gained `ListAliases` and `ListResourceTags`; a test double of
  it must add them. `TaggingClient` and `TaggingClientFactory` are new.
- **Behavior**: a label filter finds a key through the alias `GenerateKey`
  gave it, not by reading the description of every key (decision K4). A key
  that has only a matching description, such as one created outside xpki or
  one whose alias could not be created, is not found unless the token config
  sets `LabelSearch=scan`, which restores the v1 scan, or `TagSearch=true`,
  which also finds keys by their `xpki-label` tag.
- `ListKeys` lists keys of every usage and state. The v1 `EnumKeys` listed
  `SIGN_VERIFY` keys that were not pending deletion; ask for that with
  `Filter.Usage: KeyUsageSign` and `Filter.States`.
- `KeyInfo.ID` is the key id whatever name the key was asked by (alias, ARN),
  and `Name` is the ARN. `Meta` gained `manager` and `spec`.
- An invalid value of a listing attribute fails `Init`.
- A secp256k1 key has an empty `Type` (v1: `ECDSA`).

### gcpkmscrypto

- **Behavior**: `KeyInfo.Label` is the value of the `label` label. v1
  returned `protection=…,label=…,k=v`; the labels are now in `Tags` and the
  protection level in `Meta["protection"]`.
- `KeyInfo.ID` keeps the version when the key was asked for by version
  (`K/cryptoKeyVersions/N`); v1 returned `K`.
- `KeyInfo` reads a version only when the ID names one or the mask has
  `KeyFieldState` or `KeyFieldPublicKey`. Without them `State` and
  `CurrentVersionID` are empty for an asymmetric key.
- Keys with the algorithm `EC_SIGN_SECP256K1_SHA256` or `EC_SIGN_ED25519`
  have an empty `Type` (v1: `ECDSA`).
- `GenerateKey` returns an error that is `cryptoprov.ErrNotSupported` when
  KMS refuses the algorithm at the HSM protection level (`INVALID_ARGUMENT`
  with the reason `ALGORITHM_NOT_SUPPORTED_FOR_PROTECTION_LEVEL`). The KMS
  error and its gRPC status are kept in the chain. Any other
  `INVALID_ARGUMENT` is returned as before.

### inmemcrypto, testprov

- Both are `cryptoprov.KeyManager`s. The handle of `inmemcrypto` implements
  `crypto.Decrypter`, as the one of `testprov` did.

### csr

- `KeyRequestGen.Generate` and `KeyRequest.Generate` take `ctx`, as do
  `Provider.GenerateKeyAndRequest` and `Provider.CreateRequestAndExportKey`.
- `SetSAN`, deprecated since v1.0, is removed; use `ApplySAN`, which reports
  the invalid names.

### authority

- `NewRoot`, `NewIssuer`, `NewIssuerWithBundles`, `NewAuthority` and
  `Issuer.GenCert` take `ctx` as their first argument.

### jwt

- `NewProvider`, `LoadProvider` and `MustNewProvider` take `ctx` as their
  first argument.

### certutil

- The `HTTPClient` variable, deprecated and unread since v1.0, is removed;
  use `WithHTTPClient`.
- `Bundler.RootPool`, `IntermediatePool` and `KnownIssuers` are no longer
  fields. `RootPool()` and `IntermediatePool()` return copies of the current
  pools and `IsKnownIssuer(cert)` replaces the map.

### hsm-tool

- The key commands moved under `hsm key`: `hsm key list`, `hsm key info`,
  `hsm key generate` and `hsm key remove`. The v1 paths (`hsm list`, …) are
  a usage error, exit status 80.
- `hsm key list` lists the RSA, ECDSA and ML-DSA keys that are enabled or
  disabled. On AWS that adds RSA encryption keys to what v1 listed; on Google
  Cloud KMS it hides keys whose versions are destroyed and symmetric keys.
  `--all` lists every key type and `--state all` every state.
- `hsm key list` and `hsm key info` print new lines (`Name`, `Size`, `Usage`, `State`,
  `Tag`), and the provider details in name order.

## New

- **Paged, filtered listings.** `ListKeysRequest` has `PageSize`, `PageToken`,
  `Filter` (`Usage`, `Types`, `Label`, `LabelPrefix`, `Tags`, `States`) and
  `Fields`. `AllKeys(ctx, km, req)` iterates over every page. A page can be
  short or empty and still have a `NextPageToken`. A page token is opaque and
  bound to the filter and the field mask it was issued for.

  ```go
  req := &cryptoprov.ListKeysRequest{
      PageSize: 50,
      Filter: cryptoprov.KeyFilter{
          Usage:  cryptoprov.KeyUsageSign,
          States: []cryptoprov.KeyState{cryptoprov.KeyStateEnabled},
      },
      Fields: cryptoprov.KeyFieldMetadata,
  }
  for key, err := range cryptoprov.AllKeys(ctx, km, req) {
      if err != nil {
          return err
      }
      fmt.Println(key.ID, key.Label, key.Type, key.Size)
  }
  ```

- **AWS KMS listing planner.** A listing of ids makes no `DescribeKey`. An
  exact label is one `DescribeKey` on its alias, and a label prefix is a
  `ListAliases` sweep. Key spec, usage, creation date, origin and manager
  never change, so the provider remembers them: a filter on usage or type
  costs one `DescribeKey` the first time a key is seen and none afterwards.
  The first such listing still describes every key of the account once.
- **AWS token config attributes**, all optional:

  | Attribute                 | Effect                                                                                                                                                              | IAM permissions                                      |
  | ------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ---------------------------------------------------- |
  | (none)                    | Listing by ids, alias index and metadata cache.                                                                                                                     | `kms:ListKeys`, `kms:DescribeKey`, `kms:ListAliases` |
  | `TagSearch=true`          | A tag filter is answered by the Resource Groups Tagging API; `GenerateKey` writes the tags `xpki-label`, `xpki-type`, `xpki-size` and `xpki-usage`. Off by default. | `tag:GetResources`, `kms:TagResource`                |
  | `TaggingEndpoint=<url>`   | Endpoint of the tagging API, for a VPC endpoint.                                                                                                                    |                                                      |
  | `LabelSearch=scan`        | A label filter describes every key and matches its description, as v1 did.                                                                                          |                                                      |
  | `DescribeConcurrency=<n>` | Per-key requests in flight at once, 1 to 64 (default 8).                                                                                                            |                                                      |
  | `MetadataCacheSize=<n>`   | Keys whose immutable metadata is remembered (default 50000; 0 disables).                                                                                            |                                                      |

  A tag filter without `TagSearch`, and `KeyFieldTags`, read
  `kms:ListResourceTags` per key. `GenerateKey` with `Tags` needs
  `kms:TagResource`. The `xpki-` tags can be written by anyone with
  `kms:TagResource`: they feed listings only, never `GetKey`, `KeyInfo` or
  `Sign`.
- **Key tags.** `GenerateKeyRequest.Tags` become AWS tags or Google Cloud
  labels; `KeyFilter.Tags` and `KeyFieldTags` read them. A PKCS#11 object has
  no tags: both are `ErrNotSupported` on `crypto11`.
- **Google Cloud KMS**: a listing is one `ListCryptoKeys` request for a full
  page, with the label and tag conditions sent to KMS in the documented
  filter forms and every condition checked again on the returned keys.
- **crypto11**: the filter becomes the `C_FindObjectsInit` template (class,
  key type, exact label, usage); attributes are read for the keys of the page
  only; a borrower at the session limit waits no longer than its context
  (roadmap item 6). `PKCS11Lib` is a `cryptoprov.TokenManager`.
- **Typed key description**: `Size`, `Usage` and `State` on every provider,
  so callers no longer parse `Meta`.
- **hsm-tool**: `hsm key list` has `--label`, `--usage`, `--type`, `--tag`,
  `--state`, `--limit` and `--all`; `hsm key info` has `--tags`.
- **Helpers**: `cryptoprov.ECDSACurve`, `MLDSASize`, `ParseKeyUsage`,
  `ParseKeyState`, `PageKeys` (a listing over an in-memory key list),
  `NewPageToken`, `ParsePageToken` and `MarkError` for provider authors.
- `internal/provtest` is the conformance suite of the contract; every
  provider of the module runs it.

## Fixed

- **XPKI-129** (`gcpkmscrypto`, correctness): `EnumKeys` logged `prefix` and
  never applied it, so every key of the key ring was listed. `ListKeys`
  applies `Filter.LabelPrefix` to the `label` label, with the filter value
  sanitized as `GenerateKey` sanitizes a label. It is fixed in v2 only; a v1
  fix on `release-v1` is made on request.

## Performance

`BenchmarkListKeys` in `awskmscrypto`, the successor of the v1
`BenchmarkEnumKeys`, on a fake KMS whose `DescribeKey` takes 200 µs, for an
account of 5000 signing keys of which 500 have the label prefix. Mean of
three runs with `-cpu=1`, Go 1.27.4, on 2026-11-12; v1 is `BenchmarkEnumKeys`
at commit `b5001f2` on the same machine, whose `EnumKeys` cost the same for
every prefix (the exact-label row uses its prefix that matched no key). The
numbers show request counts and the shape of the cost, not the latency of
the service.

| Listing                                    | v1: time, `DescribeKey` | v2: time, requests                           |
| ------------------------------------------ | ----------------------- | -------------------------------------------- |
| Ids, no filter                             | not possible            | 4.2 ms; 5 `ListKeys`                         |
| Signing keys, ids only (mean over the run) | not possible            | 17 ms; 5 `ListKeys`; 5000 `DescribeKey` once |
| Signing keys with labels (all 5000 match)  | 682 ms; 5000            | 691 ms; 5 `ListKeys`, 5000 `DescribeKey`     |
| Label prefix (500 match)                   | 682 ms; 5000            | 114 ms; 50 `ListAliases`, 500 `DescribeKey`  |
| One exact label                            | 680 ms; 5000            | 1.1 ms; 1 `DescribeKey`                      |
| Label prefix with `LabelSearch=scan`       | 682 ms; 5000            | 689 ms; 5 `ListKeys`, 5000 `DescribeKey`     |

The usage filter describes the 5000 keys on the first listing of a provider
and none afterwards; the 17 ms is the mean over a run that includes that
first listing. A listing that returns the label of every key still costs one
`DescribeKey` per returned key, because the label can change. The request counts asserted
as acceptance are in `TestListKeysRequestCounts` (AWS) and `TestListKeysPages`
(Google Cloud KMS). No benchmark was run for `gcpkmscrypto` and `crypto11`:
their acceptance is the request and attribute-read counts their tests assert.

## Constraints

- **One major version per process for PKCS#11.** v1 and v2 have separate
  `crypto11` module registries: the second to open a module treats it as
  owned by someone else, and the first finalizes it on its last `Close`.
  A binary can link both (verified with v1.1.322 and v2 on 2026-11-12: the
  in-memory providers of both work side by side). The loader registries are
  separate, loggers of one namespace are shared, the `jwt` types are
  different types, and `metricskey.Metrics` of both describe the same metric
  names, so an application registers one of the two lists.
- **AWS label search.** See "Behavior" under `awskmscrypto`. A label and its
  alias are created by two requests; when `CreateAlias` fails the key is
  usable and a warning is logged, and the key is then found by label only
  with `TagSearch` or `LabelSearch=scan`.
- **The tagging API can lag** a tag change, and it lists only keys that are
  or were tagged.
- **A PKCS#11 page token is an offset** in the search order of the token: a
  key created or destroyed between two pages can be repeated or missed. A
  listing with an exact label, one type and one usage is evaluated by the
  token and is not affected by other keys.
- **PKCS#11 usage is what the token says**: a key created by v1 on SoftHSM
  reports signing and, for RSA, encryption.
- **The signing path has no context yet.** `crypto.Signer` has none, so
  `Signer.Sign` of the KMS providers still uses `context.Background()`
  (roadmap item 1).
- **KMS encryption keys** are still not supported: `KeyUsageEncrypt` is
  `ErrNotSupported` on the KMS providers (roadmap item 2).
- **No ML-DSA keys on Google Cloud KMS.** `gcpkmscrypto` creates HSM keys
  only, and Cloud KMS offers the ML-DSA algorithms for software keys only:
  on 2026-11-12 the service refused `PQ_SIGN_ML_DSA_44/65/87_EXTERNAL_MU`
  with "not supported for protection level: HSM", and its
  [algorithms page](https://docs.cloud.google.com/kms/docs/algorithms) lists
  them under the `software` protection level. `GenerateKey` returns
  `cryptoprov.ErrNotSupported` for them. `GetKey` does not look at the
  protection level, so an ML-DSA key created outside this library is loaded
  like any other key; its request shapes are tested against the in-process
  KMS only (roadmap 3.2).

## Client changes

Rewrite the imports, then fix what the compiler reports:

```sh
grep -rl --include='*.go' '"github.com/effective-security/xpki/' . \
  | xargs sed -i 's#"github.com/effective-security/xpki/#"github.com/effective-security/xpki/v2/#'
go get github.com/effective-security/xpki/v2@latest
go mod tidy
```

A string that names the logger namespace
(`github.com/effective-security/xpki/jwt` for `dpop` and `oauth2client`,
`github.com/effective-security/xpki/cryptoprov` for `gcpkms`) must keep the
v1 path; check the diff for one outside an import block.

| v1                                                              | v2                                                                             |
| --------------------------------------------------------------- | ------------------------------------------------------------------------------ |
| `GenerateRSAKey(label, bits, purpose)`                          | `GenerateKey(ctx, &GenerateKeyRequest{Label, Type: "RSA", Size: bits, Usage})` |
| `GenerateECDSAKey(label, elliptic.P256())`                      | `GenerateKey` with `Type: "ECDSA"`, `Size: 256`                                |
| `GenerateMLDSAKey(label, mldsa.MLDSA65())`                      | `GenerateKey` with `Type: "ML-DSA"`, `Size: 65` (`MLDSASize(params)`)          |
| `GetKey(id)`, `IdentifyKey(key)`, `ExportKey(id)`               | the same with `ctx` first                                                      |
| `EnumKeys(slotID, prefix)`                                      | `ListKeys(ctx, req)` with `Filter.LabelPrefix`, or `AllKeys`                   |
| `KeyInfo(slotID, id, true)`                                     | `KeyInfo(ctx, id, KeyFieldMetadata\|KeyFieldState\|KeyFieldPublicKey)`         |
| `DestroyKeyPairOnSlot(slotID, id)`                              | `DestroyKey(ctx, id)`                                                          |
| `EnumTokens(…)`, `CurrentSlotID()`                              | `TokenManager.ListTokens(ctx)`, `Token(slotID)` on `crypto11`                  |
| `FindKeyPairOnSlot(slotID, id, label)`                          | `GetKey(ctx, id)`, or `ListKeys` with `Filter.Label`                           |
| `LoadPrivateKey(pem)`, `NewSignerFromPEM(pem)`, `TLSKeyPair(…)` | the same with `ctx` first                                                      |
| `kr.Generate()`, `GenerateKeyAndRequest(req)`                   | the same with `ctx` first                                                      |
| `authority.NewAuthority(cfg, crypto)`, `NewIssuer`, `NewRoot`   | the same with `ctx` first                                                      |
| `jwt.NewProvider(cfg, crypto)`, `LoadProvider`                  | the same with `ctx` first                                                      |
| `csr.SetSAN(template, names)`                                   | `csr.ApplySAN(template, names)` and handle the error                           |
| `bundler.RootPool`, `bundler.KnownIssuers[sig]`                 | `bundler.RootPool()`, `bundler.IsKnownIssuer(cert)`                            |
| `obj.Handle`                                                    | `obj.Handle()`                                                                 |

- An implementer of `cryptoprov.Provider` implements the four
  `KeyGenerator` methods, calls `GenerateKeyRequest.Validate` first and
  returns `ErrNotSupported` for what its backend cannot do. A `KeyManager`
  over an in-memory list can answer `ListKeys` with `cryptoprov.PageKeys`.
  Run `internal/provtest` if the implementation lives in this module.
- A caller that listed AWS keys by a label prefix and has keys without the
  alias of their label sets `LabelSearch=scan` in the token config.
- A caller that read the Google Cloud `Label` string reads `Label`, `Tags`
  and `Meta["protection"]`.
- A caller that needs the state of Google Cloud keys asks for
  `KeyFieldState`.
- A deployment that turns `TagSearch` on grants `tag:GetResources` and
  `kms:TagResource` first: without the second, `GenerateKey` fails.
- A script that calls `hsm-tool hsm list`, `info`, `generate` or `remove`
  inserts `key` (`hsm-tool hsm key list`). One that parses the listing
  allows the new lines and passes `--state all --all` for the unfiltered
  listing.
- porto moves first: its exported API uses `jwt` and `dpop` types, so an
  application moves all of its xpki imports in the release in which it takes
  the porto built on v2. The signing half of roadmap item 1 changes more
  signatures; decision K9 recommends finishing it before the applications
  migrate.

## Validation

Run on 2026-11-12 with Go 1.27.4, SoftHSM 2.6.1 and `local-kms` 3.11.7:

- The module path change alone (KM0) kept the test list (576 tests) and the
  coverage (92.2%, 6988 of 7577 statements) of the last v1 commit.
- `make covtest`: every package passes with the SoftHSM token and both
  `local-kms` containers; 92.9% total (7888 of 8491 statements; the gate is
  above 90%), 613 tests.
- `make lint` (0 issues) and `make test RACE=true`, which includes the
  metadata cache shared by concurrent listings (`TestMetadataCache`) and the
  context-aware session borrow under cancellation
  (`TestWithSessionCtx_CancelDoesNotLoseWakeups`).
- The conformance suite on `inmemcrypto` (both paging modes), `testprov`,
  `crypto11` on SoftHSM, `awskmscrypto` on the fake KMS (alias index,
  `TagSearch`, `LabelSearch=scan`) and `gcpkmscrypto` on the in-process KMS.
- `Test_KmsProvider` against `local-kms`: generation, signatures, `KeyInfo`,
  the label prefix listing through `ListAliases` and the exact label through
  its alias.
- The Go declarations and the sample of the design document, and the sample
  above, were compiled.

Run by the maintainer against the real services on 2026-11-12:

- **AWS KMS, `us-west-1`**: `TestLiveKMSListKeys` without tag search passed.
  It generates keys through `GenerateKey` (`CreateKey` with tags,
  `CreateAlias`), lists ids, finds a key by its exact label through
  `alias/<label>` and by a label prefix through `ListAliases`, filters by
  usage, reads `KeyInfo` with tags (`ListResourceTags`), and checks that a
  key scheduled for deletion is listed as pending deletion only when asked
  for.
- **Google Cloud KMS, `us-central1`**: `TestLiveKMSListKeys` passed: pages
  with page tokens, the exact label (`labels.label=v`), the label prefix
  (`labels.label:v`), a tag (`labels.k=v`), a tag with a prefix (joined
  with ` AND `), the enabled state, and `KeyInfo`. The service accepts the
  filter forms that the provider pushes down.
- **Google Cloud KMS, ML-DSA**: `TestLiveKMSMLDSA` could not create a key
  for any of the three parameter sets; see "Constraints". The test now
  skips on that answer.

Two of these runs failed in the test, not in the library, and are corrected:

- The tag search part of the AWS test tagged its keys `xpki-live`, which
  `GenerateKey` rejects because the `xpki-` prefix is reserved. It stopped
  before a key was created. The tag is now `live-test`, and the whole flow
  also runs on the fakes (`TestLiveKMSListKeysOnFake`).
- `TestMLDSAOnPKCS11v32Token` on the Kryoptic token failed in its last
  assertion, after the three parameter sets: it expected `GenerateKey` to
  return the key pair helper's error for an unknown parameter set, but
  `GenerateKeyRequest.Validate` now rejects that request first. The
  assertion is corrected and the same check runs on SoftHSM
  (`TestGenerateMLDSAKeyOnSoftHSM`).

Not validated:

- **AWS tag search, live.** The Resource Groups Tagging API (`GetResources`
  for `kms:key`, which has no emulator), its lag after `TagResource`, and
  the IAM permissions `tag:GetResources` and `kms:TagResource` ran on a
  fake written from the SDK types (`resourcegroupstaggingapi` v1.42.0) and
  the AWS documentation (PLAN.md KM11).
- **Google Cloud KMS, RSA and ECDSA key flow, live.** `TestLiveKMSSign`
  (generation of RSA 2048, 3072 and 4096 and of P-256 and P-384 HSM keys,
  signatures, loading by version, id and URI, `KeyInfo`, a CSR and a
  certificate, the listing, destruction) was written after the runs above
  and passes on the in-process KMS (`TestLiveKMSSignOnFake`) only
  (PLAN.md KM15). The listing test above did create keys, list them and
  read them on the service.
- **Google Cloud KMS, ML-DSA.** The request shapes (`PQ_SIGN_ML_DSA_*`,
  `data`/`data_crc32c`) follow the SDK types and the documentation and ran
  against the in-process KMS only (PLAN.md PQ7).
- **PKCS#11 v3.2.** `TestMLDSAOnPKCS11v32Token` has not passed on the
  Kryoptic token since the change: the reported output of the failed run
  shows only the corrected assertion, so the generation through
  `GenerateKey` and the parameter set that `KeyInfo` reads together with
  the usage are still to be confirmed by a rerun (PLAN.md KM13).
- **Downstream.** porto, kubeca, trustyca, secdi and martini were not
  migrated or compiled against v2; the removed symbols were searched for in
  the local checkouts and none is used there.
