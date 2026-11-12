# Key management interfaces: `KeyManager` and `KeyGenerator` (v2)

Design for [roadmap item 12](../../ROADMAP.md#12-key-management-interfaces-keymanager-and-keygenerator-v2):
a provider contract that lists, describes, creates and destroys keys at a
cost that follows the size of the answer, not the size of the cloud account,
and that still fits a PKCS#11 token. It replaced the v1 `KeyManager` and
`KeyGenerator` of [`cryptoprov/provider.go`](../../cryptoprov/provider.go)
and ships as module `github.com/effective-security/xpki/v2`. What changed for
a client is in the [v2.0 release notes](../RELEASE_NOTES_2.0.md), and what
still needs a run against a real service in
[PLAN.md](../../PLAN.md#key-management-interfaces-xpki-v2-remaining-work).
[cryptoprov.md](cryptoprov.md) describes the package around the contract.

## Status

Implemented in v2.0 (2026-11-12). The design and the decisions K1 to K12
were approved on 2026-11-12, K1 and K2 in a first round and K3 to K12 with
this document. The listing of each provider was tested on fakes, on SoftHSM
and on `local-kms`; the AWS alias, tag and tagging API requests and the
Google Cloud filter have not run against the real services (see
[Risks and constraints](#risks-and-constraints)). The "Problem" and
"Verified baseline" sections describe v1, as it was before the change.

## Problem

The v1 contract was shaped by PKCS#11 before the module had KMS backends:

| v1                                                      | Problem                                                                                                                                                                                                |
| ------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| No `context.Context` on any method                      | The KMS providers call their SDKs with `context.Background()`, so a caller cannot bound or cancel a listing, a key load or a key generation (roadmap item 1).                                          |
| `EnumKeys(slotID, prefix)` returns everything           | No pagination: an account with thousands of keys is returned, and paid for, in one call.                                                                                                               |
| The only filter is a label prefix                       | No filter by usage, type, tag or state. AWS hard-codes "`SIGN_VERIFY`, not `PendingDeletion`", which hides encryption keys (roadmap item 2). GCP ignores `prefix` (XPKI-129).                          |
| `EnumKeys` fills every field it can                     | AWS `ListKeys` returns ids only, so `awskmscrypto` calls `DescribeKey` for every key of the account on every listing, even when the caller only counts keys (trusty's health check does exactly that). |
| `slotID` on every method, `EnumTokens`, `CurrentSlotID` | A PKCS#11 concept in the generic contract: both KMS providers ignore it and return one pseudo token.                                                                                                   |
| `FindKeyPairOnSlot`                                     | Returns "unsupported command" on both KMS providers.                                                                                                                                                   |
| `KeyInfo` is strings and a free-form `Meta`             | Usage, state and size have no field; `Label` is the description on AWS, a `protection=…,k=v` display string on GCP and `CKA_LABEL` on PKCS#11. The fields are not documented.                          |
| One generator method per algorithm, `purpose int`       | ML-DSA needed a breaking interface change in v1.1; SLH-DSA and ML-KEM would need two more. `1` and `2` are undocumented magic numbers. A key cannot be tagged when it is created.                      |

No provider fetches a public key during `EnumKeys` today; the per-key cost
on AWS is `DescribeKey`.

## Verified baseline (2026-11-12)

- Go 1.27.4; `github.com/aws/aws-sdk-go-v2/service/kms` v1.62.6;
  `cloud.google.com/go/kms` v1.37.0; module at v1.1.322 plus one commit.
- AWS `ListKeysInput` has only `Limit` (1 to 1000) and `Marker`; the
  response has key ids and ARNs. `ListAliasesInput` has `KeyId`, `Limit`
  (1 to 100) and `Marker`, and lists every alias of the account and Region
  with its `TargetKeyId` when `KeyId` is empty. `DescribeKey` accepts an
  alias name. `KeyMetadata` carries the spec, usage, state, description,
  creation date, origin and manager. `CreateKeyInput` has `Tags`.
- `github.com/aws/aws-sdk-go-v2/service/resourcegroupstaggingapi` was not a
  dependency; v1.42.0 was added with the implementation. Its
  `GetResourcesInput` has `ResourceTypeFilters` (`kms:key`), `TagFilters`,
  `ResourcesPerPage` (at most 100) and `PaginationToken`, and each result
  carries the ARN and its tags; that it lists only resources that are or
  were tagged comes from the AWS documentation. The request quotas quoted in
  `INTENT.md` were not checked.
- GCP `ListCryptoKeysRequest` has `Parent`, `PageSize`, `PageToken`,
  `VersionView`, `Filter` and `OrderBy`. A listed `CryptoKey` carries its
  purpose, labels, creation time and version template (algorithm, protection
  level); `Primary` exists for symmetric keys only. The
  [filtering documentation](https://docs.cloud.google.com/kms/docs/sorting-and-filtering)
  says any returned field can be filtered and shows `labels.team=alpha`,
  `primary.algorithm=…` and `name: "cloud"` (`:` is a case-insensitive
  substring match); sorting is by `name` only. A filter on `purpose` or on
  the version template is not shown there and was **not** tried against the
  service. The forms the provider pushes down (`labels.k=v`,
  `labels.label:v`, ` AND `) were accepted by the service on 2026-11-12
  (`TestLiveKMSListKeys`, `us-central1`).
- PKCS#11 `C_FindObjectsInit` matches a template of exact attribute values;
  `crypto11` already uses `CKA_CLASS`, `CKA_KEY_TYPE` and `CKA_LABEL`, and
  generates keys with `CKA_SIGN` or `CKA_DECRYPT`.
- Consumers in the local checkouts: no repository outside this module
  implements `Provider` or `KeyManager`. `KeyManager` is called by
  `cmd/hsm-tool`, by trustyca (`DestroyKeyPairOnSlot`) and by trusty
  (`EnumKeys`, pinned to v0.19.164). About 370 Go files in seven
  repositories import the module (secdi 169, trustyca 70, martini 42, porto
  37, trusty 26, kubeca 23, promptviser 4). porto imports `jwt`, `jwt/dpop`,
  `certutil` and `testca`, and has `jwt.Parser`, `jwt.Signer`,
  `jwt.MapClaims`, `jwt.Revocation` and `dpop.Signer` in its exported API.

## Goals

1. A listing costs requests in proportion to the keys it returns: pages,
   filters evaluated by the backend where it can, and no request per key for
   a field the caller did not ask for.
2. A public key is fetched only by `KeyInfo` and only on request.
3. One contract for a PKCS#11 token, AWS KMS, Google Cloud KMS and the
   in-memory providers. What a backend cannot do is an error the caller can
   test for, not a silent difference.
4. `context.Context` on every method that can block.
5. A new algorithm or key usage does not change an interface.
6. Typed usage, state and size, so callers stop parsing `Meta`.

Not goals: a search index of its own, AWS Config or Resource Explorer
clients (K2), the `Sign` path of roadmap item 1, and the decrypter of
roadmap item 2. Both items build on this contract.

## The contract

The identifiers below are the v2 names in package `cryptoprov`
([`provider.go`](../../cryptoprov/provider.go),
[`keys.go`](../../cryptoprov/keys.go)), where each has its full comment.
`TokenInfo` gained `Current`, the token a provider is logged in to.
`cryptoprov` also has helpers for provider authors: `PageKeys` answers a
request from a complete in-memory list, `NewPageToken` and `ParsePageToken`
keep a `PageCursor` (source, backend marker, offset) in a token bound to the
request, and `MarkError` gives a backend error a sentinel as a second
identity.

```go
// Provider is a key backend: a PKCS#11 token, a cloud KMS or an
// in-process store. Manufacturer and Model identify it in Crypto and in
// key URIs.
type Provider interface {
	KeyGenerator
	Manufacturer() string
	Model() string
}

// KeyGenerator creates keys and returns handles to them. A handle is a
// crypto.Signer for a signing key and a crypto.Decrypter for an
// encryption key.
type KeyGenerator interface {
	GenerateKey(ctx context.Context, req *GenerateKeyRequest) (crypto.PrivateKey, error)
	GetKey(ctx context.Context, keyID string) (crypto.PrivateKey, error)
	IdentifyKey(ctx context.Context, key crypto.PrivateKey) (keyID, label string, err error)
	ExportKey(ctx context.Context, keyID string) (uri string, key []byte, err error)
}

// KeyManager lists, describes and destroys the keys of the provider's
// store: the token it is logged in to, the AWS account and Region, the
// GCP key ring. It is optional; callers type-assert a Provider.
type KeyManager interface {
	ListKeys(ctx context.Context, req *ListKeysRequest) (*ListKeysResponse, error)
	KeyInfo(ctx context.Context, keyID string, fields KeyFields) (*KeyInfo, error)
	DestroyKey(ctx context.Context, keyID string) error
}

// TokenManager is implemented by a provider with several stores, which is
// crypto11 with the slots of its module.
type TokenManager interface {
	ListTokens(ctx context.Context) ([]TokenInfo, error)
	Token(slotID uint) (KeyManager, error)
}

type GenerateKeyRequest struct {
	Label string
	Type  string            // certutil.KeyTypeRSA, KeyTypeECDSA, KeyTypeMLDSA
	Size  int               // RSA bits; curve 256, 384, 521; ML-DSA 44, 65, 87
	Usage KeyUsage          // zero means KeyUsageSign
	Tags  map[string]string // AWS tags, GCP labels
}

type ListKeysRequest struct {
	PageSize  int       // zero means the provider default
	PageToken string    // NextPageToken of the previous page
	Filter    KeyFilter // the zero filter keeps every key
	Fields    KeyFields // what to fill besides ID and Name
}

type ListKeysResponse struct {
	Keys          []KeyInfo
	NextPageToken string // empty after the last page
}

// KeyFilter keeps the keys that pass every condition that is set.
type KeyFilter struct {
	Usage       KeyUsage          // a key with at least one of these usages
	Types       []string          // a key of one of these types
	Label       string            // the exact label
	LabelPrefix string            // a label that starts with this
	Tags        map[string]string // every tag with this value
	States      []KeyState        // a key in one of these states
}

type KeyUsage uint

const (
	KeyUsageSign    KeyUsage = 1 << iota // 1, as csr.SigningKey
	KeyUsageEncrypt                      // 2, as csr.EncryptionKey
)

type KeyState string

const (
	KeyStateEnabled         KeyState = "enabled"
	KeyStateDisabled        KeyState = "disabled"
	KeyStatePendingDeletion KeyState = "pending_deletion"
	KeyStateDestroyed       KeyState = "destroyed"
	KeyStateUnavailable     KeyState = "unavailable"
)

// KeyFields selects the KeyInfo fields a call fills.
type KeyFields uint

const (
	KeyFieldMetadata  KeyFields = 1 << iota // Label, Type, Size, Usage, Class, CreationTime
	KeyFieldState                           // State, CurrentVersionID
	KeyFieldTags                            // Tags
	KeyFieldPublicKey                       // PublicKey; KeyInfo only

	KeyFieldsAll = KeyFieldMetadata | KeyFieldState | KeyFieldTags
)

var (
	ErrKeyNotFound      = errors.New("key not found")
	ErrNotSupported     = errors.New("not supported by the provider")
	ErrInvalidPageToken = errors.New("invalid page token")
)

// AllKeys iterates over every page of a listing.
func AllKeys(ctx context.Context, km KeyManager, req *ListKeysRequest) iter.Seq2[*KeyInfo, error]
```

Listing the signing and encryption keys that are enabled, and creating a
tagged key:

```go
req := &cryptoprov.ListKeysRequest{
	PageSize: 50,
	Filter: cryptoprov.KeyFilter{
		Usage:  cryptoprov.KeyUsageSign | cryptoprov.KeyUsageEncrypt,
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

key, err := prov.GenerateKey(ctx, &cryptoprov.GenerateKeyRequest{
	Label: "issuer-2026",
	Type:  certutil.KeyTypeMLDSA,
	Size:  65,
	Tags: map[string]string{
		"app": "trustyca",
	},
})
```

### Rules of a listing

1. **Pages.** `ListKeys` returns at most `PageSize` keys. A page can hold
   fewer keys than `PageSize`, or none, and still have a `NextPageToken`: a
   provider that filters on its side stops after a bounded number of
   candidates instead of scanning the account to fill a page. The listing
   ends when `NextPageToken` is empty. `AllKeys` hides the loop.
2. **Tokens.** A page token is opaque and valid only with the `Filter` and
   `Fields` it was issued for; another filter or a malformed token is a
   wrapped `ErrInvalidPageToken`. Tokens are not secret and not
   authenticated: a forged one only moves the caller's own cursor.
3. **Fields.** A provider fills `ID` and `Name` always, the fields of the
   requested groups, and any other field it has at no extra request. A field
   that was neither requested nor free is zero. A group the backend does not
   have (tags on a PKCS#11 token) is left empty; only a filter on it is an
   error. `KeyFieldPublicKey` in a `ListKeysRequest` is an error: no listing
   fetches a public key.
4. **Filters.** A condition is evaluated by the backend when it can be and
   by the provider otherwise; the provider fetches what the filter needs
   even when `Fields` does not ask for it. A condition the provider cannot
   evaluate at all (tags on a PKCS#11 token) is a wrapped `ErrNotSupported`,
   never an empty result.
5. **No state filter by default.** An empty `States` keeps every key the
   backend lists, including an AWS key pending deletion (K12): finding out
   costs a request per key on AWS and GCP.
6. **Errors.** A failure ends the call without a partial page. A key the
   caller may not describe on AWS (`AccessDeniedException`) is left out and
   logged, as today.

### `KeyInfo` fields

| Field              | Group     | PKCS#11                   | AWS KMS                                   | Google Cloud KMS                                                       |
| ------------------ | --------- | ------------------------- | ----------------------------------------- | ---------------------------------------------------------------------- |
| `ID`               | always    | `CKA_ID`                  | key id (UUID)                             | CryptoKey id `K`; `K/cryptoKeyVersions/N` when a version was asked for |
| `Name`             | always    | empty                     | key ARN                                   | resource name                                                          |
| `Label`            | Metadata  | `CKA_LABEL`               | description                               | value of the `label` label                                             |
| `Type`             | Metadata  | from `CKA_KEY_TYPE`       | from the key spec                         | from the algorithm                                                     |
| `Size`             | Metadata  | from the key attributes   | from the key spec                         | from the algorithm                                                     |
| `Usage`            | Metadata  | `CKA_SIGN`, `CKA_DECRYPT` | `SIGN_VERIFY`, `ENCRYPT_DECRYPT`          | purpose                                                                |
| `Class`            | Metadata  | object class name         | empty                                     | empty                                                                  |
| `CreationTime`     | Metadata  | nil                       | creation date                             | creation time                                                          |
| `State`            | State     | always `enabled`          | key state                                 | state of the described version                                         |
| `CurrentVersionID` | State     | empty                     | empty                                     | the described version                                                  |
| `Tags`             | Tags      | not supported             | resource tags                             | labels                                                                 |
| `PublicKey`        | PublicKey | PEM                       | PEM                                       | PEM                                                                    |
| `Meta`             | any       | `parameter_set`           | native usage, origin, manager, algorithms | native purpose, protection level, algorithm                            |

`Type` is `RSA`, `ECDSA` or `ML-DSA` and `Size` the number
`csr.KeyRequest.Size` and `certutil.KeyInfo.KeySize` use; a key of another
family (symmetric, HMAC) has an empty `Type` and its native spec in `Meta`.
A usage other than signing and encryption is zero, with the native name in
`Meta`. On AWS and Google Cloud that includes secp256k1 and Ed25519 keys,
which v1 called `ECDSA`. The in-memory providers fill every group on every
call: usage, tags and creation time are recorded when a key is generated.

## What a listing costs

| Request                   | PKCS#11                                   | AWS KMS                                                                                        | Google Cloud KMS                                        |
| ------------------------- | ----------------------------------------- | ---------------------------------------------------------------------------------------------- | ------------------------------------------------------- |
| ids, no filter            | one object search, attributes of the page | `ListKeys`, one per 1000 keys; no `DescribeKey`                                                | `ListCryptoKeys`, one per page                          |
| `KeyFieldMetadata`        | same attribute read                       | one `DescribeKey` per returned key; none for a key from the tagging API that has the xpki tags | free                                                    |
| filter `Usage`, `Types`   | search template                           | metadata cache; a key not yet seen costs one `DescribeKey`, once                               | read from the listed key                                |
| filter `Label`            | search template                           | one `DescribeKey` on the alias                                                                 | `labels.label=` in the request                          |
| filter `LabelPrefix`      | label of each candidate                   | `ListAliases`, one per 100 aliases, then the matches                                           | `labels.label:` in the request, rechecked as a prefix   |
| filter `Tags`             | `ErrNotSupported`                         | `GetResources`, one per 100 tagged keys; `ListResourceTags` per candidate without `TagSearch`  | `labels.k=v` in the request                             |
| `KeyFieldState`, `States` | free                                      | the same `DescribeKey`                                                                         | primary version; one version listing per asymmetric key |
| public key                | never                                     | never                                                                                          | never                                                   |

### AWS KMS

KMS has no search, so the provider narrows the candidates before it
describes anything. Each `ListKeys` call picks one source:

1. **Tags** (`Filter.Tags`, with `TagSearch` on): `GetResources` for
   `kms:key` with the tag filters. Each result carries the key's tags.
2. **Label**: for `Filter.Label`, `DescribeKey` on `alias/<label>`,
   sanitized as `aliasFromLabel` does at creation; for `LabelPrefix`, a
   `ListAliases` sweep. With `TagSearch` on, the `xpki-label` tag is a second
   index and the results are merged. Candidates are confirmed against the
   description, which stays the label (K4).
3. **Everything else**: `ListKeys`, 1000 ids a page.

Then, per candidate, only what the filter and `Fields` need:

- **Immutable metadata cache.** Key spec, usage, creation date, origin and
  manager cannot change after `CreateKey`, so the provider keeps them per key
  id in a bounded map for its lifetime. A filter on usage or type costs a
  `DescribeKey` the first time a key is seen and nothing afterwards, which
  matters because most keys of a typical account are symmetric data keys
  that a PKI caller filters out. Description and state are mutable and are
  never served from the cache.
- **xpki tags.** With `TagSearch` on, `GenerateKey` writes `xpki-label`,
  `xpki-type`, `xpki-size` and `xpki-usage` beside the caller's tags. A
  candidate from the tagging API that has them needs no `DescribeKey` for
  `KeyFieldMetadata`. Tags can be edited by anyone with `kms:TagResource`:
  they feed listings only. `GetKey`, `KeyInfo` and `Sign` keep reading
  `DescribeKey` and `GetPublicKey`.
- **Bounded fan-out.** `DescribeKey` calls run `DescribeConcurrency` at a
  time (8, as today); the first failure cancels the rest.

A call examines at most one backend page of candidates, in chunks, and stops
when the caller's page is full: it then returns what matched with a token
that holds the source, its marker and the offset in the page.

Token config attributes: `TagSearch=true` (K3) with `TaggingEndpoint=<url>`,
`LabelSearch=scan` to match the description of every key as v1 did (K4),
`DescribeConcurrency` (1 to 64, default 8) and `MetadataCacheSize` (default
50000 keys, 0 disables); an invalid value fails `Init`. Two refinements of
the label index came with the implementation. A key from the alias sweep is
listed only through the alias its label gives it (`aliasFromLabel` of its
description), so a key with several matching aliases is listed once. With
`TagSearch`, the keys named by the `xpki-label` tag are read after the alias
source, and the one the alias of its label points at is skipped, since the
alias source returned it. The label tag is written only when the label is a
valid tag value. Permissions: `kms:ListKeys`,
`kms:DescribeKey`, `kms:ListAliases`; with `TagSearch`, `tag:GetResources`
and `kms:TagResource`; for tags without it, `kms:ListResourceTags`.

What stays expensive: the first listing with a usage or type filter and no
label or tag describes every key of the account once. Only an index
outside KMS avoids that. The tagging API is that index for tagged keys; AWS
Config and Resource Explorer need account-level setup and are left to the
application (K2).

### Google Cloud KMS

`ListCryptoKeys` returns the whole key, so a page costs one request. The
provider passes `PageSize` and the page token through, pushes down the
documented filter forms (`labels.<k>=<v>` for tags and the exact label,
`labels.label:<v>` for a prefix) and rechecks every condition on the
returned keys, so a filter the service treats differently cannot produce a
wrong page. Usage and type are checked on the returned key; pushing
`purpose=` down waits for a run against the service (K11). `Label` becomes
the value of the `label` label; the `protection=…,k=v` string v1 put there
moves to `Tags` and `Meta`. The state of an asymmetric key is the state of
a version, which costs a version listing per key, so it is fetched only for
`KeyFieldState` or a `States` filter. `KeyInfo` with a field mask stops
listing versions when the caller wants the label only.

### PKCS#11

`ListKeys` builds the search template from the filter: the private key
class, `CKA_KEY_TYPE` for one type, `CKA_LABEL` for the exact label,
`CKA_SIGN` for the signing usage and `CKA_DECRYPT` with `CKK_RSA` for the
encryption usage, since only an RSA key decrypts. A label prefix, several
types and "either usage" are checked on the candidate's attributes, at most
`max(page, 100)` candidates a call. `Usage` is what the token says. SoftHSM
sets `CKA_SIGN` and `CKA_DECRYPT` to true when a template names neither, so
`GenerateKey` sets both explicitly for an RSA key and `KeyInfo` reports
encryption for RSA keys only. The page token is the offset in the search order, so a
key created or destroyed between two pages can be repeated or skipped.
Attributes are read for the returned page only. PKCS#11 calls cannot be
cancelled; `ctx` is checked between batches and bounds the wait for a
session, which is the context-aware borrow of roadmap item 6. The listing
keeps its own read-only session and the re-login of XPKI-110.

Slots leave the generic contract (K6). `PKCS11Lib` is the `KeyManager` of
the token it is logged in to and implements `TokenManager`, so
`hsm-tool --token/--serial` keeps selecting another token.

### In-memory providers

`inmemcrypto` and `testprov` implement `KeyManager` over their key maps
with an offset token. They are the reference implementation of the
conformance suite and make the `hsm-tool` tests fixture-free.

## Generation

`GenerateKey` replaces `GenerateRSAKey`, `GenerateECDSAKey` and
`GenerateMLDSAKey`. `Type` and `Size` are the pair `csr.KeyRequest` already
carries, so `KeyRequest.Generate` becomes one call and the algorithm switch
moves into the providers, which each have the mapping to their own key
specs. The purpose of a `KeyRequest` becomes the usage of an RSA key only: an
ECDSA or ML-DSA key is always a signing key, as in v1, where the purpose
never reached the provider for them. `GenerateKeyRequest.Validate` rejects an unknown type, size or
usage before any request. A combination a provider does not offer is a
wrapped `ErrNotSupported`: `KeyUsageEncrypt` on the KMS providers until
roadmap item 2, `Tags` on PKCS#11, P-521 on GCP. SLH-DSA or ML-KEM become a
new `Type` value.

`IdentifyKey` and `ExportKey` keep their meaning and gain `ctx`: the first
reads token attributes in `crypto11`, the second calls `DescribeKey` on AWS.

## Migration: module `xpki/v2`

### What a client changes

| v1                                            | v2                                                                         |
| --------------------------------------------- | -------------------------------------------------------------------------- |
| import `github.com/effective-security/xpki/…` | `github.com/effective-security/xpki/v2/…`, in every file                   |
| `EnumKeys(slotID, prefix)`                    | `ListKeys(ctx, req)` with `Filter.LabelPrefix`, or `AllKeys`               |
| `KeyInfo(slotID, keyID, includePublic)`       | `KeyInfo(ctx, keyID, fields)`, with `KeyFieldPublicKey` for the public key |
| `DestroyKeyPairOnSlot(slotID, keyID)`         | `DestroyKey(ctx, keyID)`                                                   |
| `EnumTokens`, `CurrentSlotID`                 | `TokenManager` on `crypto11`; removed elsewhere                            |
| `FindKeyPairOnSlot(slotID, keyID, label)`     | `GetKey(ctx, keyID)`, or `ListKeys` with `Filter.Label`                    |
| `GenerateRSAKey(label, bits, purpose)`        | `GenerateKey(ctx, req)` with `Type: "RSA"`, `Size: bits`, `Usage`          |
| `GenerateECDSAKey(label, curve)`              | `GenerateKey` with `Type: "ECDSA"`, `Size: 256`, `384` or `521`            |
| `GenerateMLDSAKey(label, params)`             | `GenerateKey` with `Type: "ML-DSA"`, `Size: 44`, `65` or `87`              |
| `GetKey`, `IdentifyKey`, `ExportKey`          | the same with `ctx` first                                                  |

`GetKey` has no context-free form in v2, so the exported functions that
load or generate a key gain `ctx` in the same release: `Crypto.LoadPrivateKey`,
`NewSignerFromFromFile`, `NewSignerFromPEM`, `LoadTLSKeyPair` and
`TLSKeyPair`; `csr.KeyRequest.Generate`, `Provider.GenerateKeyAndRequest`
and `CreateRequestAndExportKey`; `authority.NewRoot`, `NewIssuer`,
`NewIssuerWithBundles` and `NewAuthority`; `jwt.NewProvider`, `LoadProvider`
and `MustNewProvider`. That is the loading half of roadmap item 1; `authority.Issuer.GenCert` gained `ctx` for
the same reason. Its
signing half (`Issuer.Sign`, `SignRequest`, the `crypto.Signer` path) stays
in item 1.

### Mechanics

- `release-v1` is cut from the last v1 commit and takes fixes only; the CI
  workflow already builds `release-*` branches, and `settag.yml` tags from
  `.VERSION` on whichever branch it runs.
- `main` becomes `module github.com/effective-security/xpki/v2` with
  `.VERSION` `v2.0`: the import path changes in 157 Go files, the `Makefile`
  `LDFLAGS`, the install paths in the READMEs and the generated API
  reference. The `xlog` logger namespace stays
  `github.com/effective-security/xpki`.
- Dependabot does not cross a major version, so a v1 client stays on v1
  until someone moves it.

### Constraints

- **One major per process for PKCS#11.** v1 and v2 are different packages
  with separate `crypto11` module registries. The second one to open a
  module sees `CKR_CRYPTOKI_ALREADY_INITIALIZED` and treats the module as
  owned by someone else, and the first one finalizes it on its last `Close`
  while the other still has sessions. The loader registries are separate
  too: a provider registered in v1 is not registered in v2.
- **porto first.** porto's exported API uses `jwt` and `dpop` types, and a
  v1 `jwt.MapClaims` is not a v2 `jwt.MapClaims`. An application moves every
  xpki import in the release in which it moves to a porto built on v2, even
  though `jwt`, `dpop` and `certutil` do not change in this design.
- **One breaking window.** Every signature change still planned should
  land before porto and the applications migrate, or they migrate twice
  (K9).

## Decisions

| ID  | Question                                             | Decision or recommendation                                                                                                                                                                                                                             | State               |
| --- | ---------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ | ------------------- |
| K1  | Compatibility strategy                               | Module `xpki/v2`. Not `…Ctx` twins; not `V2` interfaces in v1 (a type cannot have two methods of one name, so `GetKey`, `ExportKey`, `KeyInfo` and crypto11's `ListKeys` would need new names anyway); not a break in place.                           | Approved 2026-11-12 |
| K2  | AWS search beyond `ListKeys` and `DescribeKey`       | Alias index, immutable metadata cache and the Resource Groups Tagging API, all in the first AWS batch. No AWS Config or Resource Explorer client.                                                                                                      | Approved 2026-11-12 |
| K3  | Is the tagging API on by default?                    | Off; `TagSearch=true` in the token config turns it on. It needs `tag:GetResources` and `kms:TagResource`, which an existing deployment does not have, and without the second `CreateKey` with tags fails.                                              | Approved 2026-11-12 |
| K4  | What is a label on AWS, and how is it searched?      | The description stays the label. A label filter goes through the alias and, with `TagSearch`, the `xpki-label` tag; a key that has only a matching description is not found. `LabelSearch=scan` restores the v1 scan of every description.             | Approved 2026-11-12 |
| K5  | `includePublic bool` or a field mask on `KeyInfo`?   | `KeyFields`, with `KeyFieldPublicKey` valid for `KeyInfo` only. The same mask saves the GCP version listing and the AWS tag request when the caller does not need them.                                                                                | Approved 2026-11-12 |
| K6  | Slots                                                | Out of `KeyManager`. `TokenManager` is optional and implemented by `crypto11`.                                                                                                                                                                         | Approved 2026-11-12 |
| K7  | Generation                                           | One `GenerateKey` with `Type`, `Size`, `Usage` and `Tags`. `KeyUsageSign` and `KeyUsageEncrypt` are 1 and 2, as `csr.KeyPurpose`.                                                                                                                      | Approved 2026-11-12 |
| K8  | Page semantics                                       | Short and empty pages are allowed; tokens are opaque and bound to the filter.                                                                                                                                                                          | Approved 2026-11-12 |
| K9  | What else rides the major, and when do clients move? | Thread `ctx` through key loading and generation in this work (KM2). Finish the signing path of roadmap item 1 before porto and the applications migrate. Remove the symbols already marked `Deprecated` and the ones roadmap items 6 and 7 name (KM8). | Approved 2026-11-12 |
| K10 | v1 maintenance                                       | `release-v1`, security and correctness fixes only. XPKI-129 is fixed in v2 by KM3 and backported only on request.                                                                                                                                      | Approved 2026-11-12 |
| K11 | GCP filter pushdown                                  | Push down only the documented forms and recheck on the client. `purpose=` and a sorted single-version lookup wait for a run against the service, together with PQ7.                                                                                    | Approved 2026-11-12 |
| K12 | Default state filter                                 | None. `hsm-tool hsm key list` asks for enabled and disabled keys, which is what v1 listed on AWS, and for the RSA, ECDSA and ML-DSA key types; `--state all` and `--all` drop the two filters.                                                             | Approved 2026-11-12 |

## Risks and constraints

- **GCP listing is verified, key generation is not.** `TestLiveKMSListKeys`
  in `gcpkmscrypto`, the opt-in run against the service, passed on
  2026-11-12 (`us-central1`): pages, the label and tag filters, the state
  and `KeyInfo`. Every condition is rechecked on the client in any case, so
  a difference in the service would change the pushdown, not the result.
  `TestLiveKMSSign` covers RSA and ECDSA generation and signing on the
  service and has run on the in-process fake only (PLAN.md KM15).
- **The tagging API has no emulator.** local-kms does not implement it, so
  it is tested on an in-process fake; `TestLiveKMSListKeys` in
  `awskmscrypto` with `XPKI_LIVE_AWS_KMS_TAGSEARCH=true` is the opt-in run
  against the service (PLAN.md KM11); without that variable the test passed
  on the service on 2026-11-12 (`us-west-1`). Its results can lag a tag
  change.
- **Shared state.** The AWS metadata cache is read and written by
  concurrent listings and needs a test that races, and `make test RACE=true`.
- **The path change was a wide diff.** It changed no behavior: the same 576
  tests and the same coverage (92.2%) before and after.
- **Coverage.** Five implementations of a larger contract stay above the
  90% gate (92.9% in v2.0); the conformance suite carries much of it.

## Testing

- **Conformance suite** (`internal/provtest`): one `testify/suite` every
  provider runs. It asserts the listing rules: no key repeated or missed
  over a full listing at several page sizes, a token rejected with another
  filter, every filter against a known key set, zero values for fields not
  requested, no public key in any page, `ErrNotSupported` and
  `ErrKeyNotFound` where the contract says so, and a cancelled `ctx`.
- **Request counts** on the AWS fake and the GCP in-process server were the
  acceptance criteria: `TestListKeysRequestCounts` (`awskmscrypto`),
  `TestListKeysPages` (`gcpkmscrypto`) and the attribute-read count of
  `TestListKeysOnToken` (`crypto11`). `BenchmarkListKeys` in `awskmscrypto`
  replaces the v1 `BenchmarkEnumKeys`; the release notes compare the two.
  The plan had each provider list naively first, as a baseline for the
  optimized listing; the baseline was measured on the v1 `EnumKeys` at the
  last v1 commit instead, which does what the naive listing would have.
- **Fixtures**: SoftHSM and local-kms as today, gated with
  `internal/testenv`. Live AWS and GCP runs are opt-in and create billable
  keys.
