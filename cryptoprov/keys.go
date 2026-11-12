package cryptoprov

import (
	"context"
	"crypto/elliptic"
	"iter"
	"slices"
	"strings"
	"time"

	"github.com/cockroachdb/errors"
	"github.com/effective-security/xpki/v2/certutil"
	"github.com/effective-security/xpki/v2/internal/pagetoken"
)

const (
	// DefaultPageSize is the page size of a provider without a backend page
	// of its own (PKCS#11, the in-memory providers) when
	// ListKeysRequest.PageSize is zero.
	DefaultPageSize = 100

	// MaxPageSize is the largest page a provider returns; a larger
	// ListKeysRequest.PageSize is cut to it.
	MaxPageSize = 1000

	// usageSeparator separates the names of a KeyUsage with several usages.
	usageSeparator = ","

	usageSignName    = "sign"
	usageEncryptName = "encrypt"

	// The ECDSA curve sizes of GenerateKeyRequest.Size.
	curveP256 = 256
	curveP384 = 384
	curveP521 = 521
)

// ErrKeyNotFound is the cause of the error GetKey, KeyInfo, ExportKey and
// DestroyKey return for a key the provider does not have.
var ErrKeyNotFound = errors.New("key not found")

// ErrNotSupported is the cause of the error a provider returns for a request
// it understands and its backend cannot serve: a filter on tags on a PKCS#11
// token, an encryption key on a KMS provider, a key size the backend does not
// offer. It is never reported as an empty result.
var ErrNotSupported = errors.New("not supported by the provider")

// ErrInvalidPageToken is the cause of the error ListKeys returns for a
// ListKeysRequest.PageToken that is malformed or was issued for another
// Filter or Fields.
var ErrInvalidPageToken = errors.New("invalid page token")

// KeyUsage is a set of the operations a key is for. The values are those of
// csr.KeyPurpose, so KeyUsage(csr.SigningKey) is KeyUsageSign.
type KeyUsage uint

const (
	// KeyUsageSign is a key that signs: a crypto.Signer.
	KeyUsageSign KeyUsage = 1 << iota
	// KeyUsageEncrypt is a key that decrypts: a crypto.Decrypter.
	KeyUsageEncrypt

	// keyUsageAll has every known usage.
	keyUsageAll = KeyUsageSign | KeyUsageEncrypt
)

// Has reports whether u includes every usage of v.
func (u KeyUsage) Has(v KeyUsage) bool {
	return v != 0 && u&v == v
}

// String returns "sign", "encrypt", "sign,encrypt", or "" for no usage.
func (u KeyUsage) String() string {
	var names []string
	if u.Has(KeyUsageSign) {
		names = append(names, usageSignName)
	}
	if u.Has(KeyUsageEncrypt) {
		names = append(names, usageEncryptName)
	}
	return strings.Join(names, usageSeparator)
}

// ParseKeyUsage parses the String form of a KeyUsage: "sign", "encrypt" or
// both separated by a comma, case-insensitively. An empty string is no usage.
func ParseKeyUsage(s string) (KeyUsage, error) {
	var usage KeyUsage
	for name := range strings.SplitSeq(s, usageSeparator) {
		switch strings.ToLower(strings.TrimSpace(name)) {
		case "":
		case usageSignName:
			usage |= KeyUsageSign
		case usageEncryptName:
			usage |= KeyUsageEncrypt
		default:
			return 0, errors.Errorf("invalid key usage %q: expected %s or %s", name, usageSignName, usageEncryptName)
		}
	}
	return usage, nil
}

// KeyState is the state of a key, or of the key version a KeyInfo describes.
type KeyState string

const (
	// KeyStateEnabled is a key that can be used.
	KeyStateEnabled KeyState = "enabled"
	// KeyStateDisabled is a key that cannot be used until it is enabled
	// again.
	KeyStateDisabled KeyState = "disabled"
	// KeyStatePendingDeletion is a key scheduled for deletion, which the
	// backend may still cancel.
	KeyStatePendingDeletion KeyState = "pending_deletion"
	// KeyStateDestroyed is a key whose material is gone.
	KeyStateDestroyed KeyState = "destroyed"
	// KeyStateUnavailable is every other state in which the key cannot be
	// used: being created, waiting for imported material, a failed
	// generation. The native state is in KeyInfo.Meta.
	KeyStateUnavailable KeyState = "unavailable"
)

// keyStates are the known states.
var keyStates = []KeyState{
	KeyStateEnabled,
	KeyStateDisabled,
	KeyStatePendingDeletion,
	KeyStateDestroyed,
	KeyStateUnavailable,
}

// ParseKeyState parses a KeyState, case-insensitively.
func ParseKeyState(s string) (KeyState, error) {
	state := KeyState(strings.ToLower(strings.TrimSpace(s)))
	if !slices.Contains(keyStates, state) {
		return "", errors.Errorf("invalid key state %q: expected one of %v", s, keyStates)
	}
	return state, nil
}

// KeyFields selects the groups of KeyInfo fields a call fills. ID and Name
// are always filled.
type KeyFields uint

const (
	// KeyFieldMetadata selects Label, Type, Size, Usage, Class and
	// CreationTime.
	KeyFieldMetadata KeyFields = 1 << iota
	// KeyFieldState selects State and CurrentVersionID.
	KeyFieldState
	// KeyFieldTags selects Tags.
	KeyFieldTags
	// KeyFieldPublicKey selects PublicKey. It is valid for
	// KeyManager.KeyInfo only: no listing fetches a public key.
	KeyFieldPublicKey

	// KeyFieldsAll selects every group a listing can fill.
	KeyFieldsAll = KeyFieldMetadata | KeyFieldState | KeyFieldTags

	// keyFieldsKnown has every known group.
	keyFieldsKnown = KeyFieldsAll | KeyFieldPublicKey
)

// Has reports whether f selects every group of v.
func (f KeyFields) Has(v KeyFields) bool {
	return v != 0 && f&v == v
}

// Validate reports a mask with a group this version does not know, which a
// provider must not silently ignore.
func (f KeyFields) Validate() error {
	if unknown := f &^ keyFieldsKnown; unknown != 0 {
		return errors.Errorf("invalid key fields: unknown bits %#x", uint(unknown))
	}
	return nil
}

// TokenInfo describes a token of a provider with several stores, which is a
// PKCS#11 module with its slots.
type TokenInfo struct {
	// SlotID is the slot the token is in; TokenManager.Token takes it.
	SlotID uint
	// Description is the slot description.
	Description string
	// Label is the token label.
	Label string
	// Manufacturer is the token manufacturer.
	Manufacturer string
	// Model is the token model.
	Model string
	// Serial is the token serial number.
	Serial string
	// Current reports the token the provider is logged in to: the store its
	// own KeyManager methods work on.
	Current bool
}

// KeyInfo describes a key. A call fills ID and Name, the groups its KeyFields
// select and whatever else the provider has without another request; a field
// that was neither selected nor free is zero. The design document
// Documentation/design/keymanager.md has the source of each field per
// provider.
type KeyInfo struct {
	// ID identifies the key to GetKey, KeyInfo, ExportKey and DestroyKey:
	// CKA_ID on a PKCS#11 token, the key id (UUID) on AWS KMS, the CryptoKey
	// id on Google Cloud KMS ("K", or "K/cryptoKeyVersions/N" when the call
	// named a version).
	ID string
	// Name is the full resource name of a cloud key: the AWS key ARN, the
	// GCP resource name. Empty on PKCS#11 and in-memory providers.
	Name string

	// Label is the name the key was created with (KeyFieldMetadata):
	// CKA_LABEL, the AWS key description, the GCP "label" label.
	Label string
	// Type is the key algorithm (KeyFieldMetadata): certutil.KeyTypeRSA,
	// KeyTypeECDSA or KeyTypeMLDSA, and empty for a key of another family,
	// whose native spec is in Meta.
	Type string
	// Size is the RSA modulus size in bits, the ECDSA curve size or the
	// ML-DSA parameter set number (KeyFieldMetadata), as
	// csr.KeyRequest.Size and certutil.KeyInfo.KeySize carry it; zero when
	// Type is empty or the backend does not tell.
	Size int
	// Usage is what the key is for (KeyFieldMetadata); zero for a usage
	// other than signing and encryption, whose native name is in Meta.
	Usage KeyUsage
	// Class is the PKCS#11 object class name (KeyFieldMetadata); empty on
	// the other providers.
	Class string
	// CreationTime is when the key was created (KeyFieldMetadata); nil when
	// the backend does not tell, as on PKCS#11.
	CreationTime *time.Time

	// State is the state of the key, or on Google Cloud KMS of the version
	// CurrentVersionID names (KeyFieldState). A PKCS#11 key is always
	// enabled.
	State KeyState
	// CurrentVersionID is the key version the call described
	// (KeyFieldState); empty on a provider without key versions.
	CurrentVersionID string

	// Tags are the AWS resource tags or GCP labels of the key
	// (KeyFieldTags).
	Tags map[string]string

	// PublicKey is the PEM encoded public key (KeyFieldPublicKey, from
	// KeyManager.KeyInfo only).
	PublicKey string

	// Meta carries provider-specific details for display, such as the
	// native usage, origin and algorithm names. For an ML-DSA key it has
	// MetaParameterSet, for example "ML-DSA-65". Do not parse it: the typed
	// fields above carry what callers decide on.
	Meta map[string]string
}

// KeyFilter keeps the keys that pass every condition that is set; the zero
// filter keeps every key the backend lists.
type KeyFilter struct {
	// Usage keeps a key with at least one of these usages.
	Usage KeyUsage
	// Types keeps a key whose KeyInfo.Type is one of these.
	Types []string
	// Label keeps a key with exactly this label.
	Label string
	// LabelPrefix keeps a key whose label starts with this.
	LabelPrefix string
	// Tags keeps a key that has every one of these tags with this value.
	Tags map[string]string
	// States keeps a key in one of these states. Empty keeps every state,
	// including a key that is pending deletion.
	States []KeyState
}

// IsZero reports whether the filter has no condition.
func (f *KeyFilter) IsZero() bool {
	return f.Usage == 0 && len(f.Types) == 0 && f.Label == "" && f.LabelPrefix == "" &&
		len(f.Tags) == 0 && len(f.States) == 0
}

// Fields returns the KeyInfo groups Match reads for the conditions that are
// set, which a provider has to fill before it can evaluate the filter itself.
func (f *KeyFilter) Fields() KeyFields {
	var fields KeyFields
	if f.Usage != 0 || len(f.Types) > 0 || f.Label != "" || f.LabelPrefix != "" {
		fields |= KeyFieldMetadata
	}
	if len(f.Tags) > 0 {
		fields |= KeyFieldTags
	}
	if len(f.States) > 0 {
		fields |= KeyFieldState
	}
	return fields
}

// Match reports whether key passes every condition of the filter. The groups
// Fields names must be filled in key.
func (f *KeyFilter) Match(key *KeyInfo) bool {
	if f.Usage != 0 && key.Usage&f.Usage == 0 {
		return false
	}
	if len(f.Types) > 0 && !slices.Contains(f.Types, key.Type) {
		return false
	}
	if f.Label != "" && key.Label != f.Label {
		return false
	}
	if f.LabelPrefix != "" && !strings.HasPrefix(key.Label, f.LabelPrefix) {
		return false
	}
	for name, value := range f.Tags {
		if got, ok := key.Tags[name]; !ok || got != value {
			return false
		}
	}
	if len(f.States) > 0 && !slices.Contains(f.States, key.State) {
		return false
	}
	return true
}

// validate reports a condition no key can be tested against.
func (f *KeyFilter) validate() error {
	if unknown := f.Usage &^ keyUsageAll; unknown != 0 {
		return errors.Errorf("invalid key usage filter: unknown bits %#x", uint(unknown))
	}
	if slices.Contains(f.Types, "") {
		return errors.New("invalid key type filter: empty type")
	}
	for _, state := range f.States {
		if !slices.Contains(keyStates, state) {
			return errors.Errorf("invalid key state filter %q: expected one of %v", state, keyStates)
		}
	}
	if _, ok := f.Tags[""]; ok {
		return errors.New("invalid tag filter: empty tag name")
	}
	return nil
}

// ListKeysRequest asks KeyManager.ListKeys for one page of keys.
type ListKeysRequest struct {
	// PageSize is the largest number of keys to return. Zero means the
	// provider default, and a value above MaxPageSize is cut to it.
	PageSize int
	// PageToken is the NextPageToken of the previous page, with the same
	// Filter and Fields; empty for the first page.
	PageToken string
	// Filter selects the keys.
	Filter KeyFilter
	// Fields selects what to fill besides ID and Name. KeyFieldPublicKey is
	// an error.
	Fields KeyFields
}

// Validate reports a request no provider accepts: a negative page size, a
// field mask that asks a listing for the public key or has unknown groups,
// or an invalid filter. The page token is checked by the provider it is for.
func (r *ListKeysRequest) Validate() error {
	if r == nil {
		return errors.New("invalid list keys request: nil")
	}
	if r.PageSize < 0 {
		return errors.Errorf("invalid page size: %d", r.PageSize)
	}
	if err := r.Fields.Validate(); err != nil {
		return err
	}
	if r.Fields.Has(KeyFieldPublicKey) {
		return errors.New("invalid key fields: a listing does not return public keys, use KeyInfo")
	}
	return r.Filter.validate()
}

// Limit returns the number of keys a page of the request holds at most:
// PageSize, defaultSize (or DefaultPageSize) when it is zero, and never
// more than MaxPageSize.
func (r *ListKeysRequest) Limit(defaultSize int) int {
	size := r.PageSize
	if size <= 0 {
		size = defaultSize
	}
	if size <= 0 {
		size = DefaultPageSize
	}
	return min(size, MaxPageSize)
}

// ListKeysResponse is one page of a listing.
type ListKeysResponse struct {
	// Keys are the keys of the page, at most the page size. A page can hold
	// fewer keys than asked for, or none, while NextPageToken is set.
	Keys []KeyInfo
	// NextPageToken resumes the listing after this page; empty after the
	// last page.
	NextPageToken string
}

// PageCursor is where a listing resumes. A provider keeps it in
// ListKeysResponse.NextPageToken with NewPageToken and reads it back from the
// next request with ParsePageToken; callers treat the token as opaque.
type PageCursor struct {
	// Source names the candidate source the listing reads, for a provider
	// with more than one.
	Source string `json:"s,omitempty"`
	// Marker is the backend's own marker or page token of the page the
	// listing resumes in.
	Marker string `json:"m,omitempty"`
	// Offset is the number of candidates of that page, or of the whole
	// search order, the listing has examined.
	Offset int `json:"o,omitempty"`
}

// pageBinding is what a page token is bound to: the conditions and the field
// mask of the request, in a canonical order. The page size is not part of
// it, so a caller may change it between pages.
type pageBinding struct {
	Usage       KeyUsage          `json:"u,omitempty"`
	Types       []string          `json:"t,omitempty"`
	Label       string            `json:"l,omitempty"`
	LabelPrefix string            `json:"p,omitempty"`
	Tags        map[string]string `json:"g,omitempty"`
	States      []KeyState        `json:"s,omitempty"`
	Fields      KeyFields         `json:"f,omitempty"`
}

// binding returns the page token binding of the request.
func (r *ListKeysRequest) binding() ([]byte, error) {
	b := pageBinding{
		Usage:       r.Filter.Usage,
		Types:       slices.Sorted(slices.Values(r.Filter.Types)),
		Label:       r.Filter.Label,
		LabelPrefix: r.Filter.LabelPrefix,
		Tags:        r.Filter.Tags,
		States:      slices.Sorted(slices.Values(r.Filter.States)),
		Fields:      r.Fields,
	}
	return pagetoken.Binding(b)
}

// NewPageToken returns the page token that resumes the listing of req at
// cursor. It is for provider implementations.
func NewPageToken(req *ListKeysRequest, cursor PageCursor) (string, error) {
	binding, err := req.binding()
	if err != nil {
		return "", err
	}
	return pagetoken.Encode(binding, cursor)
}

// ParsePageToken returns the cursor of req.PageToken, the zero cursor for an
// empty token, or a wrapped ErrInvalidPageToken for a token that is
// malformed, has a negative offset or was issued for another Filter or
// Fields. It is for provider implementations.
func ParsePageToken(req *ListKeysRequest) (PageCursor, error) {
	var cursor PageCursor
	if req.PageToken == "" {
		return cursor, nil
	}
	binding, err := req.binding()
	if err != nil {
		return cursor, err
	}
	if err := pagetoken.Decode(binding, req.PageToken, &cursor); err != nil {
		return PageCursor{}, MarkError(errors.WithStack(err), ErrInvalidPageToken)
	}
	if cursor.Offset < 0 {
		return PageCursor{}, errors.Wrapf(ErrInvalidPageToken, "negative offset %d", cursor.Offset)
	}
	return cursor, nil
}

// PageKeys answers req from keys, the complete list of a provider that holds
// its keys in memory, in a stable order: it validates the request, skips the
// candidates the page token has passed, applies the filter and returns at
// most a page with the token of the next one. Every key must have the groups
// the filter reads; the keys are returned as they are, whatever req.Fields
// selects. The token is an offset in keys, so a key added or removed between
// two pages can be repeated or missed.
func PageKeys(req *ListKeysRequest, keys []KeyInfo) (*ListKeysResponse, error) {
	if err := req.Validate(); err != nil {
		return nil, err
	}
	cursor, err := ParsePageToken(req)
	if err != nil {
		return nil, err
	}

	limit := req.Limit(DefaultPageSize)
	res := &ListKeysResponse{
		Keys: make([]KeyInfo, 0, min(limit, len(keys))),
	}
	for i := min(cursor.Offset, len(keys)); i < len(keys); i++ {
		if !req.Filter.Match(&keys[i]) {
			continue
		}
		if len(res.Keys) == limit {
			// keys[i] is the first key of the next page
			res.NextPageToken, err = NewPageToken(req, PageCursor{Offset: i})
			if err != nil {
				return nil, err
			}
			break
		}
		res.Keys = append(res.Keys, keys[i])
	}
	return res, nil
}

// AllKeys iterates over the keys of every page of the listing req describes,
// starting at req.PageToken; req is not modified. An error ends the
// iteration: it is yielded once, with a nil key. A page without keys is not
// the end, only an empty NextPageToken is.
//
//	for key, err := range cryptoprov.AllKeys(ctx, km, req) {
//		if err != nil {
//			return err
//		}
//		fmt.Println(key.ID, key.Label)
//	}
func AllKeys(ctx context.Context, km KeyManager, req *ListKeysRequest) iter.Seq2[*KeyInfo, error] {
	return func(yield func(*KeyInfo, error) bool) {
		if req == nil {
			yield(nil, errors.New("invalid list keys request: nil"))
			return
		}
		page := *req
		for {
			if err := ctx.Err(); err != nil {
				yield(nil, errors.WithStack(err))
				return
			}
			resp, err := km.ListKeys(ctx, &page)
			if err != nil {
				yield(nil, err)
				return
			}
			if resp == nil {
				yield(nil, errors.New("provider returned no page"))
				return
			}
			for i := range resp.Keys {
				if !yield(&resp.Keys[i], nil) {
					return
				}
			}
			if resp.NextPageToken == "" {
				return
			}
			if resp.NextPageToken == page.PageToken {
				// a provider that returns the token it was given would
				// loop forever
				yield(nil, errors.New("provider returned the page token of the request"))
				return
			}
			page.PageToken = resp.NextPageToken
		}
	}
}

// GenerateKeyRequest asks KeyGenerator.GenerateKey for a new key.
type GenerateKeyRequest struct {
	// Label names the key: CKA_LABEL, the AWS description and alias, the
	// GCP "label" label and key id prefix. It may be empty: the PKCS#11 and
	// in-memory providers then generate one, and the KMS providers create
	// the key without a label.
	Label string
	// Type is the key algorithm: certutil.KeyTypeRSA, KeyTypeECDSA or
	// KeyTypeMLDSA.
	Type string
	// Size is the RSA modulus size in bits, the ECDSA curve size (256, 384
	// or 521) or the ML-DSA parameter set (MLDSA44, MLDSA65 or MLDSA87).
	Size int
	// Usage is what the key is for; zero means KeyUsageSign.
	Usage KeyUsage
	// Tags are attached to the key as AWS tags or GCP labels. A provider
	// without tags returns ErrNotSupported when they are set.
	Tags map[string]string
}

// KeyUsage returns the usage of the key to create: Usage, or KeyUsageSign
// when it is zero.
func (r *GenerateKeyRequest) KeyUsage() KeyUsage {
	if r.Usage == 0 {
		return KeyUsageSign
	}
	return r.Usage
}

// Validate reports a request no provider can serve: an unknown type, a size
// the type does not have, or a usage the type cannot have (only an RSA key
// encrypts). It does not know what a backend offers: a provider answers a
// valid request it cannot serve with ErrNotSupported. Providers call it
// before any request to their backend.
func (r *GenerateKeyRequest) Validate() error {
	if r == nil {
		return errors.New("invalid generate key request: nil")
	}
	usage := r.KeyUsage()
	if unknown := usage &^ keyUsageAll; unknown != 0 {
		return errors.Errorf("invalid key usage: unknown bits %#x", uint(unknown))
	}
	switch r.Type {
	case certutil.KeyTypeRSA:
		if r.Size <= 0 {
			return errors.Errorf("invalid RSA key size: %d", r.Size)
		}
	case certutil.KeyTypeECDSA:
		if _, err := ECDSACurve(r.Size); err != nil {
			return err
		}
	case certutil.KeyTypeMLDSA:
		if _, err := MLDSAParameters(r.Size); err != nil {
			return err
		}
	default:
		return errors.Errorf("invalid key type %q: expected %s, %s or %s",
			r.Type, certutil.KeyTypeRSA, certutil.KeyTypeECDSA, certutil.KeyTypeMLDSA)
	}
	if r.Type != certutil.KeyTypeRSA && usage != KeyUsageSign {
		return errors.Errorf("invalid key usage %q: a %s key is a signing key", usage, r.Type)
	}
	if _, ok := r.Tags[""]; ok {
		return errors.New("invalid tags: empty tag name")
	}
	return nil
}

// ECDSACurve returns the curve of an ECDSA key size as
// GenerateKeyRequest.Size carries it: 256, 384 or 521. Any other size is an
// error.
func ECDSACurve(size int) (elliptic.Curve, error) {
	switch size {
	case curveP256:
		return elliptic.P256(), nil
	case curveP384:
		return elliptic.P384(), nil
	case curveP521:
		return elliptic.P521(), nil
	}
	return nil, errors.Errorf("invalid ECDSA curve size (expected %d, %d or %d): %d", curveP256, curveP384, curveP521, size)
}
