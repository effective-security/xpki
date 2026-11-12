package cryptoprov

import (
	"context"
	"crypto"
	"maps"
	"reflect"
	"sync"
	"sync/atomic"

	"github.com/cockroachdb/errors"
	"github.com/effective-security/xlog"
)

var logger = xlog.NewPackageLogger("github.com/effective-security/xpki", "cryptoprov")

// ErrInvalidURI is returned if the PKCS #11 URI is invalid.
var ErrInvalidURI = errors.New("invalid URI")

// ErrInvalidPrivateKeyURI is returned if the PKCS #11 URI is invalid for the private key object
var ErrInvalidPrivateKeyURI = errors.New("invalid URI for private key object")

// ErrNilProvider is returned by New and Crypto.Add for a nil provider,
// including a typed nil such as a nil *crypto11.PKCS11Lib.
var ErrNilProvider = errors.New("nil provider")

// ErrDuplicateProvider is returned by Crypto.Add, New and Load when a
// different provider is already registered for the same manufacturer and
// model.
var ErrDuplicateProvider = errors.New("duplicate provider")

// KeyGenerator creates keys and returns handles to them. A handle is a
// crypto.Signer for a signing key and a crypto.Decrypter for an encryption
// key; an ML-DSA signer follows the contract MLDSASignerOptions describes.
// Every method takes the caller's context: a KMS provider passes it to its
// requests, and crypto11, whose PKCS#11 calls cannot be cancelled, checks it
// before the call and while it waits for a session.
type KeyGenerator interface {
	// GenerateKey creates the key req describes and returns its handle. It
	// calls req.Validate first; a valid request the backend cannot serve
	// (an encryption key on a KMS provider, tags on a PKCS#11 token, a size
	// the backend does not offer) is a wrapped ErrNotSupported.
	GenerateKey(ctx context.Context, req *GenerateKeyRequest) (crypto.PrivateKey, error)
	// GetKey returns the handle of the key keyID, the KeyInfo.ID of a
	// listing or the id attribute of a key URI. A key the provider does not
	// have is a wrapped ErrKeyNotFound.
	GetKey(ctx context.Context, keyID string) (crypto.PrivateKey, error)
	// IdentifyKey returns the ID and the label of a handle this provider
	// returned.
	IdentifyKey(ctx context.Context, key crypto.PrivateKey) (keyID, label string, err error)
	// ExportKey returns what a configuration stores to load the key again:
	// the PEM encoded key from a provider with exportable keys (uri is then
	// empty), otherwise the pkcs11: URI of the key, which
	// Crypto.LoadPrivateKey resolves.
	ExportKey(ctx context.Context, keyID string) (uri string, key []byte, err error)
}

// KeyManager lists, describes and destroys the keys of the provider's store:
// the token it is logged in to, the AWS account and Region, the Google Cloud
// key ring. It is optional: callers type-assert a Provider. The rules of a
// listing are in Documentation/design/keymanager.md.
type KeyManager interface {
	// ListKeys returns one page of the keys that pass req.Filter, with the
	// fields req.Fields selects, and never a public key. A page can hold
	// fewer keys than req.PageSize, or none, and still have a
	// NextPageToken: the listing ends when that is empty (AllKeys hides the
	// loop). A condition the provider cannot evaluate is a wrapped
	// ErrNotSupported and a token of another request a wrapped
	// ErrInvalidPageToken. A failure returns no partial page.
	ListKeys(ctx context.Context, req *ListKeysRequest) (*ListKeysResponse, error)
	// KeyInfo describes the key keyID with the fields the mask selects;
	// KeyFieldPublicKey adds the PEM public key, which no other call
	// returns. A key the provider does not have is a wrapped
	// ErrKeyNotFound.
	KeyInfo(ctx context.Context, keyID string, fields KeyFields) (*KeyInfo, error)
	// DestroyKey destroys the key keyID, or schedules its destruction on a
	// backend that defers it (AWS KMS, Google Cloud KMS).
	DestroyKey(ctx context.Context, keyID string) error
}

// TokenManager is implemented by a provider with several stores, which is
// crypto11 with the slots of its PKCS#11 module. The KeyManager methods of
// the provider itself work on the token it is logged in to.
type TokenManager interface {
	// ListTokens returns the tokens of the provider; TokenInfo.Current
	// marks the one it is logged in to.
	ListTokens(ctx context.Context) ([]TokenInfo, error)
	// Token returns the KeyManager of the token in slot slotID.
	Token(slotID uint) (KeyManager, error)
}

// Provider is a key backend: a PKCS#11 token, a cloud KMS or an in-process
// store. Manufacturer and Model identify it in Crypto and in key URIs.
type Provider interface {
	KeyGenerator
	Manufacturer() string
	Model() string
}

// Crypto exposes instances of Provider, found by manufacturer and model.
// It is safe for concurrent use: Add may run while other goroutines call
// ByManufacturer or LoadPrivateKey.
type Crypto struct {
	provider   Provider
	defaultKey providerKey

	// lock serializes Add. byManufacturer is copied on write and never
	// modified once published, so lookups do not lock.
	lock           sync.Mutex
	byManufacturer atomic.Pointer[map[providerKey]Provider]
}

// providerKey identifies a provider in Crypto.
type providerKey struct {
	manufacturer string
	model        string
}

func keyOf(p Provider) providerKey {
	return providerKey{
		manufacturer: p.Manufacturer(),
		model:        p.Model(),
	}
}

// New creates an instance of Crypto providers. defaultProvider is required;
// providers are added with Add, so a nil entry or a conflicting duplicate
// fails New.
func New(defaultProvider Provider, providers []Provider) (*Crypto, error) {
	if isNilProvider(defaultProvider) {
		return nil, errors.Wrap(ErrNilProvider, "default provider is required")
	}

	c := &Crypto{
		provider:   defaultProvider,
		defaultKey: keyOf(defaultProvider),
	}

	logger.KV(xlog.NOTICE,
		"manufacturer", c.defaultKey.manufacturer,
		"model", c.defaultKey.model,
	)

	for i, p := range providers {
		if err := c.Add(p); err != nil {
			return nil, errors.WithMessagef(err, "unable to add provider at index %d", i)
		}
	}
	return c, nil
}

// Default returns a default crypto provider
func (c *Crypto) Default() Provider {
	return c.provider
}

// Add registers p for lookup by its manufacturer and model. Adding the same
// provider again, including the default one, is a no-op when its dynamic
// value is comparable, such as a pointer; the provider types in this module
// are. A provider value that is not comparable (a struct holding a map,
// slice or func) can not be matched, so adding it again returns
// ErrDuplicateProvider. A different provider with the manufacturer and model
// of a registered or the default provider returns ErrDuplicateProvider
// (XPKI-016), and a nil provider, including a typed nil, returns
// ErrNilProvider.
func (c *Crypto) Add(p Provider) error {
	if isNilProvider(p) {
		return errors.Wrap(ErrNilProvider, "unable to add provider")
	}

	key := keyOf(p)
	if c.provider != nil && key == c.defaultKey && !sameProvider(p, c.provider) {
		return duplicateProviderError(key)
	}

	c.lock.Lock()
	current := c.registered()
	if existing, ok := current[key]; ok {
		c.lock.Unlock()
		if sameProvider(p, existing) {
			return nil
		}
		return duplicateProviderError(key)
	}
	next := make(map[providerKey]Provider, len(current)+1)
	maps.Copy(next, current)
	next[key] = p
	c.byManufacturer.Store(&next)
	c.lock.Unlock()

	logger.KV(xlog.NOTICE,
		"manufacturer", key.manufacturer,
		"model", key.model,
	)
	return nil
}

// ByManufacturer returns the default provider or the registered provider for
// manufacturer and model. It does not lock and may run concurrently with Add.
func (c *Crypto) ByManufacturer(manufacturer, model string) (Provider, error) {
	key := providerKey{
		manufacturer: manufacturer,
		model:        model,
	}
	if c.provider != nil && key == c.defaultKey {
		return c.provider, nil
	}

	p, ok := c.registered()[key]
	if !ok {
		return nil, errors.Errorf("provider for %q and model %q not found", manufacturer, model)
	}
	return p, nil
}

// registered returns the published providers map, nil before the first Add.
// The caller must not modify it.
func (c *Crypto) registered() map[providerKey]Provider {
	if m := c.byManufacturer.Load(); m != nil {
		return *m
	}
	return nil
}

func duplicateProviderError(key providerKey) error {
	return errors.Wrapf(ErrDuplicateProvider, "manufacturer %q and model %q", key.manufacturer, key.model)
}

// isNilProvider reports whether p is nil or holds a nil pointer, map, slice,
// func, channel or interface, on which a Provider method may panic.
func isNilProvider(p Provider) bool {
	if p == nil {
		return true
	}
	v := reflect.ValueOf(p)
	switch v.Kind() {
	case reflect.Pointer, reflect.Map, reflect.Slice, reflect.Func, reflect.Chan,
		reflect.Interface, reflect.UnsafePointer:
		return v.IsNil()
	}
	return false
}

// sameProvider reports whether a and b are the same provider instance. It
// does not panic when the dynamic type is not comparable.
func sameProvider(a, b Provider) bool {
	va, vb := reflect.ValueOf(a), reflect.ValueOf(b)
	if va.Type() != vb.Type() || !va.Comparable() || !vb.Comparable() {
		return false
	}
	return va.Equal(vb)
}
