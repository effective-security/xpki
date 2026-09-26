package cryptoprov

import (
	"crypto"
	"crypto/elliptic"
	"maps"
	"reflect"
	"sync"
	"sync/atomic"
	"time"

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

// TokenInfo provides PKCS #11 token info
type TokenInfo struct {
	SlotID       uint
	Description  string
	Label        string
	Manufacturer string
	Model        string
	Serial       string
}

// KeyInfo provides key information
type KeyInfo struct {
	ID               string
	Label            string
	Type             string
	Class            string
	CurrentVersionID string
	CreationTime     *time.Time
	PublicKey        string
	Meta             map[string]string
}

// KeyManager defines interface for key management operations
type KeyManager interface {
	CurrentSlotID() uint
	EnumTokens(currentSlotOnly bool) ([]TokenInfo, error)
	EnumKeys(slotID uint, prefix string) ([]KeyInfo, error)
	DestroyKeyPairOnSlot(slotID uint, keyID string) error
	FindKeyPairOnSlot(slotID uint, keyID, label string) (crypto.PrivateKey, error)
	KeyInfo(slotID uint, keyID string, includePublic bool) (*KeyInfo, error)
}

// KeyGenerator defines interface for key generation operations
type KeyGenerator interface {
	// GenerateRSAKey returns RSA key for purpose: 1-signing, 2-encryption
	GenerateRSAKey(label string, bits int, purpose int) (crypto.PrivateKey, error)
	GenerateECDSAKey(label string, curve elliptic.Curve) (crypto.PrivateKey, error)
	IdentifyKey(crypto.PrivateKey) (keyID, label string, err error)
	ExportKey(keyID string) (string, []byte, error)
	GetKey(keyID string) (crypto.PrivateKey, error)
}

// Provider defines an interface to work with crypto providers: HSM, SoftHSM, KMS, crypto
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
// provider instance again, including the default one, is a no-op. A
// different provider with the manufacturer and model of a registered or the
// default provider returns ErrDuplicateProvider (XPKI-016), and a nil
// provider, including a typed nil, returns ErrNilProvider.
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
