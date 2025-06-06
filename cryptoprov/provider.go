package cryptoprov

import (
	"crypto"
	"crypto/elliptic"
	"time"

	"github.com/cockroachdb/errors"
	"github.com/effective-security/xlog"
)

var logger = xlog.NewPackageLogger("github.com/effective-security/xpki", "cryptoprov")

// ErrInvalidURI is returned if the PKCS #11 URI is invalid.
var ErrInvalidURI = errors.New("invalid URI")

// ErrInvalidPrivateKeyURI is returned if the PKCS #11 URI is invalid for the private key object
var ErrInvalidPrivateKeyURI = errors.New("invalid URI for private key object")

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

// Provider defines an interface to work with crypto providers: HSM, SoftHSM, KMS, crytpto
type Provider interface {
	KeyGenerator
	Manufacturer() string
	Model() string
}

// Crypto exposes instances of Provider
type Crypto struct {
	provider       Provider
	byManufacturer map[string]Provider
}

// New creates an instance of Crypto providers
func New(defaultProvider Provider, providers []Provider) (*Crypto, error) {
	c := &Crypto{
		provider:       defaultProvider,
		byManufacturer: map[string]Provider{},
	}

	logger.KV(xlog.NOTICE,
		"manufacturer", defaultProvider.Manufacturer(),
		"model", defaultProvider.Model(),
	)

	for _, p := range providers {
		if err := c.Add(p); err != nil {
			return nil, err
		}
	}
	return c, nil
}

// Default returns a default crypto provider
func (c *Crypto) Default() Provider {
	return c.provider
}

// Add will add new provider
func (c *Crypto) Add(p Provider) error {
	m := p.Manufacturer()
	model := p.Model()
	key := m + "@" + model
	if existing, ok := c.byManufacturer[key]; ok {
		if existing.Manufacturer() != p.Manufacturer() ||
			existing.Model() != p.Model() {
			return errors.Errorf("duplicate provider specified for manufacturer: %s", m)
		}
	}
	c.byManufacturer[key] = p
	logger.KV(xlog.NOTICE,
		"manufacturer", m,
		"model", model,
	)
	return nil
}

// ByManufacturer returns a provider by manufacturer
func (c *Crypto) ByManufacturer(manufacturer, model string) (Provider, error) {
	if c.provider != nil &&
		c.provider.Manufacturer() == manufacturer &&
		c.provider.Model() == model {
		return c.provider, nil
	}

	key := manufacturer + "@" + model
	p, ok := c.byManufacturer[key]
	if !ok {
		return nil, errors.Errorf("provider for %q and model %q not found", manufacturer, model)
	}
	return p, nil
}
